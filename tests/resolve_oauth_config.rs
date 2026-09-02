//! Happy/sad coverage for [`uf_oauth_boot::resolve_oauth_config_from_neutrino`].

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex, OnceLock};

use neutrino::create_initial_neutrino_groups;
use neutrino::list_secrets;
use neutrino::secret_store::{PutSecretRequest, SecretStore};
use neutrino::vault::store_from_valence;
use neutrino::ValenceSealedStore;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::Registry;
use uf_oauth_boot::{
    resolve_oauth_config_from_neutrino, ResolveOAuthConfigError, OAUTH_GITHUB_SECRET_NAME,
    OAUTH_GOOGLE_SECRET_NAME, OAUTH_REDIRECT_PATH, OAUTH_SECRET_KIND, OAUTH_SECRET_SCOPE,
};
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter,
    RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

const OAUTH_ENV_KEYS: &[&str] = &[
    "UF_OAUTH_GOOGLE_CLIENT_ID",
    "UF_OAUTH_GOOGLE_CLIENT_SECRET",
    "UF_OAUTH_GITHUB_CLIENT_ID",
    "UF_OAUTH_GITHUB_CLIENT_SECRET",
    "UF_OAUTH_USE_MOCK",
    "UF_MOCK_OIDC_URL",
    "NEUTRINO_MASTER_KEY",
];

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved: Vec<(String, Option<std::ffi::OsString>)>,
}

impl EnvGuard {
    fn clear_oauth_env() -> Self {
        let lock = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut saved = Vec::new();
        for key in OAUTH_ENV_KEYS {
            saved.push(((*key).to_string(), std::env::var_os(key)));
            // SAFETY: serialized by env_lock; restored in Drop.
            unsafe {
                std::env::remove_var(key);
            }
        }
        Self { _lock: lock, saved }
    }

    fn set(key: &str, value: &str) {
        // SAFETY: called only while EnvGuard holds env_lock.
        unsafe {
            std::env::set_var(key, value);
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            // SAFETY: restore process env after test (still holding lock).
            unsafe {
                match value {
                    Some(v) => std::env::set_var(&key, v),
                    None => std::env::remove_var(&key),
                }
            }
        }
    }
}

fn test_master_key_hex() -> String {
    "0".repeat(64)
}

fn prepare_store_env() {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    // SAFETY: called only while EnvGuard holds env_lock.
    unsafe {
        std::env::set_var("NEUTRINO_MASTER_KEY", test_master_key_hex());
        if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
            std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
        }
    }
}

async fn test_valence() -> Valence {
    prepare_store_env();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(
        SqliteBackend::connect_memory()
            .await
            .expect("SqliteBackend::connect_memory"),
    );
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        backend,
        neutrino::embedded_surreal::EMBEDDED_SURREAL_LOGICAL_NAMES,
        RegisterBackendLogicalNamesOptions::default(),
    );

    let v = Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(router_key(
            neutrino::embedded_surreal::LOGICAL_NAME,
            SQLITE_ENGINE_ID,
        ))
        .with_actor(Actor::System {
            operation: "uf_oauth_boot_test".to_string(),
        })
        .build()
        .expect("build valence");
    gauge::touch_schema_inventory();
    create_initial_neutrino_groups(&v)
        .await
        .expect("create_initial_neutrino_groups");
    v
}

fn store(v: Valence) -> ValenceSealedStore {
    store_from_valence(v)
}

/// Valence with an empty router so Neutrino model queries fail (List path).
fn broken_list_valence() -> Valence {
    Valence::builder()
        .database_router(Arc::new(DatabaseRouter::new()))
        .default_backend_key(router_key(
            neutrino::embedded_surreal::LOGICAL_NAME,
            SQLITE_ENGINE_ID,
        ))
        .with_actor(Actor::System {
            operation: "uf_oauth_boot_list_fail".to_string(),
        })
        .build()
        .expect("build broken valence")
}

#[derive(Default)]
struct OutcomeVisitor {
    outcome: Option<String>,
    saw_secretish: bool,
}

impl Visit for OutcomeVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.outcome = Some(value.to_string());
        }
        if value.contains("must-not") || value.contains("secret") {
            self.saw_secretish = true;
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        if field.name() == "outcome" {
            self.outcome = Some(rendered.trim_matches('"').to_string());
        }
        if rendered.contains("must-not") {
            self.saw_secretish = true;
        }
    }
}

struct OutcomeCaptureLayer {
    outcomes: Arc<Mutex<Vec<String>>>,
    leaked: Arc<Mutex<bool>>,
}

impl<S> Layer<S> for OutcomeCaptureLayer
where
    S: tracing::Subscriber,
{
    fn on_record(
        &self,
        _id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        _ctx: Context<'_, S>,
    ) {
        let mut visitor = OutcomeVisitor::default();
        values.record(&mut visitor);
        if let Some(outcome) = visitor.outcome {
            self.outcomes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(outcome);
        }
        if visitor.saw_secretish {
            *self
                .leaked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        }
    }
}

#[tokio::test]
async fn returns_none_when_unconfigured() {
    let _env = EnvGuard::clear_oauth_env();
    let store = store(test_valence().await);
    let out = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("resolve");
    assert!(out.is_none());
}

#[tokio::test]
async fn mock_without_secrets_skips_store() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_USE_MOCK", "1");
    let store = store(test_valence().await);
    // Removing the master key makes any Neutrino seal/get fail — mock must still succeed.
    // SAFETY: EnvGuard holds env_lock for this test.
    unsafe {
        std::env::remove_var("NEUTRINO_MASTER_KEY");
    }
    let cfg = resolve_oauth_config_from_neutrino(&store, "http://example.test", true)
        .await
        .expect("mock resolve must skip Neutrino I/O even without master key")
        .expect("some config")
        .into_lepton();
    assert!(cfg.use_mock_provider);
    assert_eq!(cfg.public_base_url, "http://example.test");
    assert_eq!(cfg.redirect_path, OAUTH_REDIRECT_PATH);
    assert!(cfg.google_client_secret.is_none());
    assert!(cfg.github_client_secret.is_none());

    // Restore key only to list metadata (list does not decrypt).
    // SAFETY: EnvGuard holds env_lock.
    unsafe {
        std::env::set_var("NEUTRINO_MASTER_KEY", test_master_key_hex());
    }
    let listed = list_secrets(store.valence.as_ref())
        .await
        .expect("list_secrets");
    assert!(
        !listed.iter().any(|r| {
            (r.name == OAUTH_GOOGLE_SECRET_NAME || r.name == OAUTH_GITHUB_SECRET_NAME)
                && r.scope_path == OAUTH_SECRET_SCOPE
        }),
        "mock short-circuit must not seed vault rows"
    );
}

#[tokio::test]
async fn client_id_without_secret_returns_none() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    let store = store(test_valence().await);
    let out = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect("resolve");
    assert!(out.is_none(), "id without sealed secret must skip OAuth");
    assert_eq!(OAUTH_GOOGLE_SECRET_NAME, "oauth.google.client_secret");
    assert_eq!(OAUTH_GITHUB_SECRET_NAME, "oauth.github.client_secret");
    assert_eq!(OAUTH_SECRET_SCOPE, "/lepton/oauth");
    assert_eq!(OAUTH_SECRET_KIND, "oauth_client_secret");
    assert_eq!(OAUTH_REDIRECT_PATH, "/auth/oauth/callback");
}

#[tokio::test]
async fn store_failure_is_err_without_secret_leak() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "super-secret-must-not-leak";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", secret);
    let store = store(test_valence().await);
    // SAFETY: EnvGuard holds env_lock for this test.
    unsafe {
        std::env::remove_var("NEUTRINO_MASTER_KEY");
    }
    let err = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect_err("expected store failure");
    match &err {
        ResolveOAuthConfigError::Seed { name, .. } => {
            assert_eq!(*name, OAUTH_GOOGLE_SECRET_NAME);
        }
        other => panic!("expected Seed variant, got {other}"),
    }
    let msg = err.to_string();
    assert!(
        !msg.contains(secret),
        "error must not echo client secret: {msg}"
    );
}

#[tokio::test]
async fn seeds_google_secret_from_env_and_returns_config_happy() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "google-seed-secret";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", secret);
    let store = store(test_valence().await);

    let cfg = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();

    assert_eq!(cfg.public_base_url, "http://127.0.0.1:3000");
    assert_eq!(cfg.redirect_path, OAUTH_REDIRECT_PATH);
    assert_eq!(cfg.google_client_id.as_deref(), Some("google-client-id"));
    assert_eq!(cfg.google_client_secret.as_deref(), Some(secret));
    assert!(cfg.github_client_id.is_none());
    assert!(cfg.github_client_secret.is_none());
    assert!(!cfg.use_mock_provider);

    let listed = list_secrets(store.valence.as_ref())
        .await
        .expect("list_secrets");
    assert!(
        listed.iter().any(|r| {
            r.name == OAUTH_GOOGLE_SECRET_NAME
                && r.scope_path == OAUTH_SECRET_SCOPE
                && r.kind == OAUTH_SECRET_KIND
        }),
        "seed must write stable Google name under {OAUTH_SECRET_SCOPE} with {OAUTH_SECRET_KIND}"
    );
}

#[tokio::test]
async fn seeds_github_secret_from_env_and_returns_config_happy() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "github-seed-secret";
    EnvGuard::set("UF_OAUTH_GITHUB_CLIENT_ID", "github-client-id");
    EnvGuard::set("UF_OAUTH_GITHUB_CLIENT_SECRET", secret);
    let store = store(test_valence().await);

    let cfg = resolve_oauth_config_from_neutrino(&store, "https://app.example.test", true)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();

    assert_eq!(cfg.public_base_url, "https://app.example.test");
    assert_eq!(cfg.redirect_path, OAUTH_REDIRECT_PATH);
    assert_eq!(cfg.github_client_id.as_deref(), Some("github-client-id"));
    assert_eq!(cfg.github_client_secret.as_deref(), Some(secret));
    assert!(cfg.google_client_id.is_none());
    assert!(cfg.google_client_secret.is_none());

    let listed = list_secrets(store.valence.as_ref())
        .await
        .expect("list_secrets");
    assert!(
        listed
            .iter()
            .any(|r| r.name == OAUTH_GITHUB_SECRET_NAME && r.scope_path == OAUTH_SECRET_SCOPE),
        "seed must write stable GitHub name under {OAUTH_SECRET_SCOPE}"
    );
}

#[tokio::test]
async fn loads_existing_sealed_secret_without_env_seed_happy() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    let store = store(test_valence().await);
    let plaintext = b"vault-held-google-secret";
    store
        .put_or_reuse(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: "oauth_client_secret".to_string(),
            plaintext: plaintext.to_vec(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("pre-seed vault");

    let cfg = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();

    assert_eq!(
        cfg.google_client_secret.as_deref(),
        Some("vault-held-google-secret")
    );
    assert_eq!(cfg.redirect_path, OAUTH_REDIRECT_PATH);
    assert!(!cfg.use_mock_provider);
}

#[tokio::test]
async fn seed_from_env_false_ignores_env_secret_returns_none_sad() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", "must-not-be-seeded");
    let store = store(test_valence().await);

    let out = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect("resolve");
    assert!(
        out.is_none(),
        "seed_from_env=false must not pull env secret into config"
    );

    let listed = list_secrets(store.valence.as_ref())
        .await
        .expect("list_secrets");
    assert!(
        !listed
            .iter()
            .any(|r| r.name == OAUTH_GOOGLE_SECRET_NAME && r.scope_path == OAUTH_SECRET_SCOPE),
        "vault must stay empty when seed_from_env is false"
    );
}

#[tokio::test]
async fn mock_with_oidc_url_sets_issuer_happy() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_USE_MOCK", "1");
    EnvGuard::set("UF_MOCK_OIDC_URL", "http://127.0.0.1:9999/");
    let store = store(test_valence().await);

    let cfg = resolve_oauth_config_from_neutrino(&store, "http://example.test", false)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();
    assert!(cfg.use_mock_provider);
    assert_eq!(
        cfg.mock_oidc_issuer_url.as_deref(),
        Some("http://127.0.0.1:9999/")
    );
    assert!(cfg.google_client_secret.is_none());
}

#[tokio::test]
async fn whitespace_client_id_treated_as_unconfigured_sad() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "   ");
    let store = store(test_valence().await);
    let out = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("resolve");
    assert!(
        out.is_none(),
        "whitespace-only client id must not enable OAuth"
    );
}

#[tokio::test]
async fn reseed_same_plaintext_returns_usable_config_happy() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "idempotent-google-secret";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", secret);
    let store = store(test_valence().await);

    let first = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("first resolve")
        .expect("first config")
        .into_lepton();
    let second = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("second resolve")
        .expect("second config")
        .into_lepton();

    assert_eq!(first.google_client_secret.as_deref(), Some(secret));
    assert_eq!(second.google_client_secret.as_deref(), Some(secret));
    assert_eq!(first.redirect_path, second.redirect_path);
}

#[tokio::test]
async fn seed_from_env_does_not_rotate_existing_vault_secret_deny() {
    let _env = EnvGuard::clear_oauth_env();
    let vault_secret = "vault-canonical-google-secret";
    let env_attacker = "env-must-not-overwrite-vault";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", env_attacker);
    let store = store(test_valence().await);
    store
        .put_or_reuse(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: "oauth_client_secret".to_string(),
            plaintext: vault_secret.as_bytes().to_vec(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("pre-seed vault");

    let cfg = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();

    assert_eq!(
        cfg.google_client_secret.as_deref(),
        Some(vault_secret),
        "existing sealed row must win over seed_from_env plaintext"
    );

    let listed = list_secrets(store.valence.as_ref())
        .await
        .expect("list_secrets");
    let row = listed
        .into_iter()
        .find(|r| r.name == OAUTH_GOOGLE_SECRET_NAME && r.scope_path == OAUTH_SECRET_SCOPE)
        .expect("google secret row");
    let revealed = store
        .get(&neutrino::secret_store::SecretId(row.id))
        .await
        .expect("get vault");
    assert_eq!(
        revealed.plaintext.as_slice(),
        vault_secret.as_bytes(),
        "vault ciphertext must not rotate from mismatched env"
    );
    assert_ne!(
        cfg.google_client_secret.as_deref(),
        Some(env_attacker),
        "config must not carry env overwrite secret"
    );
}

#[tokio::test]
async fn seed_from_env_fills_missing_vault_allow() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "first-boot-only-secret";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", secret);
    let store = store(test_valence().await);

    let cfg = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();
    assert_eq!(cfg.google_client_secret.as_deref(), Some(secret));

    // Clear env secret; vault load must still succeed (seed was first-boot only).
    // SAFETY: EnvGuard holds env_lock.
    unsafe {
        std::env::remove_var("UF_OAUTH_GOOGLE_CLIENT_SECRET");
    }
    let again = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect("vault resolve")
        .expect("vault config")
        .into_lepton();
    assert_eq!(again.google_client_secret.as_deref(), Some(secret));
}

#[tokio::test]
async fn resolved_config_debug_hides_seeded_secret_sad() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "debug-must-not-print-this-secret";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", secret);
    let store = store(test_valence().await);

    let resolved = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("resolve")
        .expect("some config");
    let dbg = format!("{resolved:?}");
    assert!(
        !dbg.contains(secret),
        "ResolvedOAuthClientConfig Debug must not include client secret: {dbg}"
    );
    assert!(
        dbg.contains("<redacted>"),
        "Debug should mark secrets redacted: {dbg}"
    );
    let cfg = resolved.into_lepton();
    assert_eq!(cfg.google_client_secret.as_deref(), Some(secret));
}

#[tokio::test]
async fn wrong_kind_fails_closed_without_using_secret_sad() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "wrong-kind-plaintext-must-not-leak";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    let store = store(test_valence().await);
    store
        .put_or_reuse(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: "password".to_string(),
            plaintext: secret.as_bytes().to_vec(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("pre-seed wrong kind");

    let err = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect_err("wrong kind must fail closed");
    match &err {
        ResolveOAuthConfigError::WrongKind { name, kind } => {
            assert_eq!(*name, OAUTH_GOOGLE_SECRET_NAME);
            assert_eq!(kind, "password");
        }
        other => panic!("expected WrongKind, got {other}"),
    }
    let msg = err.to_string();
    assert!(
        !msg.contains(secret),
        "WrongKind Display must not echo plaintext: {msg}"
    );
    let dbg = format!("{err:?}");
    assert!(
        !dbg.contains(secret),
        "WrongKind Debug must not echo plaintext: {dbg}"
    );
}

#[tokio::test]
async fn invalid_utf8_sealed_secret_fails_closed_sad() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    let store = store(test_valence().await);
    let non_utf8 = vec![0xff, 0xfe, 0xfd];
    store
        .put_or_reuse(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: OAUTH_SECRET_KIND.to_string(),
            plaintext: non_utf8.clone(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("pre-seed non-utf8");

    let err = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect_err("non-utf8 sealed bytes must fail");
    match &err {
        ResolveOAuthConfigError::InvalidUtf8 { name } => {
            assert_eq!(*name, OAUTH_GOOGLE_SECRET_NAME);
        }
        other => panic!("expected InvalidUtf8, got {other}"),
    }
    let msg = err.to_string();
    assert!(
        msg.contains(OAUTH_GOOGLE_SECRET_NAME) && msg.contains("UTF-8"),
        "InvalidUtf8 Display should name secret and UTF-8: {msg}"
    );
    assert!(
        !msg.as_bytes().windows(3).any(|w| w == non_utf8.as_slice()),
        "InvalidUtf8 Display must not echo raw bytes: {msg}"
    );
}

#[tokio::test]
async fn get_failure_is_err_without_secret_leak_sad() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "get-fail-secret-must-not-leak";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    let store = store(test_valence().await);
    store
        .put_or_reuse(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: OAUTH_SECRET_KIND.to_string(),
            plaintext: secret.as_bytes().to_vec(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("pre-seed vault");

    // SAFETY: EnvGuard holds env_lock — decrypt/get requires master key.
    unsafe {
        std::env::remove_var("NEUTRINO_MASTER_KEY");
    }

    let err = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect_err("get without master key must fail");
    match &err {
        ResolveOAuthConfigError::Get { name, .. } => {
            assert_eq!(*name, OAUTH_GOOGLE_SECRET_NAME);
        }
        other => panic!("expected Get variant, got {other}"),
    }
    let msg = err.to_string();
    assert!(
        !msg.contains(secret),
        "Get Display must not echo client secret: {msg}"
    );
}

#[tokio::test]
async fn list_failure_is_err_without_secret_leak_sad() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "list-fail-secret-must-not-leak";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", secret);
    let mut store = store(test_valence().await);
    // Empty router → NeutrinoSecret::query fails → List.
    store.valence = Arc::new(broken_list_valence());

    let err = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect_err("list against empty router must fail");
    match &err {
        ResolveOAuthConfigError::List { .. } => {}
        other => panic!("expected List variant, got {other}"),
    }
    let msg = err.to_string();
    assert!(
        !msg.contains(secret),
        "List Display must not echo client secret: {msg}"
    );
    assert!(
        msg.contains("list Neutrino secrets"),
        "List Display should name the operation: {msg}"
    );
}

#[tokio::test]
async fn latest_duplicate_row_wins_integ_happy() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    let store = store(test_valence().await);

    store
        .put(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: "password".to_string(),
            plaintext: b"older-wrong-kind".to_vec(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("older duplicate row");
    // Ensure created_at ordering is stable across fast puts.
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    store
        .put(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: OAUTH_SECRET_KIND.to_string(),
            plaintext: b"newer-canonical-secret".to_vec(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("newer duplicate row");

    let cfg = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();
    assert_eq!(
        cfg.google_client_secret.as_deref(),
        Some("newer-canonical-secret"),
        "latest created_at row must win over older wrong-kind duplicate"
    );
}

#[tokio::test]
async fn tracing_outcome_ok_configured_and_unconfigured() {
    let _env = EnvGuard::clear_oauth_env();
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let leaked = Arc::new(Mutex::new(false));
    let layer = OutcomeCaptureLayer {
        outcomes: Arc::clone(&outcomes),
        leaked: Arc::clone(&leaked),
    };
    let subscriber = Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let out = resolve_oauth_config_from_neutrino(
        &store(test_valence().await),
        "http://127.0.0.1:3000",
        false,
    )
    .await
    .expect("resolve");
    assert!(out.is_none());

    EnvGuard::set("UF_OAUTH_USE_MOCK", "1");
    let _ = resolve_oauth_config_from_neutrino(
        &store(test_valence().await),
        "http://127.0.0.1:3000",
        false,
    )
    .await
    .expect("mock resolve")
    .expect("mock config");

    let captured = outcomes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        captured.iter().any(|o| o == "ok_unconfigured"),
        "expected ok_unconfigured in {captured:?}"
    );
    assert!(
        captured.iter().any(|o| o == "ok_configured"),
        "expected ok_configured in {captured:?}"
    );
    assert!(
        !*leaked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        "span records must not carry secret-ish values"
    );
}

#[tokio::test]
async fn tracing_outcome_error_on_wrong_kind() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    let store = store(test_valence().await);
    store
        .put_or_reuse(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: "password".to_string(),
            plaintext: b"trace-error-secret".to_vec(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("wrong kind");

    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let leaked = Arc::new(Mutex::new(false));
    let layer = OutcomeCaptureLayer {
        outcomes: Arc::clone(&outcomes),
        leaked: Arc::clone(&leaked),
    };
    let _guard = tracing::subscriber::set_default(Registry::default().with(layer));

    let _ = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect_err("wrong kind");

    let captured = outcomes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        captured.iter().any(|o| o == "error"),
        "expected error outcome in {captured:?}"
    );
    assert!(
        !*leaked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        "error span must not record plaintext"
    );
}

#[tokio::test]
async fn dual_provider_seed_happy() {
    let _env = EnvGuard::clear_oauth_env();
    let google_secret = "dual-google-secret";
    let github_secret = "dual-github-secret";
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", google_secret);
    EnvGuard::set("UF_OAUTH_GITHUB_CLIENT_ID", "github-client-id");
    EnvGuard::set("UF_OAUTH_GITHUB_CLIENT_SECRET", github_secret);
    let store = store(test_valence().await);

    let cfg = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", true)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();
    assert_eq!(cfg.google_client_secret.as_deref(), Some(google_secret));
    assert_eq!(cfg.github_client_secret.as_deref(), Some(github_secret));
    assert_eq!(cfg.google_client_id.as_deref(), Some("google-client-id"));
    assert_eq!(cfg.github_client_id.as_deref(), Some("github-client-id"));
    assert!(!cfg.use_mock_provider);
}

#[tokio::test]
async fn mock_truthy_true_and_true_enable_mock() {
    let _env = EnvGuard::clear_oauth_env();
    for flag in ["true", "TRUE"] {
        EnvGuard::set("UF_OAUTH_USE_MOCK", flag);
        let cfg = resolve_oauth_config_from_neutrino(
            &store(test_valence().await),
            "http://example.test",
            false,
        )
        .await
        .expect("resolve")
        .expect("mock config")
        .into_lepton();
        assert!(
            cfg.use_mock_provider,
            "UF_OAUTH_USE_MOCK={flag} must be truthy"
        );
    }
}

#[tokio::test]
async fn mock_with_client_secret_env_takes_vault_path_happy() {
    let _env = EnvGuard::clear_oauth_env();
    let secret = "mock-plus-secret-forces-vault";
    EnvGuard::set("UF_OAUTH_USE_MOCK", "1");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_SECRET", secret);
    let store = store(test_valence().await);

    let cfg = resolve_oauth_config_from_neutrino(&store, "http://example.test", true)
        .await
        .expect("resolve")
        .expect("some config")
        .into_lepton();
    assert!(cfg.use_mock_provider);
    assert_eq!(cfg.google_client_secret.as_deref(), Some(secret));

    let listed = list_secrets(store.valence.as_ref())
        .await
        .expect("list_secrets");
    assert!(
        listed.iter().any(|r| {
            r.name == OAUTH_GOOGLE_SECRET_NAME
                && r.scope_path == OAUTH_SECRET_SCOPE
                && r.kind == OAUTH_SECRET_KIND
        }),
        "mock + secret env must enter vault seed path"
    );
}

#[tokio::test]
async fn empty_sealed_plaintext_returns_none_sad() {
    let _env = EnvGuard::clear_oauth_env();
    EnvGuard::set("UF_OAUTH_GOOGLE_CLIENT_ID", "google-client-id");
    let store = store(test_valence().await);
    store
        .put_or_reuse(PutSecretRequest {
            name: OAUTH_GOOGLE_SECRET_NAME.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: OAUTH_SECRET_KIND.to_string(),
            plaintext: Vec::new(),
            owner_actor: "system".to_string(),
        })
        .await
        .expect("empty plaintext row");

    let out = resolve_oauth_config_from_neutrino(&store, "http://127.0.0.1:3000", false)
        .await
        .expect("resolve");
    assert!(
        out.is_none(),
        "empty sealed secret must not enable OAuth (not ready)"
    );
}
