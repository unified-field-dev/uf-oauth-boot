//! Shared harness: one in-memory SQLite backend behind every logical database
//! the delivery boot touches (Lepton identity, Gauge, Neutrino).

#![allow(dead_code)]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use chrono::Utc;
use neutrino::clear_master_key_cache;
use tokio::sync::{Mutex, MutexGuard};
use valence::{
    register_backend_logical_names, router_key, Actor, DatabaseBackend, DatabaseRouter, Model,
    RegisterBackendLogicalNamesOptions, SqliteBackend, Valence, SQLITE_ENGINE_ID,
};

pub const ENV_KEYS: &[&str] = &[
    "UF_EMAIL_DRIVER",
    "UF_SMTP_HOST",
    "UF_SMTP_PORT",
    "UF_SMTP_USE_TLS",
    "UF_SMTP_USERNAME",
    "UF_SMTP_PASSWORD",
    "UF_EMAIL_FROM",
    "UF_EMAIL_FROM_NAME",
    "UF_TWILIO_EMAIL_API_KEY",
    "UF_TWILIO_ACCOUNT_SID",
    "UF_TWILIO_API_KEY",
    "UF_TWILIO_API_SECRET",
    "UF_TWILIO_AUTH_TOKEN",
    "UF_TWILIO_FROM",
    "UF_TWILIO_VERIFY_SERVICE_SID",
    "UF_TWILIO_API_BASE_URL",
    "UF_SENDGRID_API_BASE_URL",
    "UF_OAUTH_GOOGLE_CLIENT_ID",
    "UF_OAUTH_GOOGLE_CLIENT_SECRET",
    "UF_OAUTH_GITHUB_CLIENT_ID",
    "UF_OAUTH_GITHUB_CLIENT_SECRET",
    "UF_OAUTH_USE_MOCK",
    "UF_MOCK_OIDC_URL",
    "LEPTON_TOTP_SEAL_KEY",
    "NEUTRINO_MASTER_KEY",
];

fn lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Serializes tests (process env and the TOTP key ring are global) and clears env.
pub struct Env {
    _guard: MutexGuard<'static, ()>,
    saved: Vec<(String, Option<std::ffi::OsString>)>,
}

impl Env {
    pub async fn clean() -> Self {
        let guard = lock().lock().await;
        let mut saved = Vec::new();
        for key in ENV_KEYS {
            saved.push(((*key).to_string(), std::env::var_os(key)));
            // SAFETY: serialized by the global test lock; restored in Drop.
            unsafe { std::env::remove_var(key) };
        }
        // SAFETY: serialized by the global test lock; restored in Drop.
        unsafe {
            std::env::set_var("NEUTRINO_MASTER_KEY", "0".repeat(64));
            if std::env::var_os("VALENCE_OWNERSHIP_UNIFIED_FETCH").is_none() {
                std::env::set_var("VALENCE_OWNERSHIP_UNIFIED_FETCH", "0");
            }
        }
        clear_master_key_cache();
        Self {
            _guard: guard,
            saved,
        }
    }

    #[allow(clippy::unused_self)] // `&self` proves the global test lock is held.
    pub fn set(&self, key: &str, value: &str) {
        // SAFETY: the global test lock is held by `self`.
        unsafe { std::env::set_var(key, value) };
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..) {
            // SAFETY: still holding the global test lock.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(&key, v),
                    None => std::env::remove_var(&key),
                }
            }
        }
    }
}

/// A fresh System Valence over a fresh in-memory SQLite backend.
pub async fn system_valence() -> Valence {
    valence::deletion::register_noop_deletion_dispatcher_for_tests();
    valence::clear_for_test();
    let backend: Arc<dyn DatabaseBackend> = Arc::new(
        SqliteBackend::connect_memory()
            .await
            .expect("SqliteBackend::connect_memory"),
    );
    let mut router = DatabaseRouter::new();
    register_backend_logical_names(
        &mut router,
        Arc::clone(&backend),
        &["default"],
        RegisterBackendLogicalNamesOptions::default(),
    );
    register_backend_logical_names(
        &mut router,
        Arc::clone(&backend),
        neutrino::embedded_surreal::EMBEDDED_SURREAL_LOGICAL_NAMES,
        RegisterBackendLogicalNamesOptions::default(),
    );
    gauge::embedded_surreal::register_storage(&mut router, backend);
    gauge::touch_schema_inventory();
    uf_lepton_delivery_boot::ensure_schema_linked();
    Valence::builder()
        .database_router(Arc::new(router))
        .default_backend_key(router_key("default", SQLITE_ENGINE_ID))
        .with_actor(Actor::System {
            operation: "uf_lepton_delivery_boot_test".to_string(),
        })
        .build()
        .expect("build valence")
}

/// Create the permission row the host's manifest sync would create.
pub async fn sync_manage_delivery_permission(system: &Valence) {
    let now = Utc::now();
    let domain = gauge::generated::PermissionDomain::new(
        false,
        None,
        "Lepton".into(),
        Some("test domain".into()),
        now,
        now,
    )
    .expect("domain");
    gauge::generated::PermissionDomain::upsert(
        "lepton_test_domain",
        domain,
        system,
        valence::use_!(r"**Test:** Fixture **Permission Domain** save for `delivery_boot` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert domain");
    let perm = gauge::generated::Permission::new(
        valence::RecordId::new("user", "system"),
        valence::RecordId::new("permission_group", "super_user_group"),
        valence::RecordId::new("permission_domain", "lepton_test_domain"),
        uf_lepton_delivery_boot::MANAGE_DELIVERY_PERMISSION.into(),
        Some("Manage sign-in and delivery".into()),
        now,
        now,
    )
    .expect("permission");
    gauge::generated::Permission::upsert(
        "lepton_manage_delivery",
        perm,
        system,
        valence::use_!(r"**Test:** Fixture **Permission** save for `delivery_boot` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert permission");
}

/// Create a Lepton user plus its Gauge principal.
pub async fn seed_user(system: &Valence, id: &str) {
    let now = Utc::now();
    let user = lepton_identity::generated::User::new(
        Some(lepton_identity::generated::UserUserType::Person),
        Some("test-password-hash".to_string()),
        Some(lepton_identity::generated::UserStatus::Active),
        None,
        None,
        Some(now),
        None,
        None,
        now,
        now,
    )
    .expect("build user");
    let created = lepton_identity::generated::User::upsert(
        id,
        user,
        system,
        valence::use_!(r"**Test:** Fixture **User** save for `delivery_boot` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert user");
    gauge::generated::PermissionUserPrincipal::upsert(
        &format!("user:{id}"),
        gauge::generated::PermissionUserPrincipal::new(
            created.id().expect("user id").clone(),
            id.to_string(),
        )
        .expect("principal"),
        system,
        valence::use_!(r"**Test:** Fixture **Permission User Principal** save for `delivery_boot` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("upsert principal");
}

/// Make `user_id` a member of the delivery admins group.
pub async fn add_to_delivery_admins(system: &Valence, user_id: &str) {
    let group = gauge::generated::PermissionGroup::get(
        uf_lepton_delivery_boot::DELIVERY_ADMINS_GROUP_ID,
        system,
        valence::use_!(r"**Test:** Fixture **Permission Group** load for `delivery_boot` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("get group")
    .expect("admins group seeded");
    let principal = gauge::generated::PermissionUserPrincipal::get(
        &format!("user:{user_id}"),
        system,
        valence::use_!(r"**Test:** Fixture **Permission User Principal** load for `delivery_boot` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
    )
    .await
    .expect("get principal")
    .expect("principal");
    group
        .relate_to_member_record(
            principal.id().expect("pid"),
            system,
            valence::use_!(r"**Test:** Fixture member-edge relate for `delivery_boot` so the suite can arrange and assert persistence behavior. CI and developers running the suite only."),
        )
        .await
        .expect("relate member");
}

pub fn as_user(system: &Valence, id: &str) -> Valence {
    system.with_actor(Actor::User {
        user_id: id.to_string(),
    })
}

/// Poll `check` until it is true or `timeout` passes. No fixed sleeps standing in
/// for a condition.
pub async fn eventually<F, Fut>(timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
