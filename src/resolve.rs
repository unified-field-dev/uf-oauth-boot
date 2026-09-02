//! Resolve [`ResolvedOAuthClientConfig`] from Neutrino sealed secrets (+ env seed).

use lepton_auth::oauth::OAuthClientConfig;
use neutrino::secret_store::{PutSecretRequest, SecretId, SecretStore};
use neutrino::{list_secrets, ListedSecret, ValenceSealedStore};
use tracing::Instrument;

use crate::config::ResolvedOAuthClientConfig;
use crate::env;
use crate::error::ResolveOAuthConfigError;
use crate::{
    OAUTH_GITHUB_SECRET_NAME, OAUTH_GOOGLE_SECRET_NAME, OAUTH_REDIRECT_PATH, OAUTH_SECRET_KIND,
    OAUTH_SECRET_SCOPE,
};

const OWNER_ACTOR: &str = "system";

/// Build [`ResolvedOAuthClientConfig`] from Neutrino secrets (+ public client ids from env).
///
/// Loads existing Neutrino rows by stable name + [`OAUTH_SECRET_SCOPE`] first.
/// The latest matching row must have kind [`OAUTH_SECRET_KIND`] or resolve
/// returns [`ResolveOAuthConfigError::WrongKind`] without calling `get`.
/// When `seed_from_env` is true and env provides `UF_OAUTH_*_CLIENT_SECRET`,
/// seeds via `put_or_reuse` **only if** that name+scope is missing (first-boot
/// bootstrap). An existing sealed row always wins over env — later boots with
/// `seed_from_env=true` must not rotate vault ciphertext from a mismatched env.
///
/// Returns `Ok(None)` when OAuth is not configured (no mock flag and no usable
/// provider credentials).
///
/// Tracing span `uf_oauth_boot.resolve` records `operation` and `outcome` only.
///
/// # Errors
///
/// Returns [`ResolveOAuthConfigError`] when Neutrino `put_or_reuse` / `get` or
/// Valence secret listing fails while a provider path is active (client ids
/// present and/or `seed_from_env` seeding), when sealed bytes are not UTF-8, or
/// when the latest name+scope row has the wrong kind. Optional-OAuth hosts should
/// log once at SSR boot with `error = %e` (Display has no client-secret plaintext)
/// and continue without `.oauth(...)`.
///
/// # Examples
///
/// ```rust,ignore
/// use neutrino::vault::store_from_valence;
/// use uf_oauth_boot::resolve_oauth_config_from_neutrino;
///
/// let store = store_from_valence(oauth_valence);
/// match resolve_oauth_config_from_neutrino(&store, &public_base_url, true).await {
///     Ok(Some(cfg)) => builder = builder.oauth(cfg.into_lepton()),
///     Ok(None) => {}
///     Err(e) => tracing::warn!(error = %e, "OAuth Neutrino resolve skipped"),
/// }
/// ```
pub async fn resolve_oauth_config_from_neutrino(
    store: &ValenceSealedStore,
    public_base_url: &str,
    seed_from_env: bool,
) -> Result<Option<ResolvedOAuthClientConfig>, ResolveOAuthConfigError> {
    async move {
        let result =
            resolve_oauth_config_from_neutrino_inner(store, public_base_url, seed_from_env).await;
        let outcome = match &result {
            Ok(Some(_)) => "ok_configured",
            Ok(None) => "ok_unconfigured",
            Err(_) => "error",
        };
        tracing::Span::current().record("outcome", outcome);
        result
    }
    .instrument(tracing::info_span!(
        "uf_oauth_boot.resolve",
        operation = "resolve_oauth_config",
        outcome = tracing::field::Empty,
    ))
    .await
}

async fn resolve_oauth_config_from_neutrino_inner(
    store: &ValenceSealedStore,
    public_base_url: &str,
    seed_from_env: bool,
) -> Result<Option<ResolvedOAuthClientConfig>, ResolveOAuthConfigError> {
    let google_id = env::nonempty("UF_OAUTH_GOOGLE_CLIENT_ID");
    let github_id = env::nonempty("UF_OAUTH_GITHUB_CLIENT_ID");
    let use_mock = env::truthy("UF_OAUTH_USE_MOCK");
    let mock_oidc = env::nonempty("UF_MOCK_OIDC_URL");

    if !use_mock && google_id.is_none() && github_id.is_none() {
        return Ok(None);
    }

    // Mock CI path: no Neutrino I/O required when secrets are not being seeded.
    if use_mock
        && env::nonempty("UF_OAUTH_GOOGLE_CLIENT_SECRET").is_none()
        && env::nonempty("UF_OAUTH_GITHUB_CLIENT_SECRET").is_none()
    {
        return Ok(Some(oauth_config(
            public_base_url,
            google_id,
            None,
            github_id,
            None,
            true,
            mock_oidc,
        )));
    }

    let listed = list_secrets(store.valence.as_ref())
        .await
        .map_err(|source| ResolveOAuthConfigError::List {
            source: source.into(),
        })?;

    let google_secret = resolve_named_secret(
        store,
        &listed,
        OAUTH_GOOGLE_SECRET_NAME,
        seed_from_env
            .then(|| env::nonempty("UF_OAUTH_GOOGLE_CLIENT_SECRET"))
            .flatten(),
    )
    .await?;
    let github_secret = resolve_named_secret(
        store,
        &listed,
        OAUTH_GITHUB_SECRET_NAME,
        seed_from_env
            .then(|| env::nonempty("UF_OAUTH_GITHUB_CLIENT_SECRET"))
            .flatten(),
    )
    .await?;

    if !use_mock {
        let google_ready = google_id.as_ref().is_some_and(|id| !id.is_empty())
            && google_secret.as_ref().is_some_and(|s| !s.is_empty());
        let github_ready = github_id.as_ref().is_some_and(|id| !id.is_empty())
            && github_secret.as_ref().is_some_and(|s| !s.is_empty());
        if !google_ready && !github_ready {
            return Ok(None);
        }
    }

    Ok(Some(oauth_config(
        public_base_url,
        google_id,
        google_secret,
        github_id,
        github_secret,
        use_mock,
        mock_oidc,
    )))
}

fn oauth_config(
    public_base_url: &str,
    google_client_id: Option<String>,
    google_client_secret: Option<String>,
    github_client_id: Option<String>,
    github_client_secret: Option<String>,
    use_mock_provider: bool,
    mock_oidc_issuer_url: Option<String>,
) -> ResolvedOAuthClientConfig {
    ResolvedOAuthClientConfig::from_lepton(OAuthClientConfig {
        public_base_url: public_base_url.to_string(),
        redirect_path: OAUTH_REDIRECT_PATH.into(),
        google_client_id,
        google_client_secret,
        github_client_id,
        github_client_secret,
        use_mock_provider,
        mock_oidc_issuer_url,
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    })
}

fn plaintext_utf8(
    name: &'static str,
    plaintext: impl AsRef<[u8]>,
) -> Result<String, ResolveOAuthConfigError> {
    std::str::from_utf8(plaintext.as_ref())
        .map(str::to_owned)
        .map_err(|_| ResolveOAuthConfigError::InvalidUtf8 { name })
}

/// Latest matching row by `(created_at, current_version)` when duplicates exist.
fn latest_named_row<'a>(listed: &'a [ListedSecret], name: &str) -> Option<&'a ListedSecret> {
    listed
        .iter()
        .filter(|r| r.name == name && r.scope_path == OAUTH_SECRET_SCOPE)
        .max_by_key(|r| (r.created_at, r.current_version))
}

async fn load_named_secret(
    store: &ValenceSealedStore,
    listed: &[ListedSecret],
    name: &'static str,
) -> Result<Option<String>, ResolveOAuthConfigError> {
    let Some(row) = latest_named_row(listed, name) else {
        return Ok(None);
    };
    if row.kind != OAUTH_SECRET_KIND {
        return Err(ResolveOAuthConfigError::WrongKind {
            name,
            kind: row.kind.clone(),
        });
    }
    let revealed = store
        .get(&SecretId(row.id.clone()))
        .await
        .map_err(|source| ResolveOAuthConfigError::Get {
            name,
            source: source.into(),
        })?;
    Ok(Some(plaintext_utf8(name, revealed.plaintext.as_slice())?))
}

async fn resolve_named_secret(
    store: &ValenceSealedStore,
    listed: &[ListedSecret],
    name: &'static str,
    seed_plaintext: Option<String>,
) -> Result<Option<String>, ResolveOAuthConfigError> {
    // Sealed vault always wins: first-boot seed must not rotate on later boots.
    if let Some(existing) = load_named_secret(store, listed, name).await? {
        return Ok(Some(existing));
    }

    let Some(plaintext) = seed_plaintext else {
        return Ok(None);
    };

    let req = PutSecretRequest {
        name: name.to_string(),
        scope_path: OAUTH_SECRET_SCOPE.to_string(),
        kind: OAUTH_SECRET_KIND.to_string(),
        plaintext: plaintext.into_bytes(),
        owner_actor: OWNER_ACTOR.to_string(),
    };
    let secret_ref =
        store
            .put_or_reuse(req)
            .await
            .map_err(|source| ResolveOAuthConfigError::Seed {
                name,
                source: source.into(),
            })?;
    let revealed =
        store
            .get(&secret_ref.id)
            .await
            .map_err(|source| ResolveOAuthConfigError::Get {
                name,
                source: source.into(),
            })?;
    Ok(Some(plaintext_utf8(name, revealed.plaintext.as_slice())?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use chrono::{TimeZone, Utc};
    use neutrino::ListedSecret;

    use super::latest_named_row;
    use crate::{OAUTH_SECRET_KIND, OAUTH_SECRET_SCOPE};

    fn listed(id: &str, name: &str, kind: &str, version: i64, created_secs: i64) -> ListedSecret {
        ListedSecret {
            id: id.to_string(),
            name: name.to_string(),
            scope_path: OAUTH_SECRET_SCOPE.to_string(),
            kind: kind.to_string(),
            current_version: version,
            created_at: Utc.timestamp_opt(created_secs, 0).unwrap(),
            owner_subject_json: "{}".to_string(),
        }
    }

    #[test]
    fn latest_named_row_picks_highest_created_at_then_version() {
        let name = "oauth.google.client_secret";
        let mut other = listed("other-scope", name, OAUTH_SECRET_KIND, 99, 999);
        other.scope_path = "/other".to_string();
        let rows = vec![
            listed("old", name, OAUTH_SECRET_KIND, 9, 100),
            listed("mid", name, "password", 1, 200),
            listed("new", name, OAUTH_SECRET_KIND, 2, 200),
            other,
        ];

        let latest = latest_named_row(&rows, name).expect("match");
        assert_eq!(latest.id, "new");
        assert_eq!(latest.kind, OAUTH_SECRET_KIND);
        assert_eq!(latest.current_version, 2);
    }

    #[test]
    fn latest_named_row_empty_when_no_name_scope_match() {
        let rows = vec![listed(
            "x",
            "oauth.github.client_secret",
            OAUTH_SECRET_KIND,
            1,
            1,
        )];
        assert!(latest_named_row(&rows, "oauth.google.client_secret").is_none());
    }
}
