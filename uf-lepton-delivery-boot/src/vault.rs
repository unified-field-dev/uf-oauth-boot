//! Fixed secret names and the few Neutrino operations this crate needs.
//!
//! Secrets are looked up by name and scope, never by a stored id, so a row
//! re-created by another process resolves the same way (the pattern
//! `uf-oauth-boot` uses).

use gauge::resource_permissions::ResourceAction;
use neutrino::secret_store::{PutSecretRequest, SecretId, SecretStore};
use neutrino::{list_secrets, ListedSecret, ValenceSealedStore, NEUTRINO_SECRET};
use valence::Valence;

use crate::error::BootError;
use crate::DELIVERY_ADMINS_GROUP_ID;

/// One fixed secret: name, scope, kind and a label for the permission bundle.
#[derive(Clone, Copy, Debug)]
pub struct SecretSpec {
    /// Fixed Neutrino name.
    pub name: &'static str,
    /// Neutrino scope path.
    pub scope: &'static str,
    /// Neutrino kind.
    pub kind: &'static str,
    /// Human label used for the Gauge bundle.
    pub display: &'static str,
}

/// Neutrino scope for delivery credentials.
pub const DELIVERY_SCOPE: &str = "/lepton/delivery";
/// Neutrino scope for the TOTP seal key.
pub const TOTP_SCOPE: &str = "/lepton/totp";
/// Kind for delivery credentials.
pub const DELIVERY_KIND: &str = "delivery_credential";
/// Kind for the TOTP seal key.
pub const TOTP_KIND: &str = "totp_seal_key";

/// SMTP password.
pub const SMTP_PASSWORD: SecretSpec = SecretSpec {
    name: "lepton.smtp.password",
    scope: DELIVERY_SCOPE,
    kind: DELIVERY_KIND,
    display: "Lepton SMTP password",
};
/// `SendGrid` API key.
pub const SENDGRID_API_KEY: SecretSpec = SecretSpec {
    name: "lepton.sendgrid.api_key",
    scope: DELIVERY_SCOPE,
    kind: DELIVERY_KIND,
    display: "Lepton SendGrid API key",
};
/// Twilio API secret.
pub const TWILIO_API_SECRET: SecretSpec = SecretSpec {
    name: "lepton.twilio.api_secret",
    scope: DELIVERY_SCOPE,
    kind: DELIVERY_KIND,
    display: "Lepton Twilio API secret",
};
/// TOTP seal key. One secret, rotated in place; the Neutrino version is the key version.
pub const TOTP_SEAL_KEY: SecretSpec = SecretSpec {
    name: "lepton.totp.seal_key",
    scope: TOTP_SCOPE,
    kind: TOTP_KIND,
    display: "Lepton TOTP seal key",
};
/// Google OAuth client secret (same name and scope `uf-oauth-boot` seeds).
pub const GOOGLE_CLIENT_SECRET: SecretSpec = SecretSpec {
    name: uf_oauth_boot::OAUTH_GOOGLE_SECRET_NAME,
    scope: uf_oauth_boot::OAUTH_SECRET_SCOPE,
    kind: uf_oauth_boot::OAUTH_SECRET_KIND,
    display: "Lepton Google OAuth client secret",
};
/// GitHub OAuth client secret (same name and scope `uf-oauth-boot` seeds).
pub const GITHUB_CLIENT_SECRET: SecretSpec = SecretSpec {
    name: uf_oauth_boot::OAUTH_GITHUB_SECRET_NAME,
    scope: uf_oauth_boot::OAUTH_SECRET_SCOPE,
    kind: uf_oauth_boot::OAUTH_SECRET_KIND,
    display: "Lepton GitHub OAuth client secret",
};

/// Every secret this crate manages, in seeding order.
pub const ALL_SECRETS: [SecretSpec; 6] = [
    SMTP_PASSWORD,
    SENDGRID_API_KEY,
    TWILIO_API_SECRET,
    GOOGLE_CLIENT_SECRET,
    GITHUB_CLIENT_SECRET,
    TOTP_SEAL_KEY,
];

fn vault_err(
    operation: &'static str,
    name: &'static str,
) -> impl FnOnce(neutrino::NeutrinoError) -> BootError {
    move |source| BootError::Vault {
        operation,
        name,
        source,
    }
}

/// Newest listed row for `spec`, by `(created_at, current_version)`.
///
/// # Errors
///
/// [`BootError::Vault`] when listing fails.
pub async fn find(valence: &Valence, spec: &SecretSpec) -> Result<Option<ListedSecret>, BootError> {
    let listed = list_secrets(valence, Some(spec.scope))
        .await
        .map_err(vault_err("list", spec.name))?;
    let (name, scope) = (spec.name, spec.scope);
    Ok(listed
        .into_iter()
        .filter(|r| r.name == name && r.scope_path == scope)
        .max_by_key(|r| (r.created_at, r.current_version)))
}

/// Current plaintext for `spec`. `None` when the secret is missing or still the
/// empty placeholder.
///
/// # Errors
///
/// [`BootError::Vault`] or [`BootError::NotUtf8`].
pub async fn read(
    store: &ValenceSealedStore,
    spec: &SecretSpec,
) -> Result<Option<String>, BootError> {
    let Some(row) = find(store.valence.as_ref(), spec).await? else {
        return Ok(None);
    };
    let revealed = store
        .get(&SecretId(row.id))
        .await
        .map_err(vault_err("get", spec.name))?;
    let text = String::from_utf8(revealed.plaintext.to_vec())
        .map_err(|_| BootError::NotUtf8 { name: spec.name })?;
    Ok((!text.trim().is_empty()).then_some(text))
}

/// Plaintext of one specific Neutrino version, for TOTP key history.
///
/// # Errors
///
/// [`BootError::Vault`] or [`BootError::NotUtf8`].
pub async fn read_version(
    store: &ValenceSealedStore,
    spec: &SecretSpec,
    id: &str,
    version: i64,
) -> Result<String, BootError> {
    let revealed = store
        .reveal_at_version(&SecretId(id.to_string()), version)
        .await
        .map_err(vault_err("reveal_version", spec.name))?;
    String::from_utf8(revealed.plaintext.to_vec())
        .map_err(|_| BootError::NotUtf8 { name: spec.name })
}

/// Create `spec` when missing, sealing `seed` (or an empty placeholder), and
/// make sure delivery admins hold View, Reveal and Edit on it. Returns the
/// secret id and whether it was created.
///
/// Boot-only: needs the System Valence the host started with. The placeholder
/// exists so admins, who may not *create* secrets, can *rotate* them later.
///
/// # Errors
///
/// [`BootError::Vault`] or [`BootError::Gauge`].
pub async fn ensure_exists(
    system_store: &ValenceSealedStore,
    spec: &SecretSpec,
    seed: Option<Vec<u8>>,
) -> Result<(String, bool), BootError> {
    let existing = find(system_store.valence.as_ref(), spec).await?;
    let (id, created) = if let Some(row) = existing {
        (row.id, false)
    } else {
        let secret_ref = system_store
            .put_or_reuse(PutSecretRequest {
                name: spec.name.to_string(),
                scope_path: spec.scope.to_string(),
                kind: spec.kind.to_string(),
                plaintext: seed.unwrap_or_default(),
                owner_actor: "system".to_string(),
            })
            .await
            .map_err(vault_err("seed", spec.name))?;
        (secret_ref.id.0, true)
    };
    gauge::resource_permissions::ensure_resource_permission_bundle_for_group(
        system_store.valence.as_ref(),
        NEUTRINO_SECRET,
        &id,
        spec.display,
        &[
            ResourceAction::View,
            ResourceAction::Reveal,
            ResourceAction::Edit,
        ],
        DELIVERY_ADMINS_GROUP_ID,
    )
    .await
    .map_err(|source| BootError::Gauge {
        operation: "secret_bundle",
        source,
    })?;
    Ok((id, created))
}

/// Replace the value of an existing secret as the actor behind `store`.
///
/// # Errors
///
/// [`BootError::SecretMissing`] when the secret was never created,
/// [`BootError::Vault`] when Neutrino refuses (for example no Edit right).
pub async fn replace(
    store: &ValenceSealedStore,
    spec: &SecretSpec,
    plaintext: &str,
    actor_label: &str,
) -> Result<(), BootError> {
    let Some(row) = find(store.valence.as_ref(), spec).await? else {
        return Err(BootError::SecretMissing { name: spec.name });
    };
    store
        .rotate(
            &SecretId(row.id),
            plaintext.as_bytes().to_vec(),
            actor_label,
        )
        .await
        .map_err(vault_err("rotate", spec.name))?;
    Ok(())
}

/// Lowercase hex of `bytes`.
#[must_use]
pub fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
