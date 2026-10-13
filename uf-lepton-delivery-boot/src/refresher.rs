//! The boot-started task that keeps live delivery services in step with the
//! settings row.
//!
//! It runs with the System Valence the host booted with, the same class of
//! System use as `uf-oauth-boot`'s boot resolve. Sign-up and password-reset
//! sends have no session actor, so something that already holds the secrets must
//! rebuild the services. Request handlers never reach System: an admin save only
//! pings [`Shared::notify`].

use std::sync::Arc;
use std::time::Duration;

use lepton_auth::delivery_settings::{SwappableEmail, SwappableSms};
use lepton_auth::services::OAuthHandle;
use lepton_auth::totp::key_ring::{install_key_ring, TotpKeyRing};
use neutrino::ValenceSealedStore;
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use valence::Valence;

use crate::error::BootError;
use crate::services::{build_email, build_oauth, build_sms, EmailSecrets, SmsSecrets};
use crate::store;
use crate::stored::StoredSettings;
use crate::vault::{self, read, read_version};

/// State the refresher and the backend share.
pub struct Shared {
    pub system: Valence,
    pub store: ValenceSealedStore,
    pub public_base_url: String,
    pub email: Arc<SwappableEmail>,
    pub sms: Arc<SwappableSms>,
    pub oauth: OAuthHandle,
    pub notify: Arc<Notify>,
}

/// Which revision each component last applied, so a failing component retries
/// without redoing the ones that worked.
#[derive(Debug, Default)]
pub struct Applied {
    email: Option<i64>,
    sms: Option<i64>,
    oauth: Option<i64>,
    totp_key_version: Option<i64>,
}

/// What one refresh pass did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The settings row does not exist yet.
    NoRow,
    /// Everything is already at the stored revision.
    Unchanged,
    /// Components were rebuilt; `failed` of them kept their previous service.
    Applied { revision: i64, failed: u8 },
}

fn parse_hex_key(hex: &str, version: i64) -> Result<[u8; 32], BootError> {
    let trimmed = hex.trim();
    if trimmed.len() != 64 {
        return Err(BootError::BadSealKey { version });
    }
    let mut out = [0u8; 32];
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| BootError::BadSealKey { version })?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| BootError::BadSealKey { version })?;
    }
    Ok(out)
}

async fn refresh_totp(shared: &Shared, applied: &mut Applied) -> Result<(), BootError> {
    let Some(row) = vault::find(&shared.system, &vault::TOTP_SEAL_KEY).await? else {
        return Ok(());
    };
    let current = row.current_version;
    if applied.totp_key_version == Some(current) {
        return Ok(());
    }
    let mut keys: Vec<(u32, [u8; 32])> = Vec::new();
    for version in 1..=current {
        let Ok(v32) = u32::try_from(version) else {
            continue;
        };
        match read_version(&shared.store, &vault::TOTP_SEAL_KEY, &row.id, version).await {
            Ok(hex) => match parse_hex_key(&hex, version) {
                Ok(key) => keys.push((v32, key)),
                Err(e) => {
                    tracing::warn!(target: "lepton.delivery.refresh", key_version = version, error = %e, "skipping unreadable TOTP key version");
                }
            },
            Err(e) if version == current => return Err(e),
            Err(e) => {
                tracing::warn!(target: "lepton.delivery.refresh", key_version = version, error = %e, "skipping unreadable TOTP key version");
            }
        }
    }
    let current32 = u32::try_from(current).map_err(|_| BootError::Build {
        channel: "totp_key",
    })?;
    let ring = TotpKeyRing::new(current32, keys).map_err(|_| BootError::Build {
        channel: "totp_key",
    })?;
    install_key_ring(ring);
    applied.totp_key_version = Some(current);
    tracing::info!(target: "lepton.totp.key_ring", key_version = current, "installed TOTP key ring");
    Ok(())
}

async fn refresh_email(
    shared: &Shared,
    applied: &mut Applied,
    settings: &StoredSettings,
    revision: i64,
) -> bool {
    let result = async {
        let secrets = EmailSecrets {
            smtp_password: read(&shared.store, &vault::SMTP_PASSWORD).await?,
            sendgrid_api_key: read(&shared.store, &vault::SENDGRID_API_KEY).await?,
        };
        build_email(&settings.email, &settings.endpoints, &secrets)
            .map_err(|_| BootError::Build { channel: "email" })
    }
    .await;
    match result {
        Ok(service) => {
            shared.email.swap(service);
            applied.email = Some(revision);
            tracing::info!(target: "lepton.delivery.swap", channel = "email", revision, "swapped email service");
            true
        }
        Err(e) => {
            tracing::warn!(target: "lepton.delivery.refresh", channel = "email", revision, error = %e, "keeping previous email service");
            false
        }
    }
}

async fn refresh_sms(
    shared: &Shared,
    applied: &mut Applied,
    settings: &StoredSettings,
    revision: i64,
) -> bool {
    let result = async {
        let secrets = SmsSecrets {
            twilio_api_secret: read(&shared.store, &vault::TWILIO_API_SECRET).await?,
        };
        build_sms(&settings.sms, &settings.endpoints, &secrets)
            .map_err(|_| BootError::Build { channel: "sms" })
    }
    .await;
    match result {
        Ok(service) => {
            shared.sms.swap(service);
            applied.sms = Some(revision);
            tracing::info!(target: "lepton.delivery.swap", channel = "sms", revision, "swapped sms service");
            true
        }
        Err(e) => {
            tracing::warn!(target: "lepton.delivery.refresh", channel = "sms", revision, error = %e, "keeping previous sms service");
            false
        }
    }
}

async fn refresh_oauth(
    shared: &Shared,
    applied: &mut Applied,
    settings: &StoredSettings,
    revision: i64,
) -> bool {
    let result: Result<(), BootError> = async {
        let google = read(&shared.store, &vault::GOOGLE_CLIENT_SECRET).await?;
        let github = read(&shared.store, &vault::GITHUB_CLIENT_SECRET).await?;
        shared.oauth.set(build_oauth(
            &shared.public_base_url,
            &settings.oauth,
            google,
            github,
        ));
        Ok(())
    }
    .await;
    match result {
        Ok(()) => {
            applied.oauth = Some(revision);
            tracing::info!(target: "lepton.delivery.swap", channel = "oauth", revision, "applied oauth settings");
            true
        }
        Err(e) => {
            tracing::warn!(target: "lepton.delivery.refresh", channel = "oauth", revision, error = %e, "keeping previous oauth settings");
            false
        }
    }
}

/// One refresh pass: reload the row, rebuild what changed, swap what built.
///
/// A component that fails to build keeps its previous service and is retried on
/// the next pass; the others still apply.
///
/// # Errors
///
/// [`BootError`] when the settings row cannot be read.
pub async fn refresh_once(shared: &Shared, applied: &mut Applied) -> Result<Outcome, BootError> {
    let totp = refresh_totp(shared, applied).await;
    let Some(loaded) = store::load(&shared.system).await? else {
        totp?;
        return Ok(Outcome::NoRow);
    };
    let revision = loaded.revision;
    let settings = &loaded.settings;
    let mut failed: u8 = u8::from(totp.is_err());
    if let Err(e) = totp {
        tracing::warn!(target: "lepton.delivery.refresh", error = %e, "TOTP key ring refresh failed; keeping previous ring");
    }
    let mut changed = false;
    if applied.email != Some(revision) {
        changed = true;
        failed += u8::from(!refresh_email(shared, applied, settings, revision).await);
    }
    if applied.sms != Some(revision) {
        changed = true;
        failed += u8::from(!refresh_sms(shared, applied, settings, revision).await);
    }
    if applied.oauth != Some(revision) {
        changed = true;
        failed += u8::from(!refresh_oauth(shared, applied, settings, revision).await);
    }
    if !changed && failed == 0 {
        return Ok(Outcome::Unchanged);
    }
    Ok(Outcome::Applied { revision, failed })
}

fn jitter(base: Duration) -> Duration {
    let mut b = [0u8; 1];
    if getrandom::getrandom(&mut b).is_err() {
        return base;
    }
    base + Duration::from_millis(u64::from(b[0]) * 8)
}

/// Spawn the supervised refresh loop.
pub fn spawn(
    shared: Arc<Shared>,
    interval: Duration,
    mut applied: Applied,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    const MAX_BACKOFF: Duration = Duration::from_secs(60);
    tokio::spawn(async move {
        let mut wait = interval;
        // Dropping the handle without calling `shutdown` leaves the loop running for
        // the life of the process, so a host that only keeps the services is safe.
        let mut watching_shutdown = true;
        loop {
            tokio::select! {
                () = tokio::time::sleep(jitter(wait)) => {}
                () = shared.notify.notified() => {}
                changed = shutdown.changed(), if watching_shutdown => {
                    match changed {
                        Ok(()) if *shutdown.borrow() => break,
                        Ok(()) => {}
                        Err(_) => watching_shutdown = false,
                    }
                }
            }
            match refresh_once(&shared, &mut applied).await {
                Ok(Outcome::Applied { failed, .. }) if failed > 0 => {
                    wait = (wait * 2).min(MAX_BACKOFF);
                }
                Ok(_) => wait = interval,
                Err(e) => {
                    wait = (wait * 2).min(MAX_BACKOFF);
                    tracing::warn!(target: "lepton.delivery.refresh", error = %e, "refresh failed; keeping previous services");
                }
            }
        }
    })
}
