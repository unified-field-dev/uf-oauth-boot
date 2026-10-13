//! Lepton email, SMS, OAuth and TOTP-seal settings kept in Neutrino, applied
//! live with no restart.
//!
//! Non-secret settings live in one Valence row (`lepton_delivery_settings`);
//! secrets (SMTP password, `SendGrid` key, Twilio API secret, OAuth client
//! secrets, the TOTP seal key) are sealed in Neutrino under fixed names. First
//! boot seeds both from env once; after that the env values are ignored. A
//! boot-started task polls the row's revision and swaps the live services, so a
//! change saved on the "Sign-in and delivery" page takes effect in every
//! process within seconds.
//!
//! # Examples
//!
//! Host boot, after Gauge manifest sync and under the System Valence the host
//! started with:
//!
//! ```rust,ignore
//! use lepton_auth::services::LeptonAuthServicesBuilder;
//! use uf_lepton_delivery_boot::{install_delivery, DeliveryOptions};
//!
//! let boot = install_delivery(
//!     &boot_valence,
//!     DeliveryOptions::new(public_base.clone()),
//! )
//! .await?;
//!
//! let services = LeptonAuthServicesBuilder::new()
//!     .email(boot.email())
//!     .sms(boot.sms())
//!     .oauth_handle(boot.oauth())
//!     .public_base_url(public_base)
//!     .build()?;
//! // Per request: provide_context(boot.settings_backend());
//! ```
//!
//! After a delivery admin saves new settings, `boot.email().send(..)` uses them
//! within one refresh interval, and the next TOTP verify opens secrets sealed
//! under older key versions.

mod backend;
mod error;
mod generated;
mod groups;
mod privacy_policies;
mod refresher;
mod services;
mod store;
mod stored;
mod vault;

use std::sync::Arc;
use std::time::Duration;

use lepton_auth::delivery_settings::{DeliverySettingsBackend, SwappableEmail, SwappableSms};
use lepton_auth::services::OAuthHandle;
use lepton_sms::{SmsDeliveryService, SmsServiceBuilder, TwilioVerifyConfig};
use lepton_smtp::{EmailDeliveryService, EmailServiceBuilder};
use neutrino::vault::store_from_valence;
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use valence::Valence;

pub use backend::NeutrinoDeliveryBackend;
pub use error::BootError;
pub use groups::ensure_delivery_admin_group;
pub use privacy_policies::{LeptonDeliveryGate, LEPTON_DELIVERY_GATE, MANAGE_DELIVERY_PERMISSION};
pub use store::{Loaded, SETTINGS_ROW_ID};
pub use stored::{StoredEmail, StoredEndpoints, StoredOAuth, StoredSettings, StoredSms};
pub use vault::{SecretSpec, ALL_SECRETS};

/// Group whose members hold [`MANAGE_DELIVERY_PERMISSION`].
pub const DELIVERY_ADMINS_GROUP_ID: &str = "lepton.delivery.admins";

/// Generated settings model, re-exported so hosts keep the schema linked.
pub use generated::LeptonDeliverySettings;

/// Touch the schema inventory so the settings table registers before the host
/// syncs typed tables. Call once at boot, before `sync_typed_tables_from_registry`.
pub fn ensure_schema_linked() {
    let _ = std::any::type_name::<LeptonDeliverySettings>();
}

/// How to install delivery settings.
#[derive(Clone, Debug)]
pub struct DeliveryOptions {
    /// Public origin used in OAuth redirect URLs.
    pub public_base_url: String,
    /// Seed the settings row and secrets from env when they do not exist yet.
    /// Existing rows and secrets always win.
    pub seed_from_env: bool,
    /// How often each process checks the settings revision.
    pub refresh_interval: Duration,
}

impl DeliveryOptions {
    /// Options with env seeding on and a 5 second refresh interval.
    #[must_use]
    pub fn new(public_base_url: impl Into<String>) -> Self {
        Self {
            public_base_url: public_base_url.into(),
            seed_from_env: true,
            refresh_interval: Duration::from_secs(5),
        }
    }
}

/// Handles produced by [`install_delivery`].
pub struct DeliveryBoot {
    email: Arc<SwappableEmail>,
    sms: Arc<SwappableSms>,
    oauth: OAuthHandle,
    backend: Arc<NeutrinoDeliveryBackend>,
    notify: Arc<Notify>,
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl DeliveryBoot {
    /// Email adapter for `LeptonAuthServicesBuilder::email`. Swaps on settings change.
    #[must_use]
    pub fn email(&self) -> Arc<dyn EmailDeliveryService> {
        self.email.clone()
    }

    /// SMS adapter for `LeptonAuthServicesBuilder::sms`. Swaps on settings change.
    #[must_use]
    pub fn sms(&self) -> Arc<dyn SmsDeliveryService> {
        self.sms.clone()
    }

    /// OAuth handle for `LeptonAuthServicesBuilder::oauth_handle`.
    #[must_use]
    pub fn oauth(&self) -> OAuthHandle {
        self.oauth.clone()
    }

    /// Backend to `provide_context` for the settings page's server functions.
    #[must_use]
    pub fn settings_backend(&self) -> Arc<dyn DeliverySettingsBackend> {
        self.backend.clone()
    }

    /// Ask the refresher to re-read settings now instead of at the next tick.
    pub fn refresh_now(&self) {
        self.notify.notify_one();
    }

    /// Stop the refresher and wait for it to finish.
    ///
    /// Dropping the handle without calling this leaves the refresher running for
    /// the life of the process, which is what most hosts want.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_seed(spec: &SecretSpec) -> Option<Vec<u8>> {
    let key = match spec.name {
        n if n == vault::SMTP_PASSWORD.name => "UF_SMTP_PASSWORD",
        n if n == vault::SENDGRID_API_KEY.name => "UF_TWILIO_EMAIL_API_KEY",
        n if n == vault::TWILIO_API_SECRET.name => "UF_TWILIO_API_SECRET",
        n if n == vault::GOOGLE_CLIENT_SECRET.name => "UF_OAUTH_GOOGLE_CLIENT_SECRET",
        n if n == vault::GITHUB_CLIENT_SECRET.name => "UF_OAUTH_GITHUB_CLIENT_SECRET",
        n if n == vault::TOTP_SEAL_KEY.name => "LEPTON_TOTP_SEAL_KEY",
        _ => return None,
    };
    env_nonempty(key).map(String::into_bytes)
}

fn random_key_hex() -> Result<Vec<u8>, BootError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| BootError::Random)?;
    Ok(vault::hex_lower(&bytes).into_bytes())
}

/// What the process would have used before settings moved to Neutrino, so a
/// host keeps working if the first Neutrino refresh cannot complete.
fn env_fallback() -> (Arc<dyn EmailDeliveryService>, Arc<dyn SmsDeliveryService>) {
    let email = EmailServiceBuilder::from_env()
        .and_then(EmailServiceBuilder::build)
        .or_else(|_| EmailServiceBuilder::new().noop().build())
        .unwrap_or_else(|_| unreachable_noop_email());
    let sms = TwilioVerifyConfig::from_env()
        .and_then(|cfg| SmsServiceBuilder::new().twilio_verify(cfg).build())
        .or_else(|_| SmsServiceBuilder::new().noop().build())
        .unwrap_or_else(|_| unreachable_noop_sms());
    (email, sms)
}

fn unreachable_noop_email() -> Arc<dyn EmailDeliveryService> {
    Arc::new(lepton_smtp::NoopEmailAdapter)
}

fn unreachable_noop_sms() -> Arc<dyn SmsDeliveryService> {
    Arc::new(lepton_sms::NoopSmsAdapter)
}

/// Seed the admins group and every managed secret. Returns the names of the
/// secrets that were created from a real value (env or generated).
async fn seed_secrets(
    shared: &refresher::Shared,
    options: &DeliveryOptions,
) -> Result<Vec<&'static str>, BootError> {
    let mut seeded_names: Vec<&'static str> = Vec::new();
    if let Err(e) = groups::ensure_delivery_admin_group(&shared.system).await {
        tracing::warn!(target: "lepton.delivery.install", error = %e, "delivery admin group seed skipped; keeping env services");
        return Ok(seeded_names);
    }
    for spec in ALL_SECRETS {
        let seed = if spec.name == vault::TOTP_SEAL_KEY.name {
            // The seal key must always exist; env supplies version 1 when set.
            match options.seed_from_env.then(|| env_seed(&spec)).flatten() {
                Some(v) => Some(v),
                None => Some(random_key_hex()?),
            }
        } else {
            options.seed_from_env.then(|| env_seed(&spec)).flatten()
        };
        let had_seed = seed.as_ref().is_some_and(|s| !s.is_empty());
        match vault::ensure_exists(&shared.store, &spec, seed).await {
            Ok((_, true)) if had_seed => seeded_names.push(spec.name),
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(target: "lepton.delivery.install", secret = spec.name, error = %e, "secret seed skipped");
            }
        }
    }
    Ok(seeded_names)
}

/// Create the settings row from env when missing, and record which secrets were
/// just seeded. Returns whether the row was created.
async fn seed_row(system: &Valence, options: &DeliveryOptions, seeded: &[&'static str]) -> bool {
    let now = chrono::Utc::now();
    let mut initial = if options.seed_from_env {
        StoredSettings::from_env()
    } else {
        StoredSettings::default()
    };
    for name in seeded {
        initial.secret_rotated.insert((*name).to_string(), now);
    }
    if initial
        .secret_rotated
        .contains_key(vault::TOTP_SEAL_KEY.name)
    {
        initial.totp_key_rotated_at = Some(now);
    }
    let created_row = match store::seed_if_missing(system, &initial).await {
        Ok(created) => created,
        Err(e) => {
            tracing::warn!(target: "lepton.delivery.install", error = %e, "settings row seed skipped");
            false
        }
    };
    if !created_row && !seeded.is_empty() {
        let names: Vec<&'static str> = seeded.to_vec();
        if let Err(e) = store::save(system, move |s| {
            for n in names {
                s.secret_rotated.entry(n.to_string()).or_insert(now);
            }
        })
        .await
        {
            tracing::warn!(target: "lepton.delivery.install", error = %e, "recording seeded secrets failed");
        }
    }
    created_row
}

/// Seed, resolve and start live delivery settings.
///
/// Runs once at host boot under `system`, the System Valence the host started
/// with. Steps: register the settings table; seed the admins group; create each
/// secret (from env when seeding is on, else an empty placeholder) and let
/// delivery admins rotate it; create the settings row from env when missing;
/// build the services once; start the refresher.
///
/// A step that cannot complete is logged and skipped, and the process keeps the
/// services it would have had from env, so a Neutrino problem never stops boot.
///
/// # Errors
///
/// [`BootError`] only when the OS random source fails.
pub async fn install_delivery(
    system: &Valence,
    options: DeliveryOptions,
) -> Result<DeliveryBoot, BootError> {
    ensure_schema_linked();
    if let Err(e) = system.sync_typed_tables_from_registry().await {
        tracing::warn!(target: "lepton.delivery.install", error = %e, "settings table sync failed");
    }

    let (email_fallback, sms_fallback) = if options.seed_from_env {
        env_fallback()
    } else {
        (unreachable_noop_email(), unreachable_noop_sms())
    };
    let email = Arc::new(SwappableEmail::new(email_fallback));
    let sms = Arc::new(SwappableSms::new(sms_fallback));
    let oauth = OAuthHandle::default();
    let notify = Arc::new(Notify::new());

    let shared = Arc::new(refresher::Shared {
        system: system.clone(),
        store: store_from_valence(system.clone()),
        public_base_url: options.public_base_url.clone(),
        email: Arc::clone(&email),
        sms: Arc::clone(&sms),
        oauth: oauth.clone(),
        notify: Arc::clone(&notify),
    });

    let seeded_names = seed_secrets(&shared, &options).await?;
    let created_row = seed_row(system, &options, &seeded_names).await;
    tracing::info!(
        target: "lepton.delivery.install",
        operation = "install_delivery",
        seeded_row = created_row,
        seeded_secrets = seeded_names.len(),
        "delivery settings installed"
    );

    let mut applied = refresher::Applied::default();
    if let Err(e) = refresher::refresh_once(&shared, &mut applied).await {
        tracing::warn!(target: "lepton.delivery.install", error = %e, "first refresh failed; keeping env services");
    }

    let hook_notify = Arc::clone(&notify);
    lepton_auth::totp::key_ring::set_resync_hook(move || hook_notify.notify_one());

    let backend = Arc::new(NeutrinoDeliveryBackend::new(&shared));
    let (stop, stop_rx) = watch::channel(false);
    let task = refresher::spawn(shared, options.refresh_interval, applied, stop_rx);
    Ok(DeliveryBoot {
        email,
        sms,
        oauth,
        backend,
        notify,
        stop,
        task,
    })
}
