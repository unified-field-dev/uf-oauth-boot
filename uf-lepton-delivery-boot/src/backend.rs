//! [`DeliverySettingsBackend`] over Neutrino and the settings row.
//!
//! Every method runs as the request actor. Secrets are read and replaced through
//! a Neutrino store bound to that actor, so Gauge decides what the actor may do.
//! Nothing here rebinds to System; the refresher picks up saved changes.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use lepton_auth::delivery_settings::{
    DeliveryError, DeliverySettingsBackend, DeliverySettingsView, EmailCandidate,
    EmailDriverChoice, EmailSettingsView, OAuthCandidate, OAuthProviderView, OAuthSettingsView,
    SecretStatus, SmsCandidate, SmsMode, SmsSettingsView, TotpKeyView,
};
use neutrino::vault::store_from_valence_for_request;
use neutrino::ValenceSealedStore;
use tokio::sync::Notify;
use valence::Valence;

use crate::error::BootError;
use crate::privacy_policies::MANAGE_DELIVERY_PERMISSION;
use crate::refresher::Shared;
use crate::services::{
    build_email, build_sms, send_test_email, send_test_sms, EmailSecrets, SmsSecrets,
};
use crate::store;
use crate::stored::{StoredEmail, StoredSettings, StoredSms};
use crate::vault::{self, SecretSpec};

/// Backend handed to the settings page through Leptos context.
pub struct NeutrinoDeliveryBackend {
    notify: Arc<Notify>,
}

impl NeutrinoDeliveryBackend {
    pub(crate) fn new(shared: &Shared) -> Self {
        Self {
            notify: Arc::clone(&shared.notify),
        }
    }
}

fn secret_store_err(operation: &'static str) -> impl Fn(BootError) -> DeliveryError {
    move |e| {
        tracing::warn!(target: "lepton.delivery.save", operation, error = %e, "secret vault operation failed");
        DeliveryError::SecretStore { operation }
    }
}

fn store_err(e: &BootError) -> DeliveryError {
    tracing::warn!(target: "lepton.delivery.save", error = %e, "settings store operation failed");
    DeliveryError::Store
}

async fn ensure_admin(v: &Valence) -> Result<(), DeliveryError> {
    match gauge::service::actor_can(v, MANAGE_DELIVERY_PERMISSION).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(DeliveryError::PermissionDenied),
        Err(e) => {
            tracing::warn!(target: "lepton.delivery.save", error = %e, "permission check failed");
            Err(DeliveryError::PermissionDenied)
        }
    }
}

fn session_store(v: &Valence) -> Result<(ValenceSealedStore, String), DeliveryError> {
    let user = v
        .actor()
        .user_id()
        .map(str::to_string)
        .ok_or(DeliveryError::PermissionDenied)?;
    let label = format!("user:{}", user.strip_prefix("user:").unwrap_or(&user));
    Ok((
        store_from_valence_for_request(v.clone(), label.clone()),
        label,
    ))
}

fn status(settings: &StoredSettings, spec: &SecretSpec) -> SecretStatus {
    let at = settings.secret_rotated.get(spec.name).copied();
    SecretStatus {
        is_set: at.is_some(),
        rotated_at: at,
    }
}

fn nonblank(secret: Option<&lepton_auth::delivery_settings::WriteOnlySecret>) -> Option<String> {
    secret
        .filter(|s| !s.is_empty())
        .map(|s| s.expose_secret().to_string())
}

fn stored_email(c: &EmailCandidate) -> StoredEmail {
    StoredEmail {
        driver: c.driver,
        smtp_host: c.smtp_host.trim().to_string(),
        smtp_port: c.smtp_port,
        smtp_tls: c.smtp_tls,
        smtp_username: c.smtp_username.trim().to_string(),
        from_email: c.from_email.trim().to_string(),
        from_name: c.from_name.trim().to_string(),
    }
}

fn stored_sms(c: &SmsCandidate) -> StoredSms {
    StoredSms {
        mode: c.mode,
        twilio_account_sid: c.twilio_account_sid.trim().to_string(),
        twilio_api_key_sid: c.twilio_api_key_sid.trim().to_string(),
        twilio_verify_service_sid: c.twilio_verify_service_sid.trim().to_string(),
        twilio_from: c.twilio_from.trim().to_string(),
    }
}

async fn email_secrets(
    store: &ValenceSealedStore,
    c: &EmailCandidate,
) -> Result<EmailSecrets, DeliveryError> {
    let mut out = EmailSecrets::default();
    match c.driver {
        EmailDriverChoice::Smtp if !c.smtp_username.trim().is_empty() => {
            out.smtp_password = match nonblank(c.smtp_password.as_ref()) {
                Some(p) => Some(p),
                None => vault::read(store, &vault::SMTP_PASSWORD)
                    .await
                    .map_err(secret_store_err("read"))?,
            };
        }
        EmailDriverChoice::SendGrid => {
            out.sendgrid_api_key = match nonblank(c.sendgrid_api_key.as_ref()) {
                Some(k) => Some(k),
                None => vault::read(store, &vault::SENDGRID_API_KEY)
                    .await
                    .map_err(secret_store_err("read"))?,
            };
        }
        _ => {}
    }
    Ok(out)
}

async fn sms_secrets(
    store: &ValenceSealedStore,
    c: &SmsCandidate,
) -> Result<SmsSecrets, DeliveryError> {
    if c.mode == SmsMode::Off {
        return Ok(SmsSecrets::default());
    }
    let twilio_api_secret = match nonblank(c.twilio_api_secret.as_ref()) {
        Some(s) => Some(s),
        None => vault::read(store, &vault::TWILIO_API_SECRET)
            .await
            .map_err(secret_store_err("read"))?,
    };
    Ok(SmsSecrets { twilio_api_secret })
}

async fn endpoints(v: &Valence) -> Result<crate::stored::StoredEndpoints, DeliveryError> {
    Ok(store::load(v)
        .await
        .map_err(|e| store_err(&e))?
        .map(|l| l.settings.endpoints)
        .unwrap_or_default())
}

fn random_seal_key_hex() -> Result<String, DeliveryError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| DeliveryError::Store)?;
    Ok(vault::hex_lower(&bytes))
}

#[async_trait]
impl DeliverySettingsBackend for NeutrinoDeliveryBackend {
    async fn view(&self, v: &Valence) -> Result<DeliverySettingsView, DeliveryError> {
        ensure_admin(v).await?;
        let loaded = store::load(v).await.map_err(|e| store_err(&e))?;
        let (revision, s) = loaded.map_or_else(
            || (0, StoredSettings::default()),
            |l| (l.revision, l.settings),
        );
        let key_version = vault::find(v, &vault::TOTP_SEAL_KEY)
            .await
            .map_err(secret_store_err("list"))?
            .map_or(0, |r| u32::try_from(r.current_version).unwrap_or(0));
        Ok(DeliverySettingsView {
            revision,
            email: EmailSettingsView {
                driver: s.email.driver,
                smtp_host: s.email.smtp_host.clone(),
                smtp_port: s.email.smtp_port,
                smtp_tls: s.email.smtp_tls,
                smtp_username: s.email.smtp_username.clone(),
                from_email: s.email.from_email.clone(),
                from_name: s.email.from_name.clone(),
                smtp_password: status(&s, &vault::SMTP_PASSWORD),
                sendgrid_api_key: status(&s, &vault::SENDGRID_API_KEY),
            },
            sms: SmsSettingsView {
                mode: s.sms.mode,
                twilio_account_sid: s.sms.twilio_account_sid.clone(),
                twilio_api_key_sid: s.sms.twilio_api_key_sid.clone(),
                twilio_verify_service_sid: s.sms.twilio_verify_service_sid.clone(),
                twilio_from: s.sms.twilio_from.clone(),
                twilio_api_secret: status(&s, &vault::TWILIO_API_SECRET),
            },
            oauth: OAuthSettingsView {
                google: OAuthProviderView {
                    client_id: s.oauth.google_client_id.clone(),
                    secret: status(&s, &vault::GOOGLE_CLIENT_SECRET),
                },
                github: OAuthProviderView {
                    client_id: s.oauth.github_client_id.clone(),
                    secret: status(&s, &vault::GITHUB_CLIENT_SECRET),
                },
            },
            totp_key: TotpKeyView {
                version: key_version,
                rotated_at: s.totp_key_rotated_at,
            },
        })
    }

    async fn test_email(&self, v: &Valence, c: &EmailCandidate) -> Result<(), DeliveryError> {
        ensure_admin(v).await?;
        c.validate()?;
        let (store, _) = session_store(v)?;
        let secrets = email_secrets(&store, c).await?;
        let service = build_email(&stored_email(c), &endpoints(v).await?, &secrets)?;
        send_test_email(service.as_ref(), &c.test_recipient).await
    }

    async fn test_sms(&self, v: &Valence, c: &SmsCandidate) -> Result<(), DeliveryError> {
        ensure_admin(v).await?;
        c.validate()?;
        let (store, _) = session_store(v)?;
        let secrets = sms_secrets(&store, c).await?;
        let service = build_sms(&stored_sms(c), &endpoints(v).await?, &secrets)?;
        send_test_sms(service.as_ref(), &c.test_recipient).await
    }

    async fn save_email(&self, v: &Valence, c: EmailCandidate) -> Result<(), DeliveryError> {
        ensure_admin(v).await?;
        c.validate()?;
        let (store, label) = session_store(v)?;
        let secrets = email_secrets(&store, &c).await?;
        let service = build_email(&stored_email(&c), &endpoints(v).await?, &secrets)?;
        if c.driver != EmailDriverChoice::Off {
            send_test_email(service.as_ref(), &c.test_recipient).await?;
        }
        let mut rotated: Vec<&'static str> = Vec::new();
        if c.driver == EmailDriverChoice::Smtp {
            if let Some(p) = nonblank(c.smtp_password.as_ref()) {
                vault::replace(&store, &vault::SMTP_PASSWORD, &p, &label)
                    .await
                    .map_err(secret_store_err("rotate"))?;
                rotated.push(vault::SMTP_PASSWORD.name);
            }
        }
        if c.driver == EmailDriverChoice::SendGrid {
            if let Some(k) = nonblank(c.sendgrid_api_key.as_ref()) {
                vault::replace(&store, &vault::SENDGRID_API_KEY, &k, &label)
                    .await
                    .map_err(secret_store_err("rotate"))?;
                rotated.push(vault::SENDGRID_API_KEY.name);
            }
        }
        let email = stored_email(&c);
        let now = Utc::now();
        let had_secrets = !rotated.is_empty();
        store::save(v, move |s| {
            s.email = email;
            for name in rotated {
                s.secret_rotated.insert(name.to_string(), now);
            }
        })
        .await
        .map_err(|e| {
            tracing::warn!(target: "lepton.delivery.save", channel = "email", error = %e, "row save failed");
            if had_secrets {
                DeliveryError::SaveNotApplied
            } else {
                DeliveryError::Store
            }
        })?;
        self.notify.notify_one();
        tracing::info!(target: "lepton.delivery.save", channel = "email", outcome = "saved");
        Ok(())
    }

    async fn save_sms(&self, v: &Valence, c: SmsCandidate) -> Result<(), DeliveryError> {
        ensure_admin(v).await?;
        c.validate()?;
        let (store, label) = session_store(v)?;
        let secrets = sms_secrets(&store, &c).await?;
        let service = build_sms(&stored_sms(&c), &endpoints(v).await?, &secrets)?;
        if c.mode != SmsMode::Off {
            send_test_sms(service.as_ref(), &c.test_recipient).await?;
        }
        let mut rotated: Vec<&'static str> = Vec::new();
        if c.mode != SmsMode::Off {
            if let Some(s) = nonblank(c.twilio_api_secret.as_ref()) {
                vault::replace(&store, &vault::TWILIO_API_SECRET, &s, &label)
                    .await
                    .map_err(secret_store_err("rotate"))?;
                rotated.push(vault::TWILIO_API_SECRET.name);
            }
        }
        let sms = stored_sms(&c);
        let now = Utc::now();
        let had_secrets = !rotated.is_empty();
        store::save(v, move |s| {
            s.sms = sms;
            for name in rotated {
                s.secret_rotated.insert(name.to_string(), now);
            }
        })
        .await
        .map_err(|e| {
            tracing::warn!(target: "lepton.delivery.save", channel = "sms", error = %e, "row save failed");
            if had_secrets {
                DeliveryError::SaveNotApplied
            } else {
                DeliveryError::Store
            }
        })?;
        self.notify.notify_one();
        tracing::info!(target: "lepton.delivery.save", channel = "sms", outcome = "saved");
        Ok(())
    }

    async fn save_oauth(&self, v: &Valence, c: OAuthCandidate) -> Result<(), DeliveryError> {
        ensure_admin(v).await?;
        let (store, label) = session_store(v)?;
        let mut rotated: Vec<&'static str> = Vec::new();
        if let Some(s) = nonblank(c.google_client_secret.as_ref()) {
            vault::replace(&store, &vault::GOOGLE_CLIENT_SECRET, &s, &label)
                .await
                .map_err(secret_store_err("rotate"))?;
            rotated.push(vault::GOOGLE_CLIENT_SECRET.name);
        }
        if let Some(s) = nonblank(c.github_client_secret.as_ref()) {
            vault::replace(&store, &vault::GITHUB_CLIENT_SECRET, &s, &label)
                .await
                .map_err(secret_store_err("rotate"))?;
            rotated.push(vault::GITHUB_CLIENT_SECRET.name);
        }
        let now = Utc::now();
        let had_secrets = !rotated.is_empty();
        let google = c.google_client_id.trim().to_string();
        let github = c.github_client_id.trim().to_string();
        store::save(v, move |s| {
            s.oauth.google_client_id = google;
            s.oauth.github_client_id = github;
            for name in rotated {
                s.secret_rotated.insert(name.to_string(), now);
            }
        })
        .await
        .map_err(|e| {
            tracing::warn!(target: "lepton.delivery.save", channel = "oauth", error = %e, "row save failed");
            if had_secrets {
                DeliveryError::SaveNotApplied
            } else {
                DeliveryError::Store
            }
        })?;
        self.notify.notify_one();
        tracing::info!(target: "lepton.delivery.save", channel = "oauth", outcome = "saved");
        Ok(())
    }

    async fn rotate_totp_key(&self, v: &Valence) -> Result<(), DeliveryError> {
        ensure_admin(v).await?;
        let (store, label) = session_store(v)?;
        let key = random_seal_key_hex()?;
        vault::replace(&store, &vault::TOTP_SEAL_KEY, &key, &label)
            .await
            .map_err(secret_store_err("rotate"))?;
        let now = Utc::now();
        store::save(v, move |s| s.totp_key_rotated_at = Some(now))
            .await
            .map_err(|e| {
                tracing::warn!(target: "lepton.totp.key_rotate", error = %e, "row save failed");
                DeliveryError::SaveNotApplied
            })?;
        self.notify.notify_one();
        tracing::info!(target: "lepton.totp.key_rotate", outcome = "rotated");
        Ok(())
    }
}
