//! The non-secret settings document kept in the settings row.
//!
//! One JSON document, not one column per setting: the table syncs additively
//! only, and a document grows without a migration. Every field has a default so
//! an older row still reads after a field is added.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use lepton_auth::delivery_settings::{EmailDriverChoice, SmsMode};
use serde::{Deserialize, Serialize};

/// Email settings (no secrets).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredEmail {
    /// Active path.
    pub driver: EmailDriverChoice,
    /// SMTP host.
    pub smtp_host: String,
    /// SMTP port.
    pub smtp_port: u16,
    /// Whether the SMTP connection uses TLS.
    pub smtp_tls: bool,
    /// SMTP username.
    pub smtp_username: String,
    /// `From` address.
    pub from_email: String,
    /// `From` display name.
    pub from_name: String,
}

/// Text-message settings (no secrets).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredSms {
    /// Active path.
    pub mode: SmsMode,
    /// Twilio account SID.
    pub twilio_account_sid: String,
    /// Twilio API key SID.
    pub twilio_api_key_sid: String,
    /// Twilio Verify service SID.
    pub twilio_verify_service_sid: String,
    /// Sender number for Messages mode.
    pub twilio_from: String,
}

/// OAuth provider settings (no secrets).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredOAuth {
    /// Google client id.
    pub google_client_id: String,
    /// GitHub client id.
    pub github_client_id: String,
    /// Use the mock OIDC provider (CI and lab hosts). Seeded once, not shown on the page.
    pub use_mock: bool,
    /// Mock issuer URL. Seeded once, not shown on the page.
    pub mock_oidc_url: Option<String>,
}

/// Provider endpoint overrides. Seeded once from env so CI and lab hosts can
/// point at a mock; the page never shows or changes them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredEndpoints {
    /// Twilio API base URL override.
    pub twilio_api_base_url: Option<String>,
    /// `SendGrid` API base URL override.
    pub sendgrid_api_base_url: Option<String>,
}

/// Everything in the settings row's document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredSettings {
    /// Email.
    pub email: StoredEmail,
    /// Text messages.
    pub sms: StoredSms,
    /// OAuth providers.
    pub oauth: StoredOAuth,
    /// Endpoint overrides.
    pub endpoints: StoredEndpoints,
    /// When each secret was last set, by fixed secret name. Presence means "set".
    pub secret_rotated: BTreeMap<String, DateTime<Utc>>,
    /// When the TOTP seal key was last rotated.
    pub totp_key_rotated_at: Option<DateTime<Utc>>,
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_truthy(key: &str) -> bool {
    matches!(
        env_nonempty(key)
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1" | "true" | "yes")
    )
}

impl StoredSettings {
    /// Build the first-boot document from env. Read once, when the row does not
    /// exist yet; later env changes are ignored.
    #[must_use]
    pub fn from_env() -> Self {
        let smtp_host = env_nonempty("UF_SMTP_HOST").unwrap_or_default();
        let driver = match env_nonempty("UF_EMAIL_DRIVER")
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("smtp") => EmailDriverChoice::Smtp,
            Some("twilio") => EmailDriverChoice::SendGrid,
            Some("direct_mx" | "direct-mx") => EmailDriverChoice::DirectMx,
            Some("noop" | "none" | "off") => EmailDriverChoice::Off,
            _ if !smtp_host.is_empty() => EmailDriverChoice::Smtp,
            _ => EmailDriverChoice::Off,
        };
        let smtp_port = env_nonempty("UF_SMTP_PORT")
            .and_then(|p| p.parse().ok())
            .unwrap_or(587);
        let verify_sid = env_nonempty("UF_TWILIO_VERIFY_SERVICE_SID").unwrap_or_default();
        let twilio_from = env_nonempty("UF_TWILIO_FROM").unwrap_or_default();
        let mode = if !verify_sid.is_empty() {
            SmsMode::Verify
        } else if !twilio_from.is_empty() {
            SmsMode::Messages
        } else {
            SmsMode::Off
        };
        Self {
            email: StoredEmail {
                driver,
                smtp_host,
                smtp_port,
                smtp_tls: env_nonempty("UF_SMTP_USE_TLS").is_none_or(|v| v != "0" && v != "false"),
                smtp_username: env_nonempty("UF_SMTP_USERNAME").unwrap_or_default(),
                from_email: env_nonempty("UF_EMAIL_FROM").unwrap_or_default(),
                from_name: env_nonempty("UF_EMAIL_FROM_NAME").unwrap_or_default(),
            },
            sms: StoredSms {
                mode,
                twilio_account_sid: env_nonempty("UF_TWILIO_ACCOUNT_SID").unwrap_or_default(),
                twilio_api_key_sid: env_nonempty("UF_TWILIO_API_KEY").unwrap_or_default(),
                twilio_verify_service_sid: verify_sid,
                twilio_from,
            },
            oauth: StoredOAuth {
                google_client_id: env_nonempty("UF_OAUTH_GOOGLE_CLIENT_ID").unwrap_or_default(),
                github_client_id: env_nonempty("UF_OAUTH_GITHUB_CLIENT_ID").unwrap_or_default(),
                use_mock: env_truthy("UF_OAUTH_USE_MOCK"),
                mock_oidc_url: env_nonempty("UF_MOCK_OIDC_URL"),
            },
            endpoints: StoredEndpoints {
                twilio_api_base_url: env_nonempty("UF_TWILIO_API_BASE_URL"),
                sendgrid_api_base_url: env_nonempty("UF_SENDGRID_API_BASE_URL"),
            },
            secret_rotated: BTreeMap::new(),
            totp_key_rotated_at: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn missing_fields_default_so_old_rows_still_read() {
        let doc = serde_json::json!({ "email": { "driver": "Smtp", "smtp_host": "h" } });
        let parsed: StoredSettings = serde_json::from_value(doc).unwrap();
        assert_eq!(parsed.email.driver, EmailDriverChoice::Smtp);
        assert_eq!(parsed.email.smtp_host, "h");
        assert_eq!(parsed.sms.mode, SmsMode::Off);
        assert!(parsed.secret_rotated.is_empty());
    }

    #[test]
    fn document_roundtrips_without_losing_rotation_times() {
        let mut s = StoredSettings::default();
        s.secret_rotated
            .insert("lepton.smtp.password".into(), Utc::now());
        let back: StoredSettings =
            serde_json::from_value(serde_json::to_value(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }
}
