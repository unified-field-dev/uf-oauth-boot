//! Build delivery services from settings plus secrets, and run test sends.
//!
//! Nothing here reads process env or persists anything. Callers decide what a
//! built service is used for: swapped into the live handle, or used once for a
//! test send.

use std::sync::Arc;

use lepton_auth::delivery_settings::{
    Channel, DeliveryError, EmailDriverChoice, SmsMode, TestFailureClass,
};
use lepton_auth::oauth::OAuthClientConfig;
use lepton_sms::{
    SmsDeliveryError, SmsDeliveryService, SmsEnvelope, SmsServiceBuilder, TwilioSmsConfig,
    TwilioVerifyConfig,
};
use lepton_smtp::{
    DirectMxConfig, EmailDeliveryError, EmailDeliveryService, EmailEnvelope, EmailServiceBuilder,
    SmtpConfig, TwilioEmailConfig,
};

use crate::stored::{StoredEmail, StoredEndpoints, StoredOAuth, StoredSms};

/// Secret values an email service may need.
#[derive(Default)]
pub struct EmailSecrets {
    /// SMTP password.
    pub smtp_password: Option<String>,
    /// `SendGrid` API key.
    pub sendgrid_api_key: Option<String>,
}

/// Secret values a text-message service may need.
#[derive(Default)]
pub struct SmsSecrets {
    /// Twilio API secret.
    pub twilio_api_secret: Option<String>,
}

const fn invalid(field: &'static str, reason: &'static str) -> DeliveryError {
    DeliveryError::Invalid { field, reason }
}

/// Build the email service for `email`.
///
/// # Errors
///
/// [`DeliveryError::Invalid`] naming the setting that does not build.
pub fn build_email(
    email: &StoredEmail,
    endpoints: &StoredEndpoints,
    secrets: &EmailSecrets,
) -> Result<Arc<dyn EmailDeliveryService>, DeliveryError> {
    let built = match email.driver {
        EmailDriverChoice::Off => EmailServiceBuilder::new().noop().build(),
        EmailDriverChoice::Smtp => {
            let mut cfg = SmtpConfig::builder()
                .host(email.smtp_host.trim())
                .port(email.smtp_port)
                .use_tls(email.smtp_tls)
                .from_email(email.from_email.trim())
                .from_name(email.from_name.trim());
            if !email.smtp_username.trim().is_empty() {
                let Some(password) = secrets.smtp_password.as_deref() else {
                    return Err(invalid("smtp_password", "is not set"));
                };
                cfg = cfg.username(email.smtp_username.trim()).password(password);
            }
            let cfg = cfg
                .build()
                .map_err(|_| invalid("smtp", "settings are not valid"))?;
            EmailServiceBuilder::new().smtp(cfg).build()
        }
        EmailDriverChoice::SendGrid => {
            let Some(key) = secrets.sendgrid_api_key.as_deref() else {
                return Err(invalid("sendgrid_api_key", "is not set"));
            };
            let mut cfg = TwilioEmailConfig::builder()
                .api_key(key)
                .from_email(email.from_email.trim())
                .from_name(email.from_name.trim());
            if let Some(base) = endpoints.sendgrid_api_base_url.as_deref() {
                cfg = cfg.api_base_url(base);
            }
            let cfg = cfg
                .build()
                .map_err(|_| invalid("sendgrid", "settings are not valid"))?;
            EmailServiceBuilder::new().twilio(cfg).build()
        }
        EmailDriverChoice::DirectMx => {
            let cfg = DirectMxConfig::builder()
                .from_email(email.from_email.trim())
                .from_name(email.from_name.trim())
                .build()
                .map_err(|_| invalid("direct_mx", "settings are not valid"))?;
            EmailServiceBuilder::new().direct_mx(cfg).build()
        }
    };
    built.map_err(|_| invalid("email", "settings do not build a delivery service"))
}

/// Build the text-message service for `sms`.
///
/// # Errors
///
/// [`DeliveryError::Invalid`] naming the setting that does not build.
pub fn build_sms(
    sms: &StoredSms,
    endpoints: &StoredEndpoints,
    secrets: &SmsSecrets,
) -> Result<Arc<dyn SmsDeliveryService>, DeliveryError> {
    let built = match sms.mode {
        SmsMode::Off => SmsServiceBuilder::new().noop().build(),
        SmsMode::Verify => {
            let Some(secret) = secrets.twilio_api_secret.as_deref() else {
                return Err(invalid("twilio_api_secret", "is not set"));
            };
            let mut cfg = TwilioVerifyConfig::builder()
                .service_sid(sms.twilio_verify_service_sid.trim())
                .account_sid(sms.twilio_account_sid.trim())
                .api_key(sms.twilio_api_key_sid.trim())
                .api_secret(secret);
            if let Some(base) = endpoints.twilio_api_base_url.as_deref() {
                cfg = cfg.api_base_url(base);
            }
            let cfg = cfg
                .build()
                .map_err(|_| invalid("twilio_verify", "settings are not valid"))?;
            SmsServiceBuilder::new().twilio_verify(cfg).build()
        }
        SmsMode::Messages => {
            let Some(secret) = secrets.twilio_api_secret.as_deref() else {
                return Err(invalid("twilio_api_secret", "is not set"));
            };
            let mut cfg = TwilioSmsConfig::builder()
                .account_sid(sms.twilio_account_sid.trim())
                .api_key(sms.twilio_api_key_sid.trim())
                .api_secret(secret)
                .from(sms.twilio_from.trim());
            if let Some(base) = endpoints.twilio_api_base_url.as_deref() {
                cfg = cfg.api_base_url(base);
            }
            let cfg = cfg
                .build()
                .map_err(|_| invalid("twilio_messages", "settings are not valid"))?;
            SmsServiceBuilder::new().twilio(cfg).build()
        }
    };
    built.map_err(|_| invalid("sms", "settings do not build a delivery service"))
}

/// Build the OAuth client config. `None` when no provider is usable.
#[must_use]
pub fn build_oauth(
    public_base_url: &str,
    oauth: &StoredOAuth,
    google_secret: Option<String>,
    github_secret: Option<String>,
) -> Option<OAuthClientConfig> {
    let google_id = Some(oauth.google_client_id.trim().to_string()).filter(|s| !s.is_empty());
    let github_id = Some(oauth.github_client_id.trim().to_string()).filter(|s| !s.is_empty());
    let google_ready = google_id.is_some() && google_secret.is_some();
    let github_ready = github_id.is_some() && github_secret.is_some();
    if !oauth.use_mock && !google_ready && !github_ready {
        return None;
    }
    Some(OAuthClientConfig {
        public_base_url: public_base_url.to_string(),
        redirect_path: uf_oauth_boot::OAUTH_REDIRECT_PATH.into(),
        google_client_id: google_id,
        google_client_secret: google_secret,
        github_client_id: github_id,
        github_client_secret: github_secret,
        use_mock_provider: oauth.use_mock,
        mock_oidc_issuer_url: oauth.mock_oidc_url.clone(),
        google_token_url: None,
        google_userinfo_url: None,
        github_token_url: None,
        github_user_url: None,
        github_emails_url: None,
    })
}

fn classify(text: &str, transport: bool) -> TestFailureClass {
    let t = text.to_ascii_lowercase();
    if t.contains("401")
        || t.contains("403")
        || t.contains("unauthor")
        || t.contains("authentication")
    {
        TestFailureClass::Unauthorized
    } else if t.contains("sender") || t.contains("from address") || t.contains("not verified") {
        TestFailureClass::UnverifiedSender
    } else if t.contains("invalid number")
        || t.contains("not a valid phone")
        || t.contains("invalid recipient")
        || t.contains("mailbox")
    {
        TestFailureClass::InvalidRecipient
    } else if transport || t.contains("timeout") || t.contains("connect") {
        TestFailureClass::Network
    } else {
        TestFailureClass::Other
    }
}

fn email_class(err: &EmailDeliveryError) -> TestFailureClass {
    match err {
        EmailDeliveryError::TransportError(m) | EmailDeliveryError::Transient(m) => {
            classify(m, true)
        }
        EmailDeliveryError::ProviderRejected(m) | EmailDeliveryError::ConfigError(m) => {
            classify(m, false)
        }
    }
}

fn sms_class(err: &SmsDeliveryError) -> TestFailureClass {
    match err {
        SmsDeliveryError::TransportError(m) | SmsDeliveryError::Transient(m) => classify(m, true),
        SmsDeliveryError::Rejected(m) | SmsDeliveryError::ConfigError(m) => classify(m, false),
    }
}

/// Send one test email through `service`.
///
/// # Errors
///
/// [`DeliveryError::TestSendFailed`] with an actionable class; the provider's
/// message is dropped.
pub async fn send_test_email(
    service: &dyn EmailDeliveryService,
    to: &str,
) -> Result<(), DeliveryError> {
    let envelope = EmailEnvelope {
        to: to.trim().to_string(),
        subject: "Test message from Sign-in and delivery".to_string(),
        text_body: "This is a test message. Your email settings can send mail.".to_string(),
        html_body: "<p>This is a test message. Your email settings can send mail.</p>".to_string(),
    };
    service
        .send(&envelope)
        .await
        .map(|_| ())
        .map_err(|e| DeliveryError::TestSendFailed {
            channel: Channel::Email,
            class: email_class(&e),
        })
}

/// Send one test text message through `service`.
///
/// # Errors
///
/// [`DeliveryError::TestSendFailed`] with an actionable class.
pub async fn send_test_sms(
    service: &dyn SmsDeliveryService,
    to_e164: &str,
) -> Result<(), DeliveryError> {
    let mut digits = [0u8; 4];
    getrandom::getrandom(&mut digits).map_err(|_| DeliveryError::Store)?;
    let code = u32::from_le_bytes(digits) % 900_000 + 100_000;
    let envelope = SmsEnvelope {
        to_e164: to_e164.trim().to_string(),
        body: format!("Your test code is {code}."),
        otp_code: Some(code.to_string()),
    };
    service
        .send(&envelope)
        .await
        .map(|_| ())
        .map_err(|e| DeliveryError::TestSendFailed {
            channel: Channel::Sms,
            class: sms_class(&e),
        })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn off_builds_noop_for_both_channels() {
        let email = build_email(
            &StoredEmail::default(),
            &StoredEndpoints::default(),
            &EmailSecrets::default(),
        )
        .expect("noop email");
        assert_eq!(email.driver(), lepton_smtp::EmailDriver::Noop);
        let sms = build_sms(
            &StoredSms::default(),
            &StoredEndpoints::default(),
            &SmsSecrets::default(),
        )
        .expect("noop sms");
        assert_eq!(sms.driver_name(), "noop");
    }

    #[test]
    fn smtp_with_username_requires_the_password_secret_sad() {
        let email = StoredEmail {
            driver: EmailDriverChoice::Smtp,
            smtp_host: "smtp.example.test".into(),
            smtp_port: 587,
            smtp_username: "mailer".into(),
            from_email: "cell@example.test".into(),
            ..StoredEmail::default()
        };
        let err = build_email(
            &email,
            &StoredEndpoints::default(),
            &EmailSecrets::default(),
        )
        .err()
        .expect("missing password");
        assert!(matches!(
            err,
            DeliveryError::Invalid {
                field: "smtp_password",
                ..
            }
        ));
    }

    #[test]
    fn verify_mode_builds_twilio_verify_and_needs_secret() {
        let sms = StoredSms {
            mode: SmsMode::Verify,
            twilio_account_sid: "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            twilio_api_key_sid: "SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            twilio_verify_service_sid: "VAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ..StoredSms::default()
        };
        assert!(matches!(
            build_sms(&sms, &StoredEndpoints::default(), &SmsSecrets::default())
                .err()
                .expect("no secret"),
            DeliveryError::Invalid {
                field: "twilio_api_secret",
                ..
            }
        ));
        let ok = build_sms(
            &sms,
            &StoredEndpoints::default(),
            &SmsSecrets {
                twilio_api_secret: Some("s3cret".into()),
            },
        )
        .expect("verify builds");
        assert_eq!(ok.driver_name(), "twilio_verify");
    }

    #[test]
    fn oauth_needs_id_and_secret_per_provider() {
        let oauth = StoredOAuth {
            google_client_id: "gid".into(),
            github_client_id: "hid".into(),
            ..StoredOAuth::default()
        };
        assert!(build_oauth("http://x", &oauth, None, None).is_none());
        let cfg = build_oauth("http://x", &oauth, Some("gs".into()), None).expect("google ready");
        assert_eq!(cfg.google_client_id.as_deref(), Some("gid"));
        assert_eq!(cfg.google_client_secret.as_deref(), Some("gs"));
        assert_eq!(cfg.redirect_path, uf_oauth_boot::OAUTH_REDIRECT_PATH);
    }

    #[test]
    fn failure_classes_never_carry_provider_text() {
        assert_eq!(
            email_class(&EmailDeliveryError::ProviderRejected(
                "HTTP 401 Unauthorized key=abc".into()
            )),
            TestFailureClass::Unauthorized
        );
        assert_eq!(
            sms_class(&SmsDeliveryError::TransportError("connect timeout".into())),
            TestFailureClass::Network
        );
        let e = DeliveryError::TestSendFailed {
            channel: Channel::Email,
            class: TestFailureClass::Unauthorized,
        };
        assert!(!e.to_string().contains("abc"));
    }
}
