//! Happy and sad coverage for [`uf_lepton_delivery_boot::install_delivery`].

#![allow(missing_docs)]
#![allow(clippy::expect_used, clippy::unwrap_used)]
// `Env` holds the global test lock and the process env; it must live until the
// end of each test, so "can be dropped earlier" does not apply.
#![allow(clippy::significant_drop_tightening)]

mod common;

use std::time::Duration;

use common::{eventually, sync_manage_delivery_permission, system_valence, Env};
use lepton_smtp::EmailDriver;
use uf_lepton_delivery_boot::{install_delivery, DeliveryOptions};
use valence::Model;

fn fast(opts: DeliveryOptions) -> DeliveryOptions {
    DeliveryOptions {
        refresh_interval: Duration::from_millis(50),
        ..opts
    }
}

#[tokio::test]
async fn first_boot_seeds_row_and_secret_from_env_then_env_changes_are_ignored() {
    let env = Env::clean().await;
    env.set("UF_EMAIL_DRIVER", "smtp");
    env.set("UF_SMTP_HOST", "smtp.first.test");
    env.set("UF_SMTP_USERNAME", "mailer");
    env.set("UF_SMTP_PASSWORD", "first-password");
    env.set("UF_EMAIL_FROM", "cell@first.test");

    let system = system_valence().await;
    sync_manage_delivery_permission(&system).await;

    let first = install_delivery(&system, fast(DeliveryOptions::new("http://127.0.0.1:3000")))
        .await
        .expect("first install");
    assert_eq!(first.email().driver(), EmailDriver::Smtp, "env seeded SMTP");
    first.shutdown().await;

    // The operator edits env afterwards; a restart must not pick it up.
    env.set("UF_SMTP_HOST", "smtp.second.test");
    env.set("UF_SMTP_PASSWORD", "second-password");
    env.set("UF_EMAIL_FROM", "cell@second.test");

    let second = install_delivery(&system, fast(DeliveryOptions::new("http://127.0.0.1:3000")))
        .await
        .expect("second install");
    let backend = second.settings_backend();
    // A Super User-free system read: use the System Valence through the backend's gate.
    let view = backend.view(&system).await;
    // System has no user id, so the backend refuses it; read the row directly instead.
    assert!(view.is_err(), "backend is for session actors only");
    let row = uf_lepton_delivery_boot::LeptonDeliverySettings::get(
        uf_lepton_delivery_boot::SETTINGS_ROW_ID,
        &system,
        valence::use_!(r"**Test:** Fixture **Lepton delivery settings** load for `delivery_boot` so the suite can assert env seeding happens once. CI and developers running the suite only."),
    )
    .await
    .expect("get")
    .expect("row exists");
    let settings: uf_lepton_delivery_boot::StoredSettings =
        serde_json::from_value(row.settings().clone()).expect("decode");
    assert_eq!(settings.email.smtp_host, "smtp.first.test");
    assert_eq!(settings.email.from_email, "cell@first.test");
    assert_eq!(*row.revision(), 1, "re-boot must not bump the revision");

    let store = neutrino::vault::store_from_valence(system.clone());
    let password = neutrino::secret_store::SecretStore::get(
        &store,
        &neutrino::secret_store::SecretId(
            neutrino::list_secrets(&system, Some("/lepton/delivery"))
                .await
                .expect("list")
                .into_iter()
                .find(|r| r.name == "lepton.smtp.password")
                .expect("seeded")
                .id,
        ),
    )
    .await
    .expect("get secret");
    assert_eq!(
        String::from_utf8(password.plaintext.to_vec()).unwrap(),
        "first-password",
        "sealed value wins over changed env"
    );
    second.shutdown().await;
}

// ---------------------------------------------------------------------------
// Admin save path: real Neutrino, real Gauge, mock providers.
// ---------------------------------------------------------------------------

use base64::Engine as _;
use lepton_auth::delivery_settings::{
    Channel, DeliveryError, EmailCandidate, EmailDriverChoice, OAuthCandidate, SmsCandidate,
    SmsMode, TestFailureClass, WriteOnlySecret,
};
use lepton_sms::SmsEnvelope;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Cell {
    system: valence::Valence,
    boot: uf_lepton_delivery_boot::DeliveryBoot,
}

const ADMIN: &str = "delivery_admin_1";

/// Install with every channel off, then add `ADMIN` to the delivery admins group.
async fn cell(env: &Env, sendgrid: &MockServer, twilio: &MockServer) -> Cell {
    env.set("UF_SENDGRID_API_BASE_URL", &sendgrid.uri());
    env.set("UF_TWILIO_API_BASE_URL", &twilio.uri());
    let system = system_valence().await;
    sync_manage_delivery_permission(&system).await;
    let boot = install_delivery(&system, fast(DeliveryOptions::new("http://127.0.0.1:3000")))
        .await
        .expect("install");
    common::seed_user(&system, ADMIN).await;
    common::add_to_delivery_admins(&system, ADMIN).await;
    Cell { system, boot }
}

async fn sendgrid_ok() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v3/mail/send"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;
    server
}

async fn twilio_ok() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/v2/Services/.+/Verifications$"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(serde_json::json!({ "sid": "VEtest" })),
        )
        .mount(&server)
        .await;
    server
}

fn sendgrid_candidate(key: Option<&str>) -> EmailCandidate {
    EmailCandidate {
        driver: EmailDriverChoice::SendGrid,
        from_email: "cell@example.test".into(),
        from_name: "Cell".into(),
        sendgrid_api_key: key.map(WriteOnlySecret::new),
        test_recipient: "ops@example.test".into(),
        ..EmailCandidate::default()
    }
}

fn verify_candidate(secret: Option<&str>) -> SmsCandidate {
    SmsCandidate {
        mode: SmsMode::Verify,
        twilio_account_sid: "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        twilio_api_key_sid: "SKbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        twilio_verify_service_sid: "VAcccccccccccccccccccccccccccccccc".into(),
        twilio_api_secret: secret.map(WriteOnlySecret::new),
        test_recipient: "+15550100".into(),
        ..SmsCandidate::default()
    }
}

fn basic_auth(user: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{secret}"))
    )
}

fn auth_header(req: &wiremock::Request) -> String {
    req.headers
        .get("authorization")
        .map(|v| v.to_str().unwrap_or_default().to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn admin_saves_sendgrid_and_twilio_then_rotation_is_used_by_the_next_send() {
    let env = Env::clean().await;
    let (sendgrid, twilio) = (sendgrid_ok().await, twilio_ok().await);
    let cell = cell(&env, &sendgrid, &twilio).await;
    let admin = common::as_user(&cell.system, ADMIN);
    let backend = cell.boot.settings_backend();
    assert_eq!(cell.boot.email().driver(), EmailDriver::Noop, "starts off");

    backend
        .save_email(&admin, sendgrid_candidate(Some("SG.first")))
        .await
        .expect("save email");
    backend
        .save_sms(&admin, verify_candidate(Some("secret-one")))
        .await
        .expect("save sms");

    assert!(
        eventually(Duration::from_secs(10), || async {
            cell.boot.email().driver() == EmailDriver::Twilio
                && cell.boot.sms().driver_name() == "twilio_verify"
        })
        .await,
        "services swap without a restart"
    );
    let mail = sendgrid.received_requests().await.expect("recorded");
    assert_eq!(mail.len(), 1, "one test send before saving");
    assert_eq!(auth_header(&mail[0]), "Bearer SG.first");

    // Rotate the Twilio secret, then send a code through the live service.
    backend
        .save_sms(&admin, verify_candidate(Some("secret-two")))
        .await
        .expect("rotate");
    let sms = cell.boot.sms();
    let want = basic_auth("SKbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "secret-two");
    let used_new_secret = eventually(Duration::from_secs(10), || {
        let sms = sms.clone();
        let want = want.clone();
        let twilio = &twilio;
        async move {
            let _ = sms
                .send(&SmsEnvelope {
                    to_e164: "+15550100".into(),
                    body: "code".into(),
                    otp_code: Some("123456".into()),
                })
                .await;
            let seen = twilio.received_requests().await.unwrap_or_default();
            seen.last().is_some_and(|r| auth_header(r) == want)
        }
    })
    .await;
    assert!(used_new_secret, "next code is sent with the rotated secret");

    let view = backend.view(&admin).await.expect("view");
    assert!(view.sms.twilio_api_secret.is_set);
    assert!(view.email.sendgrid_api_key.is_set);
    assert_eq!(view.email.driver, EmailDriverChoice::SendGrid);
    assert!(view.revision >= 3, "every save bumps the revision");
    cell.boot.shutdown().await;
}

#[tokio::test]
async fn failed_test_send_persists_nothing_and_keeps_the_previous_service_sad() {
    let env = Env::clean().await;
    let rejecting = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v3/mail/send"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&rejecting)
        .await;
    let twilio = twilio_ok().await;
    let cell = cell(&env, &rejecting, &twilio).await;
    let admin = common::as_user(&cell.system, ADMIN);
    let backend = cell.boot.settings_backend();
    let before = backend.view(&admin).await.expect("view");

    let err = backend
        .save_email(&admin, sendgrid_candidate(Some("SG.bad")))
        .await
        .expect_err("provider rejects");
    assert_eq!(
        err,
        DeliveryError::TestSendFailed {
            channel: Channel::Email,
            class: TestFailureClass::Unauthorized,
        }
    );
    let after = backend.view(&admin).await.expect("view");
    assert_eq!(after.revision, before.revision, "revision did not move");
    assert_eq!(after.email.driver, EmailDriverChoice::Off);
    assert!(!after.email.sendgrid_api_key.is_set, "key was not stored");
    cell.boot.refresh_now();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        cell.boot.email().driver(),
        EmailDriver::Noop,
        "never swapped"
    );
    cell.boot.shutdown().await;
}

#[tokio::test]
async fn non_admin_is_denied_by_gate_and_by_row_policy_sad() {
    let env = Env::clean().await;
    let (sendgrid, twilio) = (sendgrid_ok().await, twilio_ok().await);
    let cell = cell(&env, &sendgrid, &twilio).await;
    common::seed_user(&cell.system, "plain_user").await;
    let plain = common::as_user(&cell.system, "plain_user");
    let backend = cell.boot.settings_backend();

    assert_eq!(
        backend.view(&plain).await.expect_err("denied"),
        DeliveryError::PermissionDenied
    );
    assert_eq!(
        backend
            .save_email(&plain, sendgrid_candidate(Some("SG.x")))
            .await
            .expect_err("denied"),
        DeliveryError::PermissionDenied
    );
    assert_eq!(
        backend.rotate_totp_key(&plain).await.expect_err("denied"),
        DeliveryError::PermissionDenied
    );
    assert!(sendgrid.received_requests().await.unwrap().is_empty());

    // Defense in depth: even a caller that skips the backend's gate is refused.
    let direct = uf_lepton_delivery_boot::LeptonDeliverySettings::get(
        uf_lepton_delivery_boot::SETTINGS_ROW_ID,
        &plain,
        valence::use_!(r"**Test:** Fixture **Lepton delivery settings** load by a non-admin for `delivery_boot` so the suite can assert the row policy denies without the server-function gate. CI and developers running the suite only."),
    )
    .await;
    assert!(
        matches!(direct, Ok(None) | Err(_)),
        "row policy must not return the row to a non-admin"
    );
    cell.boot.shutdown().await;
}

#[tokio::test]
async fn unbuildable_settings_keep_previous_service_and_loop_recovers() {
    let env = Env::clean().await;
    let (sendgrid, twilio) = (sendgrid_ok().await, twilio_ok().await);
    let cell = cell(&env, &sendgrid, &twilio).await;
    let admin = common::as_user(&cell.system, ADMIN);
    let backend = cell.boot.settings_backend();
    backend
        .save_email(&admin, sendgrid_candidate(Some("SG.good")))
        .await
        .expect("save");
    assert!(
        eventually(Duration::from_secs(10), || async {
            cell.boot.email().driver() == EmailDriver::Twilio
        })
        .await
    );

    // Break the row as the System actor would see it: SMTP with no host.
    let row = uf_lepton_delivery_boot::LeptonDeliverySettings::get(
        uf_lepton_delivery_boot::SETTINGS_ROW_ID,
        &cell.system,
        valence::use_!(r"**Test:** Fixture **Lepton delivery settings** load for `delivery_boot` so the suite can corrupt it and assert the refresher keeps the previous service. CI and developers running the suite only."),
    )
    .await
    .unwrap()
    .unwrap();
    let mut settings: uf_lepton_delivery_boot::StoredSettings =
        serde_json::from_value(row.settings().clone()).unwrap();
    let good = settings.clone();
    settings.email.driver = EmailDriverChoice::Smtp;
    settings.email.smtp_host.clear();
    let write = |s: &uf_lepton_delivery_boot::StoredSettings, revision: i64| {
        uf_lepton_delivery_boot::LeptonDeliverySettings::new(
            revision,
            serde_json::to_value(s).unwrap(),
            chrono::Utc::now(),
        )
        .unwrap()
    };
    let bad_row = write(&settings, *row.revision() + 1);
    uf_lepton_delivery_boot::LeptonDeliverySettings::upsert(
        uf_lepton_delivery_boot::SETTINGS_ROW_ID,
        bad_row,
        &cell.system,
        valence::use_!(r"**Test:** Fixture **Lepton delivery settings** save for `delivery_boot` so the suite can store settings that do not build a service. CI and developers running the suite only."),
    )
    .await
    .unwrap();
    cell.boot.refresh_now();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        cell.boot.email().driver(),
        EmailDriver::Twilio,
        "a setting that cannot build leaves the working service in place"
    );

    // The loop is still alive: a good revision applies.
    let mut fixed = good;
    fixed.email.from_name = "Recovered".into();
    let good_row = write(&fixed, *row.revision() + 2);
    uf_lepton_delivery_boot::LeptonDeliverySettings::upsert(
        uf_lepton_delivery_boot::SETTINGS_ROW_ID,
        good_row,
        &cell.system,
        valence::use_!(r"**Test:** Fixture **Lepton delivery settings** save for `delivery_boot` so the suite can store a valid revision after a broken one. CI and developers running the suite only."),
    )
    .await
    .unwrap();
    let applied = eventually(Duration::from_secs(10), || async {
        backend
            .view(&admin)
            .await
            .is_ok_and(|v| v.email.from_name == "Recovered")
    })
    .await;
    assert!(applied);
    assert_eq!(cell.boot.email().driver(), EmailDriver::Twilio);
    cell.boot.shutdown().await;
}

#[tokio::test]
async fn second_process_picks_up_a_change_by_polling() {
    let env = Env::clean().await;
    let (sendgrid, twilio) = (sendgrid_ok().await, twilio_ok().await);
    let cell = cell(&env, &sendgrid, &twilio).await;
    let other = install_delivery(
        &cell.system,
        fast(DeliveryOptions::new("http://127.0.0.1:3000")),
    )
    .await
    .expect("second process");
    assert_eq!(other.email().driver(), EmailDriver::Noop);

    let admin = common::as_user(&cell.system, ADMIN);
    cell.boot
        .settings_backend()
        .save_email(&admin, sendgrid_candidate(Some("SG.shared")))
        .await
        .expect("save through the first process");

    assert!(
        eventually(Duration::from_secs(10), || async {
            other.email().driver() == EmailDriver::Twilio
        })
        .await,
        "the other process swaps within a poll interval, with no ping"
    );
    other.shutdown().await;
    cell.boot.shutdown().await;
}

#[tokio::test]
async fn admin_rotates_totp_key_and_ring_keeps_old_versions_without_elevation() {
    let env = Env::clean().await;
    env.set("LEPTON_TOTP_SEAL_KEY", &"ab".repeat(32));
    let (sendgrid, twilio) = (sendgrid_ok().await, twilio_ok().await);
    let cell = cell(&env, &sendgrid, &twilio).await;
    let ring = lepton_auth::totp::key_ring::installed_key_ring().expect("ring after install");
    assert_eq!(ring.versions(), vec![1], "env key is version 1");

    let admin = common::as_user(&cell.system, ADMIN);
    cell.boot
        .settings_backend()
        .rotate_totp_key(&admin)
        .await
        .expect("rotate as a group member");

    assert!(
        eventually(Duration::from_secs(10), || async {
            lepton_auth::totp::key_ring::installed_key_ring()
                .is_some_and(|r| r.current_version() == 2 && r.versions() == vec![1, 2])
        })
        .await,
        "ring has the new version and still holds version 1"
    );
    let view = cell
        .boot
        .settings_backend()
        .view(&admin)
        .await
        .expect("view");
    assert_eq!(view.totp_key.version, 2);
    assert!(view.totp_key.rotated_at.is_some());
    cell.boot.shutdown().await;
}

#[tokio::test]
async fn admin_oauth_secret_goes_live_through_the_handle() {
    let env = Env::clean().await;
    let (sendgrid, twilio) = (sendgrid_ok().await, twilio_ok().await);
    let cell = cell(&env, &sendgrid, &twilio).await;
    assert!(cell.boot.oauth().get().is_none());
    let admin = common::as_user(&cell.system, ADMIN);
    cell.boot
        .settings_backend()
        .save_oauth(
            &admin,
            OAuthCandidate {
                google_client_id: "google-client-id".into(),
                google_client_secret: Some(WriteOnlySecret::new("google-secret")),
                ..OAuthCandidate::default()
            },
        )
        .await
        .expect("save oauth");
    assert!(
        eventually(Duration::from_secs(10), || async {
            cell.boot.oauth().get().is_some_and(|c| {
                c.google_client_id.as_deref() == Some("google-client-id")
                    && c.google_client_secret.as_deref() == Some("google-secret")
            })
        })
        .await
    );
    cell.boot.shutdown().await;
}

#[tokio::test]
async fn delivery_admin_group_seed_is_idempotent() {
    let env = Env::clean().await;
    let (sendgrid, twilio) = (sendgrid_ok().await, twilio_ok().await);
    let cell = cell(&env, &sendgrid, &twilio).await;
    uf_lepton_delivery_boot::ensure_delivery_admin_group(&cell.system)
        .await
        .expect("second seed");
    uf_lepton_delivery_boot::ensure_delivery_admin_group(&cell.system)
        .await
        .expect("third seed");
    cell.boot.shutdown().await;
}
