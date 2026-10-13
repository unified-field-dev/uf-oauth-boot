//! Read and write the settings row.

use chrono::Utc;
use valence::{Model, Valence};

use crate::error::BootError;
use crate::generated::LeptonDeliverySettings;
use crate::stored::StoredSettings;

/// Primary key of the one settings row.
pub const SETTINGS_ROW_ID: &str = "delivery";

/// The row as loaded: revision plus the decoded document.
#[derive(Clone, Debug)]
pub struct Loaded {
    /// Bumped on every save.
    pub revision: i64,
    /// Decoded document.
    pub settings: StoredSettings,
}

/// Load the settings row, or `None` before first-boot seeding.
///
/// # Errors
///
/// [`BootError::Store`] when the read is refused or fails, [`BootError::Decode`]
/// when the stored document does not parse.
pub async fn load(v: &Valence) -> Result<Option<Loaded>, BootError> {
    let row = LeptonDeliverySettings::get(
        SETTINGS_ROW_ID,
        v,
        valence::use_!("When a **delivery admin opens or saves Sign-in and delivery**, or the **server starts or refreshes its email, text-message and sign-in provider settings**, we **load the single settings record**. It holds the chosen email and text-message providers, their non-secret details such as host, port and sender address, and when each secret was last replaced. It holds no passwords or keys, which stay sealed in the secret vault."),
    )
    .await
    .map_err(|source| BootError::Store {
        operation: "load",
        source,
    })?;
    row.map(|row| {
        let settings = serde_json::from_value(row.settings().clone()).map_err(BootError::Decode)?;
        Ok(Loaded {
            revision: *row.revision(),
            settings,
        })
    })
    .transpose()
}

/// Create the row from `initial` when it does not exist. Returns whether it was created.
///
/// Boot calls this under the System Valence the host started with.
///
/// # Errors
///
/// [`BootError::Store`] or [`BootError::Decode`].
pub async fn seed_if_missing(
    system: &Valence,
    initial: &StoredSettings,
) -> Result<bool, BootError> {
    if load(system).await?.is_some() {
        return Ok(false);
    }
    let document = serde_json::to_value(initial).map_err(BootError::Decode)?;
    let row = LeptonDeliverySettings::new(1, document, Utc::now()).map_err(|source| {
        BootError::Store {
            operation: "seed_new",
            source,
        }
    })?;
    LeptonDeliverySettings::upsert(
        SETTINGS_ROW_ID,
        row,
        system,
        valence::use_!("When the **server starts for the first time**, we **save the single settings record** with the email, text-message and sign-in provider details found in its environment, so a delivery admin can change them later from Sign-in and delivery. Passwords and keys are not copied into this record; they go into the sealed secret vault."),
    )
    .await
    .map_err(|source| BootError::Store {
        operation: "seed_save",
        source,
    })?;
    Ok(true)
}

/// Apply `change` to the stored document and save it with the next revision.
/// Returns the new revision.
///
/// Last writer wins when two admins save at once; the revision still moves
/// forward, so every process refreshes.
///
/// # Errors
///
/// [`BootError::Store`] or [`BootError::Decode`]; the load step fails with
/// [`BootError::Store`] when the actor may not read the row.
pub async fn save(
    v: &Valence,
    change: impl FnOnce(&mut StoredSettings) + Send,
) -> Result<i64, BootError> {
    let loaded = load(v).await?;
    let (next_revision, mut settings) = match loaded {
        Some(l) => (l.revision.saturating_add(1), l.settings),
        None => (1, StoredSettings::default()),
    };
    change(&mut settings);
    let document = serde_json::to_value(&settings).map_err(BootError::Decode)?;
    let now = Utc::now();
    let row = LeptonDeliverySettings::new(next_revision, document, now).map_err(|source| {
        BootError::Store {
            operation: "save_new",
            source,
        }
    })?;
    LeptonDeliverySettings::upsert(
        SETTINGS_ROW_ID,
        row,
        v,
        valence::use_!("When a **delivery admin saves Sign-in and delivery**, we **write the single settings record** with the new email, text-message and sign-in provider details and the next revision number, so every server picks up the change within seconds. Passwords and keys are not written here; they go into the sealed secret vault."),
    )
    .await
    .map_err(|source| BootError::Store {
        operation: "save",
        source,
    })?;
    Ok(next_revision)
}
