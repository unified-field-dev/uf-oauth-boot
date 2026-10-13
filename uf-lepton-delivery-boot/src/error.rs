//! Errors from boot, refresh and the vault wrapper.
//!
//! Display text names operations and fixed secret names only, never values.

use thiserror::Error;

/// Failures from installing delivery settings or refreshing them at runtime.
#[derive(Debug, Error)]
pub enum BootError {
    /// Reading or writing the settings row failed.
    #[error("settings store {operation} failed: {source}")]
    Store {
        /// Operation name.
        operation: &'static str,
        /// Underlying Valence error.
        #[source]
        source: valence::Error,
    },
    /// The stored settings document is not valid.
    #[error("stored settings document is not valid: {0}")]
    Decode(#[source] serde_json::Error),
    /// A Neutrino operation failed.
    #[error("secret vault {operation} failed for {name}: {source}")]
    Vault {
        /// Operation name.
        operation: &'static str,
        /// Fixed secret name.
        name: &'static str,
        /// Underlying Neutrino error.
        #[source]
        source: neutrino::NeutrinoError,
    },
    /// A sealed value is not UTF-8 text.
    #[error("secret {name} is not valid UTF-8")]
    NotUtf8 {
        /// Fixed secret name.
        name: &'static str,
    },
    /// A sealed seal key is not 64 hex characters.
    #[error("TOTP seal key version {version} is not 64 hex characters")]
    BadSealKey {
        /// Key version.
        version: i64,
    },
    /// The secret is missing, so there is nothing to rotate.
    #[error("secret {name} has not been created")]
    SecretMissing {
        /// Fixed secret name.
        name: &'static str,
    },
    /// The OS random source failed.
    #[error("random source failed")]
    Random,
    /// A Gauge group or permission seed failed.
    #[error("gauge seed {operation} failed: {source}")]
    Gauge {
        /// Operation name.
        operation: &'static str,
        /// Underlying Gauge error.
        #[source]
        source: gauge::resource_permissions::ResourcePermissionError,
    },
    /// A service could not be built from the settings.
    #[error("{channel} settings do not build a delivery service")]
    Build {
        /// Channel label.
        channel: &'static str,
    },
}
