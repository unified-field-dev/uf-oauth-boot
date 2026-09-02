//! Typed failures for [`crate::resolve_oauth_config_from_neutrino`].

/// Failure while resolving [`lepton_auth::oauth::OAuthClientConfig`] from Neutrino.
///
/// Variants name the Neutrino operation and the stable secret name when
/// applicable. [`Self::WrongKind`] is returned when the latest name+scope row
/// is not [`crate::OAUTH_SECRET_KIND`] (no decrypt). Display and `Error::source`
/// must not include client-secret plaintext (callers may log `{e}` at host boot).
#[derive(Debug)]
pub enum ResolveOAuthConfigError {
    /// Neutrino `put_or_reuse` failed while seeding a named secret from env.
    Seed {
        /// Stable Neutrino secret name (never plaintext).
        name: &'static str,
        /// Underlying Neutrino / Valence aggregate error.
        source: anyhow::Error,
    },
    /// Neutrino `get` failed for a named secret.
    Get {
        /// Stable Neutrino secret name (never plaintext).
        name: &'static str,
        /// Underlying Neutrino / Valence aggregate error.
        source: anyhow::Error,
    },
    /// Valence secret listing failed while looking up existing OAuth rows.
    List {
        /// Underlying Neutrino / Valence aggregate error.
        source: anyhow::Error,
    },
    /// Sealed secret bytes were not valid UTF-8 (no raw bytes in Display).
    InvalidUtf8 {
        /// Stable Neutrino secret name (never plaintext).
        name: &'static str,
    },
    /// Latest name+scope row is not [`crate::OAUTH_SECRET_KIND`] (no `get`).
    WrongKind {
        /// Stable Neutrino secret name (never plaintext).
        name: &'static str,
        /// Observed Neutrino kind (never plaintext).
        kind: String,
    },
}

impl std::fmt::Display for ResolveOAuthConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Seed { name, source } => {
                write!(
                    f,
                    "seed OAuth secret {name} via Neutrino put_or_reuse: {source}"
                )
            }
            Self::Get { name, source } => {
                write!(f, "get OAuth secret {name} from Neutrino: {source}")
            }
            Self::List { source } => {
                write!(f, "list Neutrino secrets for OAuth resolve: {source}")
            }
            Self::InvalidUtf8 { name } => {
                write!(f, "OAuth secret {name} plaintext is not valid UTF-8")
            }
            Self::WrongKind { name, kind } => {
                write!(
                    f,
                    "OAuth secret {name} has kind {kind}, expected {}",
                    crate::OAUTH_SECRET_KIND
                )
            }
        }
    }
}

impl std::error::Error for ResolveOAuthConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Seed { source, .. } | Self::Get { source, .. } | Self::List { source } => {
                Some(source.as_ref())
            }
            Self::InvalidUtf8 { .. } | Self::WrongKind { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ResolveOAuthConfigError;

    #[test]
    fn resolve_error_display_and_source() {
        let seed = ResolveOAuthConfigError::Seed {
            name: "oauth.google.client_secret",
            source: anyhow::anyhow!("seed-test"),
        };
        let msg = seed.to_string();
        assert!(
            msg.contains("seed OAuth secret oauth.google.client_secret"),
            "got: {msg}"
        );
        assert!(msg.contains("seed-test"), "got: {msg}");
        assert!(std::error::Error::source(&seed).is_some());

        let get = ResolveOAuthConfigError::Get {
            name: "oauth.github.client_secret",
            source: anyhow::anyhow!("get-test"),
        };
        let msg = get.to_string();
        assert!(
            msg.contains("get OAuth secret oauth.github.client_secret"),
            "got: {msg}"
        );

        let list = ResolveOAuthConfigError::List {
            source: anyhow::anyhow!("list-test"),
        };
        let msg = list.to_string();
        assert!(
            msg.contains("list Neutrino secrets for OAuth resolve"),
            "got: {msg}"
        );
        assert!(msg.contains("list-test"), "got: {msg}");

        let bad = ResolveOAuthConfigError::InvalidUtf8 {
            name: "oauth.google.client_secret",
        };
        let msg = bad.to_string();
        assert!(
            msg.contains("oauth.google.client_secret") && msg.contains("UTF-8"),
            "got: {msg}"
        );
        assert!(std::error::Error::source(&bad).is_none());

        let kind = ResolveOAuthConfigError::WrongKind {
            name: "oauth.google.client_secret",
            kind: "password".into(),
        };
        let msg = kind.to_string();
        assert!(
            msg.contains("oauth.google.client_secret") && msg.contains("password"),
            "got: {msg}"
        );
        assert!(
            !msg.contains("secret-value"),
            "WrongKind Display must not invent plaintext: {msg}"
        );
        assert!(std::error::Error::source(&kind).is_none());
    }
}
