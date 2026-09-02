//! Resolved Lepton OAuth config with redacted [`Debug`].

use lepton_auth::oauth::OAuthClientConfig;

/// Lepton [`OAuthClientConfig`] returned by Neutrino resolve, with secrets
/// hidden from [`Debug`].
///
/// Call [`Self::into_lepton`] before `LeptonAuthServicesBuilder::oauth`. The
/// inner lepton type still derives `Debug` with plaintext secrets; do not
/// format that value.
#[must_use]
#[derive(Clone)]
pub struct ResolvedOAuthClientConfig {
    inner: OAuthClientConfig,
}

impl ResolvedOAuthClientConfig {
    pub(crate) const fn from_lepton(inner: OAuthClientConfig) -> Self {
        Self { inner }
    }

    /// Lepton config for `LeptonAuthServicesBuilder::oauth`.
    ///
    /// [`OAuthClientConfig`] Debug includes client-secret fields. Prefer this
    /// wrapper at log sites.
    #[must_use]
    pub fn into_lepton(self) -> OAuthClientConfig {
        self.inner
    }
}

impl std::fmt::Debug for ResolvedOAuthClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedOAuthClientConfig")
            .field("public_base_url", &self.inner.public_base_url)
            .field("redirect_path", &self.inner.redirect_path)
            .field("google_client_id", &self.inner.google_client_id)
            .field(
                "google_client_secret",
                &self
                    .inner
                    .google_client_secret
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("github_client_id", &self.inner.github_client_id)
            .field(
                "github_client_secret",
                &self
                    .inner
                    .github_client_secret
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("use_mock_provider", &self.inner.use_mock_provider)
            .field("mock_oidc_issuer_url", &self.inner.mock_oidc_issuer_url)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::ResolvedOAuthClientConfig;
    use lepton_auth::oauth::OAuthClientConfig;

    #[test]
    fn debug_redacts_client_secrets() {
        let secret = "must-not-appear-in-debug";
        let cfg = ResolvedOAuthClientConfig::from_lepton(OAuthClientConfig {
            public_base_url: "http://127.0.0.1:3000".into(),
            redirect_path: "/auth/oauth/callback".into(),
            google_client_id: Some("google-client-id".into()),
            google_client_secret: Some(secret.into()),
            github_client_id: Some("github-client-id".into()),
            github_client_secret: Some(secret.into()),
            use_mock_provider: false,
            mock_oidc_issuer_url: None,
            google_token_url: None,
            google_userinfo_url: None,
            github_token_url: None,
            github_user_url: None,
            github_emails_url: None,
        });
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains(secret),
            "Debug must not include client secret: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "Debug should mark secrets redacted: {dbg}"
        );
        assert!(dbg.contains("google-client-id"), "got: {dbg}");
        let inner = cfg.into_lepton();
        assert_eq!(inner.google_client_secret.as_deref(), Some(secret));
    }
}
