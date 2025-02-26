//! Interceptors for the gRPC client to authenticate with `OpenFGA`.
use std::sync::Arc;

use http::HeaderValue;
#[cfg(feature = "tonic")]
use tonic::service::Interceptor;

use super::{require_ascii, Authorizer};
use crate::error::{Error, Result};

/// Create a simple Authorizer that attaches a given token to any request
/// a client sends. The token is attached with the `Bearer` auth-scheme.
///
/// ## Tonic
/// If the `tonic` feature is enabled, [`Interceptor`](`tonic::service::Interceptor`) is implemented for
/// [`BearerTokenAuthorizer`]. The interceptor does not insert the access token if the intercepted call
/// already has an `Authorization` header.
#[derive(Clone, veil::Redact)]
pub struct BearerTokenAuthorizer {
    #[redact]
    authorization_header: Arc<HeaderValue>,
}

impl BearerTokenAuthorizer {
    /// Create a new interceptor with the given access token.
    /// Pass only the token, without the `Bearer` prefix.
    ///
    /// # Errors
    /// Fails if "Bearer {token}" is not a valid ASCII string.
    pub fn new(token: &str) -> Result<Self> {
        require_ascii(token)?;
        let mut authentication_header = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_e| Error::InvalidHeaderValue)?;
        authentication_header.set_sensitive(true);

        Ok(Self {
            authorization_header: Arc::new(authentication_header),
        })
    }
}

impl Authorizer for BearerTokenAuthorizer {
    fn authorization_header(&self) -> Result<Arc<HeaderValue>> {
        Ok(self.authorization_header.clone())
    }
}

#[cfg(feature = "tonic")]
impl Interceptor for BearerTokenAuthorizer {
    fn call(
        &mut self,
        request: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        let mut request = request;
        let metadata = request.metadata_mut();
        if !metadata.contains_key(http::header::AUTHORIZATION.as_str()) {
            metadata.insert(
                http::header::AUTHORIZATION.as_str(),
                self.authorization_header_tonic()?,
            );
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tonic")]
    mod tonic_tests {
        use tonic::service::Interceptor;

        use super::*;

        #[test]
        fn test_tonic_access_token_added() {
            let mut interceptor = BearerTokenAuthorizer::new("my-token").unwrap();

            let request = tonic::Request::new(());
            assert!(request.metadata().is_empty());
            let modified_request = interceptor.call(request).unwrap();

            let metadata = modified_request.metadata();
            assert!(metadata.contains_key("authorization"));
            assert_eq!(
                interceptor.authorization_header().unwrap(),
                Arc::new(HeaderValue::from_str("Bearer my-token").unwrap())
            );
            assert_eq!(
                metadata.get("authorization").unwrap().to_str().unwrap(),
                "Bearer my-token"
            );
        }

        #[test]
        fn test_tonic_access_token_not_added_if_authorization_present() {
            let mut interceptor = BearerTokenAuthorizer::new("my-token").unwrap();

            let mut request = tonic::Request::new(());
            assert!(request.metadata().is_empty());
            request
                .metadata_mut()
                .insert("authorization", "Bearer existing-token".parse().unwrap());

            let modified_request = interceptor.call(request).unwrap();
            assert_eq!(
                modified_request
                    .metadata()
                    .get("authorization")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "Bearer existing-token"
            );
        }
    }
}
