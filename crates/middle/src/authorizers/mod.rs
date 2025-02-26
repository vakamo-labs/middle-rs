mod bearer_token;
#[cfg(feature = "client-credentials")]
mod client_credentials;

use std::sync::Arc;

pub use bearer_token::*;
#[cfg(feature = "client-credentials")]
pub use client_credentials::*;
use http::HeaderValue;

/// Main trait of this crate.
pub trait Authorizer {
    /// Returns the authorization header to used for requests.
    ///
    /// # Errors
    /// Fails if a token is not available, for example because the refresh failed.
    fn authorization_header(&self) -> Result<Arc<HeaderValue>, crate::error::Error>;

    #[cfg(feature = "tonic")]
    /// Returns the authorization header to used for requests.
    ///
    /// # Errors
    /// - Fails if `Self::authorization_header()` fails.
    /// - Fails if the header value is not ASCII
    fn authorization_header_tonic(
        &self,
    ) -> Result<tonic::metadata::MetadataValue<tonic::metadata::Ascii>, tonic::Status> {
        use std::str::FromStr;

        let header = self
            .authorization_header()
            .map_err(|e| tonic::Status::unauthenticated(e.to_string()))?;
        let header_str = header.to_str().map_err(|e| {
            tonic::Status::unauthenticated(format!(
                "{}: {e}",
                crate::error::Error::InvalidHeaderValue {}
            ))
        })?;

        tonic::metadata::MetadataValue::from_str(header_str).map_err(|e| {
            tonic::Status::unauthenticated(format!(
                "{}: {e}",
                crate::error::Error::InvalidHeaderValue {}
            ))
        })
    }
}

/// Helper function to ensure that a string is ASCII.
///
/// # Errors
/// Fails with `InvalidHeaderValue` if the string is not ASCII.
pub(crate) fn require_ascii(s: &str) -> Result<(), crate::error::Error> {
    if s.is_ascii() {
        Ok(())
    } else {
        Err(crate::error::Error::InvalidHeaderValue)
    }
}
