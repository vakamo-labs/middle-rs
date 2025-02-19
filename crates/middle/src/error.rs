use std::sync::Arc;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error, Clone)]
pub enum Error {
    #[error("Token cannot be used as a header value. Must be ASCII.")]
    InvalidHeaderValue,
    #[error("Request to fetch token failed: {0}")]
    OAuth2RequestFailed(String),
    #[error("Failed to parse token response: {0}")]
    OAuth2ParseError(String),
    #[error("Request failed: {0}")]
    ReqwestFailed(#[from] Arc<reqwest::Error>),
}

impl Error {
    // pub fn internal(
    //     reason: impl Into<String>,
    //     error: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    // ) -> Self {
    //     Self::InternalError {
    //         reason: reason.into(),
    //         source: error.into(),
    //     }
    // }
}
