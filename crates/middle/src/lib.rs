#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::pedantic
)]
#![forbid(unsafe_code)]

mod authorizers;
mod client;
pub mod error;
#[cfg(feature = "client-credentials")]
mod token_endpoint;
pub use authorizers::*;
pub use client::*;
pub use error::{
    ConfigError, Error, ErrorCode, HttpError, InvalidResponse, OAuthError, ResponseProblem, Result,
    TransportError,
};
