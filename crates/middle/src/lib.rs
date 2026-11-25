#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::pedantic
)]
#![forbid(unsafe_code)]

mod authorizers;
#[cfg(feature = "client-credentials")]
mod cache;
mod client;
pub mod error;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "client-credentials")]
mod token_endpoint;
pub use authorizers::*;
pub use client::*;
pub use error::{
    AssertionError, ConfigError, Error, ErrorCode, HttpError, InvalidResponse, OAuthError,
    ResponseProblem, Result, TransportError,
};
