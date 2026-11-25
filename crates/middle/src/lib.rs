#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::pedantic
)]
#![forbid(unsafe_code)]

#[cfg(any(feature = "client-credentials", feature = "jwt"))]
mod assertion;
mod authorizers;
#[cfg(feature = "client-credentials")]
mod cache;
mod client;
pub mod error;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "client-credentials")]
mod token_endpoint;
#[cfg(any(feature = "client-credentials", feature = "jwt"))]
pub use assertion::SignedJwt;
#[cfg(feature = "client-credentials")]
pub use assertion::{AssertionContext, AssertionFuture, AssertionSource, FileAssertion};
pub use authorizers::*;
pub use client::*;
pub use error::{
    AssertionError, ConfigError, Error, ErrorCode, HttpError, InvalidResponse, OAuthError,
    ResponseProblem, Result, TransportError,
};
