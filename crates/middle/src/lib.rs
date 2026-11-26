#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
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
pub mod error;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "client-credentials")]
mod token_endpoint;
#[cfg(feature = "client-credentials")]
mod token_source;
#[cfg(any(feature = "client-credentials", feature = "jwt"))]
pub use assertion::SignedJwt;
#[cfg(feature = "client-credentials")]
pub use assertion::{Assertion, AssertionContext, AssertionSource, FileAssertion};
pub use authorizers::*;
pub use error::{
    ConfigError, Error, ErrorCode, HttpError, InvalidResponse, OAuthError, ResponseProblem, Result,
    SourceError, TransportError,
};
#[cfg(feature = "client-credentials")]
pub use token_source::{AccessToken, TokenContext, TokenReason, TokenSource};
