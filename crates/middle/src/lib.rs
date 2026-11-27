#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::pedantic
)]
#![forbid(unsafe_code)]

#[cfg(feature = "oauth")]
mod assertion;
mod authorizers;
#[cfg(feature = "oauth")]
mod cache;
pub mod error;
#[cfg(feature = "jwt")]
pub mod jwt;
#[cfg(feature = "oauth")]
mod token_endpoint;
#[cfg(feature = "oauth")]
mod token_source;
#[cfg(feature = "oauth")]
pub use assertion::{Assertion, AssertionContext, AssertionSource, FileAssertion, SignedJwt};
pub use authorizers::*;
#[cfg(feature = "oauth")]
pub use error::TransportError;
pub use error::{
    ConfigError, Error, ErrorCode, HttpError, InvalidResponse, OAuthError, ResponseProblem, Result,
    SourceError,
};
#[cfg(feature = "oauth")]
pub use token_source::{AccessToken, TokenContext, TokenReason, TokenSource};
