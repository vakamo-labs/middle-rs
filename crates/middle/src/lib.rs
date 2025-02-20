#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::pedantic
)]
#![forbid(unsafe_code)]

//! [![Crates.io](https://img.shields.io/crates/v/middle)](https://crates.io/crates/middle)
//! [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
//! [![Tests](https://github.com/vakamo-labs/middle-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/vakamo-labs/middle-rs/actions/workflows/ci.yaml)
//!
//! # Client Authentication Middleware
//!
//! This crate provides authentication middleware for clients that need to access secure HTTP and gRPC APIs. Features include:
//!
//! * Automatic token renewal when expired in a background task
//! * Thread-safe token management with interior mutability
//! * `reqwest` integration by using a wrapped `HttpClient`
//! * `tonic` integration via Interceptors
//! * Support for `OAuth2` Client Credential flow
//! * Support for Bearer Token authentication
//! * Based on the `oauth2` crate
//! * Safe defaults - does not follow redirects and hides sensitive data in Debug
//! * More flows coming soon!
//!
//! # Example
//!
//! In the following example we create a `middle::HttpClient` that wraps a `reqwest::Client`.
//! The token is kept fresh with a background task of the `ClientCredentialAuthorizer`, so that the client always sends authorized requests.
//!
//! ```no_run
//! use std::str::FromStr;
//!
//! use middle::SimpleClientCredentialAuthorizerBuilder;
//! use reqwest::Client;
//! use url::Url;
//!
//! use crate::middle::Authorizer;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client_id = "my-client-id";
//!     let client_secret = "my-client-secret";
//!     let token_endpoint = Url::from_str("https://identity.example.com/oauth2/token").unwrap();
//!
//!     // Create a new Authorizer. The Authorizer keeps the token refreshed in the background.
//!     let authorizer =
//!         SimpleClientCredentialAuthorizerBuilder::new(client_id, client_secret, token_endpoint)
//!             .add_scope("my-scope")
//!             .refresh_tolerance(std::time::Duration::from_secs(30)) // Refresh 30 seconds before expiry
//!             .build()
//!             .await
//!             .unwrap();
//!
//!     // The current authorization header. The header is always kept up-to-date.
//!     // Returns an error if the last refresh failed.
//!     let header = authorizer.authorization_header().unwrap();
//!
//!     // Generate a new reqwest Client and wrap it with `HttpClient`.
//!     let reqwest_client = Client::new();
//!     let client = middle::HttpClient::new(authorizer).set_client(reqwest_client);
//!
//!     // Start using the client - the authorization header is automatically added.
//!     let request = client.get("https://api.example.com/data").unwrap();
//!     let _response = request.send().await.unwrap();
//! }
//! ```
//!
//! # Feature Flags
//!
//! - **all**: Includes `rustls-tls`, `tonic`, `client-credentials`, and `runtime-tokio`.
//! - **default**: Includes `rustls-tls`, `client-credentials`, and `runtime-tokio`.
//! - **rustls-tls**: Enables `reqwest/rustls-tls` and `reqwest/rustls-tls-native-roots`.
//! - **tonic**: Implement `tonic::service::Interceptor` for all Authorizers
//! - **runtime-tokio**: Enables the `tokio` runtime (currently the only supported async runtime). Some Authorizers depend on an async runtime to spawn refresh tasks.
//! - **client-credentials**: Enables the `ClientCredentialAuthorizer` for the `OAuth2` Client Credential flow
//!

mod authorizers;
mod client;
pub mod error;
pub use authorizers::*;
pub use client::*;
pub use error::{Error, Result};
