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
pub use authorizers::*;
pub use client::*;
pub use error::{Error, Result};
