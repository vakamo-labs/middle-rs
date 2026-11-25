[![Crates.io](https://img.shields.io/crates/v/middle)](https://crates.io/crates/middle)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://github.com/vakamo-labs/middle-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/vakamo-labs/middle-rs/actions/workflows/ci.yaml)

# Client Authentication Middleware

This crate provides authentication middleware for clients that need to access secure HTTP and gRPC APIs. Features include:

* Automatic token renewal when expired in a background task
* Thread-safe token management with interior mutability
* `reqwest` integration by using a wrapped `HttpClient`
* `tonic` integration via Interceptors
* Support for OAuth2 Client Credential flow
* Support for Bearer Token authentication
* Safe defaults - does not follow redirects and hides sensitive data in Debug
* More flows coming soon!

# Example

In the following example we create a `middle::HttpClient` that wraps a `reqwest::Client`.
The token is kept fresh with a background task of the `ClientCredentialAuthorizer`, so that the client always sends authorized requests.

```rust
use std::str::FromStr;

use middle::{Authorizer, BasicClientCredentialAuthorizer};
use reqwest::Client;
use url::Url;

#[tokio::main]
async fn main() {
    let client_id = "my-client-id";
    let client_secret = "my-client-secret";
    let token_endpoint = Url::from_str("https://identity.example.com/oauth2/token").unwrap();

    // Create a new Authorizer. The Authorizer keeps the token refreshed in the background.
    let authorizer =
        BasicClientCredentialAuthorizer::basic_builder(client_id, client_secret, token_endpoint)
            .add_scope("my-scope")
            .refresh_tolerance(std::time::Duration::from_secs(30)) // Refresh 30 seconds before expiry
            .build()
            .await
            .unwrap();

    // The current authorization header. The header is always kept up-to-date.
    // Returns an error if the last refresh failed.
    let _header = authorizer.authorization_header().unwrap();

    // Generate a new reqwest Client and wrap it with `HttpClient`.
    let reqwest_client = Client::new();
    let client = middle::HttpClient::new(authorizer).set_client(reqwest_client);

    // Start using the client - the authorization header is automatically added.
    let request = client.get("https://api.example.com/data").unwrap();
    let _response = request.send().await.unwrap();
}
```

## Tonic Integration
ALl Authorizers implemented by the `middle` crate, implement `tonic::service::Interceptor` if the `tonic` feature is enabled.

```rust
use hello_world::{greeter_service_client::GreeterServiceClient, SayHelloRequest};
use middle::BearerTokenAuthorizer;
use tonic::transport::Endpoint;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // All authorizers provided by the `middle` crate implement the `tonic::Interceptor` trait.
    let authorizer = BearerTokenAuthorizer::new("my-super-secret-token")?;

    let channel = Endpoint::from_static("http://service.example.com:50051")
        .connect()
        .await?;
    // Use the authorizer as an interceptor.
    let mut client = GreeterServiceClient::with_interceptor(channel, authorizer);

    // All following requests include the authorization header.
    let request = tonic::Request::new(SayHelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
```

# Feature Flags

- **all**: Includes `rustls-tls`, `tonic`, `client-credentials`, `runtime-tokio`, `jwt`, and `aws-lc-rs`.
- **default**: Includes `rustls-tls`, `client-credentials`, and `runtime-tokio`.
- **rustls-tls**: Enables reqwest's `rustls` feature: TLS with rustls and aws-lc-rs, checking certificates against the root certificates of the operating system. A container image needs them installed, for example with the `ca-certificates` package.
- **tonic**: Implement `tonic::service::Interceptor` for all Authorizers
- **runtime-tokio**: Enables the `tokio` runtime (currently the only supported async runtime). Some Authorizers depend on an async runtime to spawn refresh tasks.
- **client-credentials**: Enables the `ClientCredentialAuthorizer` for the OAuth2 Client Credential flow
- **jwt**: Signs JWT assertions (RFC 7523) with `middle::jwt`. Enable `jwt` with exactly one of these crypto backends:
    - **aws-lc-rs**: aws-lc-rs.
    - **rust-crypto**: the RustCrypto crates.

    If your application also uses jsonwebtoken 12, choose the backend your jsonwebtoken uses: `aws-lc-rs` in middle with `aws_lc_rs` in jsonwebtoken, or `rust-crypto` with `rust_crypto`. Without a backend, middle does not compile.

    The backends differ for RSA keys whose two primes differ in length: aws-lc-rs signs with them, and rust-crypto refuses them. middle signs once when it loads a key, so `SigningKey::from_pem` returns the error.

    middle passes its backend to every jsonwebtoken call, so it works whatever process-wide default jsonwebtoken has. With both backends in one build, for example with `--all-features`, middle signs with aws-lc-rs, and jsonwebtoken has no default backend: your own `jsonwebtoken::encode` and `jsonwebtoken::decode` calls panic unless your application calls `jsonwebtoken::crypto::CryptoProvider::install_default` at startup.
