[![Crates.io](https://img.shields.io/crates/v/middle)](https://crates.io/crates/middle)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://github.com/vakamo-labs/middle-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/vakamo-labs/middle-rs/actions/workflows/ci.yaml)

# Client Authentication Middleware

This crate provides authentication middleware for clients that need to access secure HTTP and gRPC APIs. Features include:

* Automatic token renewal before expiry in a background task
* One `Authorizer` type, cheap to clone and shared between threads
* Works with any HTTP client, such as `reqwest`: take the header of a valid token from the `Authorizer`
* `tonic` integration through an interceptor
* Support for OAuth2 Client Credential flow, with the client secret (Basic or form body) or a JWT client assertion (RFC 7523): `private_key_jwt`, `client_secret_jwt`, or an assertion from a file such as a Kubernetes service account token
* Support for the JWT bearer grant (RFC 7523, section 2.1), with or without client authentication
* Tokens from a `TokenSource` of your own, such as a token exchange or a cloud SDK, kept fresh in the same way
* Support for Bearer Token authentication
* Safe defaults - does not follow redirects and hides sensitive data in Debug

# Example

In the following example, an `Authorizer` requests a token with the client credentials grant and keeps it fresh in a background task. Each request takes the header of a valid token. A token that the server rejects is dropped, and the request is retried once with a new token.

```rust,no_run
use std::str::FromStr;

use middle::{Authorizer, ClientAuthentication, TokenHeader};
use reqwest::{Client, Response, StatusCode, header::AUTHORIZATION};
use url::Url;

#[tokio::main]
async fn main() {
    let client_id = "my-client-id";
    let client_secret = "my-client-secret";
    let token_endpoint = Url::from_str("https://identity.example.com/oauth2/token").unwrap();

    // Create a new Authorizer. The Authorizer keeps the token refreshed in the background.
    let authorizer = Authorizer::client_credentials(
        token_endpoint,
        ClientAuthentication::client_secret_basic(client_id, client_secret),
    )
    .add_scope("my-scope")
    .refresh_tolerance(std::time::Duration::from_secs(30)) // Refresh 30 seconds before expiry at the latest, if the token lives at least a minute
    .build()
    .await
    .unwrap();
    let client = Client::new();

    // The header of a valid token. If the token has expired, this waits for the refresh.
    let header = authorizer.wait_for_header().await.unwrap();
    let mut response = get_data(&client, &header).await;

    // If the server rejects the token, drop it. If another token can come, retry once with it.
    if response.status() == StatusCode::UNAUTHORIZED && authorizer.invalidate(&header) {
        let header = authorizer.wait_for_header().await.unwrap();
        response = get_data(&client, &header).await;
    }
    println!("{}", response.status());
}

async fn get_data(client: &Client, header: &TokenHeader) -> Response {
    client
        .get("https://api.example.com/data")
        .header(AUTHORIZATION, header.header().clone())
        .send()
        .await
        .unwrap()
}
```

## JWT Bearer Grant

With the JWT bearer grant (RFC 7523, section 2.1), a signed JWT is the grant, for example for a service account with a key file. With the `jwt` feature, middle signs the JWT itself. Without it, pass any `AssertionSource`, such as a `FileAssertion`.

```rust,ignore
use std::time::Duration;

use middle::{
    Authorizer, TokenHeader,
    jwt::{JwtAssertion, SigningAlgorithm, SigningKey},
};
use reqwest::{Client, Response, StatusCode, header::AUTHORIZATION};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The private key, the key id, the issuer, the subject and the audience come from the service account key file.
    let private_key = std::fs::read_to_string("service-account-key.pem")?;
    let key = SigningKey::from_pem(&private_key, SigningAlgorithm::Rs512)?.with_key_id("my-key-id");
    let assertion = JwtAssertion::new(
        key,
        "my-issuer",
        "my-subject",
        "https://identity.example.com",
    )
    .with_lifetime(Duration::from_secs(600))?;

    // The JWT is the grant. middle signs a new one for every token request and keeps the token refreshed in the background.
    let token_endpoint = Url::parse("https://identity.example.com/oauth2/token")?;
    let authorizer = Authorizer::jwt_bearer(token_endpoint, assertion)
        .append_param("resource", "https://api.example.com")
        .build()
        .await?;
    let client = Client::new();

    // The header of a valid token. If the token has expired, this waits for the refresh.
    let header = authorizer.wait_for_header().await?;
    let mut response = get_data(&client, &header).await?;

    // If the server rejects the token, drop it. If another token can come, retry once with it.
    if response.status() == StatusCode::UNAUTHORIZED && authorizer.invalidate(&header) {
        let header = authorizer.wait_for_header().await?;
        response = get_data(&client, &header).await?;
    }
    println!("{}", response.status());
    Ok(())
}

async fn get_data(client: &Client, header: &TokenHeader) -> reqwest::Result<Response> {
    client
        .get("https://api.example.com/data")
        .header(AUTHORIZATION, header.header().clone())
        .send()
        .await
}
```

## Tonic Integration

With the `tonic` feature, `Authorizer::interceptor` returns an interceptor that puts the authorization header on every request.

```rust,ignore
use hello_world::{SayHelloRequest, greeter_service_client::GreeterServiceClient};
use middle::Authorizer;
use tonic::transport::Endpoint;

pub mod hello_world {
    tonic::include_proto!("helloworld");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let authorizer = Authorizer::bearer("my-super-secret-token")?;

    let channel = Endpoint::from_static("http://service.example.com:50051")
        .connect()
        .await?;
    // The interceptor puts the authorization header on every request.
    let mut client = GreeterServiceClient::with_interceptor(channel, authorizer.interceptor());

    let request = tonic::Request::new(SayHelloRequest {
        name: "Tonic".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={:?}", response);

    Ok(())
}
```

# Feature Flags

- **default**: Includes `rustls` and `oauth`.
- **all**: Includes `rustls`, `tonic`, `oauth`, `jwt`, and `aws-lc-rs`.
- **oauth**: Tokens that middle requests and keeps fresh in a background task on Tokio: from a token endpoint with `Authorizer::client_credentials` or `Authorizer::jwt_bearer`, or from a `TokenSource` of your own with `Authorizer::from_source`. Without `oauth`, middle offers `Authorizer::bearer` for a token that never changes, and middle itself depends on neither reqwest nor Tokio.
- **rustls**: Enables reqwest's `rustls` feature: TLS with rustls and aws-lc-rs, checking certificates against the root certificates of the operating system. A container image needs them installed, for example with the `ca-certificates` package. Without `rustls`, enable a TLS feature of reqwest 0.13 in your own `Cargo.toml`, such as `native-tls`: middle uses the reqwest of your build, and a reqwest without TLS cannot reach an `https` token endpoint. `rustls` changes nothing without `oauth`.
- **tonic**: `Authorizer::interceptor`, a `tonic::service::Interceptor` of tonic 0.14
- **jwt**: Signs JWT assertions (RFC 7523) with `middle::jwt`, and enables `oauth`. Enable `jwt` with exactly one of these crypto backends:
    - **aws-lc-rs**: aws-lc-rs.
    - **rust-crypto**: the RustCrypto crates.

    If your application also uses jsonwebtoken 12, choose the backend your jsonwebtoken uses: `aws-lc-rs` in middle with `aws_lc_rs` in jsonwebtoken, or `rust-crypto` with `rust_crypto`. Without a backend, middle does not compile.

    The backends differ for RSA keys whose two primes differ in length: aws-lc-rs signs with them, and rust-crypto refuses them. middle signs once when it loads a key, so `SigningKey::from_pem` returns the error.

    middle passes its backend to every jsonwebtoken call, so it works whatever process-wide default jsonwebtoken has. With both backends in one build, for example with `--all-features`, middle signs with aws-lc-rs, and jsonwebtoken has no default backend: your own `jsonwebtoken::encode` and `jsonwebtoken::decode` calls panic unless your application calls `jsonwebtoken::crypto::CryptoProvider::install_default` at startup.
