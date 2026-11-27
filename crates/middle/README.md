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
* Token exchange (RFC 8693) for a server that exchanges the token of each caller: `TokenEndpoint::exchange` sends one request per call, with any client authentication of the Client Credential flow
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

## Token Exchange

With token exchange (RFC 8693), a server that calls other services for its callers exchanges the token of each caller for a token of another service. `TokenEndpoint::exchange` sends one exchange per call and returns the issued token. It keeps no token and does not retry, so your application decides what to cache and when to try again.

```rust,no_run
use middle::{ClientAuthentication, ExchangeRequest, TokenEndpoint};
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build the endpoint once, and clone it for each task.
    let token_endpoint = Url::parse("https://identity.example.com/oauth2/token")?;
    let endpoint = TokenEndpoint::builder(token_endpoint)
        .client_authentication(ClientAuthentication::client_secret_basic("my-service", "my-secret"))
        .build()?;

    // The token of a caller, which your service has validated.
    let caller_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2lnbmF0dXJl";
    let request = ExchangeRequest::new(caller_token, "urn:ietf:params:oauth:token-type:access_token")
        .add_scope("data:read")
        .append_param("resource", "https://api.example.com")
        .append_param("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");

    let started = std::time::Instant::now();
    let issued = endpoint.exchange(&request).await?;
    // Send the token as a Bearer token only if the token endpoint says it is one.
    if issued.is_bearer() {
        // Keep the token until this instant at the latest, with a margin.
        let keep_until = started + issued.lifetime().saturating_sub(std::time::Duration::from_secs(30));
        println!("the token can be used until {keep_until:?}");
    }
    Ok(())
}
```

Rules for a server that exchanges the tokens of its callers:

* Validate the token of the caller on every request, also when you answer from a cache: its signature, its issuer, an audience that names your service, and that it has not expired. Choose the token endpoint by the verified issuer. Some token endpoints do not check the audience of the subject token.
* Key a cache of issued tokens by a hash of the whole subject token and by the target parameters, such as `scope`, `resource` and `audience`. Never key it by a claim such as `sub` or `jti`: claims are not secret, so a forged token with the claim of another caller would find the token issued for that caller.
* Take the time before you call `exchange`, and keep the issued token until that time plus `lifetime()` at the latest: `lifetime()` counts from when the answer arrived, which is later. Drop the token a margin earlier, for example 30 seconds, as the `Authorizer` refreshes early, so that it is still valid when a server checks it. If the answer does not say how long the token lives and the token is not a JWT, `lifetime()` is the default token lifetime of the builder, 5 minutes unless you set another one. For a subject token that is a signed JWT, `lifetime()` ends at the `exp` of the subject token at the latest. `expires_in()` is the lifetime the token endpoint stated, `None` if it stated none: use it for a policy of your own, and cache by `lifetime()`.
* Send one exchange at a time for each cache key, and cache a failed exchange for a short time.
* What `scope` does in a token exchange depends on the token endpoint: some narrow the scopes of the subject token, others add scopes of your client, also when you send none. Check `scope()` or the issued token.
* A token endpoint may ignore `resource` or `audience`. Check `scope()` or the audience of the issued token before you rely on them.
* A token endpoint may issue a refresh token that lives longer than the subject token. Keep one only if your service must act for the caller after the token of the caller has expired, and store it as a secret.
* Never fall back to another identity, such as a token of your service, when an exchange fails. Fail the request of the caller.
* When an exchange fails, `oauth_code()` tells who caused the error. A token endpoint that fails with HTTP 5xx can send any code, so check `is_retryable()` first: if it is true, the error can go away, so try again later.
    * `invalid_request`, `invalid_grant`, `access_denied` or `invalid_scope`: refuse the request of the caller. RFC 8693 (section 2.2.2) requires `invalid_request` for a subject token the token endpoint refuses, and some token endpoints send the other codes. Some also send these codes for a request of your service they refuse, so log the `error_description`, and alert when many callers fail at once.
    * Any other code, such as `invalid_client`, `unauthorized_client` or `invalid_target`, or no code (`oauth_code()` is `None`): an error of your service.

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
- **oauth**: Tokens that middle requests on Tokio. middle keeps them fresh in a background task: from a token endpoint with `Authorizer::client_credentials` or `Authorizer::jwt_bearer`, or from a `TokenSource` of your own with `Authorizer::from_source`. `TokenEndpoint::exchange` sends one token exchange (RFC 8693) per call. Without `oauth`, middle offers `Authorizer::bearer` for a token that never changes, and middle itself depends on neither reqwest nor Tokio.
- **rustls**: Enables reqwest's `rustls` feature: TLS with rustls and aws-lc-rs, checking certificates against the root certificates of the operating system. A container image needs them installed, for example with the `ca-certificates` package. Without `rustls`, enable a TLS feature of reqwest 0.13 in your own `Cargo.toml`, such as `native-tls`: middle uses the reqwest of your build, and a reqwest without TLS cannot reach an `https` token endpoint. `rustls` changes nothing without `oauth`.
- **tonic**: `Authorizer::interceptor`, a `tonic::service::Interceptor` of tonic 0.14
- **jwt**: Signs JWT assertions (RFC 7523) with `middle::jwt`, and enables `oauth`. Enable `jwt` with exactly one of these crypto backends:
    - **aws-lc-rs**: aws-lc-rs.
    - **rust-crypto**: the RustCrypto crates.

    If your application also uses jsonwebtoken 12, choose the backend your jsonwebtoken uses: `aws-lc-rs` in middle with `aws_lc_rs` in jsonwebtoken, or `rust-crypto` with `rust_crypto`. Without a backend, middle does not compile.

    The backends differ for RSA keys whose two primes differ in length: aws-lc-rs signs with them, and rust-crypto refuses them. middle signs once when it loads a key, so `SigningKey::from_pem` returns the error.

    middle passes its backend to every jsonwebtoken call, so it works whatever process-wide default jsonwebtoken has. With both backends in one build, for example with `--all-features`, middle signs with aws-lc-rs, and jsonwebtoken has no default backend: your own `jsonwebtoken::encode` and `jsonwebtoken::decode` calls panic unless your application calls `jsonwebtoken::crypto::CryptoProvider::install_default` at startup.
