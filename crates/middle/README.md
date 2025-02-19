[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://github.com/vakamo-labs/middle-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/vakamo-labs/middle-rs/actions/workflows/ci.yaml)

# Rust Client Authentication

This crate provides client authentication for HTTP and gRPC APIs. Features include:

* Automatic token renewal when expired in a background task
* Thread-safe token management with interior mutability
* `reqwest` integration by using a wrapped `HttpClient`
* `tonic` integration via Interceptors
* Support for OAuth2 Client Credential flow
* Support for Bearer Token authentication
* Based on the `oauth2` crate
* Safe defaults - does not follow redirects and hides sensitive data in Debug
* More flows coming soon!

# Example

In the following example we create a `middle::HttpClient` that wraps a `reqwest::Client`.
The token is kept fresh with a background task of the `ClientCredentialAuthorizer`, so that the client always sends authorized requests.

```rust
use std::str::FromStr;

use middle::SimpleClientCredentialAuthorizerBuilder;
use reqwest::Client;
use url::Url;

#[tokio::main]
async fn main() {
    let client_id = "my-client-id";
    let client_secret = "my-client-secret";
    let token_endpoint = Url::from_str("https://identity.example.com/oauth2/token").unwrap();

    // Create a new Authorizer. The Authorizer keeps the token refreshed in the background.
    let authorizer =
        SimpleClientCredentialAuthorizerBuilder::new(client_id, client_secret, token_endpoint)
            .add_scope("my-scope")
            .refresh_tolerance(std::time::Duration::from_secs(30)) // Refresh 30 seconds before expiry
            .build()
            .await
            .unwrap();

    // The current authorization header. The header is always kept up-to-date.
    // Returns an error if the last refresh failed.
    let header = authorizer.authorization_header().unwrap();

    // Generate a new reqwest Client and wrap it with `HttpClient`.
    let reqwest_client = Client::new();
    let client = middle::HttpClient::new(authorizer).set_client(reqwest_client);

    // Start using the client - the authorization header is automatically added.
    let request = client.get("https://api.example.com/data").unwrap();
    let _response = request.send().await.unwrap();
}
```