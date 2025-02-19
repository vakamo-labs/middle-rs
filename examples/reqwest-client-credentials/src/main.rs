use std::str::FromStr;

use middle::{Authorizer, SimpleClientCredentialAuthorizerBuilder};
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
    let _header = authorizer.authorization_header().unwrap();

    // Generate a new reqwest Client and wrap it with `HttpClient`.
    let reqwest_client = Client::new();
    let client = middle::HttpClient::new(authorizer).set_client(reqwest_client);

    // Start using the client - the authorization header is automatically added.
    let request = client.get("https://api.example.com/data").unwrap();
    let _response = request.send().await.unwrap();
}
