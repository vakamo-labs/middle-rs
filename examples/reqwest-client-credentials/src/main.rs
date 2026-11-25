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
