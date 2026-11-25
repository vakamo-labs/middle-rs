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
