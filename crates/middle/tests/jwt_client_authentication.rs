//! `private_key_jwt` and `client_secret_jwt` (RFC 7523, section 2.2; RFC 10070; OpenID Connect Core 1.0, section 9). The keys in `fixtures/jwt` exist only for these tests.

mod support;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "aws-lc-rs")]
use jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER as PROVIDER;
#[cfg(not(feature = "aws-lc-rs"))]
use jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as PROVIDER;
use jsonwebtoken::{Algorithm, DecodingKey};
use middle::{
    ClientAuthentication, ClientCredentialAuthorizer, ConfigError,
    jwt::{Audience, JwtAssertion, SigningAlgorithm, SigningKey},
};
use serde_json::{Value, json};
use support::{FakeIdp, Reply, Request};

const EC_P256: &str = include_str!("fixtures/jwt/ec-p256-pkcs8.pem");
const EC_P256_PUBLIC: &str = include_str!("fixtures/jwt/ec-p256-public.pem");
const CLIENT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const ISSUER: &str = "https://idp.example.com/realms/test";
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

struct Decoded {
    header: Value,
    claims: serde_json::Map<String, Value>,
}

/// Checks the signature with the key, then returns header and claims.
fn verify(jwt: &str, algorithm: Algorithm, key: &DecodingKey) -> Decoded {
    let (message, signature) = jwt.rsplit_once('.').expect("three parts");
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .expect("base64url signature");
    let verifier = (PROVIDER.verifier_factory)(&algorithm, key).expect("verifier");
    verifier
        .verify(message.as_bytes(), &signature)
        .expect("the signature verifies");
    let (header, claims) = message.split_once('.').expect("header and claims");
    let Value::Object(claims) = decode_part(claims) else {
        panic!("the claims are a JSON object");
    };
    Decoded {
        header: decode_part(header),
        claims,
    }
}

fn decode_part(part: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("JSON")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn issuer() -> Audience {
    Audience::Issuer(ISSUER.to_string())
}

fn ec_key() -> SigningKey {
    SigningKey::from_pem(EC_P256, SigningAlgorithm::Es256).unwrap()
}

/// Checks the form of a client assertion request and returns the assertion.
fn client_assertion(request: &Request, client_id: &str) -> String {
    assert_eq!(request.header_all("authorization"), Vec::<&str>::new());
    let names: Vec<String> = request.form().into_iter().map(|(name, _)| name).collect();
    assert_eq!(
        names,
        [
            "grant_type",
            "client_id",
            "client_assertion_type",
            "client_assertion"
        ]
    );
    assert_eq!(request.form_value("client_id").as_deref(), Some(client_id));
    assert_eq!(
        request.form_value("client_assertion_type").as_deref(),
        Some(JWT_BEARER)
    );
    request.form_value("client_assertion").unwrap()
}

/// Checks the claims RFC 7523 (section 3) and RFC 10070 require of a client authentication JWT from `client_id` for `audience`.
/// `signed_after` is a time before the request.
fn assert_client_claims(
    claims: &serde_json::Map<String, Value>,
    client_id: &str,
    audience: &str,
    signed_after: u64,
) {
    let mut names: Vec<&str> = claims.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["aud", "exp", "iat", "iss", "jti", "sub"]);
    assert_eq!(claims["iss"], client_id);
    assert_eq!(claims["sub"], client_id);
    assert_eq!(claims["aud"], audience);
    // `iat` lies 5 seconds before the signing, and `exp` 60 seconds after `iat`.
    let iat = claims["iat"].as_u64().unwrap();
    assert!((signed_after..=now()).contains(&(iat + 5)), "iat {iat}");
    assert_eq!(claims["exp"].as_u64().unwrap(), iat + 60);
    assert_eq!(claims["jti"].as_str().unwrap().len(), 22);
}

#[tokio::test]
async fn test_private_key_jwt_signs_a_typed_assertion_for_the_issuer() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

    let before = now();
    ClientCredentialAuthorizer::builder(
        idp.token_url(),
        ClientAuthentication::private_key_jwt("my-client", ec_key().with_key_id("key-1"), issuer()),
    )
    .build()
    .await
    .unwrap();

    let assertion = client_assertion(&idp.requests()[0], "my-client");
    let public_key = DecodingKey::from_ec_pem(EC_P256_PUBLIC.as_bytes()).unwrap();
    let jwt = verify(&assertion, Algorithm::ES256, &public_key);
    assert_eq!(
        jwt.header,
        json!({"alg": "ES256", "typ": "client-authentication+jwt", "kid": "key-1"})
    );
    assert_client_claims(&jwt.claims, "my-client", ISSUER, before);
}

#[tokio::test]
async fn test_client_secret_jwt_signs_with_the_secret_and_does_not_send_it() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;

    let before = now();
    ClientCredentialAuthorizer::builder(
        idp.token_url(),
        ClientAuthentication::client_secret_jwt("my-client", CLIENT_SECRET, issuer()).unwrap(),
    )
    .build()
    .await
    .unwrap();

    let request = &idp.requests()[0];
    assert!(!request.body.contains(CLIENT_SECRET), "{}", request.body);
    let assertion = client_assertion(request, "my-client");
    let jwt = verify(
        &assertion,
        Algorithm::HS256,
        &DecodingKey::from_secret(CLIENT_SECRET.as_bytes()).unwrap(),
    );
    assert_eq!(
        jwt.header,
        json!({"alg": "HS256", "typ": "client-authentication+jwt"})
    );
    assert_client_claims(&jwt.claims, "my-client", ISSUER, before);
}

#[test]
fn test_client_secret_jwt_refuses_a_secret_shorter_than_256_bits() {
    let error = ClientAuthentication::client_secret_jwt("c", &CLIENT_SECRET[1..], issuer())
        .expect_err("RFC 7518, section 3.2");

    assert!(
        matches!(
            error,
            ConfigError::WeakSigningKey {
                algorithm: SigningAlgorithm::Hs256,
                bits: 248,
                minimum: 256
            }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn test_private_key_jwt_for_the_token_endpoint_signs_an_untyped_jwt_for_its_url() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    let mut token_url = idp.token_url();
    token_url.set_query(Some("tenant=t1"));

    let before = now();
    ClientCredentialAuthorizer::builder(
        token_url.clone(),
        ClientAuthentication::private_key_jwt("my-client", ec_key(), Audience::TokenEndpoint),
    )
    .build()
    .await
    .unwrap();

    let assertion = client_assertion(&idp.requests()[0], "my-client");
    let public_key = DecodingKey::from_ec_pem(EC_P256_PUBLIC.as_bytes()).unwrap();
    let jwt = verify(&assertion, Algorithm::ES256, &public_key);
    assert_eq!(jwt.header, json!({"alg": "ES256", "typ": "JWT"}));
    // The query of the token URL is not part of the audience.
    assert_client_claims(&jwt.claims, "my-client", idp.token_url().as_str(), before);
}

#[tokio::test]
async fn test_a_jwt_assertion_is_a_source_that_sends_its_own_header() {
    let idp = FakeIdp::start(|_| Reply::token("t", Some(3600))).await;
    // For an authorization server that refuses the type `client-authentication+jwt`.
    let assertion = JwtAssertion::new(ec_key(), "my-client", "my-client", ISSUER);

    let before = now();
    ClientCredentialAuthorizer::builder(
        idp.token_url(),
        ClientAuthentication::client_assertion("my-client", assertion),
    )
    .build()
    .await
    .unwrap();

    let assertion = client_assertion(&idp.requests()[0], "my-client");
    let public_key = DecodingKey::from_ec_pem(EC_P256_PUBLIC.as_bytes()).unwrap();
    let jwt = verify(&assertion, Algorithm::ES256, &public_key);
    assert_eq!(jwt.header, json!({"alg": "ES256", "typ": "JWT"}));
    assert_client_claims(&jwt.claims, "my-client", ISSUER, before);
}

#[test]
fn test_debug_output_hides_the_keys() {
    for authentication in [
        ClientAuthentication::private_key_jwt("my-client", ec_key(), issuer()),
        ClientAuthentication::client_secret_jwt("my-client", CLIENT_SECRET, issuer()).unwrap(),
    ] {
        let debug = format!("{authentication:?}");
        assert!(debug.contains("my-client"), "{debug}");
        assert!(debug.contains(ISSUER), "{debug}");
        assert!(!debug.contains(CLIENT_SECRET), "{debug}");
        assert!(!debug.contains("PRIVATE KEY"), "{debug}");
    }
}
