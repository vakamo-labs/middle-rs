//! Signing JWT assertions (RFC 7523, section 3) with the `jwt` feature. The keys in `fixtures/jwt` exist only for these tests.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "aws-lc-rs")]
use jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER as PROVIDER;
#[cfg(not(feature = "aws-lc-rs"))]
use jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as PROVIDER;
use jsonwebtoken::{Algorithm, DecodingKey};
use middle::{
    ConfigError,
    jwt::{JwtAssertion, SigningAlgorithm, SigningKey},
};
use serde_json::{Value, json};

const RSA_PKCS8: &str = include_str!("fixtures/jwt/rsa-2048-pkcs8.pem");
const RSA_PKCS1: &str = include_str!("fixtures/jwt/rsa-2048-pkcs1.pem");
const RSA_PUBLIC: &str = include_str!("fixtures/jwt/rsa-2048-public.pem");
const RSA_1024: &str = include_str!("fixtures/jwt/rsa-1024-pkcs8.pem");
const EC_P256: &str = include_str!("fixtures/jwt/ec-p256-pkcs8.pem");
const EC_P256_SEC1: &str = include_str!("fixtures/jwt/ec-p256-sec1.pem");
const EC_P256_PUBLIC: &str = include_str!("fixtures/jwt/ec-p256-public.pem");
const EC_P384: &str = include_str!("fixtures/jwt/ec-p384-pkcs8.pem");
const EC_P384_PUBLIC: &str = include_str!("fixtures/jwt/ec-p384-public.pem");
const ED25519: &str = include_str!("fixtures/jwt/ed25519-pkcs8.pem");
const ED25519_PUBLIC: &str = include_str!("fixtures/jwt/ed25519-public.pem");
const CERTIFICATE: &str = include_str!("fixtures/jwt/certificate.pem");
/// `openssl x509 -in certificate.pem -outform DER | openssl dgst -sha256 -binary`, base64url without padding.
const CERTIFICATE_X5T_S256: &str = "5BBv8GolnkvNYuhh8k-UmD4VXngLSqlaWE8ePJk0j9s";
const HMAC_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Decoded {
    header: Value,
    claims: serde_json::Map<String, Value>,
}

/// Checks the signature with the public key, then returns header and claims.
fn verify(jwt: &str, algorithm: Algorithm, key: &DecodingKey) -> Decoded {
    let (message, signature) = jwt.rsplit_once('.').expect("three parts");
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .expect("base64url signature");
    let verifier = (PROVIDER.verifier_factory)(&algorithm, key).expect("verifier");
    verifier
        .verify(message.as_bytes(), &signature)
        .expect("the signature verifies with the public key");
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

fn rsa_public() -> DecodingKey {
    DecodingKey::from_rsa_pem(RSA_PUBLIC.as_bytes()).unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn assertion(key: SigningKey) -> JwtAssertion {
    JwtAssertion::new(key, "my-client", "my-subject", "https://idp.example.com")
}

#[test]
fn test_an_assertion_has_the_claims_of_rfc_7523_and_verifies() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256)
        .unwrap()
        .with_key_id("key-1");
    let before = now();

    let jwt = assertion(key).sign().unwrap();

    let decoded = verify(jwt.as_str(), Algorithm::RS256, &rsa_public());
    assert_eq!(
        decoded.header,
        json!({"alg": "RS256", "typ": "JWT", "kid": "key-1"})
    );
    let claims = decoded.claims;
    assert_eq!(claims["iss"], "my-client");
    assert_eq!(claims["sub"], "my-subject");
    assert_eq!(claims["aud"], "https://idp.example.com");
    let iat = claims["iat"].as_u64().unwrap();
    assert!((before..=now()).contains(&iat), "iat {iat}");
    assert_eq!(claims["exp"].as_u64().unwrap(), iat + 60);
    let jti = claims["jti"].as_str().unwrap();
    assert_eq!(URL_SAFE_NO_PAD.decode(jti).unwrap().len(), 16);
    assert_eq!(claims.len(), 6, "{claims:?}");
}

#[test]
fn test_an_algorithm_parses_from_its_alg_value() {
    let names = [
        ("RS256", SigningAlgorithm::Rs256),
        ("RS384", SigningAlgorithm::Rs384),
        ("RS512", SigningAlgorithm::Rs512),
        ("PS256", SigningAlgorithm::Ps256),
        ("PS384", SigningAlgorithm::Ps384),
        ("PS512", SigningAlgorithm::Ps512),
        ("ES256", SigningAlgorithm::Es256),
        ("ES384", SigningAlgorithm::Es384),
        ("EdDSA", SigningAlgorithm::EdDsa),
        ("HS256", SigningAlgorithm::Hs256),
        ("HS384", SigningAlgorithm::Hs384),
        ("HS512", SigningAlgorithm::Hs512),
    ];
    for (name, algorithm) in names {
        assert_eq!(name.parse::<SigningAlgorithm>().unwrap(), algorithm);
        assert_eq!(algorithm.as_str(), name);
        assert_eq!(algorithm.to_string(), name);
    }
}

#[test]
fn test_an_unknown_or_differently_cased_alg_value_is_rejected() {
    // `alg` values are case-sensitive (RFC 7515, section 4.1.1), and `none` never signs.
    for name in ["rs256", "EDDSA", "none", "RS1", ""] {
        let error = name.parse::<SigningAlgorithm>().unwrap_err();
        assert!(
            matches!(&error, ConfigError::UnknownSigningAlgorithm(unknown) if unknown == name),
            "{error:?}"
        );
    }
}

#[test]
fn test_every_algorithm_signs_a_verifiable_assertion() {
    let rsa = rsa_public();
    let p256 = DecodingKey::from_ec_pem(EC_P256_PUBLIC.as_bytes()).unwrap();
    let p384 = DecodingKey::from_ec_pem(EC_P384_PUBLIC.as_bytes()).unwrap();
    let ed25519 = DecodingKey::from_ed_pem(ED25519_PUBLIC.as_bytes()).unwrap();
    let hmac = DecodingKey::from_secret(HMAC_SECRET).unwrap();
    let cases = [
        (
            SigningAlgorithm::Rs256,
            Algorithm::RS256,
            RSA_PKCS8,
            &rsa,
            "RS256",
        ),
        (
            SigningAlgorithm::Rs384,
            Algorithm::RS384,
            RSA_PKCS8,
            &rsa,
            "RS384",
        ),
        (
            SigningAlgorithm::Rs512,
            Algorithm::RS512,
            RSA_PKCS8,
            &rsa,
            "RS512",
        ),
        (
            SigningAlgorithm::Ps256,
            Algorithm::PS256,
            RSA_PKCS8,
            &rsa,
            "PS256",
        ),
        (
            SigningAlgorithm::Ps384,
            Algorithm::PS384,
            RSA_PKCS8,
            &rsa,
            "PS384",
        ),
        (
            SigningAlgorithm::Ps512,
            Algorithm::PS512,
            RSA_PKCS8,
            &rsa,
            "PS512",
        ),
        (
            SigningAlgorithm::Es256,
            Algorithm::ES256,
            EC_P256,
            &p256,
            "ES256",
        ),
        (
            SigningAlgorithm::Es384,
            Algorithm::ES384,
            EC_P384,
            &p384,
            "ES384",
        ),
        (
            SigningAlgorithm::EdDsa,
            Algorithm::EdDSA,
            ED25519,
            &ed25519,
            "EdDSA",
        ),
    ];
    for (algorithm, jwt_algorithm, pem, public, name) in cases {
        let key = SigningKey::from_pem(pem, algorithm).unwrap();
        let jwt = assertion(key).sign().unwrap();
        let decoded = verify(jwt.as_str(), jwt_algorithm, public);
        assert_eq!(decoded.header["alg"], name);
        assert_eq!(algorithm.as_str(), name);
    }
    for (algorithm, jwt_algorithm, name) in [
        (SigningAlgorithm::Hs256, Algorithm::HS256, "HS256"),
        (SigningAlgorithm::Hs384, Algorithm::HS384, "HS384"),
        (SigningAlgorithm::Hs512, Algorithm::HS512, "HS512"),
    ] {
        let key = SigningKey::from_secret(HMAC_SECRET, algorithm).unwrap();
        let jwt = assertion(key).sign().unwrap();
        let decoded = verify(jwt.as_str(), jwt_algorithm, &hmac);
        assert_eq!(decoded.header["alg"], name);
    }
}

#[test]
fn test_an_rsa_key_may_be_in_pkcs1_form() {
    let key = SigningKey::from_pem(RSA_PKCS1, SigningAlgorithm::Rs512).unwrap();

    let jwt = assertion(key).sign().unwrap();

    verify(jwt.as_str(), Algorithm::RS512, &rsa_public());
}

#[test]
fn test_an_ec_key_in_sec1_form_is_rejected_with_a_hint() {
    let error = SigningKey::from_pem(EC_P256_SEC1, SigningAlgorithm::Es256).unwrap_err();

    assert!(
        matches!(&error, ConfigError::InvalidSigningKey(reason) if reason.contains("openssl pkcs8 -topk8 -nocrypt")),
        "{error:?}"
    );
}

#[test]
fn test_a_key_that_does_not_fit_the_algorithm_is_rejected() {
    for (pem, algorithm) in [
        (EC_P256, SigningAlgorithm::Rs256),
        (RSA_PKCS8, SigningAlgorithm::Es256),
        (RSA_PKCS8, SigningAlgorithm::EdDsa),
        (EC_P256, SigningAlgorithm::Es384),
        (ED25519, SigningAlgorithm::Es256),
        (RSA_PKCS8, SigningAlgorithm::Hs256),
        ("not a key", SigningAlgorithm::Rs256),
    ] {
        let error = SigningKey::from_pem(pem, algorithm).unwrap_err();
        assert!(
            matches!(error, ConfigError::InvalidSigningKey(_)),
            "{algorithm:?}: {error:?}"
        );
    }
    let error = SigningKey::from_secret(HMAC_SECRET, SigningAlgorithm::Rs256).unwrap_err();
    assert!(
        matches!(error, ConfigError::InvalidSigningKey(_)),
        "{error:?}"
    );
}

#[test]
fn test_an_rsa_key_shorter_than_2048_bits_is_rejected() {
    let error = SigningKey::from_pem(RSA_1024, SigningAlgorithm::Rs256).unwrap_err();

    assert!(
        matches!(
            error,
            ConfigError::WeakSigningKey {
                algorithm: SigningAlgorithm::Rs256,
                bits: 1024,
                minimum: 2048
            }
        ),
        "{error:?}"
    );
}

#[test]
fn test_an_hmac_secret_shorter_than_its_hash_is_rejected() {
    for (algorithm, length, minimum) in [
        (SigningAlgorithm::Hs256, 31, 256),
        (SigningAlgorithm::Hs384, 47, 384),
        (SigningAlgorithm::Hs512, 63, 512),
    ] {
        let error = SigningKey::from_secret(&HMAC_SECRET[..length], algorithm).unwrap_err();
        assert!(
            matches!(error, ConfigError::WeakSigningKey { bits, minimum: m, .. } if bits == length * 8 && m == minimum),
            "{algorithm:?}: {error:?}"
        );
        assert!(SigningKey::from_secret(&HMAC_SECRET[..=length], algorithm).is_ok());
    }
}

#[test]
fn test_each_assertion_gets_a_new_jti() {
    let assertion = assertion(SigningKey::from_pem(EC_P256, SigningAlgorithm::Es256).unwrap());
    let p256 = DecodingKey::from_ec_pem(EC_P256_PUBLIC.as_bytes()).unwrap();

    let first = verify(assertion.sign().unwrap().as_str(), Algorithm::ES256, &p256);
    let second = verify(assertion.sign().unwrap().as_str(), Algorithm::ES256, &p256);

    assert_ne!(first.claims["jti"], second.claims["jti"]);
}

#[test]
fn test_the_lifetime_can_be_set_in_whole_seconds() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let jwt = assertion(key.clone())
        .with_lifetime(Duration::from_secs(600))
        .unwrap()
        .sign()
        .unwrap();

    let claims = verify(jwt.as_str(), Algorithm::RS256, &rsa_public()).claims;
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        600
    );
    let error = assertion(key)
        .with_lifetime(Duration::from_millis(999))
        .unwrap_err();
    assert!(
        matches!(error, ConfigError::AssertionLifetime(lifetime) if lifetime == Duration::from_millis(999)),
        "{error:?}"
    );
}

#[test]
fn test_extra_claims_are_added_but_registered_ones_are_refused() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let jwt = assertion(key.clone())
        .with_claim("tenant", json!("tenant-1"))
        .unwrap()
        .sign()
        .unwrap();

    let claims = verify(jwt.as_str(), Algorithm::RS256, &rsa_public()).claims;
    assert_eq!(claims["tenant"], "tenant-1");
    for name in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"] {
        let error = assertion(key.clone())
            .with_claim(name, json!("x"))
            .unwrap_err();
        assert!(
            matches!(&error, ConfigError::ReservedClaim(claim) if claim == name),
            "{error:?}"
        );
    }
}

#[test]
fn test_several_audiences_become_an_array() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let jwt = assertion(key)
        .with_audience("https://idp.example.com/token")
        .sign()
        .unwrap();

    let claims = verify(jwt.as_str(), Algorithm::RS256, &rsa_public()).claims;
    assert_eq!(
        claims["aud"],
        json!(["https://idp.example.com", "https://idp.example.com/token"])
    );
}

#[test]
fn test_the_type_header_can_be_set_or_left_out() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let client_authentication = assertion(key.clone())
        .with_type(Some("client-authentication+jwt"))
        .sign()
        .unwrap();
    let without = assertion(key).with_type(None::<String>).sign().unwrap();

    let header = verify(
        client_authentication.as_str(),
        Algorithm::RS256,
        &rsa_public(),
    )
    .header;
    assert_eq!(
        header,
        json!({"alg": "RS256", "typ": "client-authentication+jwt"})
    );
    let header = verify(without.as_str(), Algorithm::RS256, &rsa_public()).header;
    assert_eq!(header, json!({"alg": "RS256"}));
}

#[test]
fn test_the_certificate_thumbprint_is_the_sha256_of_the_der() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Ps256)
        .unwrap()
        .with_certificate_pem(CERTIFICATE)
        .unwrap();

    let jwt = assertion(key).sign().unwrap();

    let header = verify(jwt.as_str(), Algorithm::PS256, &rsa_public()).header;
    assert_eq!(header["x5t#S256"], CERTIFICATE_X5T_S256);
}

#[test]
fn test_a_certificate_that_is_not_pem_is_rejected() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Ps256).unwrap();

    let error = key.with_certificate_pem("no certificate").unwrap_err();

    assert!(
        matches!(error, ConfigError::InvalidCertificate),
        "{error:?}"
    );
}

#[test]
fn test_debug_never_shows_the_key_or_the_assertion() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256)
        .unwrap()
        .with_key_id("key-1");
    let hmac = SigningKey::from_secret(HMAC_SECRET, SigningAlgorithm::Hs256).unwrap();
    let assertion = assertion(key.clone());
    let jwt = assertion.sign().unwrap();
    let key_material = RSA_PKCS8.lines().nth(1).unwrap();
    let (_, signature) = jwt.as_str().rsplit_once('.').unwrap();

    for debug in [
        format!("{key:?}"),
        format!("{hmac:?}"),
        format!("{assertion:?}"),
        format!("{jwt:?}"),
    ] {
        assert!(!debug.contains(key_material), "{debug}");
        assert!(!debug.contains("0123456789abcdef"), "{debug}");
        assert!(!debug.contains(signature), "{debug}");
    }
    assert!(format!("{key:?}").contains("key-1"));
}
