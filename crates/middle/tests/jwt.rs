//! Signing JWT assertions (RFC 7523, section 3) with the `jwt` feature. The keys in `fixtures/jwt` exist only for these tests.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
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
const RSA_PUBLIC_PKCS1: &str = include_str!("fixtures/jwt/rsa-2048-public-pkcs1.pem");
const RSA_1024: &str = include_str!("fixtures/jwt/rsa-1024-pkcs8.pem");
const RSA_8200: &str = include_str!("fixtures/jwt/rsa-8200-pkcs8.pem");
const EC_P256: &str = include_str!("fixtures/jwt/ec-p256-pkcs8.pem");
/// `ec-p256-pkcs8.pem` with the curve as explicit parameters.
const EC_P256_EXPLICIT: &str = include_str!("fixtures/jwt/ec-p256-explicit-pkcs8.pem");
const EC_P256_SEC1: &str = include_str!("fixtures/jwt/ec-p256-sec1.pem");
const EC_P256_PUBLIC: &str = include_str!("fixtures/jwt/ec-p256-public.pem");
const EC_P384: &str = include_str!("fixtures/jwt/ec-p384-pkcs8.pem");
const EC_P384_PUBLIC: &str = include_str!("fixtures/jwt/ec-p384-public.pem");
const EC_P521: &str = include_str!("fixtures/jwt/ec-p521-pkcs8.pem");
const ED25519: &str = include_str!("fixtures/jwt/ed25519-pkcs8.pem");
const ED25519_PUBLIC: &str = include_str!("fixtures/jwt/ed25519-public.pem");
const ED448: &str = include_str!("fixtures/jwt/ed448-pkcs8.pem");
/// The certificate of `rsa-2048-pkcs8.pem`.
const CERTIFICATE: &str = include_str!("fixtures/jwt/certificate.pem");
/// The certificate of `rsa-2048-pkcs8.pem`, issued by `certificate-ed25519.pem`.
const CERTIFICATE_RSA_ED25519_ISSUER: &str =
    include_str!("fixtures/jwt/certificate-rsa-ed25519-issuer.pem");
/// The certificate of `ec-p256-pkcs8.pem`.
const CERTIFICATE_EC_P256: &str = include_str!("fixtures/jwt/certificate-ec-p256.pem");
/// The certificate of `ed25519-pkcs8.pem`.
const CERTIFICATE_ED25519: &str = include_str!("fixtures/jwt/certificate-ed25519.pem");
/// The certificate of an RSA key that is not in the fixtures.
const CERTIFICATE_OTHER: &str = include_str!("fixtures/jwt/certificate-other.pem");
/// The certificate of `rsa-2048-pkcs8.pem`, with its names as BMPString.
const CERTIFICATE_BMPSTRING: &str = include_str!("fixtures/jwt/certificate-bmpstring.pem");
/// The certificate of `rsa-2048-pkcs8.pem`, with its names as PrintableString holding `*` and `&`.
const CERTIFICATE_PRINTABLESTRING: &str =
    include_str!("fixtures/jwt/certificate-printablestring.pem");
/// The X.509 v1 certificate of `ec-p256-pkcs8.pem`: no version field, no extensions.
const CERTIFICATE_V1_EC_P256: &str = include_str!("fixtures/jwt/certificate-v1-ec-p256.pem");
/// `openssl x509 -in certificate.pem -outform DER | openssl dgst -sha256 -binary`, base64url without padding.
const CERTIFICATE_X5T_S256: &str = "5BBv8GolnkvNYuhh8k-UmD4VXngLSqlaWE8ePJk0j9s";
const HMAC_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ENCRYPTED_PRIVATE_KEY: &str =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
const NOT_PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";

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

/// The DER bytes of a PEM block.
fn der(pem: &str) -> Vec<u8> {
    let base64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(base64).expect("base64")
}

/// The reason of a [`ConfigError::InvalidSigningKey`].
fn invalid_key_reason(error: ConfigError) -> String {
    match error {
        ConfigError::InvalidSigningKey(reason) => reason,
        other => panic!("expected `InvalidSigningKey`, got {other:?}"),
    }
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

    assert_eq!(
        invalid_key_reason(error),
        "the EC key is in SEC1 form; convert it to PKCS#8 with `openssl pkcs8 -topk8 -nocrypt`"
    );
}

#[test]
fn test_a_key_that_does_not_fit_the_algorithm_is_rejected() {
    for (pem, algorithm, reason) in [
        (
            EC_P256,
            SigningAlgorithm::Rs256,
            "the key is an EC key, but RS256 needs an RSA key",
        ),
        (
            EC_P256_SEC1,
            SigningAlgorithm::Ps256,
            "the key is an EC key, but PS256 needs an RSA key",
        ),
        (
            RSA_PKCS8,
            SigningAlgorithm::Es256,
            "the key is an RSA key, but ES256 needs an EC key",
        ),
        (
            RSA_PKCS1,
            SigningAlgorithm::EdDsa,
            "the key is an RSA key, but EdDSA needs an Ed25519 key",
        ),
        (
            ED25519,
            SigningAlgorithm::Es256,
            "the key is an Ed25519 key, but ES256 needs an EC key",
        ),
        (
            EC_P256,
            SigningAlgorithm::Es384,
            "the EC key is on the curve P-256, but ES384 needs P-384",
        ),
        (
            EC_P384,
            SigningAlgorithm::Es256,
            "the EC key is on the curve P-384, but ES256 needs P-256",
        ),
        (
            EC_P521,
            SigningAlgorithm::Es384,
            "the EC key is on the curve P-521, but ES384 needs P-384",
        ),
        (
            EC_P256_EXPLICIT,
            SigningAlgorithm::Es256,
            "the EC key does not name its curve; convert it to a named curve with `openssl pkey -in key.pem -ec_param_enc named_curve -out key-named.pem`",
        ),
        (
            ED448,
            SigningAlgorithm::EdDsa,
            "the key has the algorithm 1.3.101.113, which middle does not sign with",
        ),
        (
            RSA_PKCS8,
            SigningAlgorithm::Hs256,
            "an HMAC algorithm signs with a shared secret: use `SigningKey::from_secret`",
        ),
        (
            "not a key",
            SigningAlgorithm::Rs256,
            "the key is not in PEM form",
        ),
        (
            NOT_PKCS8,
            SigningAlgorithm::Rs256,
            "the key is not in PKCS#8 form",
        ),
    ] {
        let error = SigningKey::from_pem(pem, algorithm).unwrap_err();
        assert_eq!(invalid_key_reason(error), reason, "{algorithm}");
    }
    let error = SigningKey::from_secret(HMAC_SECRET, SigningAlgorithm::Rs256).unwrap_err();
    assert_eq!(
        invalid_key_reason(error),
        "a shared secret signs only with an HMAC algorithm: use `SigningKey::from_pem` for a private key"
    );
}

#[test]
fn test_a_public_key_or_certificate_is_not_a_private_key() {
    let public_key = "the PEM holds a public key, not a private key";
    let certificate = "the PEM holds a certificate, not a private key";
    for (pem, algorithm, reason) in [
        (RSA_PUBLIC, SigningAlgorithm::Rs256, public_key),
        (RSA_PUBLIC_PKCS1, SigningAlgorithm::Rs256, public_key),
        (CERTIFICATE, SigningAlgorithm::Ps256, certificate),
        (EC_P256_PUBLIC, SigningAlgorithm::Es256, public_key),
        (CERTIFICATE_EC_P256, SigningAlgorithm::Es256, certificate),
        (ED25519_PUBLIC, SigningAlgorithm::EdDsa, public_key),
        (CERTIFICATE_ED25519, SigningAlgorithm::EdDsa, certificate),
        (
            ENCRYPTED_PRIVATE_KEY,
            SigningAlgorithm::Rs256,
            "the PEM holds `ENCRYPTED PRIVATE KEY`, not `PRIVATE KEY` or `RSA PRIVATE KEY`",
        ),
    ] {
        let error = SigningKey::from_pem(pem, algorithm).unwrap_err();
        assert_eq!(invalid_key_reason(error), reason, "{algorithm}: {pem}");
    }
}

#[test]
fn test_a_key_that_cannot_sign_is_rejected_with_the_cause() {
    // The P-256 key with its private scalar set to zero, which no backend accepts.
    let mut key = der(EC_P256);
    // ECPrivateKey (RFC 5915): version 1, then the scalar as an OCTET STRING of 32 bytes.
    let scalar = key
        .windows(5)
        .position(|window| window == [0x02, 0x01, 0x01, 0x04, 0x20])
        .expect("the scalar")
        + 5;
    key[scalar..scalar + 32].fill(0);
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        STANDARD.encode(key)
    );

    let error = SigningKey::from_pem(pem, SigningAlgorithm::Es256).unwrap_err();

    assert_eq!(
        invalid_key_reason(error),
        "the key cannot sign with ES256: InvalidEcdsaKey"
    );
}

#[test]
fn test_a_key_that_cannot_be_read_is_rejected_with_the_cause() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nbm90IERFUg==\n-----END RSA PRIVATE KEY-----\n";

    let error = SigningKey::from_pem(pem, SigningAlgorithm::Rs256).unwrap_err();

    assert_eq!(
        invalid_key_reason(error),
        "the key cannot be read: InvalidKeyFormat"
    );
}

#[test]
fn test_an_rsa_key_longer_than_8192_bits_is_rejected() {
    let error = SigningKey::from_pem(RSA_8200, SigningAlgorithm::Rs256).unwrap_err();

    assert_eq!(
        invalid_key_reason(error),
        "the RSA key has 8200 bits; middle signs with RSA keys of 2048 to 8192 bits"
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

    for (lifetime, seconds) in [
        (Duration::from_secs(1), 1),
        (Duration::from_millis(1900), 1),
        (Duration::from_secs(600), 600),
        (Duration::from_secs(3600), 3600),
    ] {
        let jwt = assertion(key.clone())
            .with_lifetime(lifetime)
            .unwrap()
            .sign()
            .unwrap();

        let claims = verify(jwt.as_str(), Algorithm::RS256, &rsa_public()).claims;
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            seconds,
            "{lifetime:?}"
        );
    }
}

#[test]
fn test_a_lifetime_outside_one_second_to_one_hour_is_rejected() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    for lifetime in [
        Duration::ZERO,
        Duration::from_millis(999),
        Duration::from_millis(3_600_001),
        Duration::MAX,
    ] {
        let error = assertion(key.clone()).with_lifetime(lifetime).unwrap_err();
        assert!(
            matches!(error, ConfigError::AssertionLifetime(rejected) if rejected == lifetime),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!("an assertion lifetime must be from one second to one hour, not {lifetime:?}")
        );
    }
}

#[test]
fn test_nbf_can_be_added_and_is_not_set_by_middle() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let with_nbf = assertion(key.clone())
        .with_claim("nbf", 1)
        .unwrap()
        .sign()
        .unwrap();
    let without = assertion(key).sign().unwrap();

    let claims = verify(with_nbf.as_str(), Algorithm::RS256, &rsa_public()).claims;
    assert_eq!(claims["nbf"], 1);
    let claims = verify(without.as_str(), Algorithm::RS256, &rsa_public()).claims;
    assert_eq!(claims.get("nbf"), None);
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
    for name in ["iss", "sub", "aud", "exp", "iat", "jti"] {
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
fn test_the_audience_is_a_single_string() {
    // RFC 10070: the authorization server's issuer identifier is the sole `aud` value, and servers reject an array.
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let jwt = assertion(key).sign().unwrap();

    let claims = verify(jwt.as_str(), Algorithm::RS256, &rsa_public()).claims;
    assert_eq!(claims["aud"], json!("https://idp.example.com"));
}

#[test]
fn test_the_type_header_can_be_set_or_left_out() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let client_authentication = assertion(key.clone())
        .with_type("client-authentication+jwt")
        .sign()
        .unwrap();
    let without = assertion(key).without_type().sign().unwrap();

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
    let from_pem = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Ps256)
        .unwrap()
        .with_certificate_pem(CERTIFICATE)
        .unwrap();
    let from_der = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Ps256)
        .unwrap()
        .with_certificate_der(der(CERTIFICATE))
        .unwrap();

    for key in [from_pem, from_der] {
        let jwt = assertion(key).sign().unwrap();

        let header = verify(jwt.as_str(), Algorithm::PS256, &rsa_public()).header;
        assert_eq!(header["x5t#S256"], CERTIFICATE_X5T_S256);
    }
}

#[test]
fn test_a_certificate_of_the_signing_key_is_accepted_for_each_key_type() {
    // Thumbprints: `openssl x509 -in <certificate> -outform DER | openssl dgst -sha256 -binary`, base64url without padding.
    for (pem, algorithm, certificate, x5t_s256) in [
        (
            RSA_PKCS8,
            SigningAlgorithm::Rs256,
            CERTIFICATE,
            CERTIFICATE_X5T_S256,
        ),
        // The issuer signed with Ed25519, so the certificate names Ed25519 before the RSA key.
        (
            RSA_PKCS1,
            SigningAlgorithm::Ps512,
            CERTIFICATE_RSA_ED25519_ISSUER,
            "wQ2FCJJeUroy_IvI9Cy9b8U3UJmJg8txgPkfmXJovS4",
        ),
        (
            EC_P256,
            SigningAlgorithm::Es256,
            CERTIFICATE_EC_P256,
            "bf6Al3EpEQ6i5LblZZDtJj88LaExMe1ym1NMA5wYxIU",
        ),
        (
            ED25519,
            SigningAlgorithm::EdDsa,
            CERTIFICATE_ED25519,
            "kI2Wss5Ns_XeFZt7xG9g6y44sv3zY1JtQAFjOEImCeM",
        ),
        (
            RSA_PKCS8,
            SigningAlgorithm::Rs256,
            CERTIFICATE_BMPSTRING,
            "v1u7_29jHmzFvXmABu8A7wImUJxVX_QOPSUPMR5SNCM",
        ),
        (
            RSA_PKCS8,
            SigningAlgorithm::Rs256,
            CERTIFICATE_PRINTABLESTRING,
            "AfKgbbSQepCoH5yFm8YV9qlLJQTGXwmDutrXXT5kOIU",
        ),
        (
            EC_P256,
            SigningAlgorithm::Es256,
            CERTIFICATE_V1_EC_P256,
            "2knYpcLafPM4nUezro8rmbWCm1whBapdoF2deDPnh4Q",
        ),
    ] {
        let key = SigningKey::from_pem(pem, algorithm)
            .unwrap()
            .with_certificate_pem(certificate)
            .unwrap();

        let jwt = assertion(key).sign().unwrap();

        let (header, _) = jwt.as_str().split_once('.').unwrap();
        assert_eq!(decode_part(header)["x5t#S256"], x5t_s256, "{algorithm}");
    }
}

#[test]
fn test_a_certificate_of_another_key_is_rejected() {
    let rsa = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();
    let p256 = SigningKey::from_pem(EC_P256, SigningAlgorithm::Es256).unwrap();
    let p384 = SigningKey::from_pem(EC_P384, SigningAlgorithm::Es384).unwrap();
    let ed25519 = SigningKey::from_pem(ED25519, SigningAlgorithm::EdDsa).unwrap();
    let hmac = SigningKey::from_secret(HMAC_SECRET, SigningAlgorithm::Hs256).unwrap();

    for error in [
        rsa.clone()
            .with_certificate_pem(CERTIFICATE_OTHER)
            .unwrap_err(),
        rsa.clone()
            .with_certificate_der(der(CERTIFICATE_OTHER))
            .unwrap_err(),
        rsa.with_certificate_pem(CERTIFICATE_EC_P256).unwrap_err(),
        p384.with_certificate_pem(CERTIFICATE_EC_P256).unwrap_err(),
        p256.with_certificate_pem(CERTIFICATE_ED25519).unwrap_err(),
        ed25519
            .with_certificate_pem(CERTIFICATE_RSA_ED25519_ISSUER)
            .unwrap_err(),
        hmac.with_certificate_pem(CERTIFICATE).unwrap_err(),
    ] {
        assert!(
            matches!(error, ConfigError::CertificateKeyMismatch),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "the public key of the certificate does not belong to the signing key"
        );
    }
}

#[test]
fn test_a_certificate_that_cannot_be_read_is_rejected() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Ps256).unwrap();
    let certificate = der(CERTIFICATE);
    let truncated = &certificate[..certificate.len() - 1];
    let with_trailing_byte = [certificate.as_slice(), &[0]].concat();
    // The outer SEQUENCE with an indefinite length, which DER does not allow.
    let indefinite = [&[0x30, 0x80], &certificate[4..], &[0, 0]].concat();

    for error in [
        key.clone().with_certificate_der(truncated).unwrap_err(),
        key.clone()
            .with_certificate_der(with_trailing_byte)
            .unwrap_err(),
        key.clone().with_certificate_der(indefinite).unwrap_err(),
        key.clone()
            .with_certificate_pem("no certificate")
            .unwrap_err(),
        key.clone().with_certificate_pem(RSA_PUBLIC).unwrap_err(),
        key.clone()
            .with_certificate_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
            .unwrap_err(),
        key.clone()
            .with_certificate_der(b"not a certificate")
            .unwrap_err(),
        key.with_certificate_der(der(RSA_PUBLIC)).unwrap_err(),
    ] {
        assert!(
            matches!(error, ConfigError::InvalidCertificate),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            "the certificate cannot be read as an X.509 certificate"
        );
    }
}

#[test]
fn test_a_deeply_nested_certificate_is_rejected_without_a_crash() {
    // 100,000 nested SEQUENCE headers with a three-byte length each, the innermost one empty.
    let depth: usize = 100_000;
    let mut nested = Vec::with_capacity(depth * 5);
    for level in (0..depth).rev() {
        let length = (level * 5).to_be_bytes();
        nested.extend_from_slice(&[0x30, 0x83]);
        nested.extend_from_slice(&length[length.len() - 3..]);
    }
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let error = key.with_certificate_der(nested).unwrap_err();

    assert!(
        matches!(error, ConfigError::InvalidCertificate),
        "{error:?}"
    );
}

#[test]
fn test_debug_never_shows_the_key_or_the_assertion() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256)
        .unwrap()
        .with_key_id("key-1")
        .with_certificate_pem(CERTIFICATE)
        .unwrap();
    let hmac = SigningKey::from_secret(HMAC_SECRET, SigningAlgorithm::Hs256).unwrap();
    let assertion = assertion(key.clone())
        .with_claim("tenant", "tenant-1")
        .unwrap();
    let jwt = assertion.sign().unwrap();

    let key_debug = r#"SigningKey { algorithm: Rs256, key_id: Some("key-1"), x5t_s256: Some("5BBv8GolnkvNYuhh8k-UmD4VXngLSqlaWE8ePJk0j9s"), .. }"#;
    assert_eq!(format!("{key:?}"), key_debug);
    assert_eq!(
        format!("{hmac:?}"),
        "SigningKey { algorithm: Hs256, key_id: None, x5t_s256: None, .. }"
    );
    assert_eq!(
        format!("{assertion:?}"),
        format!(
            r#"JwtAssertion {{ key: {key_debug}, issuer: "my-client", subject: "my-subject", audience: "https://idp.example.com", lifetime: 60s, token_type: Some("JWT"), claim_names: ["tenant"] }}"#
        )
    );
    assert_eq!(format!("{jwt:?}"), "SignedJwt([redacted])");
}
