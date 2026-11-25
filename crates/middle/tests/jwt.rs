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
/// An RSA key of 2048 bits with three primes (RFC 8017, section 3.2).
const RSA_3_PRIMES_PKCS8: &str = include_str!("fixtures/jwt/rsa-2048-3-primes-pkcs8.pem");
const RSA_3_PRIMES_PKCS1: &str = include_str!("fixtures/jwt/rsa-2048-3-primes-pkcs1.pem");
/// An RSA key of 2048 bits whose two primes have 1048 and 1000 bits.
const RSA_UNEQUAL_PRIMES: &str = include_str!("fixtures/jwt/rsa-2048-unequal-primes-pkcs8.pem");
const RSA_UNEQUAL_PRIMES_PUBLIC: &str =
    include_str!("fixtures/jwt/rsa-2048-unequal-primes-public.pem");
/// An RSA-PSS key of 2048 bits (`openssl genpkey -algorithm RSA-PSS`), which has the key algorithm id-RSASSA-PSS (RFC 4055, section 3.1).
const RSA_PSS: &str = include_str!("fixtures/jwt/rsa-pss-2048-pkcs8.pem");
/// `rsa-2048-pkcs1.pem` encrypted with the passphrase `middle-test` by `openssl rsa -aes256 -traditional`, which writes the header `Proc-Type: 4,ENCRYPTED`.
const RSA_ENCRYPTED_PKCS1: &str = include_str!("fixtures/jwt/rsa-2048-encrypted-pkcs1.pem");
const EC_P256: &str = include_str!("fixtures/jwt/ec-p256-pkcs8.pem");
/// `ec-p256-pkcs8.pem` in PKCS#8 v2 (RFC 5958, section 2), with its public key.
const EC_P256_V2: &str = include_str!("fixtures/jwt/ec-p256-pkcs8-v2.pem");
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
const CERTIFICATE_RSA_ED25519_ISSUER_X5T_S256: &str = "wQ2FCJJeUroy_IvI9Cy9b8U3UJmJg8txgPkfmXJovS4";
/// The certificate of `ec-p256-pkcs8.pem`.
const CERTIFICATE_EC_P256: &str = include_str!("fixtures/jwt/certificate-ec-p256.pem");
const CERTIFICATE_EC_P256_X5T_S256: &str = "bf6Al3EpEQ6i5LblZZDtJj88LaExMe1ym1NMA5wYxIU";
/// The certificate of `ed25519-pkcs8.pem`.
const CERTIFICATE_ED25519: &str = include_str!("fixtures/jwt/certificate-ed25519.pem");
const CERTIFICATE_ED25519_X5T_S256: &str = "kI2Wss5Ns_XeFZt7xG9g6y44sv3zY1JtQAFjOEImCeM";
/// The certificate of an RSA key that is not in the fixtures.
const CERTIFICATE_OTHER: &str = include_str!("fixtures/jwt/certificate-other.pem");
/// The certificate of `rsa-2048-pkcs8.pem`, with its names as BMPString.
const CERTIFICATE_BMPSTRING: &str = include_str!("fixtures/jwt/certificate-bmpstring.pem");
/// The certificate of `rsa-2048-pkcs8.pem`, with its names as PrintableString holding `*` and `&`.
const CERTIFICATE_PRINTABLESTRING: &str =
    include_str!("fixtures/jwt/certificate-printablestring.pem");
/// The X.509 v1 certificate of `ec-p256-pkcs8.pem`: no version field, no extensions.
const CERTIFICATE_V1_EC_P256: &str = include_str!("fixtures/jwt/certificate-v1-ec-p256.pem");
/// The certificate of a key of `openssl genpkey -algorithm RSA-PSS`, which has the key algorithm id-RSASSA-PSS (RFC 4055, section 3.1).
const CERTIFICATE_RSA_PSS: &str = include_str!("fixtures/jwt/certificate-rsa-pss.pem");
/// `openssl x509 -in certificate.pem -outform DER | openssl dgst -sha256 -binary`, base64url without padding.
const CERTIFICATE_X5T_S256: &str = "5BBv8GolnkvNYuhh8k-UmD4VXngLSqlaWE8ePJk0j9s";
const HMAC_SECRET: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ENCRYPTED_PRIVATE_KEY: &str =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
const NOT_PKCS8: &str = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
const NOT_SEC1: &str = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
/// The curve P-256, as `openssl ecparam -name prime256v1 -genkey` writes it before the key.
const EC_PARAMETERS_P256: &str =
    "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n";
/// The levels of a deep nesting: a DER decoder that recurses once per level overflows a stack of 2 MiB on a few thousand of them.
const DEEP: usize = 100_000;
/// The OID rsaEncryption (RFC 8017, appendix C) in DER, without tag and length.
const RSA_ENCRYPTION: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// The OID of the curve P-256 (RFC 5480, section 2.1.1.1) in DER, without tag and length.
const SECP256R1: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// The OID of the curve P-384 (RFC 5480, section 2.1.1.1) in DER, without tag and length.
const SECP384R1: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x22];
/// The reason for an `EC PRIVATE KEY` that is not in SEC1 form with a named curve.
const NOT_SEC1_REASON: &str = "the key is not in SEC1 form with a named curve; if it has explicit curve parameters, convert it to a named curve with `openssl pkey -in key.pem -ec_param_enc named_curve -out key-named.pem`";

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

/// DER bytes as a PEM block with the label.
fn pem_block(label: &str, der: &[u8]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        STANDARD.encode(der)
    )
}

/// The header of a DER element (X.690, section 8.1): the tag, and the length in its shortest form, as DER requires.
fn header(tag: u8, length: usize) -> Vec<u8> {
    let mut header = vec![tag];
    match u8::try_from(length) {
        Ok(short) if short < 0x80 => header.push(short),
        _ => {
            let bytes = length.to_be_bytes();
            let leading_zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
            header.push(0x80 | u8::try_from(bytes.len() - leading_zeros).unwrap());
            header.extend_from_slice(&bytes[leading_zeros..]);
        }
    }
    header
}

/// A DER element (X.690, section 8.1) with the length in its shortest form.
fn element(tag: u8, content: &[u8]) -> Vec<u8> {
    [header(tag, content.len()).as_slice(), content].concat()
}

/// The private key of `ec-p256-sec1.pem` in SEC1 form (RFC 5915, section 3) with the parameters given and without the public key, as PEM.
fn ec_p256_sec1_with(parameters: Option<&[u8]>) -> String {
    let key = der(EC_P256_SEC1);
    // Version 1, then the private key as an OCTET STRING of 32 bytes.
    let private_key = key
        .windows(5)
        .position(|window| window == [0x02, 0x01, 0x01, 0x04, 0x20])
        .expect("the private key")
        + 5;
    let mut fields = [
        element(0x02, &[1]),
        element(0x04, &key[private_key..private_key + 32]),
    ]
    .concat();
    if let Some(parameters) = parameters {
        fields.extend(element(0xa0, parameters));
    }
    pem_block("EC PRIVATE KEY", &element(0x30, &fields))
}

/// `depth` SEQUENCEs, each in the one before, the innermost one empty, each length in its shortest form.
fn nested_sequences(depth: usize) -> Vec<u8> {
    // The headers from the innermost level out: the content of each level is the levels inside it.
    let mut headers = Vec::with_capacity(depth);
    let mut length = 0;
    for _ in 0..depth {
        let level = header(0x30, length);
        length += level.len();
        headers.push(level);
    }
    headers.into_iter().rev().flatten().collect()
}

/// Runs `parse` on a thread with a stack of 2 MiB, the stack of tokio's worker threads, so that a recursion too deep for it aborts the test.
fn on_a_2_mib_stack<T: Send + 'static>(parse: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(parse)
        .expect("a thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
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
    // `iat` lies 5 seconds before the signing, so that a server whose clock is slightly behind accepts the assertion.
    let iat = claims["iat"].as_u64().unwrap();
    assert!((before..=now()).contains(&(iat + 5)), "iat {iat}");
    assert_eq!(claims["exp"].as_u64().unwrap(), iat + 5 + 60);
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
fn test_an_ec_key_may_be_in_sec1_form() {
    let with_parameters = format!("{EC_PARAMETERS_P256}{EC_P256_SEC1}");
    // RFC 5915, section 3: the public key is optional. `openssl ec -no_public` leaves it out.
    let without_public_key = ec_p256_sec1_with(Some(&element(0x06, &SECP256R1)));
    let p256 = DecodingKey::from_ec_pem(EC_P256_PUBLIC.as_bytes()).unwrap();

    for pem in [EC_P256_SEC1, &with_parameters, &without_public_key] {
        let key = SigningKey::from_pem(pem, SigningAlgorithm::Es256)
            .unwrap()
            .with_certificate_pem(CERTIFICATE_EC_P256)
            .unwrap();

        let jwt = assertion(key).sign().unwrap();

        let decoded = verify(jwt.as_str(), Algorithm::ES256, &p256);
        assert_eq!(decoded.header["x5t#S256"], CERTIFICATE_EC_P256_X5T_S256);
    }
}

#[test]
fn test_an_ec_key_in_pkcs8_v2_signs() {
    // aws-lc-rs refuses an EC key in PKCS#8 with its public key.
    let key = SigningKey::from_pem(EC_P256_V2, SigningAlgorithm::Es256)
        .unwrap()
        .with_certificate_pem(CERTIFICATE_EC_P256)
        .unwrap();

    let jwt = assertion(key).sign().unwrap();

    let p256 = DecodingKey::from_ec_pem(EC_P256_PUBLIC.as_bytes()).unwrap();
    let decoded = verify(jwt.as_str(), Algorithm::ES256, &p256);
    assert_eq!(decoded.header["x5t#S256"], CERTIFICATE_EC_P256_X5T_S256);
}

#[test]
fn test_an_ec_key_in_sec1_form_must_name_the_curve_of_the_algorithm() {
    let p384 = ec_p256_sec1_with(Some(&element(0x06, &SECP384R1)));
    let without_curve = ec_p256_sec1_with(None);
    // ECParameters as a SEQUENCE, the form of explicit parameters (`openssl ec -param_enc explicit`), which RFC 5915 does not allow.
    let explicit = ec_p256_sec1_with(Some(&element(0x30, &element(0x02, &[1]))));
    for (pem, algorithm, reason) in [
        (
            EC_P256_SEC1,
            SigningAlgorithm::Es384,
            "the EC key is on the curve P-256, but ES384 needs P-384",
        ),
        (
            p384.as_str(),
            SigningAlgorithm::Es256,
            "the EC key is on the curve P-384, but ES256 needs P-256",
        ),
        (
            without_curve.as_str(),
            SigningAlgorithm::Es256,
            "the EC key in SEC1 form does not name its curve (RFC 5915, section 3)",
        ),
        (explicit.as_str(), SigningAlgorithm::Es256, NOT_SEC1_REASON),
        (NOT_SEC1, SigningAlgorithm::Es256, NOT_SEC1_REASON),
    ] {
        let error = SigningKey::from_pem(pem, algorithm).unwrap_err();
        assert_eq!(invalid_key_reason(error), reason, "{algorithm}: {pem}");
    }
}

#[test]
fn test_a_pem_with_the_key_and_its_certificate_is_read_in_either_order() {
    // One file with both, such as the PEM export of Azure Key Vault.
    for (key, algorithm, certificate, x5t_s256) in [
        (
            RSA_PKCS8,
            SigningAlgorithm::Rs256,
            CERTIFICATE,
            CERTIFICATE_X5T_S256,
        ),
        (
            RSA_PKCS1,
            SigningAlgorithm::Ps512,
            CERTIFICATE_RSA_ED25519_ISSUER,
            CERTIFICATE_RSA_ED25519_ISSUER_X5T_S256,
        ),
        (
            EC_P256,
            SigningAlgorithm::Es256,
            CERTIFICATE_EC_P256,
            CERTIFICATE_EC_P256_X5T_S256,
        ),
        (
            ED25519,
            SigningAlgorithm::EdDsa,
            CERTIFICATE_ED25519,
            CERTIFICATE_ED25519_X5T_S256,
        ),
    ] {
        for (order, pem) in [
            ("key first", format!("{key}{certificate}")),
            ("certificate first", format!("{certificate}{key}")),
        ] {
            let key = SigningKey::from_pem(&pem, algorithm)
                .unwrap()
                .with_certificate_pem(&pem)
                .unwrap();

            let jwt = assertion(key).sign().unwrap();

            let (header, _) = jwt.as_str().split_once('.').unwrap();
            assert_eq!(
                decode_part(header)["x5t#S256"],
                x5t_s256,
                "{algorithm}, {order}"
            );
        }
    }
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
            RSA_PSS,
            SigningAlgorithm::Ps256,
            "the key is an RSA-PSS key (1.2.840.113549.1.1.10), which middle does not sign with; an RSA key in PKCS#8 needs the algorithm rsaEncryption",
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
    // Without a private key, the error names what the first block holds.
    let certificate_and_public_key = format!("{CERTIFICATE}{RSA_PUBLIC}");
    for (pem, algorithm, reason) in [
        (RSA_PUBLIC, SigningAlgorithm::Rs256, public_key),
        (RSA_PUBLIC_PKCS1, SigningAlgorithm::Rs256, public_key),
        (CERTIFICATE, SigningAlgorithm::Ps256, certificate),
        (
            certificate_and_public_key.as_str(),
            SigningAlgorithm::Rs256,
            certificate,
        ),
        (EC_P256_PUBLIC, SigningAlgorithm::Es256, public_key),
        (CERTIFICATE_EC_P256, SigningAlgorithm::Es256, certificate),
        (ED25519_PUBLIC, SigningAlgorithm::EdDsa, public_key),
        (CERTIFICATE_ED25519, SigningAlgorithm::EdDsa, certificate),
    ] {
        let error = SigningKey::from_pem(pem, algorithm).unwrap_err();
        assert_eq!(invalid_key_reason(error), reason, "{algorithm}: {pem}");
    }
}

#[test]
fn test_an_encrypted_key_is_rejected() {
    let certificate_first = format!("{CERTIFICATE}{ENCRYPTED_PRIVATE_KEY}");
    for pem in [
        RSA_ENCRYPTED_PKCS1,
        ENCRYPTED_PRIVATE_KEY,
        certificate_first.as_str(),
    ] {
        let error = SigningKey::from_pem(pem, SigningAlgorithm::Rs256).unwrap_err();

        assert_eq!(
            invalid_key_reason(error),
            "the key is encrypted; decrypt it with `openssl pkey -in key.pem -out key-decrypted.pem`",
            "{pem}"
        );
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
    let pem = pem_block("PRIVATE KEY", &key);

    let error = SigningKey::from_pem(pem, SigningAlgorithm::Es256).unwrap_err();

    assert_eq!(
        invalid_key_reason(error),
        "the key cannot sign with ES256: InvalidEcdsaKey"
    );
}

#[test]
fn test_a_key_that_cannot_be_read_is_rejected() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nbm90IERFUg==\n-----END RSA PRIVATE KEY-----\n";

    let error = SigningKey::from_pem(pem, SigningAlgorithm::Rs256).unwrap_err();

    assert_eq!(invalid_key_reason(error), "the key is not in PKCS#1 form");
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
fn test_an_rsa_key_with_more_than_two_primes_is_rejected() {
    for pem in [RSA_3_PRIMES_PKCS8, RSA_3_PRIMES_PKCS1] {
        let error = SigningKey::from_pem(pem, SigningAlgorithm::Rs256).unwrap_err();

        assert_eq!(
            invalid_key_reason(error),
            "the RSA key has more than two primes; middle signs with RSA keys of two primes",
            "{pem}"
        );
    }
}

#[test]
fn test_only_aws_lc_rs_signs_with_an_rsa_key_whose_primes_differ_in_length() {
    // With both backends, middle uses aws-lc-rs.
    let key = SigningKey::from_pem(RSA_UNEQUAL_PRIMES, SigningAlgorithm::Rs256);

    if cfg!(feature = "aws-lc-rs") {
        let jwt = assertion(key.unwrap()).sign().unwrap();
        let public = DecodingKey::from_rsa_pem(RSA_UNEQUAL_PRIMES_PUBLIC.as_bytes()).unwrap();
        verify(jwt.as_str(), Algorithm::RS256, &public);
    } else {
        // middle signs when it loads a key, so the backend refuses the key here.
        assert_eq!(
            invalid_key_reason(key.unwrap_err()),
            "the key cannot sign with RS256: signature error: PKCS#1 cryptographic key data malformed"
        );
    }
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
        // `exp` is the lifetime after the signing, which lies 5 seconds after `iat`.
        assert_eq!(
            claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
            seconds + 5,
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
            CERTIFICATE_RSA_ED25519_ISSUER_X5T_S256,
        ),
        (
            EC_P256,
            SigningAlgorithm::Es256,
            CERTIFICATE_EC_P256,
            CERTIFICATE_EC_P256_X5T_S256,
        ),
        (
            ED25519,
            SigningAlgorithm::EdDsa,
            CERTIFICATE_ED25519,
            CERTIFICATE_ED25519_X5T_S256,
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
fn test_a_certificate_on_another_curve_is_rejected() {
    // The certificate of `ec-p256-pkcs8.pem` with the curve P-192 (1.2.840.10045.3.1.1) in place of P-256 (1.2.840.10045.3.1.7): the same point, on another curve.
    let mut certificate = der(CERTIFICATE_EC_P256);
    let curve = certificate
        .windows(SECP256R1.len())
        .position(|window| window == SECP256R1)
        .expect("the curve");
    certificate[curve + SECP256R1.len() - 1] = 0x01;
    let key = SigningKey::from_pem(EC_P256, SigningAlgorithm::Es256).unwrap();

    let error = key.with_certificate_der(certificate).unwrap_err();

    assert!(
        matches!(error, ConfigError::CertificateKeyMismatch),
        "{error:?}"
    );
}

#[test]
fn test_a_certificate_with_a_key_algorithm_middle_does_not_sign_with_is_rejected() {
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Ps256).unwrap();

    let error = key.with_certificate_pem(CERTIFICATE_RSA_PSS).unwrap_err();

    assert!(
        matches!(&error, ConfigError::UnsupportedCertificateKey(algorithm) if algorithm == "1.2.840.113549.1.1.10"),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "the public key of the certificate has the algorithm 1.2.840.113549.1.1.10, which middle does not sign with"
    );
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
        key.clone().with_certificate_pem(RSA_PKCS8).unwrap_err(),
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
fn test_the_nesting_of_these_tests_is_der() {
    assert_eq!(nested_sequences(3), [0x30, 0x04, 0x30, 0x02, 0x30, 0x00]);
    // From 65 levels on, the content of the outermost level is longer than 127 bytes, and its length takes the long form.
    assert_eq!(nested_sequences(65)[..5], [0x30, 0x81, 0x80, 0x30, 0x7e]);
}

#[test]
fn test_a_deeply_nested_certificate_is_rejected_without_a_crash() {
    let nested = nested_sequences(DEEP);
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();

    let error = key.with_certificate_der(nested).unwrap_err();

    assert!(
        matches!(error, ConfigError::InvalidCertificate),
        "{error:?}"
    );
}

#[test]
fn test_a_deep_nesting_in_the_public_key_of_a_certificate_is_rejected_without_a_crash() {
    // An X.509 v1 certificate with the `subjectPublicKeyInfo` given. middle reads only the types of the other fields and parts, so they are empty.
    let certificate = |subject_public_key_info: &[u8]| {
        let empty = element(0x30, &[]);
        let to_be_signed = [
            element(0x02, &[1]),
            empty.clone(),
            empty.clone(),
            empty.clone(),
            empty.clone(),
            subject_public_key_info.to_vec(),
        ]
        .concat();
        let signature_value = element(0x03, &[0]);
        element(
            0x30,
            &[element(0x30, &to_be_signed), empty, signature_value].concat(),
        )
    };
    let key = SigningKey::from_pem(RSA_PKCS8, SigningAlgorithm::Rs256).unwrap();
    // With the public key of the signing key, middle accepts the certificate, so it reads the `subjectPublicKeyInfo`.
    assert!(
        key.clone()
            .with_certificate_der(certificate(&der(RSA_PUBLIC)))
            .is_ok()
    );
    let deep = certificate(&nested_sequences(DEEP));

    let error = on_a_2_mib_stack(move || key.with_certificate_der(deep).unwrap_err());

    assert!(
        matches!(error, ConfigError::InvalidCertificate),
        "{error:?}"
    );
}

#[test]
fn test_a_deeply_nested_pkcs8_key_is_rejected_without_a_crash() {
    let pem = pem_block("PRIVATE KEY", &nested_sequences(DEEP));

    let error =
        on_a_2_mib_stack(move || SigningKey::from_pem(pem, SigningAlgorithm::Rs256).unwrap_err());

    assert_eq!(invalid_key_reason(error), "the key is not in PKCS#8 form");
}

#[test]
fn test_a_deep_nesting_in_the_rsa_key_of_a_pkcs8_key_is_rejected_without_a_crash() {
    // PKCS#8 (RFC 5958, section 2): version 0, rsaEncryption with NULL parameters, and the RSA key as an OCTET STRING.
    let pkcs8 = |rsa: &[u8]| {
        let algorithm = element(
            0x30,
            &[element(0x06, &RSA_ENCRYPTION), element(0x05, &[])].concat(),
        );
        let pkcs8 = element(
            0x30,
            &[element(0x02, &[0]), algorithm, element(0x04, rsa)].concat(),
        );
        pem_block("PRIVATE KEY", &pkcs8)
    };
    // With the RSA key of `rsa-2048-pkcs1.pem`, the key loads, so middle reads the RSA key.
    assert!(SigningKey::from_pem(pkcs8(&der(RSA_PKCS1)), SigningAlgorithm::Rs256).is_ok());
    let pem = pkcs8(&nested_sequences(DEEP));

    let error =
        on_a_2_mib_stack(move || SigningKey::from_pem(pem, SigningAlgorithm::Rs256).unwrap_err());

    assert_eq!(invalid_key_reason(error), "the RSA key cannot be read");
}

#[test]
fn test_a_deeply_nested_pkcs1_key_is_rejected_without_a_crash() {
    let pem = pem_block("RSA PRIVATE KEY", &nested_sequences(DEEP));

    let error =
        on_a_2_mib_stack(move || SigningKey::from_pem(pem, SigningAlgorithm::Rs256).unwrap_err());

    assert_eq!(invalid_key_reason(error), "the key is not in PKCS#1 form");
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
