//! Signing JWT assertions (RFC 7523, section 3) for the JWT bearer grant and for JWT client authentication.
//!
//! middle signs with jsonwebtoken and the crypto backend that the feature `aws-lc-rs` or `rust-crypto` selects.
//! It passes that backend to every call, so signing works whatever process-wide default jsonwebtoken has.

#[cfg(not(any(feature = "aws-lc-rs", feature = "rust-crypto")))]
compile_error!("The feature `jwt` needs a crypto backend: enable `aws-lc-rs` or `rust-crypto`.");

use std::{
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "aws-lc-rs")]
use jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER as PROVIDER;
#[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
use jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as PROVIDER;
use jsonwebtoken::{Algorithm, EncodingKey, jwk::ThumbprintHash};
use serde_json::{Map, Value};

use crate::error::{AssertionError, ConfigError, Error};

/// Registered claims middle sets itself (RFC 7519, section 4.1).
const REGISTERED_CLAIMS: [&str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

/// The lifetime of an assertion unless [`JwtAssertion::with_lifetime`] sets another.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(60);

/// RFC 7518, section 3.3: RSA keys have at least 2048 bits.
const MIN_RSA_BITS: usize = 2048;

/// A JWS algorithm (RFC 7518, section 3.1) that middle signs with.
///
/// It displays as its `alg` value and parses from it, for example `RS256` or `EdDSA`. Parsing is case-sensitive, as RFC 7515, section 4.1.1, requires, and fails with [`ConfigError::UnknownSigningAlgorithm`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display, strum::EnumString, strum::IntoStaticStr,
)]
#[cfg_attr(test, derive(strum::VariantArray))]
#[strum(
    serialize_all = "UPPERCASE",
    parse_err_ty = ConfigError,
    parse_err_fn = unknown_algorithm
)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    Rs384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    Rs512,
    /// RSASSA-PSS with SHA-256.
    Ps256,
    /// RSASSA-PSS with SHA-384.
    Ps384,
    /// RSASSA-PSS with SHA-512.
    Ps512,
    /// ECDSA with P-256 and SHA-256.
    Es256,
    /// ECDSA with P-384 and SHA-384.
    Es384,
    /// `EdDSA` with Ed25519 (RFC 8037).
    #[strum(serialize = "EdDSA")]
    EdDsa,
    /// HMAC with SHA-256, for a shared secret.
    Hs256,
    /// HMAC with SHA-384, for a shared secret.
    Hs384,
    /// HMAC with SHA-512, for a shared secret.
    Hs512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Rsa,
    Ec,
    Ed,
    Hmac,
}

impl SigningAlgorithm {
    /// The `alg` value (RFC 7518, section 3.1).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    fn jsonwebtoken(self) -> Algorithm {
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Rs384 => Algorithm::RS384,
            Self::Rs512 => Algorithm::RS512,
            Self::Ps256 => Algorithm::PS256,
            Self::Ps384 => Algorithm::PS384,
            Self::Ps512 => Algorithm::PS512,
            Self::Es256 => Algorithm::ES256,
            Self::Es384 => Algorithm::ES384,
            Self::EdDsa => Algorithm::EdDSA,
            Self::Hs256 => Algorithm::HS256,
            Self::Hs384 => Algorithm::HS384,
            Self::Hs512 => Algorithm::HS512,
        }
    }

    fn family(self) -> Family {
        match self {
            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                Family::Rsa
            }
            Self::Es256 | Self::Es384 => Family::Ec,
            Self::EdDsa => Family::Ed,
            Self::Hs256 | Self::Hs384 | Self::Hs512 => Family::Hmac,
        }
    }

    /// RFC 7518, section 3.2: an HMAC key is at least as long as the hash output.
    fn hmac_minimum_bits(self) -> usize {
        match self {
            Self::Hs384 => 384,
            Self::Hs512 => 512,
            _ => 256,
        }
    }
}

fn unknown_algorithm(name: &str) -> ConfigError {
    ConfigError::UnknownSigningAlgorithm(name.to_string())
}

/// A private key or shared secret with its algorithm, checked when it is loaded.
///
/// `Debug` shows the algorithm, the key id and the certificate thumbprint, never the key.
#[derive(Clone)]
pub struct SigningKey {
    algorithm: SigningAlgorithm,
    key: EncodingKey,
    key_id: Option<String>,
    x5t_s256: Option<String>,
}

impl SigningKey {
    /// Loads a private key in PEM form: RSA in PKCS#1 or PKCS#8 for `RS*` and `PS*`, EC in PKCS#8 for `ES*`, Ed25519 in PKCS#8 for `EdDSA`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidSigningKey`] if the key does not fit the algorithm or cannot sign,
    /// [`ConfigError::WeakSigningKey`] for an RSA key shorter than 2048 bits (RFC 7518, section 3.3).
    pub fn from_pem(
        pem: impl AsRef<[u8]>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, ConfigError> {
        let pem = pem.as_ref();
        let key = match algorithm.family() {
            Family::Rsa => EncodingKey::from_rsa_pem(pem).map_err(|_| {
                invalid("the key is not an RSA private key in PEM form (PKCS#1 or PKCS#8)")
            })?,
            Family::Ec => EncodingKey::from_ec_pem(pem).map_err(|_| {
                if contains(pem, b"EC PRIVATE KEY") {
                    invalid("the EC key is in SEC1 form; convert it to PKCS#8 with `openssl pkcs8 -topk8 -nocrypt`")
                } else {
                    invalid("the key is not an EC private key in PKCS#8 PEM form; convert a SEC1 key with `openssl pkcs8 -topk8 -nocrypt`")
                }
            })?,
            Family::Ed => EncodingKey::from_ed_pem(pem)
                .map_err(|_| invalid("the key is not an Ed25519 private key in PKCS#8 PEM form"))?,
            Family::Hmac => {
                return Err(invalid(
                    "an HMAC algorithm signs with a shared secret: use `SigningKey::from_secret`",
                ));
            }
        };
        if algorithm.family() == Family::Rsa {
            let bits = rsa_modulus_bits(key.as_bytes())
                .ok_or_else(|| invalid("the RSA key cannot be read"))?;
            if bits < MIN_RSA_BITS {
                return Err(ConfigError::WeakSigningKey {
                    algorithm,
                    bits,
                    minimum: MIN_RSA_BITS,
                });
            }
        }
        Self::checked(algorithm, key)
    }

    /// A shared secret for `HS*`, such as a client secret for `client_secret_jwt`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidSigningKey`] if the algorithm is not an HMAC algorithm,
    /// [`ConfigError::WeakSigningKey`] if the secret is shorter than the hash output (RFC 7518, section 3.2).
    pub fn from_secret(
        secret: impl AsRef<[u8]>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, ConfigError> {
        if algorithm.family() != Family::Hmac {
            return Err(invalid(
                "a shared secret signs only with an HMAC algorithm: use `SigningKey::from_pem` for a private key",
            ));
        }
        let secret = secret.as_ref();
        let bits = secret.len() * 8;
        let minimum = algorithm.hmac_minimum_bits();
        if bits < minimum {
            return Err(ConfigError::WeakSigningKey {
                algorithm,
                bits,
                minimum,
            });
        }
        let key = EncodingKey::from_secret(secret)
            .map_err(|_| invalid("the shared secret cannot be used as an HMAC key"))?;
        Self::checked(algorithm, key)
    }

    /// Signs once, so a key that cannot sign fails here and not with the first token request.
    fn checked(algorithm: SigningAlgorithm, key: EncodingKey) -> Result<Self, ConfigError> {
        let key = Self {
            algorithm,
            key,
            key_id: None,
            x5t_s256: None,
        };
        key.sign_bytes(b"middle checks the key")
            .map_err(|_| invalid(&format!("the key cannot sign with {algorithm}")))?;
        Ok(key)
    }

    /// Sets the `kid` header, which tells the server which of the client's keys signed.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Sets the `x5t#S256` header (RFC 7515, section 4.1.8) from the certificate of the key in PEM form, as servers that register certificates expect.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidCertificate`] if the text holds no PEM certificate.
    pub fn with_certificate_pem(self, certificate: impl AsRef<[u8]>) -> Result<Self, ConfigError> {
        let certificate = pem::parse(certificate).map_err(|_| ConfigError::InvalidCertificate)?;
        if certificate.tag() != "CERTIFICATE" {
            return Err(ConfigError::InvalidCertificate);
        }
        self.with_certificate_der(certificate.contents())
    }

    /// Sets the `x5t#S256` header (RFC 7515, section 4.1.8) from the certificate of the key in DER form.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidCertificate`] if the thumbprint cannot be computed.
    pub fn with_certificate_der(
        mut self,
        certificate: impl AsRef<[u8]>,
    ) -> Result<Self, ConfigError> {
        let digest =
            (PROVIDER.key_utils.compute_digest)(certificate.as_ref(), ThumbprintHash::SHA256)
                .map_err(|_| ConfigError::InvalidCertificate)?;
        self.x5t_s256 = Some(URL_SAFE_NO_PAD.encode(digest));
        Ok(self)
    }

    /// The algorithm the key signs with.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The `kid` header, if set.
    #[must_use]
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// Signs synchronously. jsonwebtoken's signer is not `Send`, so it never lives across an `.await`.
    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let signer = (PROVIDER.signer_factory)(&self.algorithm.jsonwebtoken(), &self.key)
            .map_err(|error| SignError(Arc::new(error)))?;
        signer
            .try_sign(message)
            .map_err(|error| SignError(Arc::new(error)))
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id)
            .field("x5t_s256", &self.x5t_s256)
            .finish_non_exhaustive()
    }
}

/// The cause of a failed signature.
struct SignError(Arc<dyn std::error::Error + Send + Sync>);

/// A JWT assertion (RFC 7523, section 3): signed with a new `jti`, `iat` and `exp` on every call of [`JwtAssertion::sign`].
///
/// `Debug` shows the claims middle sets and the names of extra claims, never the key or their values.
#[derive(Clone)]
pub struct JwtAssertion {
    key: SigningKey,
    issuer: String,
    subject: String,
    audience: Vec<String>,
    lifetime: Duration,
    token_type: Option<String>,
    claims: Map<String, Value>,
}

impl JwtAssertion {
    /// An assertion from `issuer` about `subject` for `audience`, valid for 60 seconds, with the header `typ: JWT`.
    ///
    /// For JWT client authentication, `issuer` and `subject` are both the client id (RFC 7523, section 3).
    #[must_use]
    pub fn new(
        key: SigningKey,
        issuer: impl Into<String>,
        subject: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        Self {
            key,
            issuer: issuer.into(),
            subject: subject.into(),
            audience: vec![audience.into()],
            lifetime: DEFAULT_LIFETIME,
            token_type: Some("JWT".to_string()),
            claims: Map::new(),
        }
    }

    /// Adds an audience. With more than one, `aud` is an array.
    #[must_use]
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience.push(audience.into());
        self
    }

    /// Sets how long an assertion is valid, in whole seconds.
    ///
    /// # Errors
    ///
    /// [`ConfigError::AssertionLifetime`] for a lifetime shorter than one second.
    pub fn with_lifetime(mut self, lifetime: Duration) -> Result<Self, ConfigError> {
        if lifetime < Duration::from_secs(1) {
            return Err(ConfigError::AssertionLifetime(lifetime));
        }
        self.lifetime = lifetime;
        Ok(self)
    }

    /// Sets the `typ` header, for example `client-authentication+jwt` (RFC 10070), or leaves it out with `None`.
    #[must_use]
    pub fn with_type(mut self, token_type: Option<impl Into<String>>) -> Self {
        self.token_type = token_type.map(Into::into);
        self
    }

    /// Adds a claim.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ReservedClaim`] for a claim middle sets itself: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`.
    pub fn with_claim(
        mut self,
        name: impl Into<String>,
        value: impl Into<Value>,
    ) -> Result<Self, ConfigError> {
        let name = name.into();
        if REGISTERED_CLAIMS.contains(&name.as_str()) {
            return Err(ConfigError::ReservedClaim(name));
        }
        self.claims.insert(name, value.into());
        Ok(self)
    }

    /// Signs a new assertion: `iat` is now, `exp` is now plus the lifetime, and `jti` is 16 random bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Assertion`] if the system clock is before 1970, the system has no randomness, or signing fails.
    pub fn sign(&self) -> Result<SignedJwt, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                AssertionError::new("the system clock is before 1970", Arc::new(error))
            })?
            .as_secs();
        let mut jti = [0u8; 16];
        getrandom::fill(&mut jti).map_err(|error| {
            AssertionError::new("the system has no randomness for `jti`", Arc::new(error))
        })?;

        let mut header = Map::new();
        header.insert("alg".to_string(), self.key.algorithm.as_str().into());
        if let Some(token_type) = &self.token_type {
            header.insert("typ".to_string(), token_type.as_str().into());
        }
        if let Some(key_id) = &self.key.key_id {
            header.insert("kid".to_string(), key_id.as_str().into());
        }
        if let Some(x5t_s256) = &self.key.x5t_s256 {
            header.insert("x5t#S256".to_string(), x5t_s256.as_str().into());
        }

        let mut claims = self.claims.clone();
        claims.insert("iss".to_string(), self.issuer.as_str().into());
        claims.insert("sub".to_string(), self.subject.as_str().into());
        let audience = match self.audience.as_slice() {
            [audience] => Value::from(audience.as_str()),
            audiences => Value::from(audiences.to_vec()),
        };
        claims.insert("aud".to_string(), audience);
        claims.insert("iat".to_string(), now.into());
        claims.insert(
            "exp".to_string(),
            now.saturating_add(self.lifetime.as_secs()).into(),
        );
        claims.insert("jti".to_string(), URL_SAFE_NO_PAD.encode(jti).into());

        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(Value::Object(header).to_string()),
            URL_SAFE_NO_PAD.encode(Value::Object(claims).to_string())
        );
        let signature = self
            .key
            .sign_bytes(message.as_bytes())
            .map_err(|SignError(error)| {
                AssertionError::new("signing the assertion failed", error)
            })?;
        Ok(SignedJwt(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        )))
    }
}

impl fmt::Debug for JwtAssertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let claim_names: Vec<&String> = self.claims.keys().collect();
        f.debug_struct("JwtAssertion")
            .field("key", &self.key)
            .field("issuer", &self.issuer)
            .field("subject", &self.subject)
            .field("audience", &self.audience)
            .field("lifetime", &self.lifetime)
            .field("token_type", &self.token_type)
            .field("claim_names", &claim_names)
            .finish()
    }
}

/// A signed JWT in compact form. `Debug` never shows it.
#[derive(Clone)]
pub struct SignedJwt(String);

impl SignedJwt {
    /// The JWT in compact form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The JWT in compact form.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for SignedJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedJwt([redacted])")
    }
}

fn invalid(reason: &str) -> ConfigError {
    ConfigError::InvalidSigningKey(reason.to_string())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The modulus length of an RSA private key in PKCS#1 form (RFC 8017, appendix A.1.2), the form jsonwebtoken keeps for PKCS#1 and PKCS#8 PEM alike.
fn rsa_modulus_bits(pkcs1: &[u8]) -> Option<usize> {
    let blocks = simple_asn1::from_der(pkcs1).ok()?;
    let [simple_asn1::ASN1Block::Sequence(_, fields)] = blocks.as_slice() else {
        return None;
    };
    match fields.get(1)? {
        simple_asn1::ASN1Block::Integer(_, modulus) => usize::try_from(modulus.bits()).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use strum::VariantArray as _;

    use super::*;

    #[test]
    fn test_every_algorithm_has_the_alg_value_of_jsonwebtoken() {
        for algorithm in SigningAlgorithm::VARIANTS {
            assert_eq!(
                Algorithm::from_str(algorithm.as_str()).unwrap(),
                algorithm.jsonwebtoken(),
                "{algorithm}"
            );
        }
    }
}
