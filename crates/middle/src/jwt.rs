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
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, jwk::ThumbprintHash};
use serde_json::{Map, Value};
use simple_asn1::ASN1Block;

use crate::error::{AssertionError, ConfigError, DisplayChain, Error};

/// Registered claims middle sets itself (RFC 7519, section 4.1).
const REGISTERED_CLAIMS: [&str; 6] = ["iss", "sub", "aud", "exp", "iat", "jti"];

/// The lifetime of an assertion unless [`JwtAssertion::with_lifetime`] sets another.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(60);

/// The shortest lifetime [`JwtAssertion::with_lifetime`] accepts.
const MIN_LIFETIME: Duration = Duration::from_secs(1);

/// The longest lifetime [`JwtAssertion::with_lifetime`] accepts. Servers such as Okta refuse client assertions that live longer, and an assertion can be replayed until it expires.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// RFC 7518, section 3.3: RSA keys have at least 2048 bits.
const MIN_RSA_BITS: usize = 2048;

/// The longest RSA key middle signs with, the limit of aws-lc-rs, so that both crypto backends accept the same keys.
const MAX_RSA_BITS: usize = 8192;

/// The tag of a SEQUENCE (X.690, section 8.9).
const SEQUENCE: u8 = 0x30;

/// The tag of `[0] EXPLICIT`, the version of an X.509 certificate (RFC 5280, section 4.1).
const VERSION: u8 = 0xA0;

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

impl Family {
    /// The family of a key algorithm, given as the arcs of its OID.
    fn of_key_algorithm(arcs: &[u64]) -> Option<Self> {
        match arcs {
            // rsaEncryption (RFC 8017, appendix C)
            [1, 2, 840, 113_549, 1, 1, 1] => Some(Self::Rsa),
            // id-ecPublicKey (RFC 5480, section 2.1.1)
            [1, 2, 840, 10_045, 2, 1] => Some(Self::Ec),
            // id-Ed25519 (RFC 8410, section 3)
            [1, 3, 101, 112] => Some(Self::Ed),
            _ => None,
        }
    }

    /// A key of the family, with its article.
    fn key(self) -> &'static str {
        match self {
            Self::Rsa => "an RSA key",
            Self::Ec => "an EC key",
            Self::Ed => "an Ed25519 key",
            Self::Hmac => "a shared secret",
        }
    }
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

    /// The curve an `ES*` algorithm signs with (RFC 7518, section 3.4).
    fn curve(self) -> Option<&'static str> {
        match self {
            Self::Es256 => Some("P-256"),
            Self::Es384 => Some("P-384"),
            _ => None,
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
    /// Loads a private key in PEM form: RSA in PKCS#1 (`RSA PRIVATE KEY`) or PKCS#8 (`PRIVATE KEY`) for `RS*` and `PS*`, EC in PKCS#8 for `ES*`, Ed25519 in PKCS#8 for `EdDSA`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidSigningKey`] if the PEM holds no private key, such as a public key or a certificate, if the key does not fit the algorithm or cannot sign, or for an RSA key longer than 8192 bits,
    /// [`ConfigError::WeakSigningKey`] for an RSA key shorter than 2048 bits (RFC 7518, section 3.3).
    pub fn from_pem(
        pem: impl AsRef<[u8]>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, ConfigError> {
        let load: fn(&[u8]) -> jsonwebtoken::errors::Result<EncodingKey> = match algorithm.family()
        {
            Family::Rsa => EncodingKey::from_rsa_pem,
            Family::Ec => EncodingKey::from_ec_pem,
            Family::Ed => EncodingKey::from_ed_pem,
            Family::Hmac => {
                return Err(invalid(
                    "an HMAC algorithm signs with a shared secret: use `SigningKey::from_secret`",
                ));
            }
        };
        let pem = pem.as_ref();
        check_private_key(pem, algorithm)?;
        let key = load(pem).map_err(|error| invalid(format!("the key cannot be read: {error}")))?;
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
            if bits > MAX_RSA_BITS {
                return Err(invalid(format!(
                    "the RSA key has {bits} bits; middle signs with RSA keys of {MIN_RSA_BITS} to {MAX_RSA_BITS} bits"
                )));
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
        let key = EncodingKey::from_secret(secret).map_err(|error| {
            invalid(format!(
                "the shared secret cannot be used as an HMAC key: {error}"
            ))
        })?;
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
            .map_err(|error| error.cannot_sign(algorithm))?;
        Ok(key)
    }

    /// Sets the `kid` header, which tells the server which of the client's keys signed.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// Sets the `x5t#S256` header (RFC 7515, section 4.1.8) from the X.509 certificate of the key in PEM form, as servers that register certificates expect.
    ///
    /// middle checks that the certificate holds the public key of this key.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidCertificate`] if the text holds no PEM certificate (`CERTIFICATE`) or the certificate cannot be read,
    /// [`ConfigError::CertificateKeyMismatch`] if the public key of the certificate does not belong to this key, which is always so for a shared secret.
    pub fn with_certificate_pem(self, certificate: impl AsRef<[u8]>) -> Result<Self, ConfigError> {
        let certificate = pem::parse(certificate).map_err(|_| ConfigError::InvalidCertificate)?;
        if certificate.tag() != "CERTIFICATE" {
            return Err(ConfigError::InvalidCertificate);
        }
        self.with_certificate_der(certificate.contents())
    }

    /// Sets the `x5t#S256` header (RFC 7515, section 4.1.8) from the X.509 certificate of the key in DER form.
    ///
    /// middle checks that the certificate holds the public key of this key.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidCertificate`] if the certificate cannot be read,
    /// [`ConfigError::CertificateKeyMismatch`] if the public key of the certificate does not belong to this key, which is always so for a shared secret.
    pub fn with_certificate_der(
        mut self,
        certificate: impl AsRef<[u8]>,
    ) -> Result<Self, ConfigError> {
        let certificate = certificate.as_ref();
        self.check_certificate(certificate)?;
        let digest = (PROVIDER.key_utils.compute_digest)(certificate, ThumbprintHash::SHA256)
            .map_err(|_| ConfigError::InvalidCertificate)?;
        self.x5t_s256 = Some(URL_SAFE_NO_PAD.encode(digest));
        Ok(self)
    }

    /// Checks that a signature of this key verifies with the public key of the certificate in DER form.
    fn check_certificate(&self, certificate: &[u8]) -> Result<(), ConfigError> {
        let (family, public_key) =
            certificate_public_key(certificate).ok_or(ConfigError::InvalidCertificate)?;
        let public_key = match (self.algorithm.family(), family) {
            (Family::Rsa, Some(Family::Rsa)) => DecodingKey::from_rsa_der(&public_key),
            (Family::Ec, Some(Family::Ec)) => DecodingKey::from_ec_der(&public_key),
            // RFC 8410, section 4: an Ed25519 public key has 32 bytes. jsonwebtoken's RustCrypto verifier panics on a shorter one.
            (Family::Ed, Some(Family::Ed)) if public_key.len() == 32 => {
                DecodingKey::from_ed_der(&public_key)
            }
            _ => return Err(ConfigError::CertificateKeyMismatch),
        };
        let message = b"middle checks the certificate";
        let signature = self
            .sign_bytes(message)
            .map_err(|error| error.cannot_sign(self.algorithm))?;
        let verifier = (PROVIDER.verifier_factory)(&self.algorithm.jsonwebtoken(), &public_key)
            .map_err(|_| ConfigError::CertificateKeyMismatch)?;
        verifier
            .verify(message, &signature)
            .map_err(|_| ConfigError::CertificateKeyMismatch)
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

impl SignError {
    /// The key cannot sign, with the cause: an error kind of jsonwebtoken or a reason of the crypto backend, which hold no key material.
    fn cannot_sign(&self, algorithm: SigningAlgorithm) -> ConfigError {
        invalid(format!(
            "the key cannot sign with {algorithm}: {}",
            DisplayChain(&*self.0)
        ))
    }
}

/// A JWT assertion (RFC 7523, section 3): signed with a new `jti`, `iat` and `exp` on every call of [`JwtAssertion::sign`].
///
/// `Debug` shows the claims middle sets and the names of extra claims, never the key or their values.
#[derive(Clone)]
pub struct JwtAssertion {
    key: SigningKey,
    issuer: String,
    subject: String,
    audience: String,
    lifetime: Duration,
    token_type: Option<String>,
    claims: Map<String, Value>,
}

impl JwtAssertion {
    /// An assertion from `issuer` about `subject` for `audience`, valid for 60 seconds, with the header `typ: JWT`. `aud` is `audience` as a single string.
    ///
    /// For JWT client authentication, `issuer` and `subject` are both the client id (RFC 7523, section 3), and `audience` is the issuer identifier of the authorization server (RFC 10070). Some providers, such as Entra ID and Okta, document their token endpoint URL as the audience: pass what the provider expects.
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
            audience: audience.into(),
            lifetime: DEFAULT_LIFETIME,
            token_type: Some("JWT".to_string()),
            claims: Map::new(),
        }
    }

    /// Sets how long an assertion is valid, from one second to one hour. `exp` is `iat` plus the whole seconds of the lifetime, so a fraction of a second is cut off.
    ///
    /// # Errors
    ///
    /// [`ConfigError::AssertionLifetime`] for a lifetime shorter than one second or longer than one hour. Servers such as Okta refuse client assertions that live longer, and an assertion can be replayed until it expires.
    pub fn with_lifetime(mut self, lifetime: Duration) -> Result<Self, ConfigError> {
        if !(MIN_LIFETIME..=MAX_LIFETIME).contains(&lifetime) {
            return Err(ConfigError::AssertionLifetime(lifetime));
        }
        self.lifetime = lifetime;
        Ok(self)
    }

    /// Sets the `typ` header, for example `client-authentication+jwt` (RFC 10070).
    #[must_use]
    pub fn with_type(mut self, token_type: impl Into<String>) -> Self {
        self.token_type = Some(token_type.into());
        self
    }

    /// Leaves out the `typ` header.
    #[must_use]
    pub fn without_type(mut self) -> Self {
        self.token_type = None;
        self
    }

    /// Adds a claim.
    ///
    /// middle sets no `nbf`, because a server whose clock is slightly behind refuses an assertion whose `nbf` is its `iat`. Add `nbf` here if a server requires it.
    ///
    /// # Errors
    ///
    /// [`ConfigError::ReservedClaim`] for a claim middle sets itself: `iss`, `sub`, `aud`, `exp`, `iat`, `jti`.
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
        claims.insert("aud".to_string(), self.audience.as_str().into());
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

fn invalid(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidSigningKey(reason.into())
}

/// Checks that the first PEM block holds a private key that fits the algorithm, before jsonwebtoken loads it.
///
/// jsonwebtoken's `EncodingKey::from_rsa_pem` also loads an RSA public key or certificate, so middle reads the label and the key algorithm itself. The messages name labels, algorithms and curves, never key material.
fn check_private_key(pem: &[u8], algorithm: SigningAlgorithm) -> Result<(), ConfigError> {
    let block = pem::parse(pem).map_err(|_| invalid("the key is not in PEM form"))?;
    let (family, curve) = match block.tag() {
        "PRIVATE KEY" => pkcs8_key_algorithm(block.contents())?,
        "RSA PRIVATE KEY" => (Family::Rsa, None),
        "EC PRIVATE KEY" if algorithm.family() == Family::Ec => {
            return Err(invalid(
                "the EC key is in SEC1 form; convert it to PKCS#8 with `openssl pkcs8 -topk8 -nocrypt`",
            ));
        }
        "EC PRIVATE KEY" => (Family::Ec, None),
        "PUBLIC KEY" | "RSA PUBLIC KEY" => {
            return Err(invalid("the PEM holds a public key, not a private key"));
        }
        "CERTIFICATE" => return Err(invalid("the PEM holds a certificate, not a private key")),
        label => {
            return Err(invalid(format!(
                "the PEM holds `{label}`, not `PRIVATE KEY` or `RSA PRIVATE KEY`"
            )));
        }
    };
    if family != algorithm.family() {
        return Err(invalid(format!(
            "the key is {}, but {algorithm} needs {}",
            family.key(),
            algorithm.family().key()
        )));
    }
    match (algorithm.curve(), curve) {
        (Some(needed), Some(curve)) if curve != needed => Err(invalid(format!(
            "the EC key is on the curve {curve}, but {algorithm} needs {needed}"
        ))),
        // RFC 5480, section 2.1.1: an EC key names its curve.
        (Some(_), None) => Err(invalid(
            "the EC key does not name its curve; convert it to a named curve with `openssl pkey -in key.pem -ec_param_enc named_curve -out key-named.pem`",
        )),
        _ => Ok(()),
    }
}

/// The family and, for an EC key, the curve of a private key in PKCS#8 form (RFC 5958, section 2).
fn pkcs8_key_algorithm(der: &[u8]) -> Result<(Family, Option<String>), ConfigError> {
    let not_pkcs8 = || invalid("the key is not in PKCS#8 form");
    let blocks = simple_asn1::from_der(der).map_err(|_| not_pkcs8())?;
    let [ASN1Block::Sequence(_, fields)] = blocks.as_slice() else {
        return Err(not_pkcs8());
    };
    let (key_algorithm, parameter) = fields
        .get(1)
        .and_then(algorithm_identifier)
        .ok_or_else(not_pkcs8)?;
    let family = Family::of_key_algorithm(&key_algorithm).ok_or_else(|| {
        invalid(format!(
            "the key has the algorithm {}, which middle does not sign with",
            dotted(&key_algorithm)
        ))
    })?;
    let curve = parameter
        .filter(|_| family == Family::Ec)
        .map(|curve| match curve.as_slice() {
            // Named curves (RFC 5480, section 2.1.1.1).
            [1, 2, 840, 10_045, 3, 1, 7] => "P-256".to_string(),
            [1, 3, 132, 0, 34] => "P-384".to_string(),
            [1, 3, 132, 0, 35] => "P-521".to_string(),
            _ => dotted(&curve),
        });
    Ok((family, curve))
}

/// The algorithm and, if it is an OID, the parameter of an `AlgorithmIdentifier` (RFC 5280, section 4.1.1.2), as the arcs of their OIDs. For an EC key, the parameter is its named curve.
fn algorithm_identifier(identifier: &ASN1Block) -> Option<(Vec<u64>, Option<Vec<u64>>)> {
    let ASN1Block::Sequence(_, fields) = identifier else {
        return None;
    };
    let Some(ASN1Block::ObjectIdentifier(_, algorithm)) = fields.first() else {
        return None;
    };
    let parameter = match fields.get(1) {
        Some(ASN1Block::ObjectIdentifier(_, parameter)) => Some(parameter.as_vec().ok()?),
        _ => None,
    };
    Some((algorithm.as_vec().ok()?, parameter))
}

/// The family and the `subjectPublicKey` of an X.509 certificate in DER form (RFC 5280, section 4.1).
///
/// The `subjectPublicKey` is in the form jsonwebtoken's `DecodingKey::from_rsa_der`, `from_ec_der` and `from_ed_der` read. middle reads the certificate itself: jsonwebtoken takes the first key algorithm OID anywhere in the certificate, and when the issuer signs with Ed25519, that is the OID of the signature algorithm.
///
/// middle walks the DER headers to the `subjectPublicKeyInfo` and decodes only that element. It skips the names unread: a CA may write them as a `BMPString` or as a `PrintableString` with characters such as `*`, which `simple_asn1` refuses.
fn certificate_public_key(der: &[u8]) -> Option<(Option<Family>, Vec<u8>)> {
    let (certificate, rest) = split_element(der)?;
    if certificate.tag != SEQUENCE || !rest.is_empty() {
        return None;
    }
    let (to_be_signed, _) = split_element(certificate.content)?;
    if to_be_signed.tag != SEQUENCE {
        return None;
    }
    let mut fields = to_be_signed.content;
    // The version is `[0] EXPLICIT`, which an X.509 v1 certificate leaves out.
    if fields.first() == Some(&VERSION) {
        fields = split_element(fields)?.1;
    }
    // serialNumber, signature, issuer, validity and subject.
    for _ in 0..5 {
        fields = split_element(fields)?.1;
    }
    let (subject_public_key_info, _) = split_element(fields)?;
    let blocks = simple_asn1::from_der(subject_public_key_info.encoded).ok()?;
    let [ASN1Block::Sequence(_, subject_public_key_info)] = blocks.as_slice() else {
        return None;
    };
    let [identifier, ASN1Block::BitString(_, _, public_key)] = subject_public_key_info.as_slice()
    else {
        return None;
    };
    let (key_algorithm, _) = algorithm_identifier(identifier)?;
    Some((Family::of_key_algorithm(&key_algorithm), public_key.clone()))
}

/// A DER element (X.690, section 8.1).
struct Element<'a> {
    tag: u8,
    /// The whole element: tag, length and content.
    encoded: &'a [u8],
    content: &'a [u8],
}

/// Splits the first DER element off `der` and returns it with the bytes after it.
///
/// It reads a tag of one byte and a definite length in short or long form, and refuses an indefinite length or a length past the end. It reads no further than the element's header, so a deep nesting costs nothing.
fn split_element(der: &[u8]) -> Option<(Element<'_>, &[u8])> {
    let (&tag, after_tag) = der.split_first()?;
    // A tag number above 30 takes more bytes (X.690, section 8.1.2.4); no element before the key of a certificate has one.
    if (tag & 0x1f) == 0x1f {
        return None;
    }
    let (&first, after_first) = after_tag.split_first()?;
    let (length, after_length) = if first < 0x80 {
        (usize::from(first), after_first)
    } else {
        // The low bits count the length bytes. 0x80 alone is the indefinite length, which DER does not allow.
        let count = usize::from(first & 0x7f);
        if count == 0 || count > size_of::<usize>() {
            return None;
        }
        let (bytes, after_length) = after_first.split_at_checked(count)?;
        let length = bytes
            .iter()
            .fold(0, |length, &byte| (length << 8) | usize::from(byte));
        (length, after_length)
    };
    let (content, rest) = after_length.split_at_checked(length)?;
    let encoded = &der[..der.len() - rest.len()];
    Some((
        Element {
            tag,
            encoded,
            content,
        },
        rest,
    ))
}

/// An OID in dotted form, such as `1.3.101.112`.
fn dotted(arcs: &[u64]) -> String {
    arcs.iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
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
