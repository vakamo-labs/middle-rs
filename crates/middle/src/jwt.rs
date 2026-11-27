//! Signing JWT assertions (RFC 7523, section 3) for the JWT bearer grant and for JWT client authentication.
//!
//! middle signs with jsonwebtoken and the crypto backend that the feature `aws-lc-rs` or `rust-crypto` selects. Enable exactly one of them with `jwt`; if the application uses jsonwebtoken 12, enable the backend it uses.
//! middle passes that backend to every call, so signing works whatever process-wide default jsonwebtoken has.

#[cfg(not(any(feature = "aws-lc-rs", feature = "rust-crypto")))]
compile_error!("The feature `jwt` needs a crypto backend: enable `aws-lc-rs` or `rust-crypto`.");

use std::{
    borrow::Cow,
    fmt,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use der::{
    Decode as _, Encode as _, Reader as _, SliceReader, Tag, TagNumber, Tagged as _,
    asn1::{AnyRef, ObjectIdentifier, OctetStringRef},
};
#[cfg(feature = "aws-lc-rs")]
use jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER as PROVIDER;
#[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
use jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER as PROVIDER;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, jwk::ThumbprintHash};
use pkcs1::RsaPrivateKeyRef;
use pkcs8::PrivateKeyInfoRef;
use sec1::{EcParameters, EcPrivateKey};
use serde_json::{Map, Value};
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

use crate::{
    SignedJwt,
    error::{ConfigError, DisplayChain, SourceError},
};

/// Registered claims middle sets itself (RFC 7519, section 4.1).
const REGISTERED_CLAIMS: [&str; 6] = ["iss", "sub", "aud", "exp", "iat", "jti"];

/// The lifetime of an assertion unless [`JwtAssertion::with_lifetime`] sets another.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(60);

/// The shortest lifetime [`JwtAssertion::with_lifetime`] accepts: `iat` lies 5 seconds before the signing, so `exp` lies about 5 seconds after the signing.
const MIN_LIFETIME: Duration = Duration::from_secs(10);

/// The longest lifetime [`JwtAssertion::with_lifetime`] accepts: one hour.
/// Some servers refuse an assertion whose `exp` lies more than one hour after its `iat`, or more than one hour in the future.
/// With `iat` 5 seconds before the signing, one hour meets both. An assertion can be replayed until it expires.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// How many seconds `iat` lies before the signing, so that a server whose clock is slightly behind accepts the assertion.
const IAT_BEFORE_SIGNING: u64 = 5;

/// The `typ` header of a client authentication JWT for the issuer (RFC 10070, section 4).
const CLIENT_AUTHENTICATION_JWT_TYPE: &str = "client-authentication+jwt";

/// RFC 7518, section 3.3: RSA keys have at least 2048 bits.
const MIN_RSA_BITS: usize = 2048;

/// The longest RSA key middle signs with. aws-lc-rs refuses longer keys. rust-crypto signs with them, but reads no longer public key, so it cannot check their signatures or certificates.
const MAX_RSA_BITS: usize = 8192;

/// The tag of `[0] EXPLICIT`, the version of an X.509 certificate (RFC 5280, section 4.1).
const VERSION: Tag = Tag::ContextSpecific {
    constructed: true,
    number: TagNumber(0),
};

/// The key algorithm rsaEncryption (RFC 8017, appendix C).
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The key algorithm id-RSASSA-PSS (RFC 4055, section 3.1), of an RSA key limited to RSA-PSS signatures.
const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

/// The key algorithm id-ecPublicKey (RFC 5480, section 2.1.1).
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// The key algorithm id-Ed25519 (RFC 8410, section 3).
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// The named curve P-256 (RFC 5480, section 2.1.1.1).
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The named curve P-384 (RFC 5480, section 2.1.1.1).
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// The named curve P-521 (RFC 5480, section 2.1.1.1).
const SECP521R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// The PEM labels of private keys: the forms [`private_key_der`] reads, and the encrypted PKCS#8 form (RFC 7468, section 11), which it names in its error.
const PRIVATE_KEY_LABELS: [&str; 4] = [
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
];

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
    /// The family of a key algorithm.
    fn of_key_algorithm(algorithm: ObjectIdentifier) -> Option<Self> {
        match algorithm {
            RSA_ENCRYPTION => Some(Self::Rsa),
            ID_EC_PUBLIC_KEY => Some(Self::Ec),
            ID_ED25519 => Some(Self::Ed),
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
    fn curve(self) -> Option<ObjectIdentifier> {
        match self {
            Self::Es256 => Some(SECP256R1),
            Self::Es384 => Some(SECP384R1),
            _ => None,
        }
    }
}

/// The name of a curve, such as `P-256`, or its OID in dotted form.
fn curve_name(curve: ObjectIdentifier) -> String {
    match curve {
        SECP256R1 => "P-256".to_string(),
        SECP384R1 => "P-384".to_string(),
        SECP521R1 => "P-521".to_string(),
        _ => curve.to_string(),
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
    /// Loads a private key in PEM form: RSA in PKCS#1 (`RSA PRIVATE KEY`) or in PKCS#8 (`PRIVATE KEY`) with the algorithm rsaEncryption for `RS*` and `PS*`, EC in SEC1 (`EC PRIVATE KEY`) or PKCS#8 for `ES*`, Ed25519 in PKCS#8 for `EdDSA`. An EC key names its curve.
    ///
    /// The text may hold other PEM blocks before or after the key, such as its certificate or the `EC PARAMETERS` that `openssl ecparam -genkey` writes before an EC key: middle reads the first private key and ignores the other blocks.
    ///
    /// middle signs once with the key, so a key the crypto backend refuses fails here. The backends differ for RSA keys whose two primes differ in length: aws-lc-rs signs with them, and rust-crypto refuses them.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidSigningKey`] if the PEM holds no private key, such as only a public key or a certificate, if the key is encrypted, does not fit the algorithm or cannot sign, or for an RSA key longer than 8192 bits,
    /// [`ConfigError::WeakSigningKey`] for an RSA key shorter than 2048 bits (RFC 7518, section 3.3).
    pub fn from_pem(
        pem: impl AsRef<[u8]>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, ConfigError> {
        let load: fn(&[u8]) -> EncodingKey = match algorithm.family() {
            Family::Rsa => EncodingKey::from_rsa_der,
            Family::Ec => EncodingKey::from_ec_der,
            Family::Ed => EncodingKey::from_ed_der,
            Family::Hmac => {
                return Err(invalid(
                    "an HMAC algorithm signs with a shared secret: use `SigningKey::from_secret`",
                ));
            }
        };
        let block = private_key_block(pem.as_ref())?;
        let der = private_key_der(&block, algorithm)?;
        Self::checked(algorithm, load(&der))
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
    /// The text may hold other PEM blocks before or after the certificate, such as the private key or the certificates of the issuers: middle reads the first certificate and ignores the other blocks. middle checks that the certificate holds the public key of this key.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidCertificate`] if the text is not in PEM form, holds no PEM certificate (`CERTIFICATE`), or the certificate cannot be read,
    /// [`ConfigError::UnsupportedCertificateKey`] if the public key of the certificate has an algorithm middle does not sign with, such as RSA-PSS,
    /// [`ConfigError::CertificateKeyMismatch`] if the public key of the certificate does not belong to this key, which is always so for a shared secret.
    pub fn with_certificate_pem(self, certificate: impl AsRef<[u8]>) -> Result<Self, ConfigError> {
        let blocks = pem::parse_many(certificate).map_err(|_| ConfigError::InvalidCertificate)?;
        let certificate = blocks
            .iter()
            .find(|block| block.tag() == "CERTIFICATE")
            .ok_or(ConfigError::InvalidCertificate)?;
        self.with_certificate_der(certificate.contents())
    }

    /// Sets the `x5t#S256` header (RFC 7515, section 4.1.8) from the X.509 certificate of the key in DER form.
    ///
    /// middle checks that the certificate holds the public key of this key.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidCertificate`] if the certificate cannot be read,
    /// [`ConfigError::UnsupportedCertificateKey`] if the public key of the certificate has an algorithm middle does not sign with, such as RSA-PSS,
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

    /// Checks that a signature of this key verifies with the public key of the certificate in DER form, and that the certificate names the curve of an EC key.
    fn check_certificate(&self, certificate: &[u8]) -> Result<(), ConfigError> {
        let (key_algorithm, public_key) =
            certificate_public_key(certificate).ok_or(ConfigError::InvalidCertificate)?;
        let public_key = match (
            self.algorithm.family(),
            Family::of_key_algorithm(key_algorithm.oid),
        ) {
            (Family::Rsa, Some(Family::Rsa)) => DecodingKey::from_rsa_der(public_key),
            // The verifier reads the point on the curve of the algorithm, whatever curve the certificate names.
            (Family::Ec, Some(Family::Ec))
                if named_curve(&key_algorithm) == self.algorithm.curve() =>
            {
                DecodingKey::from_ec_der(public_key)
            }
            // RFC 8410, section 4: an Ed25519 public key has 32 bytes. jsonwebtoken's RustCrypto verifier panics on a shorter one.
            (Family::Ed, Some(Family::Ed)) if public_key.len() == 32 => {
                DecodingKey::from_ed_der(public_key)
            }
            (Family::Hmac, _) | (_, Some(_)) => return Err(ConfigError::CertificateKeyMismatch),
            (_, None) => {
                return Err(ConfigError::UnsupportedCertificateKey(
                    key_algorithm.oid.to_string(),
                ));
            }
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
    /// For JWT client authentication, `issuer` and `subject` are both the client id (RFC 7523, section 3). `ClientAuthentication::private_key_jwt` builds that assertion with an [`Audience`].
    /// Pass a `JwtAssertion` to `ClientAuthentication::client_assertion` for other claims or another header, for example for an authorization server that refuses the type `client-authentication+jwt`.
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

    /// Sets how long an assertion is valid, from 10 seconds to one hour. `exp` is `iat` plus the whole seconds of the lifetime, so a fraction of a second is cut off.
    /// `iat` lies 5 seconds before the signing, so the assertion expires about 5 seconds before the lifetime has passed since the signing.
    ///
    /// # Errors
    ///
    /// [`ConfigError::AssertionLifetime`] for a lifetime shorter than 10 seconds or longer than one hour. Some servers refuse an assertion whose `exp` lies more than one hour after its `iat` or more than one hour in the future, and an assertion can be replayed until it expires.
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

    /// Signs a new assertion: `iat` is 5 seconds before now, so that a server whose clock is slightly behind accepts it, `exp` is `iat` plus the lifetime, and `jti` is 16 random bytes.
    ///
    /// # Errors
    ///
    /// [`SourceError`] if the system clock is before 1970, the system has no randomness, or signing fails.
    pub fn sign(&self) -> Result<SignedJwt, SourceError> {
        self.sign_for(&self.audience)
    }

    /// Signs a new assertion for `audience`.
    fn sign_for(&self, audience: &str) -> Result<SignedJwt, SourceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                SourceError::new("the system clock is before 1970").with_source(error)
            })?
            .as_secs();
        let mut jti = [0u8; 16];
        getrandom::fill(&mut jti).map_err(|error| {
            SourceError::new("the system has no randomness for `jti`").with_source(error)
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
        claims.insert("aud".to_string(), audience.into());
        let iat = now.saturating_sub(IAT_BEFORE_SIGNING);
        claims.insert("iat".to_string(), iat.into());
        claims.insert(
            "exp".to_string(),
            iat.saturating_add(self.lifetime.as_secs()).into(),
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
                SourceError::new("signing the assertion failed").with_shared_source(error)
            })?;
        Ok(SignedJwt::from_signed(format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        )))
    }
}

/// Signs a new assertion for every token request.
impl crate::AssertionSource for JwtAssertion {
    async fn assertion(
        &self,
        _context: &crate::AssertionContext,
    ) -> Result<crate::Assertion, crate::SourceError> {
        self.sign().map(crate::Assertion::from)
    }
}

/// The audience of a client authentication JWT, see `ClientAuthentication::private_key_jwt`.
///
/// RFC 10070 (section 4) requires the issuer, while OpenID Connect Core 1.0 (section 9) names the token endpoint URL.
/// Authorization servers differ in which one they accept, so the caller chooses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Audience {
    /// The issuer identifier of the authorization server, exactly as its metadata names it (RFC 8414, section 2), including a trailing slash if it has one:
    /// RFC 10070 requires that servers compare it as a simple string. The header `typ` is `client-authentication+jwt`, which RFC 10070 recommends.
    Issuer(String),
    /// The URL of the token endpoint that middle connects to, without its query. The header `typ` is `JWT`.
    ///
    /// The authorization server compares it with the URL it knows itself as, so a client that reaches the server under another name, such as an internal host name, needs that name.
    TokenEndpoint,
}

/// The assertion of `private_key_jwt` and `client_secret_jwt`: `iss` and `sub` are the client id, `aud` and `typ` follow the [`Audience`].
pub(crate) struct ClientAuthenticationJwt {
    assertion: JwtAssertion,
    audience: Audience,
}

impl ClientAuthenticationJwt {
    pub(crate) fn new(key: SigningKey, client_id: &str, audience: Audience) -> Self {
        let (aud, token_type) = match &audience {
            Audience::Issuer(issuer) => (issuer.clone(), CLIENT_AUTHENTICATION_JWT_TYPE),
            // `assertion` signs for the token URL it gets with each request.
            Audience::TokenEndpoint => (String::new(), "JWT"),
        };
        Self {
            assertion: JwtAssertion::new(key, client_id, client_id, aud).with_type(token_type),
            audience,
        }
    }
}

impl crate::AssertionSource for ClientAuthenticationJwt {
    async fn assertion(
        &self,
        context: &crate::AssertionContext,
    ) -> Result<crate::Assertion, crate::SourceError> {
        let signed = match &self.audience {
            Audience::Issuer(issuer) => self.assertion.sign_for(issuer),
            Audience::TokenEndpoint => {
                // Servers compare the URL without a query, and the query may hold a secret.
                let mut token_url = context.token_url().clone();
                token_url.set_query(None);
                self.assertion.sign_for(token_url.as_str())
            }
        };
        signed.map(crate::Assertion::from)
    }
}

impl fmt::Debug for ClientAuthenticationJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientAuthenticationJwt")
            .field("key", &self.assertion.key)
            .field("client_id", &self.assertion.issuer)
            .field("audience", &self.audience)
            .field("lifetime", &self.assertion.lifetime)
            .finish()
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

fn invalid(reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidSigningKey(reason.into())
}

/// The first PEM block of the text that holds a private key. If no block does, the first block, so that [`private_key_der`] names what the text holds.
fn private_key_block(pem: &[u8]) -> Result<pem::Pem, ConfigError> {
    let not_pem = || invalid("the key is not in PEM form");
    let blocks = pem::parse_many(pem).map_err(|_| not_pem())?;
    let index = blocks
        .iter()
        .position(|block| PRIVATE_KEY_LABELS.contains(&block.tag()))
        .unwrap_or(0);
    blocks.into_iter().nth(index).ok_or_else(not_pem)
}

/// Checks that a PEM block holds a private key that fits the algorithm, and returns the key in DER in the form jsonwebtoken's backends sign with: PKCS#1 for RSA, PKCS#8 for EC and Ed25519.
///
/// jsonwebtoken's `EncodingKey::from_rsa_der`, `from_ec_der` and `from_ed_der` keep the bytes unread, and the backend reads them when it signs, so middle reads the label and the key itself. The messages name labels, algorithms and curves, never key material.
fn private_key_der(
    block: &pem::Pem,
    algorithm: SigningAlgorithm,
) -> Result<Cow<'_, [u8]>, ConfigError> {
    let der = block.contents();
    // RFC 1421, section 4.6.1.1: the header `Proc-Type: 4,ENCRYPTED` marks a key in PKCS#1 or SEC1 form that a passphrase encrypts, as `openssl rsa -aes256 -traditional` writes it.
    let encrypted = block
        .headers()
        .get("Proc-Type")
        .is_some_and(|value| value.ends_with("ENCRYPTED"));
    if encrypted || block.tag() == "ENCRYPTED PRIVATE KEY" {
        return Err(invalid(
            "the key is encrypted; decrypt it with `openssl pkey -in key.pem -out key-decrypted.pem`",
        ));
    }
    match block.tag() {
        "PRIVATE KEY" => pkcs8_private_key(der, algorithm),
        "RSA PRIVATE KEY" => {
            check_family(Family::Rsa, algorithm)?;
            let key = RsaPrivateKeyRef::from_der(der)
                .map_err(|_| invalid("the key is not in PKCS#1 form"))?;
            check_rsa_key(&key, algorithm)?;
            Ok(Cow::Borrowed(der))
        }
        "EC PRIVATE KEY" => {
            check_family(Family::Ec, algorithm)?;
            sec1_private_key(der, algorithm).map(Cow::Owned)
        }
        "PUBLIC KEY" | "RSA PUBLIC KEY" => {
            Err(invalid("the PEM holds a public key, not a private key"))
        }
        "CERTIFICATE" => Err(invalid("the PEM holds a certificate, not a private key")),
        label => Err(invalid(format!(
            "the PEM holds `{label}`, not `PRIVATE KEY`, `RSA PRIVATE KEY` or `EC PRIVATE KEY`"
        ))),
    }
}

/// The DER jsonwebtoken's backends sign with for a private key in PKCS#8 form (RFC 5958, section 2): the RSA key in PKCS#1 form it holds, the EC key in PKCS#8 without the public key, or the PKCS#8 key itself for Ed25519.
fn pkcs8_private_key(
    der: &[u8],
    algorithm: SigningAlgorithm,
) -> Result<Cow<'_, [u8]>, ConfigError> {
    let key =
        PrivateKeyInfoRef::from_der(der).map_err(|_| invalid("the key is not in PKCS#8 form"))?;
    let key_algorithm = key.algorithm.oid;
    let family = Family::of_key_algorithm(key_algorithm).ok_or_else(|| match key_algorithm {
        ID_RSASSA_PSS => invalid(format!(
            "the key is an RSA-PSS key ({ID_RSASSA_PSS}), which middle does not sign with; an RSA key in PKCS#8 needs the algorithm rsaEncryption"
        )),
        _ => invalid(format!(
            "the key has the algorithm {key_algorithm}, which middle does not sign with"
        )),
    })?;
    check_family(family, algorithm)?;
    match family {
        Family::Rsa => {
            let rsa = key.private_key.as_bytes();
            let rsa_key = RsaPrivateKeyRef::from_der(rsa)
                .map_err(|_| invalid("the RSA key cannot be read"))?;
            check_rsa_key(&rsa_key, algorithm)?;
            Ok(Cow::Borrowed(rsa))
        }
        Family::Ec => {
            let curve = named_curve(&key.algorithm).ok_or_else(|| {
                invalid(
                    "the EC key does not name its curve; convert it to a named curve with `openssl pkey -in key.pem -ec_param_enc named_curve -out key-named.pem`",
                )
            })?;
            check_curve(curve, algorithm)?;
            // The public key of PKCS#8 v2, which aws-lc-rs refuses in an EC key. The backends compute it from the private key.
            if key.public_key.is_none() {
                return Ok(Cow::Borrowed(der));
            }
            PrivateKeyInfoRef::new(key.algorithm, key.private_key)
                .to_der()
                .map(Cow::Owned)
                .map_err(|_| {
                    invalid("the EC key in PKCS#8 form cannot be written without its public key")
                })
        }
        Family::Ed | Family::Hmac => Ok(Cow::Borrowed(der)),
    }
}

/// The named curve of an EC key algorithm: RFC 5480, section 2.1.1, makes it the parameters of id-ecPublicKey.
fn named_curve(key_algorithm: &AlgorithmIdentifierRef<'_>) -> Option<ObjectIdentifier> {
    key_algorithm
        .parameters
        .and_then(|parameters| ObjectIdentifier::try_from(parameters).ok())
}

/// Wraps an EC private key in SEC1 form (RFC 5915, section 3) into PKCS#8 (RFC 5958, section 2), the form jsonwebtoken's backends sign with: the algorithm id-ecPublicKey with the curve of the key as its parameter (RFC 5480, section 2.1.1), and the SEC1 key as the private key.
fn sec1_private_key(der: &[u8], algorithm: SigningAlgorithm) -> Result<Vec<u8>, ConfigError> {
    // RFC 5915, section 3: the parameters are a named curve. `sec1` refuses explicit parameters, which `openssl ec -param_enc explicit` writes.
    let key = EcPrivateKey::from_der(der).map_err(|_| {
        invalid(
            "the key is not in SEC1 form with a named curve; if it has explicit curve parameters, convert it to a named curve with `openssl pkey -in key.pem -ec_param_enc named_curve -out key-named.pem`",
        )
    })?;
    let curve = key
        .parameters
        .and_then(EcParameters::named_curve)
        .ok_or_else(|| {
            invalid("the EC key in SEC1 form does not name its curve (RFC 5915, section 3)")
        })?;
    check_curve(curve, algorithm)?;
    let key_algorithm = AlgorithmIdentifierRef {
        oid: ID_EC_PUBLIC_KEY,
        parameters: Some(AnyRef::from(&curve)),
    };
    let cannot_convert = |_| invalid("the EC key in SEC1 form cannot be converted to PKCS#8");
    let private_key = OctetStringRef::new(der).map_err(cannot_convert)?;
    PrivateKeyInfoRef::new(key_algorithm, private_key)
        .to_der()
        .map_err(cannot_convert)
}

/// Checks that a key of the family fits the algorithm.
fn check_family(family: Family, algorithm: SigningAlgorithm) -> Result<(), ConfigError> {
    if family == algorithm.family() {
        return Ok(());
    }
    Err(invalid(format!(
        "the key is {}, but {algorithm} needs {}",
        family.key(),
        algorithm.family().key()
    )))
}

/// Checks that an EC key on the named curve fits the algorithm.
fn check_curve(curve: ObjectIdentifier, algorithm: SigningAlgorithm) -> Result<(), ConfigError> {
    match algorithm.curve() {
        Some(needed) if curve != needed => Err(invalid(format!(
            "the EC key is on the curve {}, but {algorithm} needs {}",
            curve_name(curve),
            curve_name(needed)
        ))),
        _ => Ok(()),
    }
}

/// Checks that an RSA private key in PKCS#1 form (RFC 8017, appendix A.1.2) has two primes and from 2048 to 8192 bits.
fn check_rsa_key(
    key: &RsaPrivateKeyRef<'_>,
    algorithm: SigningAlgorithm,
) -> Result<(), ConfigError> {
    // RFC 8017, section 3.2: `otherPrimeInfos` holds the primes after the first two. Neither crypto backend signs with such a key.
    if key.other_prime_infos.is_some() {
        return Err(invalid(
            "the RSA key has more than two primes; middle signs with RSA keys of two primes",
        ));
    }
    // Big-endian, without leading zeros.
    let bits = match key.modulus.as_bytes().split_first() {
        Some((&first, rest)) => rest.len() * 8 + (8 - first.leading_zeros() as usize),
        None => 0,
    };
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
    Ok(())
}

/// The key algorithm and the `subjectPublicKey` of an X.509 certificate in DER form (RFC 5280, section 4.1).
///
/// The `subjectPublicKey` is in the form jsonwebtoken's `DecodingKey::from_rsa_der`, `from_ec_der` and `from_ed_der` read.
///
/// middle checks that the certificate has its three parts and that the fields before the key have their types, and decodes only the `subjectPublicKeyInfo`, with `spki`. It skips the other fields unread: a CA may write the names as a `BMPString` or as a `PrintableString` with characters such as `*`, which strict decoders refuse.
fn certificate_public_key(der: &[u8]) -> Option<(AlgorithmIdentifierRef<'_>, &[u8])> {
    let mut reader = SliceReader::new(der).ok()?;
    // tbsCertificate, signatureAlgorithm and signatureValue (RFC 5280, section 4.1).
    let subject_public_key_info = reader
        .sequence(|certificate| {
            let subject_public_key_info = certificate.sequence(|to_be_signed| {
                // The version is `[0] EXPLICIT`, which an X.509 v1 certificate leaves out.
                if Tag::peek(to_be_signed)? == VERSION {
                    AnyRef::decode(to_be_signed)?;
                }
                // serialNumber, then signature, issuer, validity and subject.
                for tag in [
                    Tag::Integer,
                    Tag::Sequence,
                    Tag::Sequence,
                    Tag::Sequence,
                    Tag::Sequence,
                ] {
                    AnyRef::decode(to_be_signed)?.tag().assert_eq(tag)?;
                }
                let subject_public_key_info = SubjectPublicKeyInfoRef::decode(to_be_signed)?;
                // issuerUniqueID, subjectUniqueID and extensions.
                to_be_signed.read_slice(to_be_signed.remaining_len())?;
                Ok::<_, der::Error>(subject_public_key_info)
            })?;
            AnyRef::decode(certificate)?
                .tag()
                .assert_eq(Tag::Sequence)?;
            AnyRef::decode(certificate)?
                .tag()
                .assert_eq(Tag::BitString)?;
            Ok::<_, der::Error>(subject_public_key_info)
        })
        .ok()?;
    reader.finish().ok()?;
    let public_key = subject_public_key_info.subject_public_key.as_bytes()?;
    Some((subject_public_key_info.algorithm, public_key))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use strum::VariantArray as _;

    use super::*;

    #[test]
    fn test_der_that_cannot_be_read_is_refused() {
        // A length past the end, an indefinite length, a length not in its shortest form, and a tag number above 30.
        for der in [
            &[0x30, 0x01][..],
            &[0x30, 0x80, 0x00, 0x00],
            &[0x30, 0x81, 0x00],
            &[0x1f, 0x22, 0x00],
        ] {
            assert!(certificate_public_key(der).is_none(), "{der:02x?}");
        }
    }

    /// A DER element with the tag and content.
    fn element(tag: Tag, content: &[u8]) -> Vec<u8> {
        AnyRef::new(tag, content).unwrap().to_der().unwrap()
    }

    /// The P-256 test certificate in parts: the encoded fields of its tbsCertificate, and its encoded signatureAlgorithm and signatureValue.
    fn certificate_parts() -> (Vec<Vec<u8>>, Vec<u8>) {
        let pem = pem::parse(include_str!(
            "../tests/fixtures/jwt/certificate-ec-p256.pem"
        ))
        .unwrap();
        let mut reader = SliceReader::new(pem.contents()).unwrap();
        reader
            .sequence(|certificate| {
                let fields = certificate.sequence(|to_be_signed| {
                    let mut fields = Vec::new();
                    while !to_be_signed.is_finished() {
                        fields.push(to_be_signed.tlv_bytes()?.to_vec());
                    }
                    Ok::<_, der::Error>(fields)
                })?;
                let signature = certificate.read_slice(certificate.remaining_len())?;
                Ok::<_, der::Error>((fields, signature.to_vec()))
            })
            .unwrap()
    }

    fn certificate(fields: &[Vec<u8>], signature: &[u8]) -> Vec<u8> {
        element(
            Tag::Sequence,
            &[element(Tag::Sequence, &fields.concat()), signature.to_vec()].concat(),
        )
    }

    #[test]
    fn test_a_certificate_rebuilt_from_its_parts_is_read() {
        let (fields, signature) = certificate_parts();
        assert!(certificate_public_key(&certificate(&fields, &signature)).is_some());
    }

    #[test]
    fn test_a_certificate_missing_or_adding_a_part_is_refused() {
        let (fields, signature) = certificate_parts();
        let signature_algorithm = SliceReader::new(&signature)
            .unwrap()
            .tlv_bytes()
            .unwrap()
            .to_vec();
        // Only the tbsCertificate, no signatureValue, and an element after the signatureValue.
        for signature in [
            Vec::new(),
            signature_algorithm,
            [signature.clone(), element(Tag::Null, &[])].concat(),
        ] {
            assert!(certificate_public_key(&certificate(&fields, &signature)).is_none());
        }
    }

    #[test]
    fn test_a_certificate_with_a_field_of_the_wrong_type_is_refused() {
        let (fields, signature) = certificate_parts();
        let null = element(Tag::Null, &[]);
        let first = usize::from(AnyRef::from_der(&fields[0]).unwrap().tag() == VERSION);
        // serialNumber, signature, issuer, validity and subject, one at a time.
        for position in first..first + 5 {
            let mut fields = fields.clone();
            fields[position] = null.clone();
            assert!(
                certificate_public_key(&certificate(&fields, &signature)).is_none(),
                "field {position}"
            );
        }
        // Five NULLs before the subjectPublicKeyInfo of the certificate.
        let fields = [vec![null; 5], vec![fields[first + 5].clone()]].concat();
        assert!(certificate_public_key(&certificate(&fields, &signature)).is_none());
    }

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
