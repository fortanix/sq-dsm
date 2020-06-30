use std::time;

use crate::packet;
use crate::packet::{
    key,
    Key,
    key::Key4,
};
use crate::Result;
use crate::packet::Signature;
use crate::packet::signature;
use crate::cert::prelude::*;
use crate::Error;
use crate::crypto::Password;
use crate::types::{
    Features,
    HashAlgorithm,
    KeyFlags,
    SignatureType,
    SymmetricAlgorithm,
    RevocationKey,
};

/// Groups symmetric and asymmetric algorithms.
///
/// This is used to select a suite of ciphers.
///
/// # Examples
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::types::PublicKeyAlgorithm;
///
/// # fn main() -> openpgp::Result<()> {
/// let (ecc, _) =
///     CertBuilder::general_purpose(None, Some("alice@example.org"))
///         .set_cipher_suite(CipherSuite::Cv25519)
///         .generate()?;
/// assert_eq!(ecc.primary_key().pk_algo(), PublicKeyAlgorithm::EdDSA);
///
/// let (rsa, _) =
///     CertBuilder::general_purpose(None, Some("alice@example.org"))
///         .set_cipher_suite(CipherSuite::RSA4k)
///         .generate()?;
/// assert_eq!(rsa.primary_key().pk_algo(), PublicKeyAlgorithm::RSAEncryptSign);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug)]
pub enum CipherSuite {
    /// EdDSA and ECDH over Curve25519 with SHA512 and AES256
    Cv25519,
    /// 3072 bit RSA with SHA512 and AES256
    RSA3k,
    /// EdDSA and ECDH over NIST P-256 with SHA256 and AES256
    P256,
    /// EdDSA and ECDH over NIST P-384 with SHA384 and AES256
    P384,
    /// EdDSA and ECDH over NIST P-521 with SHA512 and AES256
    P521,
    /// 2048 bit RSA with SHA512 and AES256
    RSA2k,
    /// 4096 bit RSA with SHA512 and AES256
    RSA4k,
}

impl Default for CipherSuite {
    fn default() -> Self {
        CipherSuite::Cv25519
    }
}

impl CipherSuite {
    fn generate_key<R>(self, flags: &KeyFlags)
        -> Result<Key<key::SecretParts, R>>
        where R: key::KeyRole
    {
        use crate::types::Curve;

        match self {
            CipherSuite::RSA2k =>
                Key4::generate_rsa(2048),
            CipherSuite::RSA3k =>
                Key4::generate_rsa(3072),
            CipherSuite::RSA4k =>
                Key4::generate_rsa(4096),
            CipherSuite::Cv25519 | CipherSuite::P256 |
            CipherSuite::P384 | CipherSuite::P521 => {
                let sign = flags.for_certification() || flags.for_signing()
                    || flags.for_authentication();
                let encrypt = flags.for_transport_encryption()
                    || flags.for_storage_encryption();
                let curve = match self {
                    CipherSuite::Cv25519 if sign => Curve::Ed25519,
                    CipherSuite::Cv25519 if encrypt => Curve::Cv25519,
                    CipherSuite::Cv25519 => {
                        return Err(Error::InvalidOperation(
                            "No key flags set".into())
                            .into());
                    }
                    CipherSuite::P256 => Curve::NistP256,
                    CipherSuite::P384 => Curve::NistP384,
                    CipherSuite::P521 => Curve::NistP521,
                    _ => unreachable!(),
                };

                match (sign, encrypt) {
                    (true, false) => Key4::generate_ecc(true, curve),
                    (false, true) => Key4::generate_ecc(false, curve),
                    (true, true) =>
                        Err(Error::InvalidOperation(
                            "Can't use key for encryption and signing".into())
                            .into()),
                    (false, false) =>
                        Err(Error::InvalidOperation(
                            "No key flags set".into())
                            .into()),
                }
            },
        }.map(|key| key.into())
    }
}

#[derive(Clone, Debug)]
pub struct KeyBlueprint {
    flags: KeyFlags,
    expiration: Option<time::SystemTime>,
    // If not None, uses the specified ciphersuite.  Otherwise, uses
    // CertBuilder::ciphersuite.
    ciphersuite: Option<CipherSuite>,
}

/// Simplifies the generation of OpenPGP certificates.
///
/// A builder to generate complex certificate hierarchies with multiple
/// [`UserID`s], [`UserAttribute`s], and [`Key`s].
///
/// This builder does not aim to be as flexible as creating
/// certificates manually, but it should be sufficiently powerful to
/// cover most use cases.
///
/// [`UserID`s]: ../packet/struct.UserID.html
/// [`UserAttribute`s]: ../packet/user_attribute/struct.UserAttribute.html
/// [`Key`s]: ../packet/key/enum.Key.html
///
/// # Examples
///
/// Generate a general-purpose certificate with one User ID:
///
/// ```
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
///
/// # fn main() -> openpgp::Result<()> {
/// let (cert, rev) =
///     CertBuilder::general_purpose(None, Some("alice@example.org"))
///         .generate()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct CertBuilder {
    creation_time: Option<std::time::SystemTime>,
    ciphersuite: CipherSuite,
    primary: KeyBlueprint,
    subkeys: Vec<KeyBlueprint>,
    userids: Vec<packet::UserID>,
    user_attributes: Vec<packet::UserAttribute>,
    password: Option<Password>,
    revocation_keys: Option<Vec<RevocationKey>>,
}

impl CertBuilder {
    /// Returns a new `CertBuilder`.
    ///
    /// The returned builder is configured to generate a minimal
    /// OpenPGP certificate, a certificate with just a
    /// certification-capable primary key.  You'll typically want to
    /// add at least one User ID (using
    /// [`CertBuilder::add_userid`]). and some subkeys (using
    /// [`CertBuilder::add_signing_subkey`],
    /// [`CertBuilder::add_transport_encryption_subkey`], etc.).
    ///
    /// [`CertBuilder::add_signing_subkey`]: #method.add_signing_subkey
    /// [`CertBuilder::add_transport_encryption_subkey`]: #method.add_transport_encryption_subkey
    /// [`CertBuilder::add_userid`]: #method.add_userid
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let (cert, rev) =
    ///     CertBuilder::new()
    ///         .add_userid("Alice Lovelace <alice@lovelace.name>")
    ///         .add_signing_subkey()
    ///         .add_transport_encryption_subkey()
    ///         .add_storage_encryption_subkey()
    ///         .generate()?;
    /// # assert_eq!(cert.keys().count(), 1 + 3);
    /// # assert_eq!(cert.userids().count(), 1);
    /// # assert_eq!(cert.user_attributes().count(), 0);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new() -> Self {
        CertBuilder {
            creation_time: None,
            ciphersuite: CipherSuite::default(),
            primary: KeyBlueprint{
                flags: KeyFlags::default().set_certification(true),
                expiration: None,
                ciphersuite: None,
            },
            subkeys: vec![],
            userids: vec![],
            user_attributes: vec![],
            password: None,
            revocation_keys: None,
        }
    }

    /// Generates a general-purpose certificate.
    ///
    /// The returned builder is set to generate a certificate with a
    /// certification- and signature-capable primary key, and an
    /// encryption-capable subkey.  The subkey is marked as being
    /// appropriate for both data in transit and data at rest.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let (cert, rev) =
    ///     CertBuilder::general_purpose(None,
    ///                                  Some("Alice Lovelace <alice@example.org>"))
    ///         .generate()?;
    /// # assert_eq!(cert.keys().count(), 2);
    /// # assert_eq!(cert.userids().count(), 1);
    /// # Ok(())
    /// # }
    /// ```
    pub fn general_purpose<C, U>(ciphersuite: C, userids: Option<U>) -> Self
        where C: Into<Option<CipherSuite>>,
              U: Into<packet::UserID>
    {
        CertBuilder {
            creation_time: None,
            ciphersuite: ciphersuite.into().unwrap_or(Default::default()),
            primary: KeyBlueprint {
                flags: KeyFlags::default()
                    .set_certification(true)
                    .set_signing(true),
                expiration: Some(
                    time::SystemTime::now()
                        + time::Duration::new(3 * 52 * 7 * 24 * 60 * 60, 0)),
                ciphersuite: None,
            },
            subkeys: vec![
                KeyBlueprint {
                    flags: KeyFlags::default()
                        .set_transport_encryption(true)
                        .set_storage_encryption(true),
                    expiration: None,
                    ciphersuite: None,
                }
            ],
            userids: userids.into_iter().map(|x| x.into()).collect(),
            user_attributes: vec![],
            password: None,
            revocation_keys: None,
        }
    }

    /// Sets the creation time.
    ///
    /// If `creation_time` is `None`, the default, this causes the
    /// `CertBuilder` to use that time when [`CertBuilder::generate`]
    /// is called.
    ///
    /// Warning: this function takes a [`SystemTime`].  A `SystemTime`
    /// has a higher resolution, and a larger range than an OpenPGP
    /// [`Timestamp`].  Assuming the `creation_time` is in range, it
    /// will automatically be truncated to the nearest time that is
    /// representable by a `Timestamp`.  If it is not in range,
    /// [`generate`] will return an error.
    ///
    /// [`CertBuilder::generate`]: #method.generate
    /// [`SystemTime`]: https://doc.rust-lang.org/stable/std/time/struct.SystemTime.html
    /// [`Timestamp`]: ../types/struct.Timestamp.html
    /// [`generate`]: #method.generate
    ///
    /// # Examples
    ///
    /// Generate a backdated certificate:
    ///
    /// ```
    /// use std::time::{SystemTime, Duration};
    /// use std::convert::TryFrom;
    ///
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::types::Timestamp;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let t = SystemTime::now() - Duration::from_secs(365 * 24 * 60 * 60);
    /// // Roundtrip the time so that the assert below works.
    /// let t = SystemTime::from(Timestamp::try_from(t)?);
    ///
    /// let (cert, rev) =
    ///     CertBuilder::general_purpose(None,
    ///                                  Some("Alice Lovelace <alice@example.org>"))
    ///         .set_creation_time(t)
    ///         .generate()?;
    /// assert_eq!(cert.primary_key().self_signatures()[0].signature_creation_time(),
    ///            Some(t));
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_creation_time<T>(mut self, creation_time: T) -> Self
        where T: Into<Option<std::time::SystemTime>>,
    {
        self.creation_time = creation_time.into();
        self
    }

    /// Sets the default asymmetric algorithms.
    ///
    /// This method controls the set of algorithms that is used to
    /// generate the certificate's keys.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::types::PublicKeyAlgorithm;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let (ecc, _) =
    ///     CertBuilder::general_purpose(None, Some("alice@example.org"))
    ///         .set_cipher_suite(CipherSuite::Cv25519)
    ///         .generate()?;
    /// assert_eq!(ecc.primary_key().pk_algo(), PublicKeyAlgorithm::EdDSA);
    ///
    /// let (rsa, _) =
    ///     CertBuilder::general_purpose(None, Some("alice@example.org"))
    ///         .set_cipher_suite(CipherSuite::RSA4k)
    ///         .generate()?;
    /// assert_eq!(rsa.primary_key().pk_algo(), PublicKeyAlgorithm::RSAEncryptSign);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_cipher_suite(mut self, cs: CipherSuite) -> Self {
        self.ciphersuite = cs;
        self
    }

    /// Adds a User ID.
    ///
    /// Adds a User ID to the certificate.  The first User ID that is
    /// added, whether via this interface or another interface, e.g.,
    /// [`CertBuilder::general_purpose`], will have the [primary User
    /// ID flag] set.
    ///
    /// [`CertBuilder::general_purpose`]: #method.general_purpose
    /// [primary User ID flag]: https://tools.ietf.org/html/rfc4880#section-5.2.3.19
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (cert, rev) =
    ///     CertBuilder::general_purpose(None,
    ///                                  Some("Alice Lovelace <alice@example.org>"))
    ///         .add_userid("Alice Lovelace <alice@lovelace.name>")
    ///         .generate()?;
    ///
    /// assert_eq!(cert.userids().count(), 2);
    /// let mut userids = cert.with_policy(p, None)?.userids().collect::<Vec<_>>();
    /// // Sort lexicographically.
    /// userids.sort_by(|a, b| a.value().cmp(b.value()));
    /// assert_eq!(userids[0].userid(),
    ///            &UserID::from("Alice Lovelace <alice@example.org>"));
    /// assert_eq!(userids[1].userid(),
    ///            &UserID::from("Alice Lovelace <alice@lovelace.name>"));
    ///
    ///
    /// assert_eq!(userids[0].binding_signature().primary_userid().unwrap_or(false), true);
    /// assert_eq!(userids[1].binding_signature().primary_userid().unwrap_or(false), false);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_userid<'a, U>(mut self, uid: U) -> Self
        where U: Into<packet::UserID>
    {
        self.userids.push(uid.into());
        self
    }

    /// Adds a new User Attribute.
    ///
    /// Adds a User Attribute to the certificate.  If there are no
    /// User IDs, the first User attribute that is added, whether via
    /// this interface or another interface, will have the [primary
    /// User ID flag] set.
    ///
    /// [primary User ID flag]: https://tools.ietf.org/html/rfc4880#section-5.2.3.19
    ///
    /// # Examples
    ///
    /// When there are no User IDs, the first User Attribute has the
    /// primary User ID flag set:
    ///
    /// ```
    /// # use openpgp::packet::user_attribute::Subpacket;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    /// #
    /// # // Create some user attribute. Doctests do not pass cfg(test),
    /// # // so UserAttribute::arbitrary is not available
    /// # let sp = Subpacket::Unknown(7, vec![7; 7].into_boxed_slice());
    /// # let user_attribute = UserAttribute::new(&[sp])?;
    ///
    /// let (cert, rev) =
    ///     CertBuilder::new()
    ///         .add_user_attribute(user_attribute)
    ///         .generate()?;
    ///
    /// assert_eq!(cert.userids().count(), 0);
    /// assert_eq!(cert.user_attributes().count(), 1);
    /// let mut uas = cert.with_policy(p, None)?.user_attributes().collect::<Vec<_>>();
    /// assert_eq!(uas[0].binding_signature().primary_userid().unwrap_or(false), true);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Where there are User IDs, then the primary User ID flag is not
    /// set:
    ///
    /// ```
    /// # use openpgp::packet::user_attribute::Subpacket;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    /// #
    /// # // Create some user attribute. Doctests do not pass cfg(test),
    /// # // so UserAttribute::arbitrary is not available
    /// # let sp = Subpacket::Unknown(7, vec![7; 7].into_boxed_slice());
    /// # let user_attribute = UserAttribute::new(&[sp])?;
    ///
    /// let (cert, rev) =
    ///     CertBuilder::new()
    ///         .add_userid("alice@example.org")
    ///         .add_user_attribute(user_attribute)
    ///         .generate()?;
    ///
    /// assert_eq!(cert.userids().count(), 1);
    /// assert_eq!(cert.user_attributes().count(), 1);
    /// let mut uas = cert.with_policy(p, None)?.user_attributes().collect::<Vec<_>>();
    /// assert_eq!(uas[0].binding_signature().primary_userid().unwrap_or(false), false);
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_user_attribute<'a, U>(mut self, ua: U) -> Self
        where U: Into<packet::UserAttribute>
    {
        self.user_attributes.push(ua.into());
        self
    }

    /// Adds a signing-capable subkey.
    ///
    /// The key uses the default cipher suite (see
    /// [`CertBuilder::set_cipher_suite`]), and is not set to expire.
    /// Use [`CertBuilder::add_subkey`] if you need to change these
    /// parameters.
    ///
    /// [`CertBuilder::set_cipher_suite`]: #method.set_cipher_suite
    /// [`CertBuilder::add_subkey`]: #method.add_subkey
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (cert, rev) =
    ///     CertBuilder::new()
    ///         .add_signing_subkey()
    ///         .generate()?;
    ///
    /// assert_eq!(cert.keys().count(), 2);
    /// let ka = cert.with_policy(p, None)?.keys().nth(1).unwrap();
    /// assert_eq!(ka.key_flags(),
    ///            Some(KeyFlags::empty().set_signing(true)));
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_signing_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_signing(true), None, None)
    }

    /// Adds a subkey suitable for transport encryption.
    ///
    /// The key uses the default cipher suite (see
    /// [`CertBuilder::set_cipher_suite`]), and is not set to expire.
    /// Use [`CertBuilder::add_subkey`] if you need to change these
    /// parameters.
    ///
    /// [`CertBuilder::set_cipher_suite`]: #method.set_cipher_suite
    /// [`CertBuilder::add_subkey`]: #method.add_subkey
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (cert, rev) =
    ///     CertBuilder::new()
    ///         .add_transport_encryption_subkey()
    ///         .generate()?;
    ///
    /// assert_eq!(cert.keys().count(), 2);
    /// let ka = cert.with_policy(p, None)?.keys().nth(1).unwrap();
    /// assert_eq!(ka.key_flags(),
    ///            Some(KeyFlags::empty().set_transport_encryption(true)));
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_transport_encryption_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_transport_encryption(true),
                        None, None)
    }

    /// Adds a subkey suitable for storage encryption.
    ///
    /// The key uses the default cipher suite (see
    /// [`CertBuilder::set_cipher_suite`]), and is not set to expire.
    /// Use [`CertBuilder::add_subkey`] if you need to change these
    /// parameters.
    ///
    /// [`CertBuilder::set_cipher_suite`]: #method.set_cipher_suite
    /// [`CertBuilder::add_subkey`]: #method.add_subkey
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (cert, rev) =
    ///     CertBuilder::new()
    ///         .add_storage_encryption_subkey()
    ///         .generate()?;
    ///
    /// assert_eq!(cert.keys().count(), 2);
    /// let ka = cert.with_policy(p, None)?.keys().nth(1).unwrap();
    /// assert_eq!(ka.key_flags(),
    ///            Some(KeyFlags::empty().set_storage_encryption(true)));
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_storage_encryption_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_storage_encryption(true),
                        None, None)
    }

    /// Adds an certification-capable subkey.
    ///
    /// The key uses the default cipher suite (see
    /// [`CertBuilder::set_cipher_suite`]), and is not set to expire.
    /// Use [`CertBuilder::add_subkey`] if you need to change these
    /// parameters.
    ///
    /// [`CertBuilder::set_cipher_suite`]: #method.set_cipher_suite
    /// [`CertBuilder::add_subkey`]: #method.add_subkey
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (cert, rev) =
    ///     CertBuilder::new()
    ///         .add_certification_subkey()
    ///         .generate()?;
    ///
    /// assert_eq!(cert.keys().count(), 2);
    /// let ka = cert.with_policy(p, None)?.keys().nth(1).unwrap();
    /// assert_eq!(ka.key_flags(),
    ///            Some(KeyFlags::empty().set_certification(true)));
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_certification_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_certification(true), None, None)
    }

    /// Adds an authentication-capable subkey.
    ///
    /// The key uses the default cipher suite (see
    /// [`CertBuilder::set_cipher_suite`]), and is not set to expire.
    /// Use [`CertBuilder::add_subkey`] if you need to change these
    /// parameters.
    ///
    /// [`CertBuilder::set_cipher_suite`]: #method.set_cipher_suite
    /// [`CertBuilder::add_subkey`]: #method.add_subkey
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (cert, rev) =
    ///     CertBuilder::new()
    ///         .add_authentication_subkey()
    ///         .generate()?;
    ///
    /// assert_eq!(cert.keys().count(), 2);
    /// let ka = cert.with_policy(p, None)?.keys().nth(1).unwrap();
    /// assert_eq!(ka.key_flags(),
    ///            Some(KeyFlags::empty().set_authentication(true)));
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_authentication_subkey(self) -> Self {
        self.add_subkey(KeyFlags::default().set_authentication(true), None, None)
    }

    /// Adds a custom subkey.
    ///
    /// If `expiration` is `None`, the subkey uses the same expiration
    /// time as the primary key.
    ///
    /// Likewise, if `cs` is `None`, the same cipher suite is used as
    /// for the primary key.
    ///
    /// # Examples
    ///
    /// Generates a certificate with an encryption subkey that is for
    /// protecting *both* data in transit and data at rest, and
    /// expires at a different time from the primary key:
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let now = std::time::SystemTime::now();
    /// let y = std::time::Duration::new(365 * 24 * 60 * 60, 0);
    ///
    /// // Make the certificate expire in 2 years, and the subkey
    /// // expire in a year.
    /// let (cert,_) = CertBuilder::new()
    ///     .set_creation_time(now)
    ///     .set_expiration_time(now + 2 * y)
    ///     .add_subkey(KeyFlags::empty()
    ///                     .set_storage_encryption(true)
    ///                     .set_transport_encryption(true),
    ///                 now + y,
    ///                 None)
    ///     .generate()?;
    ///
    /// assert_eq!(cert.with_policy(p, now)?.keys().alive().count(), 2);
    /// assert_eq!(cert.with_policy(p, now + y)?.keys().alive().count(), 1);
    /// assert_eq!(cert.with_policy(p, now + 2 * y)?.keys().alive().count(), 0);
    ///
    /// let ka = cert.with_policy(p, None)?.keys().nth(1).unwrap();
    /// assert_eq!(ka.key_flags(),
    ///            Some(KeyFlags::empty()
    ///                     .set_storage_encryption(true)
    ///                     .set_transport_encryption(true)));
    /// # Ok(()) }
    /// ```
    pub fn add_subkey<T, C>(mut self, flags: KeyFlags, expiration: T, cs: C)
        -> Self
        where T: Into<Option<time::SystemTime>>,
              C: Into<Option<CipherSuite>>,
    {
        self.subkeys.push(KeyBlueprint {
            flags,
            expiration: expiration.into(),
            ciphersuite: cs.into(),
        });
        self
    }

    /// Sets the primary key's key flags.
    ///
    /// By default, the primary key is set to only be certification
    /// capable.  This allows the caller to set additional flags.
    ///
    /// # Examples
    ///
    /// Make the primary key certification and signing capable:
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (cert, rev) =
    ///     CertBuilder::general_purpose(None,
    ///                                  Some("Alice Lovelace <alice@example.org>"))
    ///         .set_primary_key_flags(KeyFlags::empty().set_signing(true))
    ///         .generate()?;
    ///
    /// // Observe that the primary key's certification capability is
    /// // set implicitly.
    /// assert_eq!(cert.with_policy(p, None)?.primary_key().key_flags(),
    ///            Some(KeyFlags::empty().set_signing(true).set_certification(true)));
    /// # Ok(()) }
    /// ```
    pub fn set_primary_key_flags(mut self, flags: KeyFlags) -> Self {
        self.primary.flags = flags;
        self
    }

    /// Sets a password to encrypt the secret keys with.
    ///
    /// The password is used to encrypt all secret key material.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    ///
    /// # fn main() -> Result<()> {
    /// // Make the certificate expire in 10 minutes.
    /// let (cert, rev) =
    ///     CertBuilder::general_purpose(None,
    ///                                  Some("Alice Lovelace <alice@example.org>"))
    ///         .set_password(Some("1234".into()))
    ///         .generate()?;
    ///
    /// for ka in cert.keys() {
    ///     assert!(ka.has_secret());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn set_password(mut self, password: Option<Password>) -> Self {
        self.password = password;
        self
    }

    /// Sets the certificate's expiration time.
    ///
    /// A value of None means never.
    //
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::RevocationKey;
    ///
    /// # fn main() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let now = std::time::SystemTime::now();
    /// let s = std::time::Duration::new(1, 0);
    ///
    /// // Make the certificate expire in 10 minutes.
    /// let (cert,_) = CertBuilder::new()
    ///     .set_creation_time(now)
    ///     .set_expiration_time(now + 600 * s)
    ///     .generate()?;
    ///
    /// assert!(cert.with_policy(p, now)?.primary_key().alive().is_ok());
    /// assert!(cert.with_policy(p, now + 599 * s)?.primary_key().alive().is_ok());
    /// assert!(cert.with_policy(p, now + 600 * s)?.primary_key().alive().is_err());
    /// # Ok(()) }
    /// ```
    pub fn set_expiration_time<T>(mut self, expiration: T) -> Self
        where T: Into<Option<time::SystemTime>>
    {
        self.primary.expiration = expiration.into();
        self
    }

    /// Sets designated revokers.
    ///
    /// Adds designated revokers to the primary key.  This allows the
    /// designated revoker to issue revocation certificates on behalf
    /// of the primary key.
    ///
    /// # Examples
    ///
    /// Make Alice a designated revoker for Bob:
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::RevocationKey;
    ///
    /// # fn main() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (alice, _) =
    ///     CertBuilder::general_purpose(None, Some("alice@example.org"))
    ///         .generate()?;
    /// let (bob, _) =
    ///     CertBuilder::general_purpose(None, Some("bob@example.org"))
    ///         .set_revocation_keys(vec![ (&alice).into() ])
    ///         .generate()?;
    ///
    /// // Make sure Alice is listed as a designated revoker for Bob.
    /// assert_eq!(bob.revocation_keys(p).collect::<Vec<&RevocationKey>>(),
    ///            vec![ &(&alice).into() ]);
    /// # Ok(()) }
    /// ```
    pub fn set_revocation_keys(mut self, revocation_keys: Vec<RevocationKey>)
        -> Self
    {
        self.revocation_keys = Some(revocation_keys);
        self
    }

    /// Generates a certificate.
    ///
    /// # Examples
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::RevocationKey;
    ///
    /// # fn main() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (alice, _) =
    ///     CertBuilder::general_purpose(None, Some("alice@example.org"))
    ///         .generate()?;
    /// # Ok(()) }
    /// ```
    pub fn generate(mut self) -> Result<(Cert, Signature)> {
        use crate::Packet;
        use crate::types::ReasonForRevocation;
        use std::convert::TryFrom;

        let creation_time =
            self.creation_time.unwrap_or_else(std::time::SystemTime::now);

        let mut packets = Vec::<Packet>::with_capacity(
            1 + 1 + self.subkeys.len() + self.userids.len()
                + self.user_attributes.len());

        // make sure the primary key can sign subkeys
        if !self.subkeys.is_empty() {
            self.primary.flags = self.primary.flags.set_certification(true);
        }

        // Generate & self-sign primary key.
        let (primary, sig) = self.primary_key(creation_time)?;
        let mut signer = primary.clone().into_keypair().unwrap();

        packets.push(Packet::SecretKey({
            let mut primary = primary.clone();
            if let Some(ref password) = self.password {
                primary.secret_mut().encrypt_in_place(password)?;
            }
            primary
        }));
        packets.push(sig.clone().into());

        let sig = signature::SignatureBuilder::from(sig.clone())
            .set_signature_creation_time(creation_time)?;

        // Remove subpackets that needn't be copied into the binding
        // signatures.
        let sig = sig.set_revocation_key(vec![])?;

        let mut cert = Cert::try_from(packets)?;

        let have_userids = self.userids.len() > 0;

        // Sign UserIDs.
        for (i, uid) in self.userids.into_iter().enumerate() {
            let mut builder = sig.clone()
                .set_type(SignatureType::PositiveCertification)
                // GnuPG wants at least a 512-bit hash for P521 keys.
                .set_hash_algo(HashAlgorithm::SHA512);
            if i == 0 {
                builder = builder.set_primary_userid(true)?;
            }
            let signature = uid.bind(&mut signer, &cert, builder)?;
            cert = cert.merge_packets(
                vec![Packet::from(uid), signature.into()])?;
        }

        // Sign UserAttributes.
        for (i, ua) in self.user_attributes.into_iter().enumerate() {
            let mut builder = sig.clone()
                .set_type(SignatureType::PositiveCertification)
                 // GnuPG wants at least a 512-bit hash for P521 keys.
                .set_hash_algo(HashAlgorithm::SHA512);
            if i == 0 && ! have_userids {
                builder = builder.set_primary_userid(true)?;
            }
            let signature = ua.bind(&mut signer, &cert, builder)?;
            cert = cert.merge_packets(
                vec![Packet::from(ua), signature.into()])?;
        }

        // sign subkeys
        for blueprint in self.subkeys {
            let flags = &blueprint.flags;
            let mut subkey = blueprint.ciphersuite
                .unwrap_or(self.ciphersuite)
                .generate_key(flags)?;
            subkey.set_creation_time(creation_time)?;

            let mut builder =
                signature::SignatureBuilder::new(SignatureType::SubkeyBinding)
                .set_signature_creation_time(creation_time)?
                // GnuPG wants at least a 512-bit hash for P521 keys.
                .set_hash_algo(HashAlgorithm::SHA512)
                .set_features(&Features::sequoia())?
                .set_key_flags(flags)?
                .set_key_expiration_time(
                    &subkey,
                    blueprint.expiration.or(self.primary.expiration))?;

            if flags.for_transport_encryption() || flags.for_storage_encryption()
            {
                builder = builder.set_preferred_symmetric_algorithms(vec![
                    SymmetricAlgorithm::AES256,
                ])?;
            }

            if flags.for_certification() || flags.for_signing() {
                builder = builder.set_preferred_hash_algorithms(vec![
                    HashAlgorithm::SHA512,
                ])?;

                // We need to create a primary key binding signature.
                let mut subkey_signer = subkey.clone().into_keypair().unwrap();
                let backsig =
                    signature::SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                    .set_signature_creation_time(creation_time)?
                    // GnuPG wants at least a 512-bit hash for P521 keys.
                    .set_hash_algo(HashAlgorithm::SHA512)
                    .sign_primary_key_binding(&mut subkey_signer, &primary,
                                              &subkey)?;
                builder = builder.set_embedded_signature(backsig)?;
            }

            let signature = subkey.bind(&mut signer, &cert, builder)?;

            if let Some(ref password) = self.password {
                subkey.secret_mut().encrypt_in_place(password)?;
            }
            cert = cert.merge_packets(vec![Packet::SecretSubkey(subkey),
                                           signature.into()])?;
        }

        let revocation = CertRevocationBuilder::new()
            .set_signature_creation_time(creation_time)?
            .set_reason_for_revocation(
                ReasonForRevocation::Unspecified, b"Unspecified")?
            .build(&mut signer, &cert, None)?;

        // keys generated by the builder are never invalid
        assert!(cert.bad.is_empty());
        assert!(cert.unknowns.is_empty());

        Ok((cert, revocation))
    }

    fn primary_key(&self, creation_time: std::time::SystemTime)
        -> Result<(key::SecretKey, Signature)>
    {
        let mut key = self.primary.ciphersuite
            .unwrap_or(self.ciphersuite)
            .generate_key(&KeyFlags::default().set_certification(true))?;
        key.set_creation_time(creation_time)?;
        let mut sig = signature::SignatureBuilder::new(SignatureType::DirectKey)
            // GnuPG wants at least a 512-bit hash for P521 keys.
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_features(&Features::sequoia())?
            .set_key_flags(&self.primary.flags)?
            .set_signature_creation_time(creation_time)?
            .set_key_expiration_time(&key, self.primary.expiration)?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;

        if let Some(ref revocation_keys) = self.revocation_keys {
            sig = sig.set_revocation_key(revocation_keys.clone())?;
        }

        let mut signer = key.clone().into_keypair()
            .expect("key generated above has a secret");
        let sig = sig.sign_direct_key(&mut signer, &key)?;

        Ok((key, sig.into()))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::Fingerprint;
    use crate::packet::signature::subpacket::{SubpacketTag, SubpacketValue};
    use crate::types::PublicKeyAlgorithm;
    use crate::policy::StandardPolicy as P;

    #[test]
    fn all_opts() {
        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();

        let mut userids = cert.userids().with_policy(p, None)
            .map(|u| String::from_utf8_lossy(u.userid().value()).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "test1@example.com",
                      "test2@example.com",
                   ][..]);
        assert_eq!(cert.subkeys().count(), 3);
    }

    #[test]
    fn direct_key_sig() {
        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();

        assert_eq!(cert.userids().count(), 0);
        assert_eq!(cert.subkeys().count(), 3);
        let sig =
            cert.primary_key().with_policy(p, None).unwrap().binding_signature();
        assert_eq!(sig.typ(), crate::types::SignatureType::DirectKey);
        assert!(sig.features().unwrap().supports_mdc());
    }

    #[test]
    fn setter() {
        let (cert1, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_cipher_suite(CipherSuite::RSA3k)
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();
        assert_eq!(cert1.primary_key().pk_algo(), PublicKeyAlgorithm::EdDSA);

        let (cert2, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::RSA3k)
            .add_userid("test2@example.com")
            .add_transport_encryption_subkey()
            .generate().unwrap();
        assert_eq!(cert2.primary_key().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
        assert_eq!(cert2.subkeys().next().unwrap().key().pk_algo(),
                   PublicKeyAlgorithm::RSAEncryptSign);
    }

    #[test]
    fn defaults() {
        let p = &P::new();
        let (cert1, _) = CertBuilder::new()
            .add_userid("test2@example.com")
            .generate().unwrap();
        assert_eq!(cert1.primary_key().pk_algo(),
                   PublicKeyAlgorithm::EdDSA);
        assert!(cert1.subkeys().next().is_none());
        assert!(cert1.with_policy(p, None).unwrap().primary_userid().unwrap()
                .binding_signature().features().unwrap().supports_mdc());
    }

    #[test]
    fn always_certify() {
        let p = &P::new();
        let (cert1, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_primary_key_flags(KeyFlags::default())
            .add_transport_encryption_subkey()
            .generate().unwrap();
        assert!(cert1.primary_key().with_policy(p, None).unwrap().for_certification());
        assert_eq!(cert1.keys().subkeys().count(), 1);
    }

    #[test]
    fn gen_wired_subkeys() {
        let (cert1, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_primary_key_flags(KeyFlags::default())
            .add_subkey(KeyFlags::default().set_certification(true), None, None)
            .generate().unwrap();
        let sig_pkts = cert1.subkeys().next().unwrap().bundle().self_signatures[0].hashed_area();

        match sig_pkts.lookup(SubpacketTag::KeyFlags).unwrap().value() {
            SubpacketValue::KeyFlags(ref ks) => assert!(ks.for_certification()),
            v => panic!("Unexpected subpacket: {:?}", v),
        }

        assert_eq!(cert1.subkeys().count(), 1);
    }

    #[test]
    fn generate_revocation_certificate() {
        let p = &P::new();
        use crate::types::RevocationStatus;
        let (cert, revocation) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();
        assert_eq!(cert.revocation_status(p, None),
                   RevocationStatus::NotAsFarAsWeKnow);

        let cert = cert.merge_packets(revocation.clone()).unwrap();
        assert_eq!(cert.revocation_status(p, None),
                   RevocationStatus::Revoked(vec![ &revocation ]));
    }

    #[test]
    fn builder_roundtrip() {
        use std::convert::TryFrom;

        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .generate().unwrap();
        let pile = cert.clone().into_packet_pile().into_children().collect::<Vec<_>>();
        let exp = Cert::try_from(pile).unwrap();

        assert_eq!(cert, exp);
    }

    #[test]
    fn encrypted_secrets() {
        let (cert,_) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_password(Some(String::from("streng geheim").into()))
            .generate().unwrap();
        assert!(cert.primary_key().optional_secret().unwrap().is_encrypted());
    }

    #[test]
    fn all_ciphersuites() {
        use self::CipherSuite::*;

        for cs in vec![Cv25519, RSA3k, P256, P384, P521, RSA2k, RSA4k] {
            assert!(CertBuilder::new()
                .set_cipher_suite(cs)
                .generate().is_ok());
        }
    }

    #[test]
    fn validity_periods() {
        let p = &P::new();

        let now = std::time::SystemTime::now();
        let s = std::time::Duration::new(1, 0);

        let (cert,_) = CertBuilder::new()
            .set_creation_time(now)
            .set_expiration_time(now + 600 * s)
            .add_subkey(KeyFlags::default().set_signing(true),
                        now + 300 * s, None)
            .add_subkey(KeyFlags::default().set_authentication(true),
                        None, None)
            .generate().unwrap();

        let key = cert.primary_key().key();
        let sig = &cert.primary_key().bundle().self_signatures()[0];
        assert!(sig.key_alive(key, now).is_ok());
        assert!(sig.key_alive(key, now + 590 * s).is_ok());
        assert!(! sig.key_alive(key, now + 610 * s).is_ok());

        let ka = cert.keys().with_policy(p, now).alive().revoked(false)
            .for_signing()
            .nth(0).unwrap();
        assert!(ka.alive().is_ok());
        assert!(ka.clone().with_policy(p, now + 290 * s).unwrap().alive().is_ok());
        assert!(! ka.clone().with_policy(p, now + 310 * s).unwrap().alive().is_ok());

        let ka = cert.keys().with_policy(p, now).alive().revoked(false)
            .for_authentication()
            .nth(0).unwrap();
        assert!(ka.alive().is_ok());
        assert!(ka.clone().with_policy(p, now + 590 * s).unwrap().alive().is_ok());
        assert!(! ka.clone().with_policy(p, now + 610 * s).unwrap().alive().is_ok());
    }

    #[test]
    fn creation_time() {
        let p = &P::new();

        use std::time::UNIX_EPOCH;
        let (cert, rev) = CertBuilder::new()
            .set_creation_time(UNIX_EPOCH)
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_userid("foo")
            .add_signing_subkey()
            .generate().unwrap();

        assert_eq!(cert.primary_key().creation_time(), UNIX_EPOCH);
        assert_eq!(cert.primary_key().with_policy(p, None).unwrap()
                   .binding_signature()
                   .signature_creation_time().unwrap(), UNIX_EPOCH);
        assert_eq!(cert.primary_key().with_policy(p, None).unwrap()
                   .direct_key_signature().unwrap()
                   .signature_creation_time().unwrap(), UNIX_EPOCH);
        assert_eq!(rev.signature_creation_time().unwrap(), UNIX_EPOCH);

        // (Sub)Keys.
        assert_eq!(cert.keys().with_policy(p, None).count(), 2);
        for ka in cert.keys().with_policy(p, None) {
            assert_eq!(ka.key().creation_time(), UNIX_EPOCH);
            assert_eq!(ka.binding_signature()
                       .signature_creation_time().unwrap(), UNIX_EPOCH);
        }

        // UserIDs.
        assert_eq!(cert.userids().count(), 1);
        for ui in cert.userids().with_policy(p, None) {
            assert_eq!(ui.binding_signature()
                       .signature_creation_time().unwrap(), UNIX_EPOCH);
        }
    }

    #[test]
    fn designated_revokers() -> Result<()> {
        use std::collections::HashSet;

        let p = &P::new();

        let fpr1 = "C03F A641 1B03 AE12 5764  6118 7223 B566 78E0 2528";
        let fpr2 = "50E6 D924 308D BF22 3CFB  510A C2B8 1905 6C65 2598";
        let revokers = vec![
            RevocationKey::new(PublicKeyAlgorithm::RSAEncryptSign,
                               Fingerprint::from_str(fpr1)?,
                               false),
            RevocationKey::new(PublicKeyAlgorithm::ECDSA,
                               Fingerprint::from_str(fpr2)?,
                               false)
        ];

        let (cert,_)
            = CertBuilder::general_purpose(None, Some("alice@example.org"))
            .set_revocation_keys(revokers.clone())
            .generate()?;
        let cert = cert.with_policy(p, None)?;

        assert_eq!(cert.revocation_keys(p).collect::<HashSet<_>>(),
                   revokers.iter().collect::<HashSet<_>>());

        // The designated revokers on the direct signature should also
        // be returned when querying components for designated
        // revokers.
        assert_eq!(
            cert.primary_key().revocation_keys(p).collect::<HashSet<_>>(),
            revokers.iter().collect::<HashSet<_>>());
        assert_eq!(
            cert.primary_userid()?.revocation_keys(p).collect::<HashSet<_>>(),
            revokers.iter().collect::<HashSet<_>>());


        // Do it again, with a key that has no User IDs.
        let (cert,_) = CertBuilder::new()
            .set_revocation_keys(revokers.clone())
            .generate()?;
        let cert = cert.with_policy(p, None)?;
        assert!(cert.primary_userid().is_err());

        assert_eq!(cert.revocation_keys(p).collect::<HashSet<_>>(),
                   revokers.iter().collect::<HashSet<_>>());

        // The designated revokers on the direct signature should also
        // be returned when querying components for designated
        // revokers.
        assert_eq!(
            cert.primary_key().revocation_keys(p).collect::<HashSet<_>>(),
            revokers.iter().collect::<HashSet<_>>());

        // The designated revokers on all signatures should be
        // considered.
        let now = crate::types::Timestamp::now();
        let then = now.checked_add(crate::types::Duration::days(1)?).unwrap();
        let (cert,_) = CertBuilder::new()
            .set_revocation_keys(revokers.clone())
            .set_creation_time(now)
            .generate()?;

        // Add a newer direct key signature.
        use crate::crypto::hash::Hash;
        let mut hash = HashAlgorithm::SHA512.context()?;
        cert.primary_key().hash(&mut hash);
        let mut primary_signer =
            cert.primary_key().key().clone().parts_into_secret()?
            .into_keypair()?;
        let sig = signature::SignatureBuilder::new(SignatureType::DirectKey)
            .set_signature_creation_time(then)?
            .sign_hash(&mut primary_signer, hash)?;
        let cert = cert.merge_packets(sig)?;

        assert!(cert.with_policy(p, then)?.primary_userid().is_err());
        assert_eq!(cert.revocation_keys(p).collect::<HashSet<_>>(),
                   revokers.iter().collect::<HashSet<_>>());
        Ok(())
    }
}
