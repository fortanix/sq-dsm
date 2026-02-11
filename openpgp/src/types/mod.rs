//! Primitive types.
//!
//! This module provides types used in OpenPGP, like enumerations
//! describing algorithms.
//!
//! # Common Operations
//!
//!  - *Rounding the creation time of signatures*: See the [`Timestamp::round_down`] method.
//!  - *Checking key usage flags*: See the [`KeyFlags`] data structure.
//!  - *Setting key validity ranges*: See the [`Timestamp`] and [`Duration`] data structures.
//!
//! # Data structures
//!
//! ## `CompressionLevel`
//!
//! Allows adjusting the amount of effort spent on compressing encoded data.
//! This structure additionally has several helper methods for commonly used
//! compression strategies.
//!
//! ## `Features`
//!
//! Describes particular features supported by the given OpenPGP implementation.
//!
//! ## `KeyFlags`
//!
//! Holds information about a key in particular how the given key can be used.
//!
//! ## `RevocationKey`
//!
//! Describes a key that has been designated to issue revocation signatures.
//!
//! # `KeyServerPreferences`
//!
//! Describes preferences regarding to key servers.
//!
//! ## `Timestamp` and `Duration`
//!
//! In OpenPGP time is represented as the number of seconds since the UNIX epoch stored
//! as an `u32`. These two data structures allow manipulating OpenPGP time ensuring
//! that adding or subtracting durations will never overflow or underflow without
//! notice.
//!
//! [`Timestamp::round_down`]: Timestamp::round_down()

use std::fmt;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

mod bitfield;
pub use bitfield::Bitfield;
mod compression_level;
pub use compression_level::CompressionLevel;
mod features;
pub use self::features::Features;
mod key_flags;
pub use self::key_flags::KeyFlags;
mod revocation_key;
pub use revocation_key::RevocationKey;
mod server_preferences;
pub use self::server_preferences::KeyServerPreferences;
mod timestamp;
pub use timestamp::{Timestamp, Duration};
pub(crate) use timestamp::normalize_systemtime;

#[allow(dead_code)] // Used in assert_send_and_sync.
pub(crate) trait Sendable : Send {}
#[allow(dead_code)] // Used in assert_send_and_sync.
pub(crate) trait Syncable : Sync {}

pub use crate::crypto::AEADAlgorithm;
pub use crate::crypto::Curve;
pub use crate::crypto::HashAlgorithm;
pub use crate::crypto::PublicKeyAlgorithm;
pub use crate::crypto::SymmetricAlgorithm;

/// The OpenPGP compression algorithms as defined in [Section 9.4 of RFC 9580].
///
///   [Section 9.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.4
///
/// # Examples
///
/// Use `CompressionAlgorithm` to set the preferred compressions algorithms on
/// a signature:
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// use openpgp::packet::signature::SignatureBuilder;
/// use openpgp::types::{HashAlgorithm, CompressionAlgorithm, SignatureType};
///
/// # fn main() -> openpgp::Result<()> {
/// let mut builder = SignatureBuilder::new(SignatureType::DirectKey)
///     .set_hash_algo(HashAlgorithm::SHA512)
///     .set_preferred_compression_algorithms(vec![
///         CompressionAlgorithm::Zlib,
///         CompressionAlgorithm::BZip2,
///     ])?;
/// # Ok(()) }
#[non_exhaustive]
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum CompressionAlgorithm {
    /// Null compression.
    Uncompressed,
    /// DEFLATE Compressed Data.
    ///
    /// See [RFC 1951] for details.  [Section 9.4 of RFC 9580]
    /// recommends that this algorithm should be implemented.
    ///
    /// [RFC 1951]: https://tools.ietf.org/html/rfc1951
    /// [Section 9.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.4
    Zip,
    /// ZLIB Compressed Data.
    ///
    /// See [RFC 1950] for details.
    ///
    /// [RFC 1950]: https://tools.ietf.org/html/rfc1950
    Zlib,
    /// bzip2
    BZip2,
    /// Private compression algorithm identifier.
    Private(u8),
    /// Unknown compression algorithm identifier.
    Unknown(u8),
}
assert_send_and_sync!(CompressionAlgorithm);

const COMPRESSION_ALGORITHM_VARIANTS: [CompressionAlgorithm; 4] = [
    CompressionAlgorithm::Uncompressed,
    CompressionAlgorithm::Zip,
    CompressionAlgorithm::Zlib,
    CompressionAlgorithm::BZip2,
];

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        use self::CompressionAlgorithm::*;
        #[cfg(feature = "compression-deflate")]
        { Zip }
        #[cfg(all(feature = "compression-bzip2",
                  not(feature = "compression-deflate")))]
        { BZip2 }
        #[cfg(all(not(feature = "compression-bzip2"),
                  not(feature = "compression-deflate")))]
        { Uncompressed }
    }
}

impl CompressionAlgorithm {
    /// Returns whether this algorithm is supported.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::CompressionAlgorithm;
    ///
    /// assert!(CompressionAlgorithm::Uncompressed.is_supported());
    ///
    /// assert!(!CompressionAlgorithm::Private(101).is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        use self::CompressionAlgorithm::*;
        match &self {
            Uncompressed => true,
            #[cfg(feature = "compression-deflate")]
            Zip | Zlib => true,
            #[cfg(feature = "compression-bzip2")]
            BZip2 => true,
            _ => false,
        }
    }

    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`CompressionAlgorithm::Private`], or
    /// [`CompressionAlgorithm::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        COMPRESSION_ALGORITHM_VARIANTS.iter().cloned()
    }
}

impl From<u8> for CompressionAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            0 => CompressionAlgorithm::Uncompressed,
            1 => CompressionAlgorithm::Zip,
            2 => CompressionAlgorithm::Zlib,
            3 => CompressionAlgorithm::BZip2,
            100..=110 => CompressionAlgorithm::Private(u),
            u => CompressionAlgorithm::Unknown(u),
        }
    }
}

impl From<CompressionAlgorithm> for u8 {
    fn from(c: CompressionAlgorithm) -> u8 {
        match c {
            CompressionAlgorithm::Uncompressed => 0,
            CompressionAlgorithm::Zip => 1,
            CompressionAlgorithm::Zlib => 2,
            CompressionAlgorithm::BZip2 => 3,
            CompressionAlgorithm::Private(u) => u,
            CompressionAlgorithm::Unknown(u) => u,
        }
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CompressionAlgorithm::Uncompressed => f.write_str("Uncompressed"),
            CompressionAlgorithm::Zip => f.write_str("ZIP"),
            CompressionAlgorithm::Zlib => f.write_str("ZLIB"),
            CompressionAlgorithm::BZip2 => f.write_str("BZip2"),
            CompressionAlgorithm::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental compression algorithm {}", u)),
            CompressionAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown compression algorithm {}", u)),
        }
    }
}

#[cfg(test)]
impl Arbitrary for CompressionAlgorithm {
    fn arbitrary(g: &mut Gen) -> Self {
        u8::arbitrary(g).into()
    }
}

/// Signature type as defined in [Section 5.2.1 of RFC 9580].
///
///   [Section 5.2.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.1
///
/// # Examples
///
/// Use `SignatureType` to create a timestamp signature:
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// use std::time::SystemTime;
/// use openpgp::packet::signature::SignatureBuilder;
/// use openpgp::types::SignatureType;
///
/// # fn main() -> openpgp::Result<()> {
/// let mut builder = SignatureBuilder::new(SignatureType::Timestamp)
///     .set_signature_creation_time(SystemTime::now())?;
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SignatureType {
    /// Signature over a binary document.
    Binary,
    /// Signature over a canonical text document.
    Text,
    /// Standalone signature.
    Standalone,

    /// Generic certification of a User ID and Public-Key packet.
    GenericCertification,
    /// Persona certification of a User ID and Public-Key packet.
    PersonaCertification,
    /// Casual certification of a User ID and Public-Key packet.
    CasualCertification,
    /// Positive certification of a User ID and Public-Key packet.
    PositiveCertification,

    /// Certification Approval Key Signature (experimental).
    ///
    /// Allows the certificate owner to attest to third party
    /// certifications. See [Certification Approval Key Signature] for
    /// details.
    ///
    ///   [Certification Approval Key Signature]: https://www.ietf.org/archive/id/draft-dkg-openpgp-1pa3pc-02.html#name-certification-approval-key-
    CertificationApproval,

    /// Subkey Binding Signature
    SubkeyBinding,
    /// Primary Key Binding Signature
    PrimaryKeyBinding,
    /// Signature directly on a key
    DirectKey,

    /// Key revocation signature
    KeyRevocation,
    /// Subkey revocation signature
    SubkeyRevocation,
    /// Certification revocation signature
    CertificationRevocation,

    /// Timestamp signature.
    Timestamp,
    /// Third-Party Confirmation signature.
    Confirmation,

    /// Catchall.
    Unknown(u8),
}
assert_send_and_sync!(SignatureType);

const SIGNATURE_TYPE_VARIANTS: [SignatureType; 16] = [
    SignatureType::Binary,
    SignatureType::Text,
    SignatureType::Standalone,
    SignatureType::GenericCertification,
    SignatureType::PersonaCertification,
    SignatureType::CasualCertification,
    SignatureType::PositiveCertification,
    SignatureType::CertificationApproval,
    SignatureType::SubkeyBinding,
    SignatureType::PrimaryKeyBinding,
    SignatureType::DirectKey,
    SignatureType::KeyRevocation,
    SignatureType::SubkeyRevocation,
    SignatureType::CertificationRevocation,
    SignatureType::Timestamp,
    SignatureType::Confirmation,
];

impl From<u8> for SignatureType {
    fn from(u: u8) -> Self {
        match u {
            0x00 => SignatureType::Binary,
            0x01 => SignatureType::Text,
            0x02 => SignatureType::Standalone,
            0x10 => SignatureType::GenericCertification,
            0x11 => SignatureType::PersonaCertification,
            0x12 => SignatureType::CasualCertification,
            0x13 => SignatureType::PositiveCertification,
            0x16 => SignatureType::CertificationApproval,
            0x18 => SignatureType::SubkeyBinding,
            0x19 => SignatureType::PrimaryKeyBinding,
            0x1f => SignatureType::DirectKey,
            0x20 => SignatureType::KeyRevocation,
            0x28 => SignatureType::SubkeyRevocation,
            0x30 => SignatureType::CertificationRevocation,
            0x40 => SignatureType::Timestamp,
            0x50 => SignatureType::Confirmation,
            _ => SignatureType::Unknown(u),
        }
    }
}

impl From<SignatureType> for u8 {
    fn from(t: SignatureType) -> Self {
        match t {
            SignatureType::Binary => 0x00,
            SignatureType::Text => 0x01,
            SignatureType::Standalone => 0x02,
            SignatureType::GenericCertification => 0x10,
            SignatureType::PersonaCertification => 0x11,
            SignatureType::CasualCertification => 0x12,
            SignatureType::PositiveCertification => 0x13,
            SignatureType::CertificationApproval => 0x16,
            SignatureType::SubkeyBinding => 0x18,
            SignatureType::PrimaryKeyBinding => 0x19,
            SignatureType::DirectKey => 0x1f,
            SignatureType::KeyRevocation => 0x20,
            SignatureType::SubkeyRevocation => 0x28,
            SignatureType::CertificationRevocation => 0x30,
            SignatureType::Timestamp => 0x40,
            SignatureType::Confirmation => 0x50,
            SignatureType::Unknown(u) => u,
        }
    }
}

impl fmt::Display for SignatureType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SignatureType::Binary =>
                f.write_str("Binary"),
            SignatureType::Text =>
                f.write_str("Text"),
            SignatureType::Standalone =>
                f.write_str("Standalone"),
            SignatureType::GenericCertification =>
                f.write_str("GenericCertification"),
            SignatureType::PersonaCertification =>
                f.write_str("PersonaCertification"),
            SignatureType::CasualCertification =>
                f.write_str("CasualCertification"),
            SignatureType::PositiveCertification =>
                f.write_str("PositiveCertification"),
            SignatureType::CertificationApproval =>
                f.write_str("CertificationApproval"),
            SignatureType::SubkeyBinding =>
                f.write_str("SubkeyBinding"),
            SignatureType::PrimaryKeyBinding =>
                f.write_str("PrimaryKeyBinding"),
            SignatureType::DirectKey =>
                f.write_str("DirectKey"),
            SignatureType::KeyRevocation =>
                f.write_str("KeyRevocation"),
            SignatureType::SubkeyRevocation =>
                f.write_str("SubkeyRevocation"),
            SignatureType::CertificationRevocation =>
                f.write_str("CertificationRevocation"),
            SignatureType::Timestamp =>
                f.write_str("Timestamp"),
            SignatureType::Confirmation =>
                f.write_str("Confirmation"),
            SignatureType::Unknown(u) =>
                f.write_fmt(format_args!("Unknown signature type 0x{:x}", u)),
        }
    }
}

#[cfg(test)]
impl Arbitrary for SignatureType {
    fn arbitrary(g: &mut Gen) -> Self {
        u8::arbitrary(g).into()
    }
}

impl SignatureType {
    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`SignatureType::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        SIGNATURE_TYPE_VARIANTS.iter().cloned()
    }
}

/// Describes the reason for a revocation.
///
/// See the description of revocation subpackets [Section 5.2.3.31 of RFC 9580].
///
///   [Section 5.2.3.31 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.31
///
/// # Examples
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::policy::StandardPolicy;
/// use openpgp::types::{RevocationStatus, ReasonForRevocation, SignatureType};
///
/// # fn main() -> openpgp::Result<()> {
/// let p = &StandardPolicy::new();
///
/// // A certificate with a User ID.
/// let (cert, _) = CertBuilder::new()
///     .add_userid("Alice <alice@example.org>")
///     .generate()?;
///
/// let mut keypair = cert.primary_key().key().clone()
///     .parts_into_secret()?.into_keypair()?;
/// let ca = cert.userids().nth(0).unwrap();
///
/// // Generate the revocation for the first and only UserID.
/// let revocation =
///     UserIDRevocationBuilder::new()
///     .set_reason_for_revocation(
///         ReasonForRevocation::UIDRetired,
///         b"Left example.org.")?
///     .build(&mut keypair, &cert, ca.userid(), None)?;
/// assert_eq!(revocation.typ(), SignatureType::CertificationRevocation);
///
/// // Now merge the revocation signature into the Cert.
/// let cert = cert.insert_packets(revocation.clone())?;
///
/// // Check that it is revoked.
/// let ca = cert.0.userids().nth(0).unwrap();
/// let status = ca.with_policy(p, None)?.revocation_status();
/// if let RevocationStatus::Revoked(revs) = status {
///     assert_eq!(revs.len(), 1);
///     let rev = revs[0];
///
///     assert_eq!(rev.typ(), SignatureType::CertificationRevocation);
///     assert_eq!(rev.reason_for_revocation(),
///                Some((ReasonForRevocation::UIDRetired,
///                      "Left example.org.".as_bytes())));
///    // User ID has been revoked.
/// }
/// # else { unreachable!(); }
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum ReasonForRevocation {
    /// No reason specified (key revocations or cert revocations)
    Unspecified,

    /// Key is superseded (key revocations)
    KeySuperseded,

    /// Key material has been compromised (key revocations)
    KeyCompromised,

    /// Key is retired and no longer used (key revocations)
    KeyRetired,

    /// User ID information is no longer valid (cert revocations)
    UIDRetired,

    /// Private reason identifier.
    Private(u8),

    /// Unknown reason identifier.
    Unknown(u8),
}
assert_send_and_sync!(ReasonForRevocation);

const REASON_FOR_REVOCATION_VARIANTS: [ReasonForRevocation; 5] = [
    ReasonForRevocation::Unspecified,
    ReasonForRevocation::KeySuperseded,
    ReasonForRevocation::KeyCompromised,
    ReasonForRevocation::KeyRetired,
    ReasonForRevocation::UIDRetired,
];

impl From<u8> for ReasonForRevocation {
    fn from(u: u8) -> Self {
        use self::ReasonForRevocation::*;
        match u {
            0 => Unspecified,
            1 => KeySuperseded,
            2 => KeyCompromised,
            3 => KeyRetired,
            32 => UIDRetired,
            100..=110 => Private(u),
            u => Unknown(u),
        }
    }
}

impl From<ReasonForRevocation> for u8 {
    fn from(r: ReasonForRevocation) -> u8 {
        use self::ReasonForRevocation::*;
        match r {
            Unspecified => 0,
            KeySuperseded => 1,
            KeyCompromised => 2,
            KeyRetired => 3,
            UIDRetired => 32,
            Private(u) => u,
            Unknown(u) => u,
        }
    }
}

impl fmt::Display for ReasonForRevocation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ReasonForRevocation::*;
        match *self {
            Unspecified =>
                f.write_str("No reason specified"),
            KeySuperseded =>
                f.write_str("Key is superseded"),
            KeyCompromised =>
                f.write_str("Key material has been compromised"),
            KeyRetired =>
                f.write_str("Key is retired and no longer used"),
            UIDRetired =>
                f.write_str("User ID information is no longer valid"),
            Private(u) =>
                f.write_fmt(format_args!(
                    "Private/Experimental revocation reason {}", u)),
            Unknown(u) =>
                f.write_fmt(format_args!(
                    "Unknown revocation reason {}", u)),
        }
    }
}

#[cfg(test)]
impl Arbitrary for ReasonForRevocation {
    fn arbitrary(g: &mut Gen) -> Self {
        u8::arbitrary(g).into()
    }
}

/// Describes whether a `ReasonForRevocation` should be consider hard
/// or soft.
///
/// A hard revocation is a revocation that indicates that the key was
/// somehow compromised, and the provenance of *all* artifacts should
/// be called into question.
///
/// A soft revocation is a revocation that indicates that the key
/// should be considered invalid *after* the revocation signature's
/// creation time.  `KeySuperseded`, `KeyRetired`, and `UIDRetired`
/// are considered soft revocations.
///
/// # Examples
///
/// A certificate is considered to be revoked when a hard revocation is present
/// even if it is not live at the specified time.
///
/// Here, a certificate is generated at `t0` and then revoked later at `t2`.
/// At `t1` (`t0` < `t1` < `t2`) depending on the revocation type it will be
/// either considered revoked (hard revocation) or not revoked (soft revocation):
///
/// ```rust
/// # use sequoia_openpgp as openpgp;
/// use std::time::{Duration, SystemTime};
/// use openpgp::cert::prelude::*;
/// use openpgp::types::{RevocationStatus, ReasonForRevocation};
/// use openpgp::policy::StandardPolicy;
///
/// # fn main() -> openpgp::Result<()> {
/// let p = &StandardPolicy::new();
///
/// let t0 = SystemTime::now();
/// let (cert, _) =
///     CertBuilder::general_purpose(Some("alice@example.org"))
///     .set_creation_time(t0)
///     .generate()?;
///
/// let t2 = t0 + Duration::from_secs(3600);
///
/// let mut signer = cert.primary_key().key().clone()
///     .parts_into_secret()?.into_keypair()?;
///
/// // Create a hard revocation (KeyCompromised):
/// let sig = CertRevocationBuilder::new()
///     .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
///                                b"The butler did it :/")?
///     .set_signature_creation_time(t2)?
///     .build(&mut signer, &cert, None)?;
///
/// let t1 = t0 + Duration::from_secs(1200);
/// let cert1 = cert.clone().insert_packets(sig.clone())?.0;
/// assert_eq!(cert1.revocation_status(p, Some(t1)),
///            RevocationStatus::Revoked(vec![&sig.into()]));
///
/// // Create a soft revocation (KeySuperseded):
/// let sig = CertRevocationBuilder::new()
///     .set_reason_for_revocation(ReasonForRevocation::KeySuperseded,
///                                b"Migrated to key XYZ")?
///     .set_signature_creation_time(t2)?
///     .build(&mut signer, &cert, None)?;
///
/// let t1 = t0 + Duration::from_secs(1200);
/// let cert2 = cert.clone().insert_packets(sig.clone())?.0;
/// assert_eq!(cert2.revocation_status(p, Some(t1)),
///            RevocationStatus::NotAsFarAsWeKnow);
/// #     Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationType {
    /// A hard revocation.
    ///
    /// Artifacts stemming from the revoked object should not be
    /// trusted.
    Hard,
    /// A soft revocation.
    ///
    /// Artifacts stemming from the revoked object *after* the
    /// revocation time should not be trusted.  Earlier objects should
    /// be considered okay.
    ///
    /// Only `KeySuperseded`, `KeyRetired`, and `UIDRetired` are
    /// considered soft revocations.  All other reasons for
    /// revocations including unknown reasons are considered hard
    /// revocations.
    Soft,
}
assert_send_and_sync!(RevocationType);

impl ReasonForRevocation {
    /// Returns the revocation's `RevocationType`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::{ReasonForRevocation, RevocationType};
    ///
    /// assert_eq!(ReasonForRevocation::KeyCompromised.revocation_type(), RevocationType::Hard);
    /// assert_eq!(ReasonForRevocation::Private(101).revocation_type(), RevocationType::Hard);
    ///
    /// assert_eq!(ReasonForRevocation::KeyRetired.revocation_type(), RevocationType::Soft);
    /// ```
    pub fn revocation_type(&self) -> RevocationType {
        match self {
            ReasonForRevocation::Unspecified => RevocationType::Hard,
            ReasonForRevocation::KeySuperseded => RevocationType::Soft,
            ReasonForRevocation::KeyCompromised => RevocationType::Hard,
            ReasonForRevocation::KeyRetired => RevocationType::Soft,
            ReasonForRevocation::UIDRetired => RevocationType::Soft,
            ReasonForRevocation::Private(_) => RevocationType::Hard,
            ReasonForRevocation::Unknown(_) => RevocationType::Hard,
        }
    }

    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`ReasonForRevocation::Private`] or
    /// [`ReasonForRevocation::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        REASON_FOR_REVOCATION_VARIANTS.iter().cloned()
    }
}

/// Describes the format of the body of a literal data packet.
///
/// See the description of literal data packets [Section 5.9 of RFC 9580].
///
///   [Section 5.9 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.9
///
/// # Examples
///
/// Construct a new [`Message`] containing one text literal packet:
///
/// [`Message`]: crate::Message
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// use std::convert::TryFrom;
/// use openpgp::packet::prelude::*;
/// use openpgp::types::DataFormat;
/// use openpgp::message::Message;
///
/// let mut packets = Vec::new();
/// let mut lit = Literal::new(DataFormat::Unicode);
/// lit.set_body(b"data".to_vec());
/// packets.push(lit.into());
///
/// let message = Message::try_from(packets);
/// assert!(message.is_ok(), "{:?}", message);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum DataFormat {
    /// Binary data.
    ///
    /// This is a hint that the content is probably binary data.
    Binary,

    /// Text data, probably valid UTF-8.
    ///
    /// This is a hint that the content is probably UTF-8 encoded.
    Unicode,

    /// Text data.
    ///
    /// This is a hint that the content is probably text; the encoding
    /// is not specified.
    #[deprecated(note = "Use Dataformat::Unicode instead.")]
    Text,

    /// Unknown format specifier.
    Unknown(u8),
}
assert_send_and_sync!(DataFormat);

#[allow(deprecated)]
const DATA_FORMAT_VARIANTS: [DataFormat; 3] = [
    DataFormat::Binary,
    DataFormat::Text,
    DataFormat::Unicode,
];

impl Default for DataFormat {
    fn default() -> Self {
        DataFormat::Binary
    }
}

impl From<u8> for DataFormat {
    fn from(u: u8) -> Self {
        #[allow(deprecated)]
        match u {
            b'b' => DataFormat::Binary,
            b'u' => DataFormat::Unicode,
            b't' => DataFormat::Text,
            _ => DataFormat::Unknown(u),
        }
    }
}

impl From<DataFormat> for u8 {
    fn from(f: DataFormat) -> u8 {
        use self::DataFormat::*;
        match f {
            Binary => b'b',
            Unicode => b'u',
            #[allow(deprecated)]
            Text => b't',
            Unknown(c) => c,
        }
    }
}

impl fmt::Display for DataFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DataFormat::*;
        match *self {
            Binary =>
                f.write_str("Binary data"),
            #[allow(deprecated)]
            Text =>
                f.write_str("Text data"),
            Unicode =>
                f.write_str("Text data (UTF-8)"),
            Unknown(c) =>
                f.write_fmt(format_args!(
                    "Unknown data format identifier {:?}", c)),
        }
    }
}

#[cfg(test)]
impl Arbitrary for DataFormat {
    fn arbitrary(g: &mut Gen) -> Self {
        u8::arbitrary(g).into()
    }
}

impl DataFormat {
    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`DataFormat::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        DATA_FORMAT_VARIANTS.iter().cloned()
    }
}

/// The revocation status.
///
/// # Examples
///
/// Generates a new certificate then checks if the User ID is revoked or not under
/// the given policy using [`ValidUserIDAmalgamation`]:
///
/// [`ValidUserIDAmalgamation`]: crate::cert::amalgamation::ValidUserIDAmalgamation
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::policy::StandardPolicy;
/// use openpgp::types::RevocationStatus;
///
/// # fn main() -> openpgp::Result<()> {
/// let p = &StandardPolicy::new();
///
/// let (cert, _) =
///     CertBuilder::general_purpose(Some("alice@example.org"))
///     .generate()?;
/// let cert = cert.with_policy(p, None)?;
/// let ua = cert.userids().nth(0).expect("User IDs");
///
/// match ua.revocation_status() {
///     RevocationStatus::Revoked(revs) => {
///         // The certificate holder revoked the User ID.
/// #       unreachable!();
///     }
///     RevocationStatus::CouldBe(revs) => {
///         // There are third-party revocations.  You still need
///         // to check that they are valid (this is necessary,
///         // because without the Certificates are not normally
///         // available to Sequoia).
/// #       unreachable!();
///     }
///     RevocationStatus::NotAsFarAsWeKnow => {
///         // We have no evidence that the User ID is revoked.
///     }
/// }
/// #     Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus<'a> {
    /// The key is definitely revoked.
    ///
    /// The relevant self-revocations are returned.
    Revoked(Vec<&'a crate::packet::Signature>),
    /// There is a revocation certificate from a possible designated
    /// revoker.
    CouldBe(Vec<&'a crate::packet::Signature>),
    /// The key does not appear to be revoked.
    ///
    /// An attacker could still have performed a DoS, which prevents
    /// us from seeing the revocation certificate.
    NotAsFarAsWeKnow,
}
assert_send_and_sync!(RevocationStatus<'_>);

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn comp_roundtrip(comp: CompressionAlgorithm) -> bool {
            let val: u8 = comp.into();
            comp == CompressionAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn comp_display(comp: CompressionAlgorithm) -> bool {
            let s = format!("{}", comp);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn comp_parse(comp: CompressionAlgorithm) -> bool {
            match comp {
                CompressionAlgorithm::Unknown(u) => u > 110 || (u > 3 && u < 100),
                CompressionAlgorithm::Private(u) => (100..=110).contains(&u),
                _ => true
            }
        }
    }


    quickcheck! {
        fn signature_type_roundtrip(t: SignatureType) -> bool {
            let val: u8 = t.into();
            t == SignatureType::from(val)
        }
    }

    quickcheck! {
        fn signature_type_display(t: SignatureType) -> bool {
            let s = format!("{}", t);
            !s.is_empty()
        }
    }


    quickcheck! {
        fn rfr_roundtrip(rfr: ReasonForRevocation) -> bool {
            let val: u8 = rfr.into();
            rfr == ReasonForRevocation::from(val)
        }
    }

    quickcheck! {
        fn rfr_display(rfr: ReasonForRevocation) -> bool {
            let s = format!("{}", rfr);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn rfr_parse(rfr: ReasonForRevocation) -> bool {
            match rfr {
                ReasonForRevocation::Unknown(u) =>
                    (u > 3 && u < 32)
                    || (u > 32 && u < 100)
                    || u > 110,
                ReasonForRevocation::Private(u) =>
                    (100..=110).contains(&u),
                _ => true
            }
        }
    }

    quickcheck! {
        fn df_roundtrip(df: DataFormat) -> bool {
            let val: u8 = df.into();
            df == DataFormat::from(val)
        }
    }

    quickcheck! {
        fn df_display(df: DataFormat) -> bool {
            let s = format!("{}", df);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn df_parse(df: DataFormat) -> bool {
            match df {
                DataFormat::Unknown(u) =>
                    u != b'b' && u != b't' && u != b'u',
                _ => true
            }
        }
    }

    #[test]
    fn compression_algorithms_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // COMPRESSION_ALGORITHM_VARIANTS is a list.  Derive it in a
        // different way to double check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(CompressionAlgorithm::from)
            .filter(|t| {
                match t {
                    CompressionAlgorithm::Private(_) => false,
                    CompressionAlgorithm::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(COMPRESSION_ALGORITHM_VARIANTS
                                 .iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }

    #[test]
    fn signature_types_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // SIGNATURE_TYPE_VARIANTS is a list.  Derive it in a
        // different way to double check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(SignatureType::from)
            .filter(|t| {
                match t {
                    SignatureType::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(SIGNATURE_TYPE_VARIANTS
                                 .iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }

    #[test]
    fn reason_for_revocation_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // REASON_FOR_REVOCATION_VARIANTS is a list.  Derive it in a
        // different way to double check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(ReasonForRevocation::from)
            .filter(|t| {
                match t {
                    ReasonForRevocation::Private(_) => false,
                    ReasonForRevocation::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(REASON_FOR_REVOCATION_VARIANTS
                                 .iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }

    #[test]
    fn data_format_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // DATA_FORMAT_VARIANTS is a list.  Derive it in a different
        // way to double check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(DataFormat::from)
            .filter(|t| {
                match t {
                    DataFormat::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(DATA_FORMAT_VARIANTS
                                 .iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }
}
