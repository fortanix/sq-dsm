//! OpenPGP data types and associated machinery.
//!
//! This crate aims to provide a complete implementation of OpenPGP as
//! defined by [RFC 4880] as well as several extensions (e.g., [RFC
//! 6637], which describes ECC cryptography for OpenPGP, and [RFC
//! 4880bis], the draft of the next OpenPGP standard).  This includes
//! support for unbuffered message processing.
//!
//! A few features that the OpenPGP community considers to be
//! deprecated (e.g., version 3 compatibility) have been left out as
//! well as support for functionality that we consider to be not only
//! completely useless, but also dangerous (e.g., support for
//! [unhashed signature subpackets]).  We have also updated some
//! OpenPGP defaults to avoid foot guns (e.g., this crate does not
//! fallback to IDEA, but instead assumes all OpenPGP implementations
//! understand AES).  If some functionality is missing, please file a
//! bug report.
//!
//! A non-goal of this crate is support for any sort of high-level,
//! bolted-on functionality.  For instance, [RFC 4880] does not define
//! trust models, such as the web of trust, direct trust, or TOFU.
//! Neither does this crate.  [RFC 4880] does provide some mechanisms
//! for creating trust models (specifically, UserID certifications),
//! and this crate does expose those mechanisms.
//!
//! We also try hard to avoid dictating how OpenPGP should be used.
//! This doesn't mean that we don't have opinions about how OpenPGP
//! should be used in a number of common scenarios (for instance,
//! message validation).  But, in this crate, we refrain from
//! expressing those opinions; we expose an opinionated, high-level
//! interface in the [sequoia-core] and related crates.  In our
//! opinion, you should generally use those crates instead of this
//! one.
//!
//! [RFC 4880]: https://tools.ietf.org/html/rfc4880
//! [RFC 6637]: https://tools.ietf.org/html/rfc6637
//! [RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05
//! [unhashed signature subpackets]: https://tools.ietf.org/html/rfc4880#section-5.2.3.2
//! [sequoia-core]: ../sequoia_core

#![warn(missing_docs)]

extern crate lalrpop_util;

#[macro_use]
extern crate failure;

extern crate buffered_reader;

extern crate memsec;
extern crate nettle;

#[cfg(feature = "compression-deflate")]
extern crate flate2;
#[cfg(feature = "compression-bzip2")]
extern crate bzip2;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[cfg(not(test))]
extern crate quickcheck;

extern crate rand;

#[macro_use] extern crate lazy_static;

extern crate idna;

#[macro_use]
mod macros;

// On debug builds, Vec<u8>::truncate is very, very slow.  For
// instance, running the decrypt_test_stream test takes 51 seconds on
// my (Neal's) computer using Vec<u8>::truncate and <0.1 seconds using
// `unsafe { v.set_len(len); }`.
//
// The issue is that the compiler calls drop on every element that is
// dropped, even though a u8 doesn't have a drop implementation.  The
// compiler optimizes this away at high optimization levels, but those
// levels make debugging harder.
fn vec_truncate(v: &mut Vec<u8>, len: usize) {
    if cfg!(debug_assertions) {
        if len < v.len() {
            unsafe { v.set_len(len); }
        }
    } else {
        v.truncate(len);
    }
}

/// Like `drop(Vec<u8>::drain(..prefix_len))`, but fast in debug
/// builds.
fn vec_drain_prefix(v: &mut Vec<u8>, prefix_len: usize) {
    if cfg!(debug_assertions) {
        // Panic like v.drain(..prefix_len).
        assert!(prefix_len <= v.len(), "prefix len {} > vector len {}",
                prefix_len, v.len());
        let new_len = v.len() - prefix_len;
        unsafe {
            std::ptr::copy(v[prefix_len..].as_ptr(),
                           v[..].as_mut_ptr(),
                           new_len);
        }
        vec_truncate(v, new_len);
    } else {
        v.drain(..prefix_len);
    }
}

// Like assert!, but checks a pattern.
//
//   assert_match!(Some(_) = x);
//
// Note: For modules to see this macro, we need to define it before we
// declare the modules.
#[allow(unused_macros)]
macro_rules! assert_match {
    ( $error: pat = $expr:expr, $fmt:expr, $($pargs:expr),* ) => {
        let x = $expr;
        if let $error = x {
            /* Pass.  */
        } else {
            let extra = format!($fmt, $($pargs),*);
            panic!("Expected {}, got {:?}{}{}",
                   stringify!($error), x,
                   if $fmt.len() > 0 { ": " } else { "." }, extra);
        }
    };
    ( $error: pat = $expr: expr, $fmt:expr ) => {
        assert_match!($error = $expr, $fmt, );
    };
    ( $error: pat = $expr: expr ) => {
        assert_match!($error = $expr, "");
    };
}

#[macro_use]
pub mod armor;
pub mod autocrypt;
pub mod fmt;
pub mod crypto;

pub mod packet;
use crate::packet::{Container, key};

pub mod parse;

pub mod cert;
pub use cert::Cert;
pub mod serialize;

mod packet_pile;
pub mod message;

pub mod types;
use crate::types::{
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
    HashAlgorithm,
    SignatureType,
};

mod fingerprint;
mod keyid;
mod keyhandle;
pub use keyhandle::KeyHandle;
pub mod policy;

pub(crate) mod utils;

#[cfg(test)]
mod tests;

/// Returns a timestamp for the tests.
///
/// The time is chosen to that the subkeys in
/// openpgp/tests/data/keys/neal.pgp are not expired.
#[cfg(test)]
fn frozen_time() -> std::time::SystemTime {
    crate::types::Timestamp::from(1554542220 - 1).into()
}

/// Crate result specialization.
pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Fail, Debug, Clone)]
/// Errors returned by this module.
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
pub enum Error {
    /// Invalid argument.
    #[fail(display = "Invalid argument: {}", _0)]
    InvalidArgument(String),

    /// Invalid operation.
    #[fail(display = "Invalid operation: {}", _0)]
    InvalidOperation(String),

    /// A malformed packet.
    #[fail(display = "Malformed packet: {}", _0)]
    MalformedPacket(String),

    /// Packet size exceeds the configured limit.
    #[fail(display = "{} Packet ({} bytes) exceeds limit of {} bytes",
           _0, _1, _2)]
    PacketTooLarge(packet::Tag, u32, u32),

    /// Unsupported packet type.
    #[fail(display = "Unsupported packet type.  Tag: {}", _0)]
    UnsupportedPacketType(packet::Tag),

    /// Unsupported hash algorithm identifier.
    #[fail(display = "Unsupported hash algorithm: {}", _0)]
    UnsupportedHashAlgorithm(HashAlgorithm),

    /// Unsupported public key algorithm identifier.
    #[fail(display = "Unsupported public key algorithm: {}", _0)]
    UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm),

    /// Unsupported elliptic curve ASN.1 OID.
    #[fail(display = "Unsupported elliptic curve: {}", _0)]
    UnsupportedEllipticCurve(types::Curve),

    /// Unsupported symmetric key algorithm.
    #[fail(display = "Unsupported symmetric algorithm: {}", _0)]
    UnsupportedSymmetricAlgorithm(SymmetricAlgorithm),

    /// Unsupported AEAD algorithm.
    #[fail(display = "Unsupported AEAD algorithm: {}", _0)]
    UnsupportedAEADAlgorithm(types::AEADAlgorithm),

    /// Unsupported Compression algorithm.
    #[fail(display = "Unsupported Compression algorithm: {}", _0)]
    UnsupportedCompressionAlgorithm(types::CompressionAlgorithm),

    /// Unsupported signature type.
    #[fail(display = "Unsupported signature type: {}", _0)]
    UnsupportedSignatureType(SignatureType),

    /// Invalid password.
    #[fail(display = "Invalid password")]
    InvalidPassword,

    /// Invalid session key.
    #[fail(display = "Invalid session key: {}", _0)]
    InvalidSessionKey(String),

    /// Missing session key.
    #[fail(display = "Missing session key: {}", _0)]
    MissingSessionKey(String),

    /// Malformed MPI.
    #[fail(display = "Malformed MPI: {}", _0)]
    MalformedMPI(String),

    /// Bad signature.
    #[fail(display = "Bad signature: {}", _0)]
    BadSignature(String),

    /// Message has been manipulated.
    #[fail(display = "Message has been manipulated")]
    ManipulatedMessage,

    /// Malformed message.
    #[fail(display = "Malformed Message: {}", _0)]
    MalformedMessage(String),

    /// Malformed certificate.
    #[fail(display = "Malformed Cert: {}", _0)]
    MalformedCert(String),

    /// Unsupported Cert.
    ///
    /// This usually occurs, because the primary key is in an
    /// unsupported format.  In particular, Sequoia does not support
    /// version 3 keys.
    #[fail(display = "Unsupported Cert: {}", _0)]
    UnsupportedCert(String),

    /// Index out of range.
    #[fail(display = "Index out of range")]
    IndexOutOfRange,

    /// Expired.
    #[fail(display = "Expired on {:?}", _0)]
    Expired(std::time::SystemTime),

    /// Not yet live.
    #[fail(display = "Not live until {:?}", _0)]
    NotYetLive(std::time::SystemTime),

    /// No binding signature.
    #[fail(display = "No binding signature at time {:?}", _0)]
    NoBindingSignature(std::time::SystemTime),

    /// Invalid key.
    #[fail(display = "Invalid key: {:?}", _0)]
    InvalidKey(String),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] #[fail(display = "__Nonexhaustive")] __Nonexhaustive,
}

/// The OpenPGP packets that Sequoia understands.
///
/// The different OpenPGP packets are detailed in [Section 5 of RFC 4880].
///
/// The `Unknown` packet allows Sequoia to deal with packets that it
/// doesn't understand.  The `Unknown` packet is basically a binary
/// blob that includes the packet's tag.
///
/// The unknown packet is also used for packets that are understood,
/// but use unsupported options.  For instance, when the packet parser
/// encounters a compressed data packet with an unknown compression
/// algorithm, it returns the packet in an `Unknown` packet rather
/// than a `CompressedData` packet.
///
///   [Section 5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[derive(Debug)]
#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Packet {
    /// Unknown packet.
    Unknown(packet::Unknown),
    /// Signature packet.
    Signature(packet::Signature),
    /// One pass signature packet.
    OnePassSig(packet::OnePassSig),
    /// Public key packet.
    PublicKey(packet::key::PublicKey),
    /// Public subkey packet.
    PublicSubkey(packet::key::PublicSubkey),
    /// Public/Secret key pair.
    SecretKey(packet::key::SecretKey),
    /// Public/Secret subkey pair.
    SecretSubkey(packet::key::SecretSubkey),
    /// Marker packet.
    Marker(packet::Marker),
    /// Trust packet.
    Trust(packet::Trust),
    /// User ID packet.
    UserID(packet::UserID),
    /// User attribute packet.
    UserAttribute(packet::UserAttribute),
    /// Literal data packet.
    Literal(packet::Literal),
    /// Compressed literal data packet.
    CompressedData(packet::CompressedData),
    /// Public key encrypted data packet.
    PKESK(packet::PKESK),
    /// Symmetric key encrypted data packet.
    SKESK(packet::SKESK),
    /// Symmetric key encrypted, integrity protected data packet.
    SEIP(packet::SEIP),
    /// Modification detection code packet.
    MDC(packet::MDC),
    /// AEAD Encrypted Data Packet.
    AED(packet::AED),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Packet {
    /// Returns the `Packet's` corresponding OpenPGP tag.
    ///
    /// Tags are explained in [Section 4.3 of RFC 4880].
    ///
    ///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
    pub fn tag(&self) -> packet::Tag {
        use crate::packet::Tag;
        match self {
            &Packet::Unknown(ref packet) => packet.tag(),
            &Packet::Signature(_) => Tag::Signature,
            &Packet::OnePassSig(_) => Tag::OnePassSig,
            &Packet::PublicKey(_) => Tag::PublicKey,
            &Packet::PublicSubkey(_) => Tag::PublicSubkey,
            &Packet::SecretKey(_) => Tag::SecretKey,
            &Packet::SecretSubkey(_) => Tag::SecretSubkey,
            &Packet::Marker(_) => Tag::Marker,
            &Packet::Trust(_) => Tag::Trust,
            &Packet::UserID(_) => Tag::UserID,
            &Packet::UserAttribute(_) => Tag::UserAttribute,
            &Packet::Literal(_) => Tag::Literal,
            &Packet::CompressedData(_) => Tag::CompressedData,
            &Packet::PKESK(_) => Tag::PKESK,
            &Packet::SKESK(_) => Tag::SKESK,
            &Packet::SEIP(_) => Tag::SEIP,
            &Packet::MDC(_) => Tag::MDC,
            &Packet::AED(_) => Tag::AED,
            Packet::__Nonexhaustive => unreachable!(),
        }
    }

    /// Returns the parsed `Packet's` corresponding OpenPGP tag.
    ///
    /// Returns the packets tag, but only if it was successfully
    /// parsed into the corresponding packet type.  If e.g. a
    /// Signature Packet uses some unsupported methods, it is parsed
    /// into an `Packet::Unknown`.  `tag()` returns `Tag::Signature`,
    /// whereas `kind()` returns `None`.
    pub fn kind(&self) -> Option<packet::Tag> {
        use crate::packet::Tag;
        match self {
            &Packet::Unknown(_) => None,
            &Packet::Signature(_) => Some(Tag::Signature),
            &Packet::OnePassSig(_) => Some(Tag::OnePassSig),
            &Packet::PublicKey(_) => Some(Tag::PublicKey),
            &Packet::PublicSubkey(_) => Some(Tag::PublicSubkey),
            &Packet::SecretKey(_) => Some(Tag::SecretKey),
            &Packet::SecretSubkey(_) => Some(Tag::SecretSubkey),
            &Packet::Marker(_) => Some(Tag::Marker),
            &Packet::Trust(_) => Some(Tag::Trust),
            &Packet::UserID(_) => Some(Tag::UserID),
            &Packet::UserAttribute(_) => Some(Tag::UserAttribute),
            &Packet::Literal(_) => Some(Tag::Literal),
            &Packet::CompressedData(_) => Some(Tag::CompressedData),
            &Packet::PKESK(_) => Some(Tag::PKESK),
            &Packet::SKESK(_) => Some(Tag::SKESK),
            &Packet::SEIP(_) => Some(Tag::SEIP),
            &Packet::MDC(_) => Some(Tag::MDC),
            &Packet::AED(_) => Some(Tag::AED),
            Packet::__Nonexhaustive => unreachable!(),
        }
    }
}

/// A `PacketPile` holds a deserialized sequence of OpenPGP messages.
///
/// To deserialize an OpenPGP usage, use either [`PacketParser`],
/// [`PacketPileParser`], or [`PacketPile::from_file`] (or related
/// routines).
///
/// Normally, you'll want to convert the `PacketPile` to a Cert or a
/// `Message`.
///
///   [`PacketParser`]: parse/struct.PacketParser.html
///   [`PacketPileParser`]: parse/struct.PacketPileParser.html
///   [`PacketPile::from_file`]: struct.PacketPile.html#method.from_file
#[derive(PartialEq, Clone)]
pub struct PacketPile {
    /// At the top level, we have a sequence of packets, which may be
    /// containers.
    top_level: Container,
}

/// An OpenPGP message.
///
/// An OpenPGP message is a structured sequence of OpenPGP packets.
/// Basically, it's an optionally encrypted, optionally signed literal
/// data packet.  The exact structure is defined in [Section 11.3 of RFC
/// 4880].
///
///   [Section 11.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-11.3
#[derive(PartialEq)]
pub struct Message {
    /// A message is just a validated packet pile.
    pile: PacketPile,
}

/// Holds a fingerprint.
///
/// A fingerprint uniquely identifies a public key.  For more details
/// about how a fingerprint is generated, see [Section 12.2 of RFC
/// 4880].
///
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum Fingerprint {
    /// 20 byte SHA-1 hash.
    V4([u8;20]),
    /// Used for holding fingerprints that we don't understand.  For
    /// instance, we don't grok v3 fingerprints.  And, it is possible
    /// that the Issuer subpacket contains the wrong number of bytes.
    Invalid(Box<[u8]>)
}

/// Holds a KeyID.
///
/// A KeyID is a fingerprint fragment.  It identifies a public key,
/// but is easy to forge.  For more details about how a KeyID is
/// generated, see [Section 12.2 of RFC 4880].
///
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum KeyID {
    /// Lower 8 byte SHA-1 hash.
    V4([u8;8]),
    /// Used for holding fingerprints that we don't understand.  For
    /// instance, we don't grok v3 fingerprints.  And, it is possible
    /// that the Issuer subpacket contains the wrong number of bytes.
    Invalid(Box<[u8]>)
}

/// The revocation status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus<'a> {
    /// The key is definitely revoked.
    ///
    /// The relevant self-revocations are returned.
    Revoked(Vec<&'a packet::Signature>),
    /// There is a revocation certificate from a possible designated
    /// revoker.
    CouldBe(Vec<&'a packet::Signature>),
    /// The key does not appear to be revoked.
    ///
    /// An attacker could still have performed a DoS, which prevents
    /// us from seeing the revocation certificate.
    NotAsFarAsWeKnow,
}
