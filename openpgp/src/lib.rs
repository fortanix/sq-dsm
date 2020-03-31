//! OpenPGP data types and associated machinery.
//!
//! This crate aims to provide a complete implementation of OpenPGP as
//! defined by [RFC 4880] as well as some extensions (e.g., [RFC
//! 6637], which describes ECC cryptography for OpenPGP.  This
//! includes support for unbuffered message processing.
//!
//! A few features that the OpenPGP community considers to be
//! deprecated (e.g., version 3 compatibility) have been left out.  We
//! have also updated some OpenPGP defaults to avoid foot guns (e.g.,
//! we selected modern algorithm defaults).  If some functionality is
//! missing, please file a bug report.
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
//! [sequoia-core]: ../sequoia_core
//!
//! # Experimental Features
//!
//! This crate implements functionality from [RFC 4880bis], notable
//! AEAD encryption containers.  As of this writing, this RFC is still
//! a draft and the syntax or semantic defined in it may change or go
//! away.  Therefore, all related functionality may change and
//! artifacts created using this functionality may not be usable in
//! the future.  Do not use it for things other than experiments.
//!
//! [RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-08

#![warn(missing_docs)]

extern crate lalrpop_util;

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
    ( $error: pat = $expr:expr, $fmt:expr, $($pargs:expr),* ) => {{
        let x = $expr;
        if let $error = x {
            /* Pass.  */
        } else {
            let extra = format!($fmt, $($pargs),*);
            panic!("Expected {}, got {:?}{}{}",
                   stringify!($error), x,
                   if $fmt.len() > 0 { ": " } else { "." }, extra);
        }
    }};
    ( $error: pat = $expr: expr, $fmt:expr ) => {
        assert_match!($error = $expr, $fmt, );
    };
    ( $error: pat = $expr: expr ) => {
        assert_match!($error = $expr, "");
    };
}

#[macro_use]
pub mod armor;
pub mod fmt;
pub mod crypto;

pub mod packet;
pub use packet::Packet;
use crate::packet::key;

pub mod parse;

pub mod cert;
pub use cert::Cert;
pub mod serialize;

mod packet_pile;
pub use packet_pile::PacketPile;
pub mod message;
pub use message::Message;

pub mod types;
use crate::types::{
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
    HashAlgorithm,
    SignatureType,
};

mod fingerprint;
pub use fingerprint::Fingerprint;
mod keyid;
pub use keyid::KeyID;
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
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

#[derive(thiserror::Error, Debug, Clone)]
/// Errors returned by this module.
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
pub enum Error {
    /// Invalid argument.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Invalid operation.
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// A malformed packet.
    #[error("Malformed packet: {0}")]
    MalformedPacket(String),

    /// Packet size exceeds the configured limit.
    #[error("{} Packet ({} bytes) exceeds limit of {} bytes",
           _0, _1, _2)]
    PacketTooLarge(packet::Tag, u32, u32),

    /// Unsupported packet type.
    #[error("Unsupported packet type.  Tag: {0}")]
    UnsupportedPacketType(packet::Tag),

    /// Unsupported hash algorithm identifier.
    #[error("Unsupported hash algorithm: {0}")]
    UnsupportedHashAlgorithm(HashAlgorithm),

    /// Unsupported public key algorithm identifier.
    #[error("Unsupported public key algorithm: {0}")]
    UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm),

    /// Unsupported elliptic curve ASN.1 OID.
    #[error("Unsupported elliptic curve: {0}")]
    UnsupportedEllipticCurve(types::Curve),

    /// Unsupported symmetric key algorithm.
    #[error("Unsupported symmetric algorithm: {0}")]
    UnsupportedSymmetricAlgorithm(SymmetricAlgorithm),

    /// Unsupported AEAD algorithm.
    #[error("Unsupported AEAD algorithm: {0}")]
    UnsupportedAEADAlgorithm(types::AEADAlgorithm),

    /// Unsupported Compression algorithm.
    #[error("Unsupported Compression algorithm: {0}")]
    UnsupportedCompressionAlgorithm(types::CompressionAlgorithm),

    /// Unsupported signature type.
    #[error("Unsupported signature type: {0}")]
    UnsupportedSignatureType(SignatureType),

    /// Invalid password.
    #[error("Invalid password")]
    InvalidPassword,

    /// Invalid session key.
    #[error("Invalid session key: {0}")]
    InvalidSessionKey(String),

    /// Missing session key.
    #[error("Missing session key: {0}")]
    MissingSessionKey(String),

    /// Malformed MPI.
    #[error("Malformed MPI: {0}")]
    MalformedMPI(String),

    /// Bad signature.
    #[error("Bad signature: {0}")]
    BadSignature(String),

    /// Message has been manipulated.
    #[error("Message has been manipulated")]
    ManipulatedMessage,

    /// Malformed message.
    #[error("Malformed Message: {0}")]
    MalformedMessage(String),

    /// Malformed certificate.
    #[error("Malformed Cert: {0}")]
    MalformedCert(String),

    /// Unsupported Cert.
    ///
    /// This usually occurs, because the primary key is in an
    /// unsupported format.  In particular, Sequoia does not support
    /// version 3 keys.
    #[error("Unsupported Cert: {0}")]
    UnsupportedCert(String),

    /// Index out of range.
    #[error("Index out of range")]
    IndexOutOfRange,

    /// Expired.
    #[error("Expired on {}", crate::fmt::time(.0))]
    Expired(std::time::SystemTime),

    /// Not yet live.
    #[error("Not live until {}", crate::fmt::time(.0))]
    NotYetLive(std::time::SystemTime),

    /// No binding signature.
    #[error("No binding signature at time {}", crate::fmt::time(.0))]
    NoBindingSignature(std::time::SystemTime),

    /// Invalid key.
    #[error("Invalid key: {0:?}")]
    InvalidKey(String),

    /// The operation is not allowed, because it violates the policy.
    ///
    /// The optional time is the time at which the operation was
    /// determined to no longer be secure.
    #[error("{0} is not considered secure{}",
            .1.as_ref().map(|t| format!(" since {}", crate::fmt::time(t)))
            .unwrap_or("".into()))]
    PolicyViolation(String, Option<std::time::SystemTime>),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] #[error("__Nonexhaustive")] __Nonexhaustive,
}
