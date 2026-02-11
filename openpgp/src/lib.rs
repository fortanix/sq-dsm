//! OpenPGP data types and associated machinery.
//!
//! This crate aims to provide a complete implementation of OpenPGP as
//! defined by [RFC 9580] as well as the deprecated OpenPGP as defined
//! by [RFC 4880].  OpenPGP is a standard by the IETF.  It was derived
//! from the PGP software, which was created by Phil Zimmermann in
//! 1991.
//!
//! This crate also includes support for unbuffered message
//! processing.
//!
//! A few features that the OpenPGP community considers to be
//! deprecated (e.g., version 3 compatibility) have been left out.  We
//! have also updated some OpenPGP defaults to avoid foot guns (e.g.,
//! we selected modern algorithm defaults).  If some functionality is
//! missing, please file a bug report.
//!
//! A non-goal of this crate is support for any sort of high-level,
//! bolted-on functionality.  For instance, [RFC 9580] does not define
//! trust models, such as the web of trust, direct trust, or TOFU.
//! Neither does this crate.  [RFC 9580] does provide some mechanisms
//! for creating trust models (specifically, UserID certifications),
//! and this crate does expose those mechanisms.
//!
//! We also try hard to avoid dictating how OpenPGP should be used.
//! This doesn't mean that we don't have opinions about how OpenPGP
//! should be used in a number of common scenarios (for instance,
//! message validation).  But, in this crate, we refrain from
//! expressing those opinions; we will expose an opinionated,
//! high-level interface in the future.  In order to figure out the
//! most appropriate high-level interfaces, we look at existing users.
//! If you are using Sequoia, please get in contact so that we can
//! learn from your use cases, discuss your opinions, and develop a
//! high-level interface based on these experiences in the future.
//!
//! Despite —or maybe because of— its unopinionated nature we found
//! it easy to develop opinionated OpenPGP software based on Sequoia.
//!
//! [RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
//! [RFC 4880]: https://tools.ietf.org/html/rfc4880
//!
//! # Experimental Features
//!
//! This crate may implement extensions where the standardization
//! effort is still ongoing.  These experimental features are marked
//! as such in the documentation.  We invite you to experiment with
//! them, but please do expect the semantics and possibly even the
//! wire format to evolve.

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]
#![warn(missing_docs)]

// Public re-exports.
//
// We should provide public re-exports for any crate defining types
// that we use in our public API.  This allows downstream consumers to
// name the types without explicitly depending on the third-party
// crates, and provides the correct version of the crates.
pub use anyhow;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

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

/// Like `Vec<u8>::resize`, but fast in debug builds.
fn vec_resize(v: &mut Vec<u8>, new_size: usize) {
    if v.len() < new_size {
        v.resize(new_size, 0);
    } else {
        vec_truncate(v, new_size);
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

/// Like std::time::SystemTime::now, but works on WASM.
fn now() -> std::time::SystemTime {
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))] {
        chrono::Utc::now().into()
    }
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] {
        std::time::SystemTime::now()
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
        assert_match!($error = $expr, $fmt, )
    };
    ( $error: pat = $expr: expr ) => {
        assert_match!($error = $expr, "")
    };
}

#[macro_use]
pub mod armor;
pub mod fmt;
pub mod crypto;

pub mod packet;
#[doc(inline)]
pub use packet::Packet;
use crate::packet::key;

pub mod parse;

pub mod cert;
#[doc(inline)]
pub use cert::Cert;
pub mod serialize;

mod packet_pile;
pub use packet_pile::PacketPile;
pub mod message;
#[doc(inline)]
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
pub mod regex;
pub mod policy;

pub(crate) mod seal;
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

/// The version of this crate.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Profiles select versions of the OpenPGP standard.
///
/// While this type implements [`Default`], please consider what a
/// good default for your use case is.
///
/// If you are doing a greenfield implementation where you know that
/// every client understands RFC9580, you can just explicitly pick
/// that.
///
/// Otherwise, you have to consider the state of the ecosystem your
/// client will interact with.  Maybe it is better to stick to
/// generating RFC4880 certificates for the time being, while rolling
/// out RFC9580 support.  Consider adding a configuration option or
/// command line switch like `--profile`, but pick a sensible default,
/// and remember to don't overwhelm your users.
///
/// For now, our default is RFC4880.  This is a safe default for every
/// downstream consumer that has existing legacy deployments
/// (including their own previous versions using a legacy version of
/// Sequoia).  We will update this default once RFC9580 is more widely
/// deployed.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// RFC9580, published in 2024, defines "v6" OpenPGP.
    RFC9580,

    /// RFC4880, published in 2007, defines "v4" OpenPGP.
    #[default]
    RFC4880,
}

/// Crate result specialization.
pub type Result<T> = ::std::result::Result<T, anyhow::Error>;

/// Errors used in this crate.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
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
    UnsupportedCert(String, Vec<Packet>),

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

    /// No hash algorithm found that would be accepted by all signers.
    #[error("No acceptable hash")]
    NoAcceptableHash,

    /// The operation is not allowed, because it violates the policy.
    ///
    /// The optional time is the time at which the operation was
    /// determined to no longer be secure.
    #[error("{} is not considered secure{}",
            .0,
            .1.as_ref().map(|t| {
                if *t == std::time::UNIX_EPOCH {
                    "".to_string()
                } else {
                    format!(" since {}", crate::fmt::time(t))
                }
            })
            .unwrap_or_else(|| "".into()))]
    PolicyViolation(String, Option<std::time::SystemTime>),

    /// Short key IDs are insecure, and not supported.
    #[error("Short key IDs are insecure, and not supported: {0}")]
    ShortKeyID(String),
}

assert_send_and_sync!(Error);

/// Provide a helper function that generates an arbitrary value from a given
/// range.  Quickcheck > 1 does not re-export rand so we need to implement this
/// ourselves.
#[cfg(test)]
mod arbitrary_helper {
    use quickcheck::{Arbitrary, Gen};

    pub(crate) fn gen_arbitrary_from_range<T>(
        range: std::ops::Range<T>,
        g: &mut Gen,
    ) -> T
    where
        T: Arbitrary
            + std::cmp::PartialOrd
            + std::ops::Sub<Output = T>
            + std::ops::Rem<Output = T>
            + std::ops::Add<Output = T>
            + Copy,
    {
        if !range.is_empty() {
            let m = range.end - range.start;
            // The % operator calculates the remainder, which is negative for
            // negative inputs, not the modulus.  This actually calculates the
            // modulus by making sure the result is positive.  The primitive
            // integer types implement .rem_euclid for that, but there is no way
            // to constrain this function to primitive types.
            range.start + (T::arbitrary(g) % m + m) % m
        } else {
            panic!()
        }
    }

    pub(crate) fn arbitrary_slice<T>(g: &mut Gen, s: &mut [T])
    where
        T: Arbitrary,
    {
        s.iter_mut().for_each(|p| *p = Arbitrary::arbitrary(g));
    }

    pub(crate) fn arbitrary_bounded_vec<T>(g: &mut Gen, limit: usize) -> Vec<T>
    where
        T: Arbitrary + Default,
    {
        let mut v = vec![Default::default();
                         gen_arbitrary_from_range(0..limit, g)];
        arbitrary_slice(g, &mut v[..]);
        v
    }
}
