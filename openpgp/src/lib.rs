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
//! [RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04
//! [unhashed signature subpackets]: https://tools.ietf.org/html/rfc4880#section-5.2.3.2
//! [sequoia-core]: ../sequoia_core

#![warn(missing_docs)]

#[macro_use]
extern crate failure;

extern crate buffered_reader;

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

extern crate time;

pub mod armor;
pub mod autocrypt;

pub mod ctb;
use ctb::{CTB, CTBOld, CTBNew};

pub mod conversions;

pub mod packet;
use packet::{BodyLength, Header, Container};
pub mod subpacket;

pub mod parse;
pub mod mpis;

pub mod tpk;
pub mod serialize;

mod hash;
pub mod symmetric;

pub mod s2k;

mod unknown;
mod signature;
pub use signature::Signature;
mod one_pass_sig;
mod key;
pub use key::SecretKey;
mod userid;
mod user_attribute;
mod literal;
mod compressed_data;
mod skesk;
pub use skesk::SKESK;
pub(crate) mod ecdh;
mod pkesk;
pub use pkesk::PKESK;
mod reader;
pub use reader::Reader;

mod packet_pile;
mod message;

pub mod constants;
use constants::{
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
    CompressionAlgorithm,
    HashAlgorithm,
    SignatureType,
};
mod tag;
use tag::Tag;

mod fingerprint;
mod keyid;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
        .iter().collect()
}

/// Crate result specialization.
pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Fail, Debug)]
/// Errors returned by this module.
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

    /// Unknown packet tag.
    #[fail(display = "Unknown packet type: {}", _0)]
    UnknownPacketTag(Tag),

    /// Unknown hash algorithm identifier.
    #[fail(display = "Unknown hash algorithm: {}", _0)]
    UnknownHashAlgorithm(HashAlgorithm),

    /// Unknown public key algorithm identifier.
    #[fail(display = "Unknown public key algorithm: {}", _0)]
    UnknownPublicKeyAlgorithm(PublicKeyAlgorithm),

    /// Unknown symmetric algorithm identifier.
    #[fail(display = "Unknown symmetric algorithm: {}", _0)]
    UnknownSymmetricAlgorithm(SymmetricAlgorithm),

    /// Unsupported hash algorithm identifier.
    #[fail(display = "Unsupported hash algorithm: {}", _0)]
    UnsupportedHashAlgorithm(HashAlgorithm),

    /// Unsupported public key algorithm identifier.
    #[fail(display = "Unsupported public key algorithm: {}", _0)]
    UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm),

    /// Unsupported elliptic curve ASN.1 OID.
    #[fail(display = "Unsupported elliptic curve: {}", _0)]
    UnsupportedEllipticCurve(constants::Curve),

    /// Unsupported symmetric key algorithm.
    #[fail(display = "Unsupported symmetric algorithm: {}", _0)]
    UnsupportedSymmetricAlgorithm(SymmetricAlgorithm),

    /// Unsupported signature type.
    #[fail(display = "Unsupported signature type: {}", _0)]
    UnsupportedSignatureType(SignatureType),

    /// Invalid password.
    #[fail(display = "Invalid password")]
    InvalidPassword,

    /// Invalid session key.
    #[fail(display = "Invalid session key: {}", _0)]
    InvalidSessionKey(String),

    /// Malformed MPI.
    #[fail(display = "Malformed MPI: {}", _0)]
    MalformedMPI(String),

    /// Bad signature.
    #[fail(display = "Bad signature: {}", _0)]
    BadSignature(String),

    /// Malformed message.
    #[fail(display = "Malformed Message: {}", _0)]
    MalformedMessage(String),

    /// Malformed tranferable public key.
    #[fail(display = "Malformed TPK: {}", _0)]
    MalformedTPK(String),

    /// Index out of range.
    #[fail(display = "Index out of range")]
    IndexOutOfRange,
}

/// A helpful debugging function.
#[allow(dead_code)]
fn to_hex(s: &[u8], pretty: bool) -> String {
    use std::fmt::Write;

    let mut result = String::new();
    for (i, b) in s.iter().enumerate() {
        // Add spaces every four digits to make the output more
        // readable.
        if pretty && i > 0 && i % 2 == 0 {
            write!(&mut result, " ").unwrap();
        }
        write!(&mut result, "{:02X}", b).unwrap();
    }
    result
}

/// A helpful function for converting a hexadecimal string to binary.
/// This function skips whitespace if `skip_whipspace` is set.
fn from_hex(hex: &str, skip_whitespace: bool) -> Option<Vec<u8>> {
    let nibbles = hex.as_bytes().iter().filter_map(|x| {
        match *x as char {
            '0' => Some(0u8),
            '1' => Some(1u8),
            '2' => Some(2u8),
            '3' => Some(3u8),
            '4' => Some(4u8),
            '5' => Some(5u8),
            '6' => Some(6u8),
            '7' => Some(7u8),
            '8' => Some(8u8),
            '9' => Some(9u8),
            'a' | 'A' => Some(10u8),
            'b' | 'B' => Some(11u8),
            'c' | 'C' => Some(12u8),
            'd' | 'D' => Some(13u8),
            'e' | 'E' => Some(14u8),
            'f' | 'F' => Some(15u8),
            ' ' if skip_whitespace => None,
            _ => Some(255u8),
        }
    }).collect::<Vec<u8>>();

    if nibbles.iter().any(|&b| b == 255u8) {
        // Not a hex character.
        return None;
    }

    // We need an even number of nibbles.
    if nibbles.len() % 2 != 0 {
        return None;
    }

    let bytes = nibbles.chunks(2).map(|nibbles| {
        (nibbles[0] << 4) | nibbles[1]
    }).collect::<Vec<u8>>();

    Some(bytes)
}

/// Holds an unknown packet.
///
/// This is used by the parser to hold packets that it doesn't know
/// how to process rather than abort.
///
/// This packet effectively holds a binary blob.
#[derive(PartialEq, Clone, Debug)]
pub struct Unknown {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// Packet tag.
    pub tag: Tag,
}

/// Holds a one-pass signature packet.
///
/// See [Section 5.4 of RFC 4880] for details.
///
///   [Section 5.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.4
#[derive(Clone)]
pub struct OnePassSig {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// One-pass-signature packet version. Must be 3.
    pub version: u8,
    /// Type of the signature.
    pub sigtype: SignatureType,
    /// Hash algorithm used to compute the signature.
    pub hash_algo: HashAlgorithm,
    /// Public key algorithm of this signature.
    pub pk_algo: PublicKeyAlgorithm,
    /// Key ID of the signing key.
    pub issuer: KeyID,
    /// A one-octet number holding a flag showing whether the signature
    /// is nested.
    pub last: u8,
}

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// See [Section 5.5 of RFC 4880] for details.
///
///   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
#[derive(PartialEq, Clone)]
pub struct Key {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// Version of the key packet. Must be 4.
    pub version: u8,
    /// When the key was created.
    pub creation_time: time::Tm,
    /// Public key algorithm of this signature.
    pub pk_algo: PublicKeyAlgorithm,
    /// Public key MPIs. Must be a *PublicKey variant.
    pub mpis: mpis::MPIs,
    /// Optional secret part of the key.
    pub secret: Option<SecretKey>,
}

/// Holds a UserID packet.
///
/// See [Section 5.11 of RFC 4880] for details.
///
///   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
#[derive(PartialEq, Clone)]
pub struct UserID {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// The user id.
    ///
    /// According to [RFC 4880], the text is by convention UTF-8 encoded
    /// and in "mail name-addr" form, i.e., "Name (Comment)
    /// <email@example.com>".
    ///
    ///   [RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
    ///
    /// Use `UserID::default()` to get a UserID with a default settings.
    pub value: Vec<u8>,
}

/// Holds a UserAttribute packet.
///
/// See [Section 5.12 of RFC 4880] for details.
///
///   [Section 5.12 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.12
#[derive(PartialEq, Clone)]
pub struct UserAttribute {
    /// CTB packet header fields.
    pub common: packet::Common,

    /// The user attribute.
    pub value: Vec<u8>,
}

/// Holds a literal packet.
///
/// A literal packet contains unstructured data.  Since the size can
/// be very large, it is advised to process messages containing such
/// packets using a `PacketParser` or a `PacketPileParser` and process
/// the data in a streaming manner rather than the using the
/// `PacketPile::from_file` and related interfaces.
///
/// See [Section 5.9 of RFC 4880] for details.
///
///   [Section 5.9 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.9
#[derive(PartialEq, Clone)]
pub struct Literal {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// A one-octet field that describes how the data is formatted.
    pub format: u8,
    /// filename is a string, but strings in Rust are valid UTF-8.
    /// There is no guarantee, however, that the filename is valid
    /// UTF-8.  Thus, we leave filename as a byte array.  It can be
    /// converted to a string using String::from_utf8() or
    /// String::from_utf8_lossy().
    pub filename: Option<Vec<u8>>,
    /// A four-octet number that indicates a date associated with the
    /// literal data.
    pub date: time::Tm,
}

/// Holds a compressed data packet.
///
/// A compressed data packet is a container.  See [Section 5.6 of RFC
/// 4880] for details.
///
/// When the parser encounters a compressed data packet with an
/// unknown compress algorithm, it returns an `Unknown` packet instead
/// of a `CompressedData` packet.
///
/// [Section 5.6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.6
#[derive(PartialEq, Clone)]
pub struct CompressedData {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// Algorithm used to compress the payload.
    pub algo: CompressionAlgorithm,
}

/// Holds an encrypted data packet.
///
/// An encrypted data packet is a container.  See [Section 5.13 of RFC
/// 4880] for details.
///
/// [Section 5.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.13
#[derive(PartialEq, Clone, Debug)]
pub struct SEIP {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// SEIP version. Must be 1.
    pub version: u8,
}

/// Holds an MDC packet.
///
/// A modification detection code packet.  This packet appears after a
/// SEIP packet.  See [Section 5.14 of RFC 4880] for details.
///
/// [Section 5.14 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.14
#[derive(PartialEq, Clone, Debug)]
pub struct MDC {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// Our SHA-1 hash.
    pub computed_hash: [u8; 20],
    /// A 20-octet SHA-1 hash of the preceding plaintext data.
    pub hash: [u8; 20],
}

impl MDC {
    /// Creates a new MDC packet for the data hashed into `hash` Hash context.
    pub fn new(hash: &mut nettle::Hash) -> Self {
        let mut mdc = MDC {
            common: Default::default(),
            computed_hash: Default::default(),
            hash: Default::default(),
        };

        hash.digest(&mut mdc.hash[..]);
        mdc
    }
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
#[derive(Debug)]
#[derive(PartialEq, Clone)]
pub enum Packet {
    /// Unknown packet.
    Unknown(Unknown),
    /// Signature packet.
    Signature(Signature),
    /// One pass signature packet.
    OnePassSig(OnePassSig),
    /// Public key packet.
    PublicKey(Key),
    /// Public subkey packet.
    PublicSubkey(Key),
    /// Public/Secret key pair.
    SecretKey(Key),
    /// Public/Secret subkey pair.
    SecretSubkey(Key),
    /// User ID packet.
    UserID(UserID),
    /// User attribute packet.
    UserAttribute(UserAttribute),
    /// Literal data packet.
    Literal(Literal),
    /// Compressed literal data packet.
    CompressedData(CompressedData),
    /// Public key encrypted data packet.
    PKESK(PKESK),
    /// Symmetric key encrypted data packet.
    SKESK(SKESK),
    /// Signed and encrypted, integrity protected data packet.
    SEIP(SEIP),
    /// Modification detection code packet.
    MDC(MDC),
}

impl Packet {
    /// Returns the `Packet's` corresponding OpenPGP tag.
    ///
    /// Tags are explained in [Section 4.3 of RFC 4880].
    ///
    ///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
    pub fn tag(&self) -> Tag {
        match self {
            &Packet::Unknown(ref packet) => packet.tag,
            &Packet::Signature(_) => Tag::Signature,
            &Packet::OnePassSig(_) => Tag::OnePassSig,
            &Packet::PublicKey(_) => Tag::PublicKey,
            &Packet::PublicSubkey(_) => Tag::PublicSubkey,
            &Packet::SecretKey(_) => Tag::SecretKey,
            &Packet::SecretSubkey(_) => Tag::SecretSubkey,
            &Packet::UserID(_) => Tag::UserID,
            &Packet::UserAttribute(_) => Tag::UserAttribute,
            &Packet::Literal(_) => Tag::Literal,
            &Packet::CompressedData(_) => Tag::CompressedData,
            &Packet::PKESK(_) => Tag::PKESK,
            &Packet::SKESK(_) => Tag::SKESK,
            &Packet::SEIP(_) => Tag::SEIP,
            &Packet::MDC(_) => Tag::MDC,
        }
    }
}

/// A `PacketPile` holds a deserialized sequence of OpenPGP messages.
///
/// To deserialize an OpenPGP usage, use either [`PacketParser`],
/// [`PacketPileParser`], or [`PacketPile::from_file`] (or related
/// routines).
///
/// Normally, you'll want to convert the `PacketPile` to a TPK or a
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

/// A transferable public key (TPK).
///
/// A TPK (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// TPKs are always canonicalized in the sense that only elements
/// (user id, user attribute, subkey) with at least one valid
/// self-signature are preserved.  Also, invalid self-signatures are
/// dropped.  The self-signatures are sorted so that the newest
/// self-signature comes first.  User IDs are sorted so that the first
/// `UserID` is the primary User ID.  Third-party certifications are
/// *not* validated, as the keys are not available; they are simply
/// passed through as is.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
///
/// # Example
///
/// ```rust
/// # extern crate openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{PacketParserResult, PacketParser};
/// use openpgp::TPK;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
/// #     let ppr = PacketParser::from_bytes(&b""[..])?;
/// match TPK::from_packet_parser(ppr) {
///     Ok(tpk) => {
///         println!("Key: {}", tpk.primary());
///         for binding in tpk.userids() {
///             println!("User ID: {}", binding.userid());
///         }
///     }
///     Err(err) => {
///         eprintln!("Error parsing TPK: {}", err);
///     }
/// }
///
/// #     Ok(())
/// # }
#[derive(Debug, Clone, PartialEq)]
pub struct TPK {
    primary: Key,
    userids: Vec<tpk::UserIDBinding>,
    user_attributes: Vec<tpk::UserAttributeBinding>,
    subkeys: Vec<tpk::SubkeyBinding>,
}

/// An OpenPGP message.
///
/// An OpenPGP message is a structured sequence of OpenPGP packets.
/// Basically, it's an optionally encrypted, optionally signed literal
/// data packet.  The exact structure is defined in [Section 11.3 of RFC
/// 4880].
///
///   [Section 11.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-11.3
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
#[derive(PartialEq, Eq, Clone, Hash)]
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

use std::io::Read;
use nettle::Hash;

/// Hash the specified file.
///
/// This is useful when verifying detached signatures.
pub fn hash_file<R: Read>(reader: R, algos: &[HashAlgorithm])
    -> Result<Vec<(HashAlgorithm, Box<Hash>)>>
{
    use std::mem;

    use ::parse::HashedReader;
    use ::parse::HashesFor;

    use buffered_reader::BufferedReader;
    use buffered_reader::BufferedReaderGeneric;

    let reader
        = BufferedReaderGeneric::with_cookie(
            reader, None, Default::default());

    let mut reader
        = HashedReader::new(reader, HashesFor::Signature, algos.to_vec());

    // Hash all of the data.
    reader.drop_eof()?;

    let hashes = mem::replace(&mut reader.cookie_mut().hashes, Vec::new());

    return Ok(hashes);
}


#[test]
fn hash_file_test() {
    use std::fs::File;

    let algos =
        [ HashAlgorithm::SHA1, HashAlgorithm::SHA512, HashAlgorithm::SHA1 ];
    let digests =
        [ "7945E3DA269C25C04F9EF435A5C0F25D9662C771",
           "DDE60DB05C3958AF1E576CD006A7F3D2C343DD8C8DECE789A15D148DF90E6E0D1454DE734F8343502CA93759F22C8F6221BE35B6BDE9728BD12D289122437CB1",
           "7945E3DA269C25C04F9EF435A5C0F25D9662C771" ];

    let result =
        hash_file(File::open(path_to("a-cypherpunks-manifesto.txt")).unwrap(),
                  &algos[..])
        .unwrap();

    for ((expected_algo, expected_digest), (algo, mut hash)) in
        algos.into_iter().zip(digests.into_iter()).zip(result) {
            let mut digest = vec![0u8; hash.digest_size()];
            hash.digest(&mut digest);

            assert_eq!(*expected_algo, algo);
            assert_eq!(*expected_digest, ::to_hex(&digest[..], false));
        }
}

