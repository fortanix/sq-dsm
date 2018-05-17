//! OpenPGP data types and associated machinery.
//!
//! This crate aims to provide a complete implementation of OpenPGP as
//! defined by [RFC 4880] as well as several extensions (e.g., [RFC
//! 6637], which describes ECC cryptography for OpenPGP).  This
//! includes support for unbuffered message processing.
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
//! [unhashed signature subpackets]: https://tools.ietf.org/html/rfc4880#section-5.2.3.2
//! [sequoia-core]: ../sequoia_core

#[macro_use]
extern crate failure;

extern crate buffered_reader;

extern crate nettle;

extern crate flate2;
extern crate bzip2;

#[cfg(test)]
#[macro_use]
extern crate quickcheck;

#[cfg(not(test))]
extern crate quickcheck;

use std::fmt;
use std::io;

pub mod armor;

pub mod ctb;
use ctb::{CTB, CTBOld, CTBNew, CTBCommon, PacketLengthType};

pub mod packet;
use packet::{BodyLength, Header, Container};

pub mod parse;
use parse::SubpacketArea;
pub mod mpis;

pub mod tpk;
pub mod serialize;

mod hash;
pub mod symmetric;
pub use symmetric::SymmetricAlgo;

mod s2k;
pub use s2k::S2K;

mod unknown;
mod signature;
mod one_pass_sig;
mod key;
mod userid;
mod user_attribute;
mod literal;
mod compressed_data;

mod skesk;
pub use skesk::SKESK;

mod message;
mod constants;
// XXX: Do we really want to put that into the toplevel?  Why not make
// constants public?
pub use constants::{
    PublicKeyAlgorithm,
    CompressionAlgorithm,
    HashAlgorithm,
    SignatureType,
};
mod tag;
pub use tag::Tag;

pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Fail, Debug)]
/// Errors returned by this module.
pub enum Error {
    #[fail(display = "Invalid argument: {}", _0)]
    InvalidArgument(String),

    #[fail(display = "Invalid operation: {}", _0)]
    InvalidOperation(String),

    /// A malformed packet.
    #[fail(display = "Malformed packet: {}", _0)]
    MalformedPacket(String),

    #[fail(display = "Unknown packet type: {}", _0)]
    UnknownPacketTag(u8),

    #[fail(display = "Unknown hash algorithm: {}", _0)]
    UnknownHashAlgorithm(u8),

    #[fail(display = "Unknown public key algorithm: {}", _0)]
    UnknownPublicKeyAlgorithm(u8),

    #[fail(display = "Unknown symmetric algorithm: {}", _0)]
    UnknownSymmetricAlgorithm(u8),

    #[fail(display = "Unsupported hash algorithm: {}", _0)]
    UnsupportedHashAlgorithm(u8),

    #[fail(display = "Unsupported public key algorithm: {}", _0)]
    UnsupportedPublicKeyAlgorithm(PublicKeyAlgorithm),

    #[fail(display = "Unsupported symmetric algorithm: {}", _0)]
    UnsupportedSymmetricAlgorithm(u8),

    #[fail(display = "Unsupported signature type: {}", _0)]
    UnsupportedSignatureType(u8),

    #[fail(display = "Invalid password")]
    InvalidPassword,

    #[fail(display = "Invalid session key: {}", _0)]
    InvalidSessionKey(String),

    #[fail(display = "Malformed MPI: {}", _0)]
    MalformedMPI(String),

    #[fail(display = "Bad signature: {}", _0)]
    BadSignature(String),

    #[fail(display = "{}", _0)]
    Io(#[cause] io::Error),
}

// A helpful debugging function.
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

// A helpful function for converting a hexadecimal string to binary.
// This function skips whitespace if `skip_whipspace` is set.
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
    pub common: packet::Common,
    pub tag: Tag,
}

/// Holds a signature packet.
///
/// Signature packets are used both for certification purposes as well
/// as for document signing purposes.
///
/// See [Section 5.2 of RFC 4880] for details.
///
///   [Section 5.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2
// Note: we can't derive PartialEq, because it includes the cached data.
#[derive(Clone)]
pub struct Signature {
    pub common: packet::Common,
    pub version: u8,
    pub sigtype: SignatureType,
    pub pk_algo: PublicKeyAlgorithm,
    pub hash_algo: HashAlgorithm,
    pub hashed_area: parse::subpacket::SubpacketArea,
    pub unhashed_area: parse::subpacket::SubpacketArea,
    pub hash_prefix: [u8; 2],
    pub mpis: mpis::MPIs,

    // When used in conjunction with a one-pass signature, this is the
    // hash computed over the enclosed message.
    pub computed_hash: Option<(HashAlgorithm, Vec<u8>)>,
}

/// Holds a one-pass signature packet.
///
/// See [Section 5.4 of RFC 4880] for details.
///
///   [Section 5.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.4
#[derive(Clone)]
pub struct OnePassSig {
    pub common: packet::Common,
    pub version: u8,
    pub sigtype: SignatureType,
    pub hash_algo: HashAlgorithm,
    pub pk_algo: PublicKeyAlgorithm,
    pub issuer: KeyID,
    pub last: u8,
}

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// See [Section 5.5 of RFC 4880] for details.
///
///   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
#[derive(PartialEq, Clone)]
pub struct Key {
    pub common: packet::Common,
    pub version: u8,
    /* When the key was created.  */
    pub creation_time: u32,
    pub pk_algo: PublicKeyAlgorithm,
    pub mpis: mpis::MPIs,
}

/// Holds a UserID packet.
///
/// See [Section 5.11 of RFC 4880] for details.
///
///   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
#[derive(PartialEq, Clone)]
pub struct UserID {
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
    pub common: packet::Common,

    /// The user attribute.
    pub value: Vec<u8>,
}

/// Holds a literal packet.
///
/// A literal packet contains unstructured data.  Since the size can
/// be very large, it is advised to process messages containing such
/// packets using a `PacketParser` or a `MessageParser` and process
/// the data in a streaming manner rather than the using the
/// `Message::from_file` and related interfaces.
///
/// See [Section 5.9 of RFC 4880] for details.
///
///   [Section 5.9 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.9
#[derive(PartialEq, Clone)]
pub struct Literal {
    pub common: packet::Common,
    pub format: u8,
    /// filename is a string, but strings in Rust are valid UTF-8.
    /// There is no guarantee, however, that the filename is valid
    /// UTF-8.  Thus, we leave filename as a byte array.  It can be
    /// converted to a string using String::from_utf8() or
    /// String::from_utf8_lossy().
    pub filename: Option<Vec<u8>>,
    pub date: u32,
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
    pub common: packet::Common,
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
    pub common: packet::Common,
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
    pub common: packet::Common,
    pub computed_hash: [u8; 20],
    pub hash: [u8; 20],
}

impl MDC {
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
    Unknown(Unknown),
    Signature(Signature),
    OnePassSig(OnePassSig),
    PublicKey(Key),
    PublicSubkey(Key),
    SecretKey(Key),
    SecretSubkey(Key),
    UserID(UserID),
    UserAttribute(UserAttribute),
    Literal(Literal),
    CompressedData(CompressedData),
    SKESK(SKESK),
    SEIP(SEIP),
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
            &Packet::SKESK(_) => Tag::SKESK,
            &Packet::SEIP(_) => Tag::SEIP,
            &Packet::MDC(_) => Tag::MDC,
        }
    }
}

/// A `Message` holds a deserialized OpenPGP message.
///
/// To deserialize an OpenPGP usage, use either [`PacketParser`],
/// [`MessageParser`], or [`Message::from_file`] (or related
/// routines).
///
///   [`PacketParser`]: parse/struct.PacketParser.html
///   [`MessageParser`]: parse/struct.MessageParser.html
///   [`Message::from_file`]: struct.Message.html#method.from_file
#[derive(PartialEq, Clone)]
pub struct Message {
    // At the top level, we have a sequence of packets, which may be
    // containers.
    top_level: Container,
}

/// A transferable public key (TPK).
///
/// A TPK (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
#[derive(Debug, Clone, PartialEq)]
pub struct TPK {
    primary: Key,
    userids: Vec<tpk::UserIDBinding>,
    user_attributes: Vec<tpk::UserAttributeBinding>,
    subkeys: Vec<tpk::SubkeyBinding>,
}

/// Holds a fingerprint.
///
/// A fingerprint uniquely identifies a public key.  For more details
/// about how a fingerprint is generated, see [Section 12.2 of RFC
/// 4880].
///
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
#[derive(PartialEq, Clone, Hash)]
pub enum Fingerprint {
    V4([u8;20]),
    // Used for holding fingerprints that we don't understand.  For
    // instance, we don't grok v3 fingerprints.  And, it is possible
    // that the Issuer subpacket contains the wrong number of bytes.
    Invalid(Box<[u8]>)
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Fingerprint")
            .field(&self.to_string())
            .finish()
    }
}

impl Fingerprint {
    /// Reads a binary fingerprint.
    pub fn from_bytes(raw: &[u8]) -> Fingerprint {
        if raw.len() == 20 {
            let mut fp : [u8; 20] = Default::default();
            fp.copy_from_slice(raw);
            Fingerprint::V4(fp)
        } else {
            Fingerprint::Invalid(raw.to_vec().into_boxed_slice())
        }
    }

    /// Reads a hexadecimal fingerprint.
    ///
    /// This function ignores whitespace.
    ///
    /// # Example
    ///
    /// ```
    /// # use openpgp::Fingerprint;
    /// let hex = "3E8877C877274692975189F5D03F6F865226FE8B";
    /// let fp = Fingerprint::from_hex(hex);
    /// assert!(fp.is_some());
    /// assert_eq!(fp.unwrap().to_hex(), hex);
    /// ```
    pub fn from_hex(hex: &str) -> Option<Fingerprint> {
        Some(Fingerprint::from_bytes(&from_hex(hex, true)?[..]))
    }

    /// Converts the fingerprint to its standard representation.
    ///
    /// Returns the fingerprint suitable for human consumption.
    pub fn to_string(&self) -> String {
        self.convert_to_string(true)
    }

    /// Converts the fingerprint to a hexadecimal number.
    pub fn to_hex(&self) -> String {
        self.convert_to_string(false)
    }

    /// Common code for the above functions.
    fn convert_to_string(&self, pretty: bool) -> String {
        let raw = match self {
            &Fingerprint::V4(ref fp) => &fp[..],
            &Fingerprint::Invalid(ref fp) => &fp[..],
        };

        // We currently only handle V4 fingerprints, which look like:
        //
        //   8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9
        //
        // Since we have no idea how to format an invalid fingerprint,
        // just format it like a V4 fingerprint and hope for the best.

        let mut output = Vec::with_capacity(
            // Each byte results in to hex characters.
            raw.len() * 2
            + if pretty {
                // Every 2 bytes of output, we insert a space.
                raw.len() / 2
                // After 5 groups, there is another space.
                + raw.len() / 10
            } else { 0 });

        for (i, b) in raw.iter().enumerate() {
            if pretty && i > 0 && i % 2 == 0 {
                output.push(' ' as u8);
            }

            if pretty && i > 0 && i % 10 == 0 {
                output.push(' ' as u8);
            }

            let top = b >> 4;
            let bottom = b & 0xFu8;

            if top < 10u8 {
                output.push('0' as u8 + top)
            } else {
                output.push('A' as u8 + (top - 10u8))
            }

            if bottom < 10u8 {
                output.push('0' as u8 + bottom)
            } else {
                output.push('A' as u8 + (bottom - 10u8))
            }
        }

        // We know the content is valid UTF-8.
        String::from_utf8(output).unwrap()
    }

    /// Converts the fingerprint to a key ID.
    pub fn to_keyid(&self) -> KeyID {
        match self {
            &Fingerprint::V4(ref fp) =>
                KeyID::from_bytes(&fp[fp.len() - 8..]),
            &Fingerprint::Invalid(ref fp) => {
                if fp.len() < 8 {
                    KeyID::from_bytes(&[0; 8])
                } else {
                    KeyID::from_bytes(&fp[fp.len() - 8..])
                }
            }
        }
    }
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
    V4([u8;8]),
    // Used for holding fingerprints that we don't understand.  For
    // instance, we don't grok v3 fingerprints.  And, it is possible
    // that the Issuer subpacket contains the wrong number of bytes.
    Invalid(Box<[u8]>)
}

impl fmt::Display for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl fmt::Debug for KeyID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("KeyID")
            .field(&self.to_string())
            .finish()
    }
}

impl From<KeyID> for Vec<u8> {
    fn from(id: KeyID) -> Self {
        let mut r = Vec::with_capacity(8);
        match id {
            KeyID::V4(ref b) => r.extend_from_slice(b),
            KeyID::Invalid(ref b) => r.extend_from_slice(b),
        }
        r
    }
}

impl KeyID {
    /// Converts a u64 to a KeyID.
    pub fn new(data: u64) -> KeyID {
        let bytes = [
            (data >> (7 * 8)) as u8,
            (data >> (6 * 8)) as u8,
            (data >> (5 * 8)) as u8,
            (data >> (4 * 8)) as u8,
            (data >> (3 * 8)) as u8,
            (data >> (2 * 8)) as u8,
            (data >> (1 * 8)) as u8,
            (data >> (0 * 8)) as u8
        ];
        Self::from_bytes(&bytes[..])
    }

    /// Reads a binary key ID.
    pub fn from_bytes(raw: &[u8]) -> KeyID {
        if raw.len() == 8 {
            let mut keyid : [u8; 8] = Default::default();
            keyid.copy_from_slice(raw);
            KeyID::V4(keyid)
        } else {
            KeyID::Invalid(raw.to_vec().into_boxed_slice())
        }
    }

    /// Reads a hex-encoded Key ID.
    pub fn from_hex(hex: &str) -> Option<KeyID> {
        let bytes = from_hex(hex, true)?;

        // A KeyID is exactly 8 bytes long.
        if bytes.len() != 8 {
            return None;
        }

        Some(KeyID::from_bytes(&bytes[..]))
    }

    /// Returns a reference to the raw KeyID.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            &KeyID::V4(ref id) => id,
            &KeyID::Invalid(ref id) => id,
        }
    }

    /// Converts the key ID to its standard representation.
    ///
    /// Returns the fingerprint suitable for human consumption.
    pub fn to_string(&self) -> String {
        self.convert_to_string(true)
    }

    /// Converts the key ID to a hexadecimal number.
    pub fn to_hex(&self) -> String {
        self.convert_to_string(false)
    }

    /// Common code for the above functions.
    fn convert_to_string(&self, pretty: bool) -> String {
        let raw = match self {
            &KeyID::V4(ref fp) => &fp[..],
            &KeyID::Invalid(ref fp) => &fp[..],
        };

        // We currently only handle V4 key IDs, which look like:
        //
        //   AACB 3243 6300 52D9
        //
        // Since we have no idea how to format an invalid key ID, just
        // format it like a V4 fingerprint and hope for the best.

        let mut output = Vec::with_capacity(
            // Each byte results in to hex characters.
            raw.len() * 2
            + if pretty {
                // Every 2 bytes of output, we insert a space.
                raw.len() / 2
            } else { 0 });

        for (i, b) in raw.iter().enumerate() {
            if pretty && i > 0 && i % 2 == 0 {
                output.push(' ' as u8);
            }

            let top = b >> 4;
            let bottom = b & 0xFu8;

            if top < 10u8 {
                output.push('0' as u8 + top)
            } else {
                output.push('A' as u8 + (top - 10u8))
            }

            if bottom < 10u8 {
                output.push('0' as u8 + bottom)
            } else {
                output.push('A' as u8 + (bottom - 10u8))
            }
        }

        // We know the content is valid UTF-8.
        String::from_utf8(output).unwrap()
    }
}
