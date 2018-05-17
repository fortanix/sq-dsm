//! OpenPGP signature packets include a set of key-value attributes
//! called subpackets.  These subpackets are used to indicate when a
//! signature was created, who created the signature, user &
//! implementation preferences, etc.  The full details are in [Section
//! 5.2.3.1 of RFC 4880].
//!
//! [Section 5.2.3.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.1
//!
//! The standard assigns each subpacket a numeric id, and describes
//! the format of its value.  One subpacket is called Notation Data
//! and is intended as a generic key-value store.  The combined size
//! of the subpackets (including notation data) is limited to 64 KB.
//!
//! Subpackets and notations can be marked as critical.  If an OpenPGP
//! implementation processes a packet that includes critical
//! subpackets or notations that it does not understand, it is
//! required to abort processing.  This allows for forwards compatible
//! changes by indicating whether it is safe to ignore an unknown
//! subpacket or notation.
//!
//! A number of methods are defined on the [`Signature`] struct for
//! working with subpackets.
//!
//! [`Signature`]: ../../struct.Signature.html
//!
//! # Examples
//!
//! If a signature packet includes an issuer fingerprint subpacket,
//! print it:
//!
//! ```rust
//! # use openpgp::Result;
//! # use openpgp::Packet;
//! # use openpgp::parse::PacketParser;
//! #
//! # f(include_bytes!("../../tests/data/messages/signed.gpg"));
//! #
//! # fn f(message_data: &[u8]) -> Result<()> {
//! let mut ppo = PacketParser::from_bytes(message_data)?;
//! while let Some(mut pp) = ppo {
//!     if let Packet::Signature(ref sig) = pp.packet {
//!         if let Some(fp) = sig.issuer_fingerprint() {
//!             eprintln!("Signature issued by: {}", fp.to_string());
//!         }
//!     }
//!
//!     // Get the next packet.
//!     let (_packet, _packet_depth, tmp, _pp_depth) = pp.recurse()?;
//!     ppo = tmp;
//! }
//! # Ok(())
//! # }
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use quickcheck::{Arbitrary, Gen};

use buffered_reader::{BufferedReader, BufferedReaderMemory};

use {
    Result,
    Signature,
    Packet,
    Fingerprint,
    KeyID,
};

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", "messages", artifact]
        .iter().collect()
}

/// The subpacket types specified by [Section 5.2.3.1 of RFC 4880].
///
/// [Section 5.2.3.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.1
#[derive(Debug)]
#[derive(PartialEq, Eq, Hash)]
#[derive(Clone, Copy)]
pub enum SubpacketTag {
    SignatureCreationTime,
    SignatureExpirationTime,
    ExportableCertification,
    TrustSignature,
    RegularExpression,
    Revocable,
    KeyExpirationTime,
    PlaceholderForBackwardCompatibility,
    PreferredSymmetricAlgorithms,
    RevocationKey,
    Issuer,
    NotationData,
    PreferredHashAlgorithms,
    PreferredCompressionAlgorithms,
    KeyServerPreferences,
    PreferredKeyServer,
    PrimaryUserID,
    PolicyURI,
    KeyFlags,
    SignersUserID,
    ReasonForRevocation,
    Features,
    SignatureTarget,
    EmbeddedSignature,
    // Added in RFC 4880bis.
    IssuerFingerprint,
    Reserved(u8),
    Private(u8),
    Unknown(u8),
}

impl From<u8> for SubpacketTag {
    fn from(u: u8) -> Self {
        match u {
            2 => SubpacketTag::SignatureCreationTime,
            3 => SubpacketTag::SignatureExpirationTime,
            4 => SubpacketTag::ExportableCertification,
            5 => SubpacketTag::TrustSignature,
            6 => SubpacketTag::RegularExpression,
            7 => SubpacketTag::Revocable,
            9 => SubpacketTag::KeyExpirationTime,
            10 => SubpacketTag::PlaceholderForBackwardCompatibility,
            11 => SubpacketTag::PreferredSymmetricAlgorithms,
            12 => SubpacketTag::RevocationKey,
            16 => SubpacketTag::Issuer,
            20 => SubpacketTag::NotationData,
            21 => SubpacketTag::PreferredHashAlgorithms,
            22 => SubpacketTag::PreferredCompressionAlgorithms,
            23 => SubpacketTag::KeyServerPreferences,
            24 => SubpacketTag::PreferredKeyServer,
            25 => SubpacketTag::PrimaryUserID,
            26 => SubpacketTag::PolicyURI,
            27 => SubpacketTag::KeyFlags,
            28 => SubpacketTag::SignersUserID,
            29 => SubpacketTag::ReasonForRevocation,
            30 => SubpacketTag::Features,
            31 => SubpacketTag::SignatureTarget,
            32 => SubpacketTag::EmbeddedSignature,
            33 => SubpacketTag::IssuerFingerprint,
            0| 1| 8| 13| 14| 15| 17| 18| 19 => SubpacketTag::Reserved(u),
            100...110 => SubpacketTag::Private(u),
            _ => SubpacketTag::Unknown(u),
        }
    }
}

impl From<SubpacketTag> for u8 {
    fn from(t: SubpacketTag) -> Self {
        match t {
            SubpacketTag::SignatureCreationTime => 2,
            SubpacketTag::SignatureExpirationTime => 3,
            SubpacketTag::ExportableCertification => 4,
            SubpacketTag::TrustSignature => 5,
            SubpacketTag::RegularExpression => 6,
            SubpacketTag::Revocable => 7,
            SubpacketTag::KeyExpirationTime => 9,
            SubpacketTag::PlaceholderForBackwardCompatibility => 10,
            SubpacketTag::PreferredSymmetricAlgorithms => 11,
            SubpacketTag::RevocationKey => 12,
            SubpacketTag::Issuer => 16,
            SubpacketTag::NotationData => 20,
            SubpacketTag::PreferredHashAlgorithms => 21,
            SubpacketTag::PreferredCompressionAlgorithms => 22,
            SubpacketTag::KeyServerPreferences => 23,
            SubpacketTag::PreferredKeyServer => 24,
            SubpacketTag::PrimaryUserID => 25,
            SubpacketTag::PolicyURI => 26,
            SubpacketTag::KeyFlags => 27,
            SubpacketTag::SignersUserID => 28,
            SubpacketTag::ReasonForRevocation => 29,
            SubpacketTag::Features => 30,
            SubpacketTag::SignatureTarget => 31,
            SubpacketTag::EmbeddedSignature => 32,
            SubpacketTag::IssuerFingerprint => 33,
            SubpacketTag::Reserved(u) => u,
            SubpacketTag::Private(u) => u,
            SubpacketTag::Unknown(u) => u,
        }
    }
}

impl Arbitrary for SubpacketTag {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    quickcheck! {
        fn roundtrip(tag: SubpacketTag) -> bool {
            let val: u8 = tag.clone().into();
            tag == SubpacketTag::from(val)
        }
    }

    quickcheck! {
        fn parse(tag: SubpacketTag) -> bool {
            match tag {
                SubpacketTag::Reserved(u) =>
                    (u == 0 || u == 1 || u == 8
                     || u == 13 || u == 14 || u == 15
                     || u == 17 || u == 18 || u == 19),
                SubpacketTag::Private(u) => u >= 100 && u <= 110,
                SubpacketTag::Unknown(u) => (u > 33 && u < 100) || u > 110,
                _ => true
            }
        }
    }
}


// Struct holding an arbitrary subpacket.
//
// The value is uninterpreted.
struct SubpacketRaw<'a> {
    pub critical: bool,
    pub tag: SubpacketTag,
    pub value: &'a [u8],
}

impl<'a> fmt::Debug for SubpacketRaw<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = if self.value.len() > 16 {
            &self.value[..16]
        } else {
            self.value
        };

        f.debug_struct("SubpacketArea")
            .field("critical", &self.critical)
            .field("tag", &self.tag)
            .field(&format!("value ({} bytes)", self.value.len())[..],
                   &value)
            .finish()
    }
}

/// Subpacket area.
#[derive(Clone)]
pub struct SubpacketArea {
    pub data: Vec<u8>,

    // The subpacket area, but parsed so that the map is indexed by
    // the subpacket tag, and the value corresponds to the *last*
    // occurance of that subpacket in the subpacket area.
    //
    // Since self-referential structs are a no-no, we use (start, len)
    // to reference the content in the area.
    //
    // This is an option, because we parse the subpacket area lazily.
    parsed: RefCell<Option<HashMap<SubpacketTag, (bool, u16, u16)>>>,
}

struct SubpacketAreaIter<'a> {
    reader: BufferedReaderMemory<'a, ()>,
    data: &'a [u8],
}

impl<'a> Iterator for SubpacketAreaIter<'a> {
    // Start, length.
    type Item = (usize, usize, SubpacketRaw<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let len = subpacket_length(&mut self.reader);
        if len.is_err() {
            return None;
        }
        let len = len.unwrap() as usize;

        if self.reader.data(len).unwrap().len() < len {
            // Subpacket extends beyond the end of the hashed
            // area.  Skip it.
            self.reader.drop_eof().unwrap();
            eprintln!("Invalid subpacket: subpacket extends beyond \
                       end of hashed area ({} bytes, but  {} bytes left).",
                      len, self.reader.data(0).unwrap().len());
            return None;
        }

        if len == 0 {
            // Hmm, a zero length packet.  In that case, there is
            // no header.
            return self.next();
        }

        let tag = if let Ok(tag) = self.reader.data_consume_hard(1) {
            tag[0]
        } else {
            return None;
        };
        let len = len - 1;

        // The critical bit is the high bit.  Extract it.
        let critical = tag & (1 << 7) != 0;
        // Then clear it from the type.
        let tag = tag & !(1 << 7);

        let start = self.reader.total_out();
        assert!(start <= ::std::u16::MAX as usize);
        assert!(len <= ::std::u16::MAX as usize);

        let _ = self.reader.consume(len);

        Some((start, len,
              SubpacketRaw {
                  critical: critical,
                  tag: tag.into(),
                  value: &self.data[start..start + len],
              }))
    }
}

impl SubpacketArea {
    fn iter(&self) -> SubpacketAreaIter {
        SubpacketAreaIter {
            reader: BufferedReaderMemory::new(&self.data[..]),
            data: &self.data[..],
        }
    }
}

impl fmt::Debug for SubpacketArea {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map().entries(
            self.iter().map(|(_start, _len, sb)| {
                (sb.tag, sb)
            }))
            .finish()
    }
}

impl SubpacketArea {
    /// Returns a new subpacket area based on `data`.
    pub fn new(data: Vec<u8>) -> SubpacketArea {
        SubpacketArea { data: data, parsed: RefCell::new(None) }
    }

    /// Returns a empty subpacket area.
    pub fn empty() -> SubpacketArea {
        SubpacketArea::new(Vec::new())
    }
}

impl SubpacketArea{
    // Initialize `Signature::hashed_area_parsed` from
    // `Signature::hashed_area`, if necessary.
    fn cache_init(&self) {
        if self.parsed.borrow().is_none() {
            let mut hash = HashMap::new();
            for (start, len, sb) in self.iter() {
                hash.insert(sb.tag, (sb.critical, start as u16, len as u16));
            }

            *self.parsed.borrow_mut() = Some(hash);
        }
    }

    // Returns the last subpacket, if any, with the specified tag.
    fn lookup(&self, tag: SubpacketTag) -> Option<SubpacketRaw> {
        self.cache_init();

        match self.parsed.borrow().as_ref().unwrap().get(&tag) {
            Some(&(critical, start, len)) =>
                return Some(SubpacketRaw {
                    critical: critical,
                    tag: tag,
                    value: &self.data[
                        start as usize..start as usize + len as usize]
                }.into()),
            None => None,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct NotationData<'a> {
    flags: u32,
    name: &'a [u8],
    value: &'a [u8],
}

/// Struct holding an arbitrary subpacket.
///
/// The value is well structured.
#[derive(Debug, PartialEq, Clone)]
pub enum SubpacketValue<'a> {
    // The subpacket is unknown.
    Unknown(&'a [u8]),
    // The packet is present, but the value is structured incorrectly.
    Invalid(&'a [u8]),

    SignatureCreationTime(u32),
    SignatureExpirationTime(u32),
    ExportableCertification(bool),
    TrustSignature((u8, u8)),
    RegularExpression(&'a [u8]),
    Revocable(bool),
    KeyExpirationTime(u32),
    PreferredSymmetricAlgorithms(&'a [u8]),
    RevocationKey((u8, u8, Fingerprint)),
    Issuer(KeyID),
    NotationData(NotationData<'a>),
    PreferredHashAlgorithms(&'a [u8]),
    PreferredCompressionAlgorithms(&'a [u8]),
    KeyServerPreferences(&'a [u8]),
    PreferredKeyServer(&'a [u8]),
    PrimaryUserID(bool),
    PolicyURI(&'a [u8]),
    KeyFlags(&'a [u8]),
    SignersUserID(&'a [u8]),
    ReasonForRevocation((u8, &'a [u8])),
    Features(&'a [u8]),
    SignatureTarget((u8, u8, &'a [u8])),
    /// This is a packet rather than a `Signature`, because we also
    /// want to return an `Unknown` packet.
    EmbeddedSignature(Packet),
    IssuerFingerprint(Fingerprint),
}

#[derive(Debug, PartialEq, Clone)]
pub struct Subpacket<'a> {
    pub critical: bool,
    pub tag: SubpacketTag,
    pub value: SubpacketValue<'a>,
}

fn from_be_u16(value: &[u8]) -> Option<u16> {
    if value.len() >= 2 {
        Some((value[0] as u16) << 8
             | (value[1] as u16))
    } else {
        None
    }
}

fn from_be_u32(value: &[u8]) -> Option<u32> {
    if value.len() >= 4 {
        Some((value[0] as u32) << 24
             | (value[1] as u32) << 16
             | (value[2] as u32) << 8
             | (value[3] as u32))
    } else {
        None
    }
}

impl<'a> From<SubpacketRaw<'a>> for Subpacket<'a> {
    fn from(raw: SubpacketRaw<'a>) -> Self {
        let value : Option<SubpacketValue>
                = match raw.tag {
            SubpacketTag::SignatureCreationTime =>
                // The timestamp is in big endian format.
                from_be_u32(raw.value).map(|v| {
                    SubpacketValue::SignatureCreationTime(v)
                }),

            SubpacketTag::SignatureExpirationTime =>
                // The time delta is in big endian format.
                from_be_u32(raw.value).map(|v| {
                    SubpacketValue::SignatureExpirationTime(v)
                }),

            SubpacketTag::ExportableCertification =>
                // One u8 holding a bool.
                if raw.value.len() == 1 {
                    Some(SubpacketValue::ExportableCertification(
                        raw.value[0] == 1u8))
                } else {
                    None
                },

            SubpacketTag::TrustSignature =>
                // Two u8s.
                if raw.value.len() == 2 {
                    Some(SubpacketValue::TrustSignature(
                        (raw.value[0], raw.value[1])))
                } else {
                    None
                },

            SubpacketTag::RegularExpression => {
                let trim = if raw.value.len() > 0
                    && raw.value[raw.value.len() - 1] == 0 { 1 } else { 0 };
                Some(SubpacketValue::RegularExpression(
                    &raw.value[..raw.value.len() - trim]))
            },

            SubpacketTag::Revocable =>
                // One u8 holding a bool.
                if raw.value.len() == 1 {
                    Some(SubpacketValue::Revocable(raw.value[0] != 0u8))
                } else {
                    None
                },

            SubpacketTag::KeyExpirationTime =>
                // The time delta is in big endian format.
                from_be_u32(raw.value).map(|v| {
                    SubpacketValue::KeyExpirationTime(v)
                }),

            SubpacketTag::PreferredSymmetricAlgorithms =>
                // array of one-octet values.
                Some(SubpacketValue::PreferredSymmetricAlgorithms(
                    raw.value)),

            SubpacketTag::RevocationKey =>
                // 1 octet of class, 1 octet of pk algorithm, 20 bytes
                // for a v4 fingerprint and 32 bytes for a v5
                // fingerprint.
                if raw.value.len() > 2 {
                    let class = raw.value[0];
                    let pk_algo = raw.value[1];
                    let fp = Fingerprint::from_bytes(&raw.value[2..]);

                    Some(SubpacketValue::RevocationKey((class, pk_algo, fp)))
                } else {
                    None
                },

            SubpacketTag::Issuer =>
                Some(SubpacketValue::Issuer(
                    KeyID::from_bytes(&raw.value[..]))),

            SubpacketTag::NotationData =>
                if raw.value.len() > 8 {
                    let flags = from_be_u32(raw.value).unwrap();
                    let name_len
                        = from_be_u16(&raw.value[4..]).unwrap() as usize;
                    let value_len
                        = from_be_u16(&raw.value[6..]).unwrap() as usize;

                    if raw.value.len() == 8 + name_len + value_len {
                        Some(SubpacketValue::NotationData(
                            NotationData {
                                flags: flags,
                                name: &raw.value[8..8 + name_len],
                                value: &raw.value[8 + name_len..]
                            }))
                    } else {
                        None
                    }
                } else {
                    None
                },

            SubpacketTag::PreferredHashAlgorithms =>
                // array of one-octet values.
                Some(SubpacketValue::PreferredHashAlgorithms(
                    raw.value)),

            SubpacketTag::PreferredCompressionAlgorithms =>
                // array of one-octet values.
                Some(SubpacketValue::PreferredCompressionAlgorithms(
                    raw.value)),

            SubpacketTag::KeyServerPreferences =>
                // N octets of flags.
                Some(SubpacketValue::KeyServerPreferences(raw.value)),

            SubpacketTag::PreferredKeyServer =>
                // String.
                Some(SubpacketValue::PreferredKeyServer(
                    raw.value)),

            SubpacketTag::PrimaryUserID =>
                // 1 octet, Boolean
                if raw.value.len() == 1 {
                    Some(SubpacketValue::PrimaryUserID(
                        raw.value[0] != 0u8))
                } else {
                    None
                },

            SubpacketTag::PolicyURI =>
                // String.
                Some(SubpacketValue::PolicyURI(raw.value)),

            SubpacketTag::KeyFlags =>
                // N octets of flags.
                Some(SubpacketValue::KeyFlags(raw.value)),

            SubpacketTag::SignersUserID =>
                // String.
                Some(SubpacketValue::SignersUserID(raw.value)),

            SubpacketTag::ReasonForRevocation =>
                // 1 octet of revocation code, N octets of reason string
                if raw.value.len() >= 1 {
                    Some(SubpacketValue::ReasonForRevocation(
                        (raw.value[0], &raw.value[1..])))
                } else {
                    None
                },

            SubpacketTag::Features =>
                // N octets of flags
                Some(SubpacketValue::Features(raw.value)),

            SubpacketTag::SignatureTarget =>
                // 1 octet public-key algorithm, 1 octet hash algorithm,
                // N octets hash
                if raw.value.len() > 2 {
                    let pk_algo = raw.value[0];
                    let hash_algo = raw.value[1];
                    let hash = &raw.value[2..];

                    Some(SubpacketValue::SignatureTarget(
                        (pk_algo, hash_algo, hash)))
                } else {
                    None
                },

            SubpacketTag::EmbeddedSignature => {
                // A signature packet.
                if let Ok(p) = Signature::parse_naked(&raw.value) {
                    Some(SubpacketValue::EmbeddedSignature(p))
                } else {
                    None
                }
            },

            SubpacketTag::IssuerFingerprint => {
                let version = raw.value.get(0);
                if let Some(version) = version {
                    if *version == 4 {
                        Some(SubpacketValue::IssuerFingerprint(
                            Fingerprint::from_bytes(&raw.value[1..])))
                    } else {
                        None
                    }
                } else {
                    None
                }
            },

            SubpacketTag::Reserved(_)
                    | SubpacketTag::PlaceholderForBackwardCompatibility
                    | SubpacketTag::Private(_)
                    | SubpacketTag::Unknown(_) =>
                // Unknown tag.
                Some(SubpacketValue::Unknown(raw.value)),
            };

        if let Some(value) = value {
            Subpacket {
                critical: raw.critical,
                tag: raw.tag,
                value: value,
            }
        } else {
            // Invalid.
            Subpacket {
                critical: raw.critical,
                tag: raw.tag,
                value: SubpacketValue::Invalid(raw.value),
            }
        }
    }
}

/// Decode a subpacket length as described in Section 5.2.3.1 of RFC 4880.
fn subpacket_length<C>(bio: &mut BufferedReaderMemory<C>)
      -> Result<u32> {
    let octet1 = bio.data_consume_hard(1)?[0];
    if octet1 < 192 {
        // One octet.
        return Ok(octet1 as u32);
    }
    if 192 <= octet1 && octet1 < 255 {
        // Two octets length.
        let octet2 = bio.data_consume_hard(1)?[0];
        return Ok(((octet1 as u32 - 192) << 8) + octet2 as u32 + 192);
    }

    // Five octets.
    assert_eq!(octet1, 255);
    return Ok(bio.read_be_u32()?);
}

impl Signature {
    /// Returns the *last* instance of the specified subpacket.
    fn subpacket<'a>(&'a self, tag: SubpacketTag) -> Option<Subpacket<'a>> {
        if let Some(sb) = self.hashed_area.lookup(tag) {
            return Some(sb.into());
        }

        // There are a couple of subpackets that we are willing to
        // take from the unhashed area.  The others we ignore
        // completely.
        if !(tag == SubpacketTag::Issuer
             || tag == SubpacketTag::EmbeddedSignature) {
            return None;
        }

        self.unhashed_area.lookup(tag).map(|sb| sb.into())
    }

    /// Returns all instances of the specified subpacket.
    ///
    /// In general, you only want to do this for NotationData.
    /// Otherwise, taking the last instance of a specified subpacket
    /// is a reasonable approach for dealing with ambiguity.
    fn subpackets<'a>(&'a self, target: SubpacketTag) -> Vec<Subpacket<'a>> {
        let mut result = Vec::new();

        for (_start, _len, sb) in self.hashed_area.iter() {
            if sb.tag == target {
                result.push(sb.into());
            }
        }

        result
    }

    /// Returns the value of the Creation Time subpacket, which
    /// contains the time when the signature was created as a unix
    /// timestamp.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn signature_creation_time(&self) -> Option<u32> {
        // 4-octet time field
        if let Some(sb)
                = self.subpacket(SubpacketTag::SignatureCreationTime) {
            if let SubpacketValue::SignatureCreationTime(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Signature Expiration Time subpacket,
    /// which contains when the signature expires as the number of
    /// seconds after its creation.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn signature_expiration_time(&self) -> Option<u32> {
        // 4-octet time field
        if let Some(sb)
                = self.subpacket(SubpacketTag::SignatureExpirationTime) {
            if let SubpacketValue::SignatureExpirationTime(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Exportable Certification subpacket,
    /// which contains whether the certification should be exported
    /// (i.e., whether the packet is *not* a local signature).
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn exportable_certification(&self) -> Option<bool> {
        // 1 octet of exportability, 0 for not, 1 for exportable
        if let Some(sb)
                = self.subpacket(SubpacketTag::ExportableCertification) {
            if let SubpacketValue::ExportableCertification(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Trust Signature subpacket.
    ///
    /// The return value is a tuple consisting of the level or depth
    /// and the trust amount.
    ///
    /// Recall from [Section 5.2.3.13 of RFC 4880]:
    ///
    /// ```text
    /// Level 0 has the same meaning as an ordinary
    /// validity signature.  Level 1 means that the signed key is asserted to
    /// be a valid trusted introducer, with the 2nd octet of the body
    /// specifying the degree of trust.  Level 2 means that the signed key is
    /// asserted to be trusted to issue level 1 trust signatures, i.e., that
    /// it is a "meta introducer".
    /// ```
    ///
    /// And, the trust amount is:
    ///
    /// ```text
    /// interpreted such that values less than 120 indicate partial
    /// trust and values of 120 or greater indicate complete trust.
    /// Implementations SHOULD emit values of 60 for partial trust and
    /// 120 for complete trust.
    /// ```
    ///
    ///   [Section 5.2.3.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.13
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn trust_signature(&self) -> Option<(u8, u8)> {
        // 1 octet "level" (depth), 1 octet of trust amount
        if let Some(sb)
                = self.subpacket(SubpacketTag::TrustSignature) {
            if let SubpacketValue::TrustSignature(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Regular Expression subpacket.
    ///
    /// This automatically strips any trailing NUL byte from the
    /// string.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn regular_expression(&self) -> Option<&[u8]> {
        // null-terminated regular expression
        if let Some(sb)
                = self.subpacket(SubpacketTag::RegularExpression) {
            if let SubpacketValue::RegularExpression(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Regular Expression subpacket, which
    /// indicates whether the signature is revocable, i.e., whether
    /// revocation certificates for this signature should be ignored.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn revocable(&self) -> Option<bool> {
        // 1 octet of revocability, 0 for not, 1 for revocable
        if let Some(sb)
                = self.subpacket(SubpacketTag::Revocable) {
            if let SubpacketValue::Revocable(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Key Expiration Time subpacket, which
    /// contains when the referenced key expires as the number of
    /// seconds after the key's creation.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn key_expiration_time(&self) -> Option<u32> {
        // 4-octet time field
        if let Some(sb)
                = self.subpacket(SubpacketTag::KeyExpirationTime) {
            if let SubpacketValue::KeyExpirationTime(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Preferred Symmetric Algorithms
    /// subpacket, which contains the list of symmetric algorithms
    /// that the key holder prefers, ordered according by the key
    /// holder's preference.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn preferred_symmetric_algorithms(&self) -> Option<&[u8]> {
        // array of one-octet values
        if let Some(sb)
                = self.subpacket(
                    SubpacketTag::PreferredSymmetricAlgorithms) {
            if let SubpacketValue::PreferredSymmetricAlgorithms(v)
                    = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Revocation Key subpacket, which
    /// contains a designated revoker.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn revocation_key(&self) -> Option<(u8, u8, Fingerprint)> {
        // 1 octet of class, 1 octet of public-key algorithm ID, 20 or
        // 32 octets of fingerprint.
        if let Some(sb)
                = self.subpacket(SubpacketTag::RevocationKey) {
            if let SubpacketValue::RevocationKey(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Issuer subpacket, which contains the
    /// KeyID of the key that allegedly created this signature.
    ///
    /// Note: for historical reasons this packet is usually stored in
    /// the unhashed area of the signature and, consequently, it is
    /// *not* protected by the signature.  Thus, it is trivial to
    /// modify it in transit.  For this reason, the Issuer Fingerprint
    /// subpacket should be preferred, when it is present.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn issuer(&self) -> Option<KeyID> {
        // 8-octet Key ID
        if let Some(sb)
                = self.subpacket(SubpacketTag::Issuer) {
            if let SubpacketValue::Issuer(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of all Notation Data packets.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: unlike other subpacket accessor functions, this function
    /// returns all the Notation Data subpackets, not just the last
    /// one.
    pub fn notation_data(&self) -> Vec<NotationData> {
        // 4 octets of flags, 2 octets of name length (M),
        // 2 octets of value length (N),
        // M octets of name data,
        // N octets of value data
        self.subpackets(SubpacketTag::NotationData)
            .into_iter().filter_map(|sb| {
                if let SubpacketValue::NotationData(v) = sb.value {
                    Some(v)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the value of the Preferred Hash Algorithms subpacket,
    /// which contains the list of hash algorithms that the key
    /// holders prefers, ordered according by the key holder's
    /// preference.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn preferred_hash_algorithms(&self) -> Option<&[u8]> {
        // array of one-octet values
        if let Some(sb)
                = self.subpacket(
                    SubpacketTag::PreferredHashAlgorithms) {
            if let SubpacketValue::PreferredHashAlgorithms(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Preferred Compression Algorithms
    /// subpacket, which contains the list of compression algorithms
    /// that the key holder prefers, ordered according by the key
    /// holder's preference.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn preferred_compression_algorithms(&self) -> Option<&[u8]> {
        // array of one-octet values
        if let Some(sb)
                = self.subpacket(
                    SubpacketTag::PreferredCompressionAlgorithms) {
            if let SubpacketValue::PreferredCompressionAlgorithms(v)
                    = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Key Server Preferences subpacket,
    /// which contains the key holder's key server preferences.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn key_server_preferences(&self) -> Option<&[u8]> {
        // N octets of flags
        if let Some(sb)
                = self.subpacket(SubpacketTag::KeyServerPreferences) {
            if let SubpacketValue::KeyServerPreferences(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Preferred Key Server subpacket, which
    /// contains the user's preferred key server for updates.
    ///
    /// Note: this packet should be ignored, because it acts as key
    /// tracker.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn preferred_key_server(&self) -> Option<&[u8]> {
        // String
        if let Some(sb)
                = self.subpacket(SubpacketTag::PreferredKeyServer) {
            if let SubpacketValue::PreferredKeyServer(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Primary UserID subpacket, which
    /// indicates whether the referenced UserID should be considered
    /// the user's primary User ID.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn primary_userid(&self) -> Option<bool> {
        // 1 octet, Boolean
        if let Some(sb)
                = self.subpacket(SubpacketTag::PrimaryUserID) {
            if let SubpacketValue::PrimaryUserID(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Policy URI subpacket.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn policy_uri(&self) -> Option<&[u8]> {
        // String
        if let Some(sb)
                = self.subpacket(SubpacketTag::PolicyURI) {
            if let SubpacketValue::PolicyURI(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Key Flags subpacket, which contains
    /// information about the referenced key, in particular, how it is
    /// used (certification, signing, encryption, authentication), and
    /// how it is stored (split, held by multiple people).
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn key_flags(&self) -> Option<&[u8]> {
        // N octets of flags
        if let Some(sb)
                = self.subpacket(SubpacketTag::KeyFlags) {
            if let SubpacketValue::KeyFlags(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Signer's UserID subpacket, which
    /// contains the User ID that the key holder considers responsible
    /// for the signature.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn signers_user_id(&self) -> Option<&[u8]> {
        // String
        if let Some(sb)
                = self.subpacket(SubpacketTag::SignersUserID) {
            if let SubpacketValue::SignersUserID(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Reason for Revocation subpacket.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn reason_for_revocation(&self) -> Option<(u8, &[u8])> {
        // 1 octet of revocation code, N octets of reason string
        if let Some(sb)
                = self.subpacket(SubpacketTag::ReasonForRevocation) {
            if let SubpacketValue::ReasonForRevocation(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Features subpacket, which contains a
    /// list of features that the user's OpenPGP implementation
    /// supports.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn features(&self) -> Option<&[u8]> {
        // N octets of flags
        if let Some(sb)
                = self.subpacket(SubpacketTag::Features) {
            if let SubpacketValue::Features(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Signature Target subpacket, which
    /// contains the hash of hash of the referenced signature packet.
    ///
    /// This is used, for instance, by a signature revocation
    /// certification to designate the signature that is being
    /// revoked.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn signature_target(&self) -> Option<(u8, u8, &[u8])> {
        // 1 octet public-key algorithm, 1 octet hash algorithm, N
        // octets hash
        if let Some(sb)
                = self.subpacket(SubpacketTag::SignatureTarget) {
            if let SubpacketValue::SignatureTarget(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Embedded Signature subpacket, which
    /// contains a signature.
    ///
    /// This is used, for instance, to store a subkey's primary key
    /// binding signature (0x19).
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn embedded_signature(&self) -> Option<Packet> {
        // 1 signature packet body
        if let Some(sb)
                = self.subpacket(SubpacketTag::EmbeddedSignature) {
            if let SubpacketValue::EmbeddedSignature(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Returns the value of the Issuer Fingerprint subpacket, which
    /// contains the fingerprint of the key that allegedly created
    /// this signature.
    ///
    /// This subpacket should be preferred to the Issuer subpacket,
    /// because Fingerprints are not subject to collisions, and the
    /// Issuer subpacket is, for historic reasons, traditionally
    /// stored in the unhashed area, i.e., it is not cryptographically
    /// secured.
    ///
    /// This is used, for instance, to store a subkey's primary key
    /// binding signature (0x19).
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn issuer_fingerprint(&self) -> Option<Fingerprint> {
        // 1 octet key version number, N octets of fingerprint
        if let Some(sb)
                = self.subpacket(SubpacketTag::IssuerFingerprint) {
            if let SubpacketValue::IssuerFingerprint(v) = sb.value {
                Some(v)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[test]
fn subpacket_test_1 () {
    use Message;

    let path = path_to("signed.gpg");
    let message = Message::from_file(&path).unwrap();
    eprintln!("Message has {} top-level packets.", message.children().len());
    eprintln!("Message: {:?}", message);

    let mut count = 0;
    for p in message.descendants() {
        if let &Packet::Signature(ref sig) = p {
            count += 1;

            let mut got2 = false;
            let mut got16 = false;
            let mut got33 = false;

            for i in 0..255 {
                if let Some(sb) = sig.subpacket(i.into()) {
                    if i == 2 {
                        got2 = true;
                        assert!(!sb.critical);
                    } else if i == 16 {
                        got16 = true;
                        assert!(!sb.critical);
                    } else if i == 33 {
                        got33 = true;
                        assert!(!sb.critical);
                    } else {
                        panic!("Unexpectedly found subpacket {}", i);
                    }
                }
            }

            assert!(got2 && got16 && got33);

            let fp = sig.issuer_fingerprint().unwrap().to_string();
            // eprintln!("Issuer: {}", fp);
            assert!(
                fp == "7FAF 6ED7 2381 4355 7BDF  7ED2 6863 C9AD 5B4D 22D3"
                || fp == "C03F A641 1B03 AE12 5764  6118 7223 B566 78E0 2528");

            let hex = sig.issuer_fingerprint().unwrap().to_hex();
            assert!(
                hex == "7FAF6ED7238143557BDF7ED26863C9AD5B4D22D3"
                || hex == "C03FA6411B03AE12576461187223B56678E02528");
        }
    }
    // 2 packets have subpackets.
    assert_eq!(count, 2);
}

#[test]
fn subpacket_test_2() {
    use Message;

    //   Test #    Subpacket
    // 1 2 3 4 5 6   SignatureCreationTime
    //               * SignatureExpirationTime
    //   2           ExportableCertification
    //           6   TrustSignature
    //           6   RegularExpression
    //     3         Revocable
    // 1           7 KeyExpirationTime
    // 1             PreferredSymmetricAlgorithms
    //     3         RevocationKey
    // 1   3       7 Issuer
    // 1   3   5     NotationData
    // 1             PreferredHashAlgorithms
    // 1             PreferredCompressionAlgorithms
    // 1             KeyServerPreferences
    //               * PreferredKeyServer
    //               * PrimaryUserID
    //               * PolicyURI
    // 1             KeyFlags
    //               * SignersUserID
    //       4       ReasonForRevocation
    // 1             Features
    //               * SignatureTarget
    //             7 EmbeddedSignature
    // 1   3       7 IssuerFingerprint
    //
    // XXX: The subpackets marked with * are not tested.

    let message
        = Message::from_file(path_to("../keys/subpackets/shaw.gpg")).unwrap();

    // Test #1
    if let Some(&Packet::Signature(ref sig)) = message.children().nth(2) {
        //  tag: 2, SignatureCreationTime(1515791508) }
        //  tag: 9, KeyExpirationTime(63072000) }
        //  tag: 11, PreferredSymmetricAlgorithms([9, 8, 7, 2]) }
        //  tag: 16, Issuer(KeyID("F004 B9A4 5C58 6126")) }
        //  tag: 20, NotationData(NotationData { flags: 2147483648, name: [114, 97, 110, 107, 64, 110, 97, 118, 121, 46, 109, 105, 108], value: [109, 105, 100, 115, 104, 105, 112, 109, 97, 110] }) }
        //  tag: 21, PreferredHashAlgorithms([8, 9, 10, 11, 2]) }
        //  tag: 22, PreferredCompressionAlgorithms([2, 3, 1]) }
        //  tag: 23, KeyServerPreferences([128]) }
        //  tag: 27, KeyFlags([3]) }
        //  tag: 30, Features([1]) }
        //  tag: 33, IssuerFingerprint(Fingerprint("361A 96BD E1A6 5B6D 6C25  AE9F F004 B9A4 5C58 6126")) }
        // for i in 0..256 {
        //     if let Some(sb) = sig.subpacket(i as u8) {
        //         eprintln!("  {:?}", sb);
        //     }
        // }

        assert_eq!(sig.signature_creation_time(), Some(1515791508));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(1515791508)
                   }));

        assert_eq!(sig.key_expiration_time(), Some(63072000));
        assert_eq!(sig.subpacket(SubpacketTag::KeyExpirationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::KeyExpirationTime,
                       value: SubpacketValue::KeyExpirationTime(63072000)
                   }));

        assert_eq!(sig.preferred_symmetric_algorithms(),
                   Some(&[9, 8, 7, 2][..]));
        assert_eq!(sig.subpacket(SubpacketTag::PreferredSymmetricAlgorithms),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::PreferredSymmetricAlgorithms,
                       value: SubpacketValue::PreferredSymmetricAlgorithms(
                           &[9, 8, 7, 2][..])
                   }));

        assert_eq!(sig.preferred_hash_algorithms(),
                   Some(&[8, 9, 10, 11, 2][..]));
        assert_eq!(sig.subpacket(SubpacketTag::PreferredHashAlgorithms),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::PreferredHashAlgorithms,
                       value: SubpacketValue::PreferredHashAlgorithms(
                           &[8, 9, 10, 11, 2][..])
                   }));

        assert_eq!(sig.preferred_compression_algorithms(),
                   Some(&[2, 3, 1][..]));
        assert_eq!(sig.subpacket(SubpacketTag::PreferredCompressionAlgorithms),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::PreferredCompressionAlgorithms,
                       value: SubpacketValue::PreferredCompressionAlgorithms(
                           &[2, 3, 1][..])
                   }));

        assert_eq!(sig.key_server_preferences(), Some(&[0x80][..]));
        assert_eq!(sig.subpacket(SubpacketTag::KeyServerPreferences),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::KeyServerPreferences,
                       value: SubpacketValue::KeyServerPreferences(
                           &[0x80][..])
                   }));

        assert_eq!(sig.key_flags(), Some(&[0x03][..]));
        assert_eq!(sig.subpacket(SubpacketTag::KeyFlags),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::KeyFlags,
                       value: SubpacketValue::KeyFlags(&[0x03][..])
                   }));

        assert_eq!(sig.features(), Some(&[0x01][..]));
        assert_eq!(sig.subpacket(SubpacketTag::Features),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::Features,
                       value: SubpacketValue::Features(&[0x01][..])
                   }));

        let keyid = KeyID::from_hex("F004 B9A4 5C58 6126").unwrap();
        assert_eq!(sig.issuer(), Some(keyid.clone()));
        assert_eq!(sig.subpacket(SubpacketTag::Issuer),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::Issuer,
                       value: SubpacketValue::Issuer(keyid)
                   }));

        let fp = Fingerprint::from_hex(
            "361A96BDE1A65B6D6C25AE9FF004B9A45C586126").unwrap();
        assert_eq!(sig.issuer_fingerprint(), Some(fp.clone()));
        assert_eq!(sig.subpacket(SubpacketTag::IssuerFingerprint),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::IssuerFingerprint,
                       value: SubpacketValue::IssuerFingerprint(fp)
                   }));

        let n = NotationData {
            flags: 1 << 31,
            name: "rank@navy.mil".as_bytes(),
            value: "midshipman".as_bytes()
        };
        assert_eq!(sig.notation_data(), vec![n.clone()]);
        assert_eq!(sig.subpacket(SubpacketTag::NotationData),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::NotationData,
                       value: SubpacketValue::NotationData(n.clone())
                   }));
        assert_eq!(sig.subpackets(SubpacketTag::NotationData),
                   vec![(Subpacket {
                       critical: false,
                       tag: SubpacketTag::NotationData,
                       value: SubpacketValue::NotationData(n.clone())
                   })]);
    } else {
        panic!("Expected signature!");
    }

    // Test #2
    if let Some(&Packet::Signature(ref sig)) = message.children().nth(3) {
        // tag: 2, SignatureCreationTime(1515791490)
        // tag: 4, ExportableCertification(false)
        // tag: 16, Issuer(KeyID("CEAD 0621 0934 7957"))
        // tag: 33, IssuerFingerprint(Fingerprint("B59B 8817 F519 DCE1 0AFD  85E4 CEAD 0621 0934 7957"))

        // for i in 0..256 {
        //     if let Some(sb) = sig.subpacket(i as u8) {
        //         eprintln!("  {:?}", sb);
        //     }
        // }

        assert_eq!(sig.signature_creation_time(), Some(1515791490));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(1515791490)
                   }));

        assert_eq!(sig.exportable_certification(), Some(false));
        assert_eq!(sig.subpacket(SubpacketTag::ExportableCertification),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::ExportableCertification,
                       value: SubpacketValue::ExportableCertification(false)
                   }));
    }

    let message
        = Message::from_file(path_to("../keys/subpackets/marven.gpg")).unwrap();

    // Test #3
    if let Some(&Packet::Signature(ref sig)) = message.children().nth(1) {
        // tag: 2, SignatureCreationTime(1515791376)
        // tag: 7, Revocable(false)
        // tag: 12, RevocationKey((128, 1, Fingerprint("361A 96BD E1A6 5B6D 6C25  AE9F F004 B9A4 5C58 6126")))
        // tag: 16, Issuer(KeyID("CEAD 0621 0934 7957"))
        // tag: 33, IssuerFingerprint(Fingerprint("B59B 8817 F519 DCE1 0AFD  85E4 CEAD 0621 0934 7957"))

        // for i in 0..256 {
        //     if let Some(sb) = sig.subpacket(i as u8) {
        //         eprintln!("  {:?}", sb);
        //     }
        // }

        assert_eq!(sig.signature_creation_time(), Some(1515791376));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(1515791376)
                   }));

        assert_eq!(sig.revocable(), Some(false));
        assert_eq!(sig.subpacket(SubpacketTag::Revocable),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::Revocable,
                       value: SubpacketValue::Revocable(false)
                   }));

        let fp = Fingerprint::from_hex(
            "361A96BDE1A65B6D6C25AE9FF004B9A45C586126").unwrap();
        assert_eq!(sig.revocation_key(), Some((128, 1, fp.clone())));
        assert_eq!(sig.subpacket(SubpacketTag::RevocationKey),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::RevocationKey,
                       value: SubpacketValue::RevocationKey((0x80, 1, fp))
                   }));


        let keyid = KeyID::from_hex("CEAD 0621 0934 7957").unwrap();
        assert_eq!(sig.issuer(), Some(keyid.clone()));
        assert_eq!(sig.subpacket(SubpacketTag::Issuer),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::Issuer,
                       value: SubpacketValue::Issuer(keyid)
                   }));

        let fp = Fingerprint::from_hex(
            "B59B8817F519DCE10AFD85E4CEAD062109347957").unwrap();
        assert_eq!(sig.issuer_fingerprint(), Some(fp.clone()));
        assert_eq!(sig.subpacket(SubpacketTag::IssuerFingerprint),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::IssuerFingerprint,
                       value: SubpacketValue::IssuerFingerprint(fp)
                   }));

        // This signature does not contain any notation data.
        assert_eq!(sig.notation_data(), vec![]);
        assert_eq!(sig.subpacket(SubpacketTag::NotationData),
                   None);
        assert_eq!(sig.subpackets(SubpacketTag::NotationData),
                   vec![]);
    } else {
        panic!("Expected signature!");
    }

    // Test #4
    if let Some(&Packet::Signature(ref sig)) = message.children().nth(6) {
        // for i in 0..256 {
        //     if let Some(sb) = sig.subpacket(i as u8) {
        //         eprintln!("  {:?}", sb);
        //     }
        // }

        assert_eq!(sig.signature_creation_time(), Some(1515886658));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(1515886658)
                   }));

        assert_eq!(sig.reason_for_revocation(),
                   Some((0, &b"Forgot to set a sig expiration."[..])));
        assert_eq!(sig.subpacket(SubpacketTag::ReasonForRevocation),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::ReasonForRevocation,
                       value: SubpacketValue::ReasonForRevocation(
                           (0, &b"Forgot to set a sig expiration."[..]))
                   }));
    }


    // Test #5
    if let Some(&Packet::Signature(ref sig)) = message.children().nth(7) {
        // The only thing interesting about this signature is that it
        // has multiple notations.

        assert_eq!(sig.signature_creation_time(), Some(1515791467));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(1515791467)
                   }));

        let n1 = NotationData {
            flags: 1 << 31,
            name: "rank@navy.mil".as_bytes(),
            value: "third lieutenant".as_bytes()
        };
        let n2 = NotationData {
            flags: 1 << 31,
            name: "foo@navy.mil".as_bytes(),
            value: "bar".as_bytes()
        };
        let n3 = NotationData {
            flags: 1 << 31,
            name: "whistleblower@navy.mil".as_bytes(),
            value: "true".as_bytes()
        };

        // We expect all three notations, in order.
        assert_eq!(sig.notation_data(), vec![n1.clone(), n2.clone(), n3.clone()]);

        // We expect only the last notation.
        assert_eq!(sig.subpacket(SubpacketTag::NotationData),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::NotationData,
                       value: SubpacketValue::NotationData(n3.clone())
                   }));

        // We expect all three notations, in order.
        assert_eq!(sig.subpackets(SubpacketTag::NotationData),
                   vec![
                       Subpacket {
                           critical: false,
                           tag: SubpacketTag::NotationData,
                           value: SubpacketValue::NotationData(n1)
                       },
                       Subpacket {
                           critical: false,
                           tag: SubpacketTag::NotationData,
                           value: SubpacketValue::NotationData(n2)
                       },
                       Subpacket {
                           critical: false,
                           tag: SubpacketTag::NotationData,
                           value: SubpacketValue::NotationData(n3)
                       },
                   ]);
    }

    // # Test 6
    if let Some(&Packet::Signature(ref sig)) = message.children().nth(8) {
        // A trusted signature.

        // tag: 2, SignatureCreationTime(1515791223)
        // tag: 5, TrustSignature((2, 120))
        // tag: 6, RegularExpression([60, 91, 94, 62, 93, 43, 91, 64, 46, 93, 110, 97, 118, 121, 92, 46, 109, 105, 108, 62, 36])
        // tag: 16, Issuer(KeyID("F004 B9A4 5C58 6126"))
        // tag: 33, IssuerFingerprint(Fingerprint("361A 96BD E1A6 5B6D 6C25  AE9F F004 B9A4 5C58 6126"))

        // for i in 0..256 {
        //     if let Some(sb) = sig.subpacket(i as u8) {
        //         eprintln!("  {:?}", sb);
        //     }
        // }

        assert_eq!(sig.signature_creation_time(), Some(1515791223));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(1515791223)
                   }));

        assert_eq!(sig.trust_signature(), Some((2, 120)));
        assert_eq!(sig.subpacket(SubpacketTag::TrustSignature),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::TrustSignature,
                       value: SubpacketValue::TrustSignature((2, 120))
                   }));

        // Note: our parser strips the trailing NUL.
        let regex = &b"<[^>]+[@.]navy\\.mil>$"[..];
        assert_eq!(sig.regular_expression(), Some(regex));
        assert_eq!(sig.subpacket(SubpacketTag::RegularExpression),
                   Some(Subpacket {
                       critical: true,
                       tag: SubpacketTag::RegularExpression,
                       value: SubpacketValue::RegularExpression(regex)
                   }));
    }

    // Test #7
    if let Some(&Packet::Signature(ref sig)) = message.children().nth(11) {
        // A subkey self-sig, which contains an embedded signature.
        //  tag: 2, SignatureCreationTime(1515798986)
        //  tag: 9, KeyExpirationTime(63072000)
        //  tag: 16, Issuer(KeyID("CEAD 0621 0934 7957"))
        //  tag: 27, KeyFlags([2])
        //  tag: 32, EmbeddedSignature(Signature(Signature {
        //    version: 4, sigtype: 25, timestamp: Some(1515798986),
        //    issuer: "F682 42EA 9847 7034 5DEC  5F08 4688 10D3 D67F 6CA9",
        //    pk_algo: 1, hash_algo: 8, hashed_area: "29 bytes",
        //    unhashed_area: "10 bytes", hash_prefix: [162, 209],
        //    mpis: "258 bytes"))
        //  tag: 33, IssuerFingerprint(Fingerprint("B59B 8817 F519 DCE1 0AFD  85E4 CEAD 0621 0934 7957"))

        // for i in 0..256 {
        //     if let Some(sb) = sig.subpacket(i as u8) {
        //         eprintln!("  {:?}", sb);
        //     }
        // }

        assert_eq!(sig.key_expiration_time(), Some(63072000));
        assert_eq!(sig.subpacket(SubpacketTag::KeyExpirationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::KeyExpirationTime,
                       value: SubpacketValue::KeyExpirationTime(63072000)
                   }));

        let keyid = KeyID::from_hex("CEAD 0621 0934 7957").unwrap();
        assert_eq!(sig.issuer(), Some(keyid.clone()));
        assert_eq!(sig.subpacket(SubpacketTag::Issuer),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::Issuer,
                       value: SubpacketValue::Issuer(keyid)
                   }));

        let fp = Fingerprint::from_hex(
            "B59B8817F519DCE10AFD85E4CEAD062109347957").unwrap();
        assert_eq!(sig.issuer_fingerprint(), Some(fp.clone()));
        assert_eq!(sig.subpacket(SubpacketTag::IssuerFingerprint),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::IssuerFingerprint,
                       value: SubpacketValue::IssuerFingerprint(fp)
                   }));

        assert!(sig.embedded_signature().is_some());
        assert!(sig.subpacket(SubpacketTag::EmbeddedSignature)
                .is_some());
    }

//     for (i, p) in message.children().enumerate() {
//         if let &Packet::Signature(ref sig) = p {
//             eprintln!("{:?}: {:?}", i, sig);
//             for j in 0..256 {
//                 if let Some(sb) = sig.subpacket(j as u8) {
//                     eprintln!("  {:?}", sb);
//                 }
//             }
//         }
//     }
}
