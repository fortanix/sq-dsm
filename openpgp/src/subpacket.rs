//! Signature subpackets.
//!
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
//! [`Signature`]: ../struct.Signature.html
//!
//! # Examples
//!
//! If a signature packet includes an issuer fingerprint subpacket,
//! print it:
//!
//! ```rust
//! # use openpgp::Result;
//! # use openpgp::Packet;
//! # use openpgp::parse::{PacketParserResult, PacketParser};
//! #
//! # f(include_bytes!("../tests/data/messages/signed.gpg"));
//! #
//! # fn f(message_data: &[u8]) -> Result<()> {
//! let mut ppr = PacketParser::from_bytes(message_data)?;
//! while let PacketParserResult::Some(mut pp) = ppr {
//!     if let Packet::Signature(ref sig) = pp.packet {
//!         if let Some(fp) = sig.issuer_fingerprint() {
//!             eprintln!("Signature issued by: {}", fp.to_string());
//!         }
//!     }
//!
//!     // Get the next packet.
//!     let (_packet, _packet_depth, tmp, _pp_depth) = pp.recurse()?;
//!     ppr = tmp;
//! }
//! # Ok(())
//! # }
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::io;
use time;

use quickcheck::{Arbitrary, Gen};

use buffered_reader::{BufferedReader, BufferedReaderMemory};

use {
    Error,
    Result,
    Signature,
    Packet,
    Fingerprint,
    Key,
    KeyID,
};
use constants::{
    CompressionAlgorithm,
    HashAlgorithm,
    PublicKeyAlgorithm,
    ReasonForRevocation,
    SymmetricAlgorithm,
};
use conversions::{
    Time,
    Duration,
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
#[allow(missing_docs)]
pub enum SubpacketTag {
    /// The time the signature was made.
    SignatureCreationTime,
    /// The validity period of the signature.
    SignatureExpirationTime,
    /// This subpacket denotes whether a certification signature is
    /// "exportable", to be used by other users than the signature's issuer.
    ExportableCertification,
    /// Signer asserts that the key is not only valid but also trustworthy at
    /// the specified level.
    TrustSignature,
    /// Used in conjunction with trust Signature packets (of level > 0) to
    /// limit the scope of trust that is extended.
    RegularExpression,
    /// Signature's revocability status.
    Revocable,
    /// The validity period of the key.
    KeyExpirationTime,
    /// Deprecated
    PlaceholderForBackwardCompatibility,
    /// Symmetric algorithm numbers that indicate which algorithms the key
    /// holder prefers to use.
    PreferredSymmetricAlgorithms,
    /// Authorizes the specified key to issue revocation signatures for this
    /// key.
    RevocationKey,
    /// The OpenPGP Key ID of the key issuing the signature.
    Issuer,
    /// This subpacket describes a "notation" on the signature that the
    /// issuer wishes to make.
    NotationData,
    /// Message digest algorithm numbers that indicate which algorithms the
    /// key holder prefers to receive.
    PreferredHashAlgorithms,
    /// Compression algorithm numbers that indicate which algorithms the key
    /// holder prefers to use.
    PreferredCompressionAlgorithms,
    /// This is a list of one-bit flags that indicate preferences that the
    /// key holder has about how the key is handled on a key server.
    KeyServerPreferences,
    /// This is a URI of a key server that the key holder prefers be used for
    /// updates.
    PreferredKeyServer,
    /// This is a flag in a User ID's self-signature that states whether this
    /// User ID is the main User ID for this key.
    PrimaryUserID,
    /// This subpacket contains a URI of a document that describes the policy
    /// under which the signature was issued.
    PolicyURI,
    /// This subpacket contains a list of binary flags that hold information
    /// about a key.
    KeyFlags,
    /// This subpacket allows a keyholder to state which User ID is
    /// responsible for the signing.
    SignersUserID,
    /// This subpacket is used only in key revocation and certification
    /// revocation signatures.
    ReasonForRevocation,
    /// The Features subpacket denotes which advanced OpenPGP features a
    /// user's implementation supports.
    Features,
    /// This subpacket identifies a specific target signature to which a
    /// signature refers.
    SignatureTarget,
    /// This subpacket contains a complete Signature packet body
    EmbeddedSignature,
    /// Added in RFC 4880bis.
    IssuerFingerprint,
    /// Intended Recipient Fingerprint [proposed].
    IntendedRecipient,
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
            35 => SubpacketTag::IntendedRecipient,
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
            SubpacketTag::IntendedRecipient => 35,
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

        f.debug_struct("SubpacketRaw")
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
    /// Raw, unparsed subpacket data.
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
        let len = SubpacketLength::parse(&mut self.reader);
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
        f.debug_list().entries(
            self.iter().map(|(_start, _len, sb)| {
                Subpacket::from(sb)
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

impl SubpacketArea {
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

    /// Invalidates the cache.
    fn cache_invalidate(&self) {
        *self.parsed.borrow_mut() = None;
    }

    /// Returns the last subpacket, if any, with the specified tag.
    pub fn lookup(&self, tag: SubpacketTag) -> Option<Subpacket> {
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

    /// Adds the given subpacket.
    ///
    /// # Errors
    ///
    /// Returns `Error::MalformedPacket` if adding the packet makes
    /// the subpacket area exceed the size limit.
    pub fn add(&mut self, packet: Subpacket) -> Result<()> {
        use serialize::Serialize;

        if self.data.len() + packet.len() > ::std::u16::MAX as usize {
            return Err(Error::MalformedPacket(
                "Subpacket area exceeds maximum size".into()).into());
        }

        self.cache_invalidate();
        packet.serialize(&mut self.data)
    }

    /// Adds the given subpacket, replacing all other subpackets with
    /// the same tag.
    ///
    /// # Errors
    ///
    /// Returns `Error::MalformedPacket` if adding the packet makes
    /// the subpacket area exceed the size limit.
    pub fn replace(&mut self, packet: Subpacket) -> Result<()> {
        let old = self.remove_all(packet.tag);
        if let Err(e) = self.add(packet) {
            // Restore old state.
            self.data = old;
            return Err(e);
        }
        Ok(())
    }

    /// Removes all subpackets with the given tag.
    ///
    /// Returns the old subpacket area, so that it can be restored if
    /// necessary.
    pub fn remove_all(&mut self, tag: SubpacketTag) -> Vec<u8> {
        let mut new = Vec::new();

        // Copy all but the matching subpackets.
        for (_, _, raw) in self.iter() {
            if raw.tag == tag {
                // Drop.
                continue;
            }

            let l: SubpacketLength = 1 + raw.value.len() as u32;
            let tag = u8::from(raw.tag)
                | if raw.critical { 1 << 7 } else { 0 };

            l.serialize(&mut new).unwrap();
            new.push(tag);
            new.extend_from_slice(raw.value);
        }

        self.cache_invalidate();
        ::std::mem::replace(&mut self.data, new)
    }
}

/// Payload of a NotationData subpacket.
#[derive(Debug, PartialEq, Clone)]
pub struct NotationData<'a> {
    flags: u32,
    name: &'a [u8],
    value: &'a [u8],
}

impl<'a> NotationData<'a> {
    /// Returns the flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the name.
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// Returns the value.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// Struct holding an arbitrary subpacket.
///
/// The value is well structured.  See `SubpacketTag` for a
/// description of these tags.
#[derive(Debug, PartialEq, Clone)]
pub enum SubpacketValue<'a> {
    /// The subpacket is unknown.
    Unknown(&'a [u8]),
    /// The packet is present, but the value is structured incorrectly.
    Invalid(&'a [u8]),

    /// 4-octet time field
    SignatureCreationTime(time::Tm),
    /// 4-octet time field
    SignatureExpirationTime(time::Duration),
    /// 1 octet of exportability, 0 for not, 1 for exportable
    ExportableCertification(bool),
    /// 1 octet "level" (depth), 1 octet of trust amount
    TrustSignature {
        /// Trust level, or depth.
        ///
        /// Level 0 has the same meaning as an ordinary validity
        /// signature.  Level 1 means that the signed key is asserted
        /// to be a valid trusted introducer, with the 2nd octet of
        /// the body specifying the degree of trust.  Level 2 means
        /// that the signed key is asserted to be trusted to issue
        /// level 1 trust signatures, i.e., that it is a "meta
        /// introducer".
        level: u8,

        /// Trust amount.
        ///
        /// This is interpreted such that values less than 120
        /// indicate partial trust and values of 120 or greater
        /// indicate complete trust.  Implementations SHOULD emit
        /// values of 60 for partial trust and 120 for complete trust.
        trust: u8,
    },
    /// Null-terminated regular expression
    RegularExpression(&'a [u8]),
    /// 1 octet of revocability, 0 for not, 1 for revocable
    Revocable(bool),
    /// 4-octet time field.
    KeyExpirationTime(time::Duration),
    /// Array of one-octet values
    PreferredSymmetricAlgorithms(Vec<SymmetricAlgorithm>),
    /// 1 octet of class, 1 octet of public-key algorithm ID, 20 octets of
    /// fingerprint
    RevocationKey {
        /// Class octet must have bit 0x80 set.  If the bit 0x40 is
        /// set, then this means that the revocation information is
        /// sensitive.  Other bits are for future expansion to other
        /// kinds of authorizations.
        class: u8,

        /// XXX: RFC4880 says nothing about this.
        pk_algo: PublicKeyAlgorithm,

        /// Fingerprint of authorized key.
        fp: Fingerprint,
    },
    /// 8-octet Key ID
    Issuer(KeyID),
    /// The notation has a name and a value, each of
    /// which are strings of octets..
    NotationData(NotationData<'a>),
    /// Array of one-octet values
    PreferredHashAlgorithms(Vec<HashAlgorithm>),
    /// Array of one-octet values
    PreferredCompressionAlgorithms(Vec<CompressionAlgorithm>),
    /// N octets of flags
    KeyServerPreferences(KeyServerPreferences),
    /// String (URL)
    PreferredKeyServer(&'a [u8]),
    /// 1 octet, Boolean
    PrimaryUserID(bool),
    /// String (URL)
    PolicyURI(&'a [u8]),
    /// N octets of flags
    KeyFlags(KeyFlags),
    /// String
    SignersUserID(&'a [u8]),
    /// 1 octet of revocation code, N octets of reason string
    ReasonForRevocation {
        /// Machine-readable reason for revocation.
        code: ReasonForRevocation,

        /// Human-readable reason for revocation.
        reason: &'a [u8],
    },
    /// N octets of flags
    Features(Features),
    /// 1-octet public-key algorithm, 1 octet hash algorithm, N octets hash
    SignatureTarget {
        /// Public-key algorithm of the target signature.
        pk_algo: PublicKeyAlgorithm,
        /// Hash algorithm of the target signature.
        hash_algo: HashAlgorithm,
        /// Hash digest of the target signature.
        digest: &'a [u8],
    },
    /// An embedded signature.
    ///
    /// This is a packet rather than a `Signature`, because we also
    /// want to return an `Unknown` packet.
    EmbeddedSignature(Packet),
    /// 20-octet V4 fingerprint.
    IssuerFingerprint(Fingerprint),
    /// Intended Recipient Fingerprint [proposed].
    IntendedRecipient(Fingerprint),
}

impl<'a> SubpacketValue<'a> {
    /// Returns the length of the serialized value.
    pub fn len(&self) -> SubpacketLength {
        use self::SubpacketValue::*;
        (match self {
            SignatureCreationTime(_) => 4,
            SignatureExpirationTime(_) => 4,
            ExportableCertification(_) => 1,
            TrustSignature { .. } => 2,
            RegularExpression(re) => re.len() + 1 /* terminator */,
            Revocable(_) => 1,
            KeyExpirationTime(_) => 4,
            PreferredSymmetricAlgorithms(p) => p.len(),
            RevocationKey { ref fp, .. } => 1 + 1 + fp.as_slice().len(),
            Issuer(_) => 8,
            NotationData(nd) => 4 + 2 + 2 + nd.name.len() + nd.value.len(),
            PreferredHashAlgorithms(p) => p.len(),
            PreferredCompressionAlgorithms(p) => p.len(),
            KeyServerPreferences(p) => p.as_slice().len(),
            PreferredKeyServer(p) => p.len(),
            PrimaryUserID(_) => 1,
            PolicyURI(p) => p.len(),
            KeyFlags(f) => f.0.len(),
            SignersUserID(u) => u.len(),
            ReasonForRevocation { ref reason, .. } => 1 + reason.len(),
            Features(f) => f.0.len(),
            SignatureTarget { ref digest, .. } => 1 + 1 + digest.len(),
            EmbeddedSignature(p) => match p {
                &Packet::Signature(ref sig) => {
                    let mut w = Vec::new();
                    sig.serialize_naked(&mut w).unwrap();
                    w.len()
                },
                // Bogus.
                _ => 0,
            },
            IssuerFingerprint(ref fp) => match fp {
                Fingerprint::V4(_) => 1 + 20,
                // Educated guess for unknown versions.
                Fingerprint::Invalid(_) => 1 + fp.as_slice().len(),
            },
            IntendedRecipient(ref fp) => match fp {
                Fingerprint::V4(_) => 1 + 20,
                // Educated guess for unknown versions.
                Fingerprint::Invalid(_) => 1 + fp.as_slice().len(),
            },
            Unknown(u) => u.len(),
            Invalid(i) => i.len(),
        } as u32)
    }

    /// Returns the subpacket tag for this value.
    pub fn tag(&self) -> Result<SubpacketTag> {
        use self::SubpacketValue::*;
        match &self {
            SignatureCreationTime(_) => Ok(SubpacketTag::SignatureCreationTime),
            SignatureExpirationTime(_) =>
                Ok(SubpacketTag::SignatureExpirationTime),
            ExportableCertification(_) =>
                Ok(SubpacketTag::ExportableCertification),
            TrustSignature { .. } => Ok(SubpacketTag::TrustSignature),
            RegularExpression(_) => Ok(SubpacketTag::RegularExpression),
            Revocable(_) => Ok(SubpacketTag::Revocable),
            KeyExpirationTime(_) => Ok(SubpacketTag::KeyExpirationTime),
            PreferredSymmetricAlgorithms(_) =>
                Ok(SubpacketTag::PreferredSymmetricAlgorithms),
            RevocationKey { .. } => Ok(SubpacketTag::RevocationKey),
            Issuer(_) => Ok(SubpacketTag::Issuer),
            NotationData(_) => Ok(SubpacketTag::NotationData),
            PreferredHashAlgorithms(_) =>
                Ok(SubpacketTag::PreferredHashAlgorithms),
            PreferredCompressionAlgorithms(_) =>
                Ok(SubpacketTag::PreferredCompressionAlgorithms),
            KeyServerPreferences(_) => Ok(SubpacketTag::KeyServerPreferences),
            PreferredKeyServer(_) => Ok(SubpacketTag::PreferredKeyServer),
            PrimaryUserID(_) => Ok(SubpacketTag::PrimaryUserID),
            PolicyURI(_) => Ok(SubpacketTag::PolicyURI),
            KeyFlags(_) => Ok(SubpacketTag::KeyFlags),
            SignersUserID(_) => Ok(SubpacketTag::SignersUserID),
            ReasonForRevocation { .. } => Ok(SubpacketTag::ReasonForRevocation),
            Features(_) => Ok(SubpacketTag::Features),
            SignatureTarget { .. } => Ok(SubpacketTag::SignatureTarget),
            EmbeddedSignature(_) => Ok(SubpacketTag::EmbeddedSignature),
            IssuerFingerprint(_) => Ok(SubpacketTag::IssuerFingerprint),
            IntendedRecipient(_) => Ok(SubpacketTag::IntendedRecipient),
            _ => Err(Error::InvalidArgument(
                "Unknown or invalid subpacket value".into()).into()),
        }
    }
}

/// Signature subpacket specified by [Section 5.2.3.1 of RFC 4880].
///
/// [Section 5.2.3.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.1
#[derive(PartialEq, Clone)]
pub struct Subpacket<'a> {
    /// Critical flag.
    pub critical: bool,
    /// Packet type.
    pub tag: SubpacketTag,
    /// Packet value, must match packet type.
    pub value: SubpacketValue<'a>,
}

impl<'a> fmt::Debug for Subpacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = f.debug_struct("Subpacket");

        if self.critical {
            s.field("critical", &self.critical);
        }
        s.field("value", &self.value);
        s.finish()
    }
}

impl<'a> Subpacket<'a> {
    /// Creates a new subpacket.
    pub fn new(value: SubpacketValue<'a>, critical: bool) -> Result<Subpacket<'a>> {
        Ok(Subpacket {
            critical: critical,
            tag: value.tag()?,
            value: value,
        })
    }

    /// Returns the length of the serialized subpacket.
    pub fn len(&self) -> usize {
        let value_len = self.value.len();
        1 + value_len.len() + value_len as usize

    }
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
                    SubpacketValue::SignatureCreationTime(time::Tm::from_pgp(v))
                }),

            SubpacketTag::SignatureExpirationTime =>
                // The time delta is in big endian format.
                from_be_u32(raw.value).map(|v| {
                    SubpacketValue::SignatureExpirationTime(
                        time::Duration::from_pgp(v))
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
                    Some(SubpacketValue::TrustSignature {
                        level: raw.value[0],
                        trust: raw.value[1],
                    })
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
                    SubpacketValue::KeyExpirationTime(
                        time::Duration::from_pgp(v))
                }),

            SubpacketTag::PreferredSymmetricAlgorithms =>
                // array of one-octet values.
                Some(SubpacketValue::PreferredSymmetricAlgorithms(
                    raw.value.iter().map(|o| (*o).into()).collect())),

            SubpacketTag::RevocationKey =>
                // 1 octet of class, 1 octet of pk algorithm, 20 bytes
                // for a v4 fingerprint and 32 bytes for a v5
                // fingerprint.
                if raw.value.len() > 2 {
                    Some(SubpacketValue::RevocationKey {
                        class: raw.value[0],
                        pk_algo: raw.value[1].into(),
                        fp: Fingerprint::from_bytes(&raw.value[2..]),
                    })
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
                    raw.value.iter().map(|o| (*o).into()).collect())),

            SubpacketTag::PreferredCompressionAlgorithms =>
                // array of one-octet values.
                Some(SubpacketValue::PreferredCompressionAlgorithms(
                    raw.value.iter().map(|o| (*o).into()).collect())),

            SubpacketTag::KeyServerPreferences =>
                // N octets of flags.
                Some(SubpacketValue::KeyServerPreferences(
                    KeyServerPreferences(raw.value.to_vec()))),

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
                Some(SubpacketValue::KeyFlags(KeyFlags(raw.value.to_vec()))),

            SubpacketTag::SignersUserID =>
                // String.
                Some(SubpacketValue::SignersUserID(raw.value)),

            SubpacketTag::ReasonForRevocation =>
                // 1 octet of revocation code, N octets of reason string
                if raw.value.len() >= 1 {
                    Some(SubpacketValue::ReasonForRevocation {
                        code: raw.value[0].into(),
                        reason: &raw.value[1..],
                    })
                } else {
                    None
                },

            SubpacketTag::Features =>
                // N octets of flags
                Some(SubpacketValue::Features(Features(raw.value.to_vec()))),

            SubpacketTag::SignatureTarget =>
                // 1 octet public-key algorithm, 1 octet hash algorithm,
                // N octets hash
                if raw.value.len() > 2 {
                    Some(SubpacketValue::SignatureTarget {
                        pk_algo: raw.value[0].into(),
                        hash_algo: raw.value[1].into(),
                        digest: &raw.value[2..],
                    })
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

            SubpacketTag::IntendedRecipient => {
                let version = raw.value.get(0);
                if let Some(version) = version {
                    if *version == 4 {
                        Some(SubpacketValue::IntendedRecipient(
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

pub(crate) type SubpacketLength = u32;
pub(crate) trait SubpacketLengthTrait {
    /// Parses a subpacket length.
    fn parse<C>(bio: &mut BufferedReaderMemory<C>) -> io::Result<u32>;
    /// Writes the subpacket length to `w`.
    fn serialize<W: io::Write>(&self, sink: &mut W) -> io::Result<()>;
    /// Returns the length of the serialized subpacket length.
    fn len(&self) -> usize;
}

impl SubpacketLengthTrait for SubpacketLength {
    fn parse<C>(bio: &mut BufferedReaderMemory<C>) -> io::Result<u32> {
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
        Ok(bio.read_be_u32()?)
    }

    fn serialize<W: io::Write>(&self, sink: &mut W) -> io::Result<()> {
        let v = *self;
        if v < 192 {
            sink.write_all(&[v as u8])
        } else if v < 16320 {
            let v = v - 192 + (192 << 8);
            sink.write_all(&[(v >> 8) as u8,
                             (v >> 0) as u8])
        } else {
            sink.write_all(&[(v >> 24) as u8,
                             (v >> 16) as u8,
                             (v >> 8) as u8,
                             (v >> 0) as u8])
        }
    }

    fn len(&self) -> usize {
        if *self < 192 {
            1
        } else if *self < 16320 {
            2
        } else {
            5
        }
    }
}

#[cfg(test)]
quickcheck! {
    fn length_roundtrip(length: SubpacketLength) -> bool {
        let mut encoded = Vec::new();
        length.serialize(&mut encoded).unwrap();
        assert_eq!(encoded.len(), length.len());
        let mut reader = BufferedReaderMemory::new(&encoded);
        SubpacketLength::parse(&mut reader).unwrap() == length
    }
}

/// Describes how a key may be used, and stores additional
/// information.
#[derive(Clone)]
pub struct KeyFlags(Vec<u8>);

impl Default for KeyFlags {
    fn default() -> Self {
        KeyFlags(vec![0])
    }
}

impl PartialEq for KeyFlags {
    fn eq(&self, other: &KeyFlags) -> bool {
        // To deal with unknown flags, we do a bitwise comparison.
        // First, we need to bring both flag fields to the same
        // length.
        let len = ::std::cmp::max(self.0.len(), other.0.len());
        let mut mine = vec![0; len];
        let mut hers = vec![0; len];
        &mut mine[..self.0.len()].copy_from_slice(&self.0);
        &mut hers[..other.0.len()].copy_from_slice(&other.0);

        mine == hers
    }
}

impl fmt::Debug for KeyFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.can_certify() {
            f.write_str("C")?;
        }
        if self.can_sign() {
            f.write_str("S")?;
        }
        if self.can_encrypt_for_transport() {
            f.write_str("Et")?;
        }
        if self.can_encrypt_at_rest() {
            f.write_str("Er")?;
        }
        if self.can_authenticate() {
            f.write_str("A")?;
        }
        if self.is_split_key() {
            f.write_str("S")?;
        }
        if self.is_group_key() {
            f.write_str("G")?;
        }

        Ok(())
    }
}


impl KeyFlags {
    /// Grows the vector to the given length.
    fn grow(&mut self, target: usize) {
        while self.0.len() < target {
            self.0.push(0);
        }
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// This key may be used to certify other keys.
    pub fn can_certify(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_CERTIFY > 0).unwrap_or(false)
    }


    /// Sets whether or not this key may be used to certify other keys.
    pub fn set_certify(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_CERTIFY;
        } else {
            self.0[0] &= !KEY_FLAG_CERTIFY;
        }
        self
    }

    /// This key may be used to sign data.
    pub fn can_sign(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_SIGN > 0).unwrap_or(false)
    }


    /// Sets whether or not this key may be used to sign data.
    pub fn set_sign(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_SIGN;
        } else {
            self.0[0] &= !KEY_FLAG_SIGN;
        }
        self
    }

    /// This key may be used to encrypt communications.
    pub fn can_encrypt_for_transport(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_ENCRYPT_FOR_TRANSPORT > 0).unwrap_or(false)
    }

    /// Sets whether or not this key may be used to encrypt communications.
    pub fn set_encrypt_for_transport(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_ENCRYPT_FOR_TRANSPORT;
        } else {
            self.0[0] &= !KEY_FLAG_ENCRYPT_FOR_TRANSPORT;
        }
        self
    }

    /// This key may be used to encrypt storage.
    pub fn can_encrypt_at_rest(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_ENCRYPT_AT_REST > 0).unwrap_or(false)
    }

    /// Sets whether or not this key may be used to encrypt storage.
    pub fn set_encrypt_at_rest(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_ENCRYPT_AT_REST;
        } else {
            self.0[0] &= !KEY_FLAG_ENCRYPT_AT_REST;
        }
        self
    }

    /// This key may be used for authentication.
    pub fn can_authenticate(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_AUTHENTICATE > 0).unwrap_or(false)
    }

    /// Sets whether or not this key may be used for authentication.
    pub fn set_authenticate(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_AUTHENTICATE;
        } else {
            self.0[0] &= !KEY_FLAG_AUTHENTICATE;
        }
        self
    }

    /// The private component of this key may have been split
    /// using a secret-sharing mechanism.
    pub fn is_split_key(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_SPLIT_KEY > 0).unwrap_or(false)
    }

    /// Sets whether or not the private component of this key may have been split
    /// using a secret-sharing mechanism.
    pub fn set_split_key(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_SPLIT_KEY;
        } else {
            self.0[0] &= !KEY_FLAG_SPLIT_KEY;
        }
        self
    }

    /// The private component of this key may be in
    /// possession of more than one person.
    pub fn is_group_key(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEY_FLAG_GROUP_KEY > 0).unwrap_or(false)
    }

    /// Sets whether or not the private component of this key may be in
    /// possession of more than one person.
    pub fn set_group_key(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEY_FLAG_GROUP_KEY;
        } else {
            self.0[0] &= !KEY_FLAG_GROUP_KEY;
        }
        self
    }
}

// Numeric key capability flags.

/// This key may be used to certify other keys.
const KEY_FLAG_CERTIFY: u8 = 0x01;

/// This key may be used to sign data.
const KEY_FLAG_SIGN: u8 = 0x02;

/// This key may be used to encrypt communications.
const KEY_FLAG_ENCRYPT_FOR_TRANSPORT: u8 = 0x04;

/// This key may be used to encrypt storage.
const KEY_FLAG_ENCRYPT_AT_REST: u8 = 0x08;

/// The private component of this key may have been split by a
/// secret-sharing mechanism.
const KEY_FLAG_SPLIT_KEY: u8 = 0x10;

/// This key may be used for authentication.
const KEY_FLAG_AUTHENTICATE: u8 = 0x20;

/// The private component of this key may be in the possession of more
/// than one person.
const KEY_FLAG_GROUP_KEY: u8 = 0x80;


/// Describes features supported by an OpenPGP implementation.
#[derive(Clone)]
pub struct Features(Vec<u8>);

impl Default for Features {
    fn default() -> Self {
        Features(vec![0])
    }
}

impl PartialEq for Features {
    fn eq(&self, other: &Features) -> bool {
        // To deal with unknown flags, we do a bitwise comparison.
        // First, we need to bring both flag fields to the same
        // length.
        let len = ::std::cmp::max(self.0.len(), other.0.len());
        let mut mine = vec![0; len];
        let mut hers = vec![0; len];
        &mut mine[..self.0.len()].copy_from_slice(&self.0);
        &mut hers[..other.0.len()].copy_from_slice(&other.0);

        mine == hers
    }
}

impl fmt::Debug for Features {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.supports_mdc() {
            f.write_str("MDC")?;
        }

        Ok(())
    }
}

impl Features {
    /// Grows the vector to the given length.
    fn grow(&mut self, target: usize) {
        while self.0.len() < target {
            self.0.push(0);
        }
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Whether or not MDC is supported.
    pub fn supports_mdc(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & FEATURE_FLAG_MDC > 0).unwrap_or(false)
    }


    /// Sets whether or not MDC is supported.
    pub fn set_mdc(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= FEATURE_FLAG_MDC;
        } else {
            self.0[0] &= !FEATURE_FLAG_MDC;
        }
        self
    }
}

/// The private component of this key may be in the possession of more
/// than one person.
const FEATURE_FLAG_MDC: u8 = 0x01;


/// Describes preferences regarding key servers.
#[derive(Clone)]
pub struct KeyServerPreferences(Vec<u8>);

impl Default for KeyServerPreferences {
    fn default() -> Self {
        KeyServerPreferences(vec![0])
    }
}

impl PartialEq for KeyServerPreferences {
    fn eq(&self, other: &KeyServerPreferences) -> bool {
        // To deal with unknown flags, we do a bitwise comparison.
        // First, we need to bring both flag fields to the same
        // length.
        let len = ::std::cmp::max(self.0.len(), other.0.len());
        let mut mine = vec![0; len];
        let mut hers = vec![0; len];
        &mut mine[..self.0.len()].copy_from_slice(&self.0);
        &mut hers[..other.0.len()].copy_from_slice(&other.0);

        mine == hers
    }
}

impl fmt::Debug for KeyServerPreferences {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.no_modify() {
            f.write_str("no modify")?;
        }

        Ok(())
    }
}

impl KeyServerPreferences {
    /// Grows the vector to the given length.
    fn grow(&mut self, target: usize) {
        while self.0.len() < target {
            self.0.push(0);
        }
    }

    /// Returns a slice referencing the raw values.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Whether or not the key on the key severs should only be
    /// modified by the owner or server administrator.
    pub fn no_modify(&self) -> bool {
        self.0.get(0)
            .map(|v0| v0 & KEYSERVER_PREFERENCE_NO_MODIFY > 0).unwrap_or(false)
    }


    /// Sets whether or not the key on the key severs should only be
    /// modified by the owner or server administrator.
    pub fn set_no_modify(mut self, v: bool) -> Self {
        self.grow(1);
        if v {
            self.0[0] |= KEYSERVER_PREFERENCE_NO_MODIFY;
        } else {
            self.0[0] &= !KEYSERVER_PREFERENCE_NO_MODIFY;
        }
        self
    }
}

/// The private component of this key may be in the possession of more
/// than one person.
const KEYSERVER_PREFERENCE_NO_MODIFY: u8 = 0x80;


impl Signature {
    /// Returns the *last* instance of the specified subpacket.
    fn subpacket<'a>(&'a self, tag: SubpacketTag) -> Option<Subpacket<'a>> {
        if let Some(sb) = self.hashed_area.lookup(tag) {
            return Some(sb);
        }

        // There are a couple of subpackets that we are willing to
        // take from the unhashed area.  The others we ignore
        // completely.
        if !(tag == SubpacketTag::Issuer
             || tag == SubpacketTag::EmbeddedSignature) {
            return None;
        }

        self.unhashed_area.lookup(tag)
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
    pub fn signature_creation_time(&self) -> Option<time::Tm> {
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

    /// Sets the value of the Creation Time subpacket.
    pub fn set_signature_creation_time(&mut self, creation_time: time::Tm)
                                       -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::SignatureCreationTime(creation_time),
            true)?)
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
    pub fn signature_expiration_time(&self) -> Option<time::Duration> {
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

    /// Sets the value of the Signature Expiration Time subpacket.
    ///
    /// If `None` is given, any expiration subpacket is removed.
    pub fn set_signature_expiration_time(&mut self,
                                         expiration: Option<time::Duration>)
                                       -> Result<()> {
        if let Some(e) = expiration {
            self.hashed_area.replace(Subpacket::new(
                SubpacketValue::SignatureExpirationTime(e),
                true)?)
        } else {
            self.hashed_area.remove_all(SubpacketTag::SignatureExpirationTime);
            Ok(())
        }
    }

    /// Returns whether or not the signature is expired.
    ///
    /// Note that [Section 5.2.3.4 of RFC 4880] states that "[[A
    /// Signature Creation Time subpacket]] MUST be present in the
    /// hashed area."  Consequently, if such a packet does not exist,
    /// but a "Signature Expiration Time" subpacket exists, we
    /// conservatively treat the signature as expired, because there
    /// is no way to evaluate the expiration time.
    ///
    ///  [Section 5.2.3.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
    pub fn signature_expired(&self) -> bool {
        self.signature_expired_at(time::now_utc())
    }

    /// Returns whether or not the signature is expired at the given time.
    ///
    /// Note that [Section 5.2.3.4 of RFC 4880] states that "[[A
    /// Signature Creation Time subpacket]] MUST be present in the
    /// hashed area."  Consequently, if such a packet does not exist,
    /// but a "Signature Expiration Time" subpacket exists, we
    /// conservatively treat the signature as expired, because there
    /// is no way to evaluate the expiration time.
    ///
    ///  [Section 5.2.3.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
    pub fn signature_expired_at(&self, tm: time::Tm) -> bool {
        match (self.signature_creation_time(), self.signature_expiration_time())
        {
            (Some(_), Some(e)) if e.num_seconds() == 0 =>
                false, // Zero expiration time, does not expire.
            (Some(c), Some(e)) =>
                (c + e) <= tm,
            (None, Some(_)) =>
                true, // No creation time, treat as always expired.
            (_, None) =>
                false, // No expiration time, does not expire.
        }
    }

    /// Returns whether or not the signature is alive, i.e. the
    /// creation time has passed, but the expiration time has not.
    ///
    /// Note that [Section 5.2.3.4 of RFC 4880] states that "[[A
    /// Signature Creation Time subpacket]] MUST be present in the
    /// hashed area."  Consequently, if such a packet does not exist,
    /// but a "Signature Expiration Time" subpacket exists, we
    /// conservatively treat the signature as expired, because there
    /// is no way to evaluate the expiration time.
    ///
    ///  [Section 5.2.3.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
    pub fn signature_alive(&self) -> bool {
        self.signature_alive_at(time::now_utc())
    }

    /// Returns whether or not the signature is alive at the given
    /// time, i.e. the creation time has passed, but the expiration
    /// time has not.
    ///
    /// Note that [Section 5.2.3.4 of RFC 4880] states that "[[A
    /// Signature Creation Time subpacket]] MUST be present in the
    /// hashed area."  Consequently, if such a packet does not exist,
    /// but a "Signature Expiration Time" subpacket exists, we
    /// conservatively treat the signature as expired, because there
    /// is no way to evaluate the expiration time.
    ///
    ///  [Section 5.2.3.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
    pub fn signature_alive_at(&self, tm: time::Tm) -> bool {
        if let Some(creation_time) = self.signature_creation_time() {
            creation_time <= tm && ! self.signature_expired_at(tm)
        } else {
            false
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

    /// Sets the value of the Exportable Certification subpacket,
    /// which contains whether the certification should be exported
    /// (i.e., whether the packet is *not* a local signature).
    pub fn set_exportable_certification(&mut self, exportable: bool)
                                        -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::ExportableCertification(exportable),
            true)?)
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
        if let Some(sb) = self.subpacket(SubpacketTag::TrustSignature) {
            if let SubpacketValue::TrustSignature{ level, trust } = sb.value {
                Some((level, trust))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Sets the value of the Trust Signature subpacket.
    pub fn set_trust_signature(&mut self, level: u8, trust: u8)
                               -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::TrustSignature {
                level: level,
                trust: trust,
            },
            true)?)
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

    /// Sets the value of the Regular Expression subpacket.
    pub fn set_regular_expression(&mut self, re: &[u8]) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::RegularExpression(re),
            true)?)
    }

    /// Returns the value of the Revocable subpacket, which indicates
    /// whether the signature is revocable, i.e., whether revocation
    /// certificates for this signature should be ignored.
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

    /// Sets the value of the Revocable subpacket, which indicates
    /// whether the signature is revocable, i.e., whether revocation
    /// certificates for this signature should be ignored.
    pub fn set_revocable(&mut self, revocable: bool) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::Revocable(revocable),
            true)?)
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
    pub fn key_expiration_time(&self) -> Option<time::Duration> {
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

    /// Sets the value of the Key Expiration Time subpacket, which
    /// contains when the referenced key expires as the number of
    /// seconds after the key's creation.
    ///
    /// If `None` is given, any expiration subpacket is removed.
    pub fn set_key_expiration_time(&mut self,
                                   expiration: Option<time::Duration>)
                                   -> Result<()> {
        if let Some(e) = expiration {
            self.hashed_area.replace(Subpacket::new(
                SubpacketValue::KeyExpirationTime(e),
                true)?)
        } else {
            self.hashed_area.remove_all(SubpacketTag::KeyExpirationTime);
            Ok(())
        }
    }

    /// Returns whether or not the key is expired.
    ///
    /// See [Section 5.2.3.6 of RFC 4880].
    ///
    ///  [Section 5.2.3.6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.6
    pub fn key_expired(&self, key: &Key) -> bool {
        self.key_expired_at(key, time::now_utc())
    }

    /// Returns whether or not the key is expired at the given time.
    ///
    /// See [Section 5.2.3.6 of RFC 4880].
    ///
    ///  [Section 5.2.3.6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.6
    pub fn key_expired_at(&self, key: &Key, tm: time::Tm) -> bool {
        match self.key_expiration_time() {
            Some(e) if e.num_seconds() == 0 =>
                false, // Zero expiration time, does not expire.
            Some(e) =>
                key.creation_time + e <= tm,
            None =>
                false, // No expiration time, does not expire.
        }
    }

    /// Returns whether or not the given key is alive, i.e. the
    /// creation time has passed, but the expiration time has not.
    ///
    /// See [Section 5.2.3.6 of RFC 4880].
    ///
    ///  [Section 5.2.3.6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.6
    pub fn key_alive(&self, key: &Key) -> bool {
        self.key_alive_at(key, time::now_utc())
    }

    /// Returns whether or not the given key is alive at the given
    /// time, i.e. the creation time has passed, but the expiration
    /// time has not.
    ///
    /// See [Section 5.2.3.6 of RFC 4880].
    ///
    ///  [Section 5.2.3.6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.6
    pub fn key_alive_at(&self, key: &Key, tm: time::Tm) -> bool {
        key.creation_time <= tm && ! self.key_expired_at(key, tm)
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
    pub fn preferred_symmetric_algorithms(&self)
                                          -> Option<Vec<SymmetricAlgorithm>> {
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

    /// Sets the value of the Preferred Symmetric Algorithms
    /// subpacket, which contains the list of symmetric algorithms
    /// that the key holder prefers, ordered according by the key
    /// holder's preference.
    pub fn set_preferred_symmetric_algorithms(&mut self,
                                              preferences: Vec<SymmetricAlgorithm>)
                                              -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::PreferredSymmetricAlgorithms(preferences),
            true)?)
    }

    /// Returns the value of the Revocation Key subpacket, which
    /// contains a designated revoker.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn revocation_key(&self) -> Option<(u8,
                                            PublicKeyAlgorithm,
                                            Fingerprint)> {
        // 1 octet of class, 1 octet of public-key algorithm ID, 20 or
        // 32 octets of fingerprint.
        if let Some(sb) = self.subpacket(SubpacketTag::RevocationKey) {
            if let SubpacketValue::RevocationKey {
                class, pk_algo, fp,
            } = sb.value {
                Some((class, pk_algo, fp))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Sets the value of the Revocation Key subpacket, which contains
    /// a designated revoker.
    pub fn set_revocation_key(&mut self, class: u8, pk_algo: PublicKeyAlgorithm,
                              fp: Fingerprint) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::RevocationKey {
                class: class,
                pk_algo: pk_algo,
                fp: fp,
            },
            true)?)
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

    /// Sets the value of the Issuer subpacket, which contains the
    /// KeyID of the key that allegedly created this signature.
    pub fn set_issuer(&mut self, id: KeyID) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::Issuer(id),
            true)?)
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
    pub fn preferred_hash_algorithms(&self) -> Option<Vec<HashAlgorithm>> {
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

    /// Sets the value of the Preferred Hash Algorithms subpacket,
    /// which contains the list of hash algorithms that the key
    /// holders prefers, ordered according by the key holder's
    /// preference.
    pub fn set_preferred_hash_algorithms(&mut self,
                                         preferences: Vec<HashAlgorithm>)
                                         -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::PreferredHashAlgorithms(preferences),
            true)?)
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
    pub fn preferred_compression_algorithms(&self)
                                            -> Option<Vec<CompressionAlgorithm>>
    {
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

    /// Sets the value of the Preferred Compression Algorithms
    /// subpacket, which contains the list of compression algorithms
    /// that the key holder prefers, ordered according by the key
    /// holder's preference.
    pub fn set_preferred_compression_algorithms(&mut self,
                                                preferences: Vec<CompressionAlgorithm>)
                                                -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::PreferredCompressionAlgorithms(preferences),
            true)?)
    }

    /// Returns the value of the Key Server Preferences subpacket,
    /// which contains the key holder's key server preferences.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn key_server_preferences(&self) -> KeyServerPreferences {
        // N octets of flags
        if let Some(sb) = self.subpacket(SubpacketTag::KeyServerPreferences) {
            if let SubpacketValue::KeyServerPreferences(v) = sb.value {
                v
            } else {
                KeyServerPreferences::default()
            }
        } else {
            KeyServerPreferences::default()
        }
    }

    /// Sets the value of the Key Server Preferences subpacket, which
    /// contains the key holder's key server preferences.
    pub fn set_key_server_preferences(&mut self,
                                      preferences: KeyServerPreferences)
                                      -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::KeyServerPreferences(preferences),
            true)?)
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

    /// Sets the value of the Preferred Key Server subpacket, which
    /// contains the user's preferred key server for updates.
    pub fn set_preferred_key_server(&mut self, uri: &[u8])
                                    -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::PreferredKeyServer(uri),
            true)?)
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

    /// Sets the value of the Primary UserID subpacket, which
    /// indicates whether the referenced UserID should be considered
    /// the user's primary User ID.
    pub fn set_primary_userid(&mut self, primary: bool) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::PrimaryUserID(primary),
            true)?)
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

    /// Sets the value of the Policy URI subpacket.
    pub fn set_policy_uri(&mut self, uri: &[u8]) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::PolicyURI(uri),
            true)?)
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
    pub fn key_flags(&self) -> KeyFlags {
        // N octets of flags
        if let Some(sb) = self.subpacket(SubpacketTag::KeyFlags) {
            if let SubpacketValue::KeyFlags(v) = sb.value {
                v
            } else {
                KeyFlags::default()
            }
        } else {
            KeyFlags::default()
        }
    }

    /// Sets the value of the Key Flags subpacket, which contains
    /// information about the referenced key, in particular, how it is
    /// used (certification, signing, encryption, authentication), and
    /// how it is stored (split, held by multiple people).
    pub fn set_key_flags(&mut self, flags: &KeyFlags) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::KeyFlags(flags.clone()),
            true)?)
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

    /// Sets the value of the Signer's UserID subpacket, which
    /// contains the User ID that the key holder considers responsible
    /// for the signature.
    pub fn set_signers_user_id(&mut self, uid: &[u8]) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::SignersUserID(uid),
            true)?)
    }

    /// Returns the value of the Reason for Revocation subpacket.
    ///
    /// If the subpacket is not present or malformed, this returns
    /// `None`.
    ///
    /// Note: if the signature contains multiple instances of this
    /// subpacket, only the last one is considered.
    pub fn reason_for_revocation(&self)
                                 -> Option<(ReasonForRevocation, &[u8])> {
        // 1 octet of revocation code, N octets of reason string
        if let Some(sb) = self.subpacket(SubpacketTag::ReasonForRevocation) {
            if let SubpacketValue::ReasonForRevocation {
                code, reason,
            } = sb.value {
                Some((code, reason))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Sets the value of the Reason for Revocation subpacket.
    pub fn set_reason_for_revocation(&mut self, code: ReasonForRevocation,
                                     reason: &[u8])
                                     -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::ReasonForRevocation {
                code: code,
                reason: reason,
            },
            true)?)
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
    pub fn features(&self) -> Features {
        // N octets of flags
        if let Some(sb)
                = self.subpacket(SubpacketTag::Features) {
            if let SubpacketValue::Features(v) = sb.value {
                v
            } else {
                Features::default()
            }
        } else {
            Features::default()
        }
    }

    /// Sets the value of the Features subpacket, which contains a
    /// list of features that the user's OpenPGP implementation
    /// supports.
    pub fn set_features(&mut self, features: &Features) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::Features(features.clone()),
            true)?)
    }

    /// Returns the value of the Signature Target subpacket, which
    /// contains the hash of the referenced signature packet.
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
    pub fn signature_target(&self) -> Option<(PublicKeyAlgorithm,
                                              HashAlgorithm,
                                              &[u8])> {
        // 1 octet public-key algorithm, 1 octet hash algorithm, N
        // octets hash
        if let Some(sb) = self.subpacket(SubpacketTag::SignatureTarget) {
            if let SubpacketValue::SignatureTarget {
                pk_algo, hash_algo, digest,
            } = sb.value {
                Some((pk_algo, hash_algo, digest))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Sets the value of the Signature Target subpacket, which
    /// contains the hash of the referenced signature packet.
    pub fn set_signature_target(&mut self,
                                pk_algo: PublicKeyAlgorithm,
                                hash_algo: HashAlgorithm,
                                digest: &[u8])
                                -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::SignatureTarget {
                pk_algo: pk_algo,
                hash_algo: hash_algo,
                digest: digest
            },
            true)?)
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

    /// Sets the value of the Embedded Signature subpacket, which
    /// contains a signature.
    pub fn set_embedded_signature(&mut self, signature: Signature)
                                  -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::EmbeddedSignature(signature.to_packet()),
            true)?)
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


    /// Sets the value of the Issuer Fingerprint subpacket, which
    /// contains the fingerprint of the key that allegedly created
    /// this signature.
    pub fn set_issuer_fingerprint(&mut self, fp: Fingerprint) -> Result<()> {
        self.hashed_area.replace(Subpacket::new(
            SubpacketValue::IssuerFingerprint(fp),
            true)?)
    }

    /// Returns the intended recipients.
    pub fn intended_recipients(&self) -> Vec<Fingerprint> {
        let mut result = Vec::new();

        for (_start, _len, sb) in self.hashed_area.iter() {
            if sb.tag == SubpacketTag::IntendedRecipient {
                let s = Subpacket::from(sb);
                if let SubpacketValue::IntendedRecipient(fp) = s.value {
                    result.push(fp);
                }
            }
        }

        result
    }

    /// Sets the intended recipients.
    pub fn set_intended_recipients(&mut self, recipients: Vec<Fingerprint>)
                                   -> Result<()> {
        self.hashed_area.remove_all(SubpacketTag::IntendedRecipient);
        for fp in recipients.into_iter() {
            self.hashed_area.add(
                Subpacket::new(SubpacketValue::IntendedRecipient(fp), false)?)?;
        }

        Ok(())
    }
}


#[test]
fn accessors() {
    use mpis::{MPIs, MPI};

    let pk_algo = PublicKeyAlgorithm::EdDSA;
    let hash_algo = HashAlgorithm::SHA512;
    let mut sig = Signature::new(::constants::SignatureType::Binary);
    sig.set_pk_algo(pk_algo);
    sig.set_hash_algo(hash_algo);

    // Fake some MPIs to make the serialization code happy.
    sig.mpis = MPIs::EdDSASignature {
        r: MPI::new(b"byte sequence of length 32 bytes"),
        s: MPI::new(b"byte sequence of length 32 bytes"),
    };

    // Cook up a timestamp without ns resolution.
    let now = time::Tm::from_pgp(time::now_utc().to_pgp().unwrap());

    sig.set_signature_creation_time(now).unwrap();
    assert_eq!(sig.signature_creation_time(), Some(now));

    let five_minutes = time::Duration::minutes(5);
    let ten_minutes = time::Duration::minutes(10);
    sig.set_signature_expiration_time(Some(five_minutes)).unwrap();
    assert_eq!(sig.signature_expiration_time(), Some(five_minutes));

    assert!(!sig.signature_expired());
    assert!(!sig.signature_expired_at(now));
    assert!(sig.signature_expired_at(now + ten_minutes));

    assert!(sig.signature_alive());
    assert!(sig.signature_alive_at(now));
    assert!(!sig.signature_alive_at(now - five_minutes));
    assert!(!sig.signature_alive_at(now + ten_minutes));

    sig.set_signature_expiration_time(None).unwrap();
    assert_eq!(sig.signature_expiration_time(), None);
    assert!(!sig.signature_expired());
    assert!(!sig.signature_expired_at(now));
    assert!(!sig.signature_expired_at(now + ten_minutes));

    assert!(sig.signature_alive());
    assert!(sig.signature_alive_at(now));
    assert!(!sig.signature_alive_at(now - five_minutes));
    assert!(sig.signature_alive_at(now + ten_minutes));

    sig.set_exportable_certification(true).unwrap();
    assert_eq!(sig.exportable_certification(), Some(true));
    sig.set_exportable_certification(false).unwrap();
    assert_eq!(sig.exportable_certification(), Some(false));

    sig.set_trust_signature(2, 3).unwrap();
    assert_eq!(sig.trust_signature(), Some((2, 3)));

    sig.set_regular_expression(b"foobar").unwrap();
    assert_eq!(sig.regular_expression(), Some(&b"foobar"[..]));

    sig.set_revocable(true).unwrap();
    assert_eq!(sig.revocable(), Some(true));
    sig.set_revocable(false).unwrap();
    assert_eq!(sig.revocable(), Some(false));

    let mut key = ::Key::default();
    key.set_creation_time(now);
    sig.set_key_expiration_time(Some(five_minutes)).unwrap();
    assert_eq!(sig.key_expiration_time(), Some(five_minutes));

    assert!(!sig.key_expired(&key));
    assert!(!sig.key_expired_at(&key, now));
    assert!(sig.key_expired_at(&key, now + ten_minutes));

    assert!(sig.key_alive(&key));
    assert!(sig.key_alive_at(&key, now));
    assert!(!sig.key_alive_at(&key, now - five_minutes));
    assert!(!sig.key_alive_at(&key, now + ten_minutes));

    sig.set_key_expiration_time(None).unwrap();
    assert_eq!(sig.key_expiration_time(), None);
    assert!(!sig.key_expired(&key));
    assert!(!sig.key_expired_at(&key, now));
    assert!(!sig.key_expired_at(&key, now + ten_minutes));

    assert!(sig.key_alive(&key));
    assert!(sig.key_alive_at(&key, now));
    assert!(!sig.key_alive_at(&key, now - five_minutes));
    assert!(sig.key_alive_at(&key, now + ten_minutes));

    let pref = vec![SymmetricAlgorithm::AES256,
                    SymmetricAlgorithm::AES192,
                    SymmetricAlgorithm::AES128];
    sig.set_preferred_symmetric_algorithms(pref.clone()).unwrap();
    assert_eq!(sig.preferred_symmetric_algorithms(), Some(pref));

    let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    sig.set_revocation_key(2, pk_algo, fp.clone()).unwrap();
    assert_eq!(sig.revocation_key(),
               Some((2, pk_algo.into(), fp.clone())));

    sig.set_issuer(fp.to_keyid()).unwrap();
    assert_eq!(sig.issuer(), Some(fp.to_keyid()));

    let pref = vec![HashAlgorithm::SHA512,
                    HashAlgorithm::SHA384,
                    HashAlgorithm::SHA256];
    sig.set_preferred_hash_algorithms(pref.clone()).unwrap();
    assert_eq!(sig.preferred_hash_algorithms(), Some(pref));

    let pref = vec![CompressionAlgorithm::BZip2,
                    CompressionAlgorithm::Zlib,
                    CompressionAlgorithm::Zip];
    sig.set_preferred_compression_algorithms(pref.clone()).unwrap();
    assert_eq!(sig.preferred_compression_algorithms(), Some(pref));

    let pref = KeyServerPreferences::default()
        .set_no_modify(true);
    sig.set_key_server_preferences(pref.clone()).unwrap();
    assert_eq!(sig.key_server_preferences(), pref);

    sig.set_primary_userid(true).unwrap();
    assert_eq!(sig.primary_userid(), Some(true));
    sig.set_primary_userid(false).unwrap();
    assert_eq!(sig.primary_userid(), Some(false));

    sig.set_policy_uri(b"foobar").unwrap();
    assert_eq!(sig.policy_uri(), Some(&b"foobar"[..]));

    let key_flags = KeyFlags::default()
        .set_certify(true)
        .set_sign(true);
    sig.set_key_flags(&key_flags).unwrap();
    assert_eq!(sig.key_flags(), key_flags);

    sig.set_signers_user_id(b"foobar").unwrap();
    assert_eq!(sig.signers_user_id(), Some(&b"foobar"[..]));

    sig.set_reason_for_revocation(ReasonForRevocation::KeyRetired,
                                  b"foobar").unwrap();
    assert_eq!(sig.reason_for_revocation(),
               Some((ReasonForRevocation::KeyRetired, &b"foobar"[..])));

    let feats = Features::default().set_mdc(true);
    sig.set_features(&feats).unwrap();
    assert_eq!(sig.features(), feats);

    let digest = vec![0; hash_algo.context().unwrap().digest_size()];
    sig.set_signature_target(pk_algo, hash_algo, &digest).unwrap();
    assert_eq!(sig.signature_target(), Some((pk_algo.into(),
                                             hash_algo.into(),
                                             &digest[..])));

    let embedded_sig = sig.clone();
    sig.set_embedded_signature(embedded_sig.clone()).unwrap();
    assert_eq!(sig.embedded_signature(), Some(Packet::Signature(embedded_sig)));

    sig.set_issuer_fingerprint(fp.clone()).unwrap();
    assert_eq!(sig.issuer_fingerprint(), Some(fp));

    let fps = vec![
        Fingerprint::from_bytes(b"aaaaaaaaaaaaaaaaaaaa"),
        Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb"),
    ];
    sig.set_intended_recipients(fps.clone()).unwrap();
    assert_eq!(sig.intended_recipients(), fps);
}

#[cfg(feature = "compression-deflate")]
#[test]
fn subpacket_test_1 () {
    use PacketPile;

    let path = path_to("signed.gpg");
    let pile = PacketPile::from_file(&path).unwrap();
    eprintln!("PacketPile has {} top-level packets.", pile.children().len());
    eprintln!("PacketPile: {:?}", pile);

    let mut count = 0;
    for p in pile.descendants() {
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
    use conversions::Time;
    use PacketPile;

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

    let pile = PacketPile::from_file(
        path_to("../keys/subpackets/shaw.gpg")).unwrap();

    // Test #1
    if let (Some(&Packet::PublicKey(ref key)),
            Some(&Packet::Signature(ref sig)))
        = (pile.children().nth(0), pile.children().nth(2))
    {
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

        assert_eq!(sig.signature_creation_time(),
                   Some(time::Tm::from_pgp(1515791508)));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(
                           time::Tm::from_pgp(1515791508))
                   }));

        // The signature does not expire.
        assert!(! sig.signature_expired());

        assert_eq!(sig.key_expiration_time(),
                   Some(time::Duration::from_pgp(63072000)));
        assert_eq!(sig.subpacket(SubpacketTag::KeyExpirationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::KeyExpirationTime,
                       value: SubpacketValue::KeyExpirationTime(
                           time::Duration::from_pgp(63072000))
                   }));

        // Check key expiration.
        assert!(! sig.key_expired_at(
            key,
            key.creation_time + time::Duration::seconds(63072000 - 1)));
        assert!(sig.key_expired_at(
            key,
            key.creation_time + time::Duration::seconds(63072000)));

        assert_eq!(sig.preferred_symmetric_algorithms(),
                   Some(vec![SymmetricAlgorithm::AES256,
                             SymmetricAlgorithm::AES192,
                             SymmetricAlgorithm::AES128,
                             SymmetricAlgorithm::TripleDES]));
        assert_eq!(sig.subpacket(SubpacketTag::PreferredSymmetricAlgorithms),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::PreferredSymmetricAlgorithms,
                       value: SubpacketValue::PreferredSymmetricAlgorithms(
                           vec![SymmetricAlgorithm::AES256,
                                SymmetricAlgorithm::AES192,
                                SymmetricAlgorithm::AES128,
                                SymmetricAlgorithm::TripleDES]
                       )}));

        assert_eq!(sig.preferred_hash_algorithms(),
                   Some(vec![HashAlgorithm::SHA256,
                             HashAlgorithm::SHA384,
                             HashAlgorithm::SHA512,
                             HashAlgorithm::SHA224,
                             HashAlgorithm::SHA1]));
        assert_eq!(sig.subpacket(SubpacketTag::PreferredHashAlgorithms),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::PreferredHashAlgorithms,
                       value: SubpacketValue::PreferredHashAlgorithms(
                           vec![HashAlgorithm::SHA256,
                                HashAlgorithm::SHA384,
                                HashAlgorithm::SHA512,
                                HashAlgorithm::SHA224,
                                HashAlgorithm::SHA1]
                       )}));

        assert_eq!(sig.preferred_compression_algorithms(),
                   Some(vec![CompressionAlgorithm::Zlib,
                             CompressionAlgorithm::BZip2,
                             CompressionAlgorithm::Zip]));
        assert_eq!(sig.subpacket(SubpacketTag::PreferredCompressionAlgorithms),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::PreferredCompressionAlgorithms,
                       value: SubpacketValue::PreferredCompressionAlgorithms(
                           vec![CompressionAlgorithm::Zlib,
                                CompressionAlgorithm::BZip2,
                                CompressionAlgorithm::Zip]
                       )}));

        assert_eq!(sig.key_server_preferences(),
                   KeyServerPreferences::default().set_no_modify(true));
        assert_eq!(sig.subpacket(SubpacketTag::KeyServerPreferences),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::KeyServerPreferences,
                       value: SubpacketValue::KeyServerPreferences(
                           KeyServerPreferences::default().set_no_modify(true)),
                   }));

        assert!(sig.key_flags().can_certify() && sig.key_flags().can_sign());
        assert_eq!(sig.subpacket(SubpacketTag::KeyFlags),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::KeyFlags,
                       value: SubpacketValue::KeyFlags(
                           KeyFlags::default().set_certify(true).set_sign(true))
                   }));

        assert_eq!(sig.features(), Features::default().set_mdc(true));
        assert_eq!(sig.subpacket(SubpacketTag::Features),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::Features,
                       value: SubpacketValue::Features(
                           Features::default().set_mdc(true))
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
    if let Some(&Packet::Signature(ref sig)) = pile.children().nth(3) {
        // tag: 2, SignatureCreationTime(1515791490)
        // tag: 4, ExportableCertification(false)
        // tag: 16, Issuer(KeyID("CEAD 0621 0934 7957"))
        // tag: 33, IssuerFingerprint(Fingerprint("B59B 8817 F519 DCE1 0AFD  85E4 CEAD 0621 0934 7957"))

        // for i in 0..256 {
        //     if let Some(sb) = sig.subpacket(i as u8) {
        //         eprintln!("  {:?}", sb);
        //     }
        // }

        assert_eq!(sig.signature_creation_time(),
                   Some(time::Tm::from_pgp(1515791490)));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(
                           time::Tm::from_pgp(1515791490))
                   }));

        assert_eq!(sig.exportable_certification(), Some(false));
        assert_eq!(sig.subpacket(SubpacketTag::ExportableCertification),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::ExportableCertification,
                       value: SubpacketValue::ExportableCertification(false)
                   }));
    }

    let pile = PacketPile::from_file(
        path_to("../keys/subpackets/marven.gpg")).unwrap();

    // Test #3
    if let Some(&Packet::Signature(ref sig)) = pile.children().nth(1) {
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

        assert_eq!(sig.signature_creation_time(),
                   Some(time::Tm::from_pgp(1515791376)));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(
                           time::Tm::from_pgp(1515791376))
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
        assert_eq!(sig.revocation_key(),
                   Some((128, PublicKeyAlgorithm::RSAEncryptSign, fp.clone())));
        assert_eq!(sig.subpacket(SubpacketTag::RevocationKey),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::RevocationKey,
                       value: SubpacketValue::RevocationKey {
                           class: 0x80,
                           pk_algo: PublicKeyAlgorithm::RSAEncryptSign,
                           fp: fp,
                       },
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
    if let Some(&Packet::Signature(ref sig)) = pile.children().nth(6) {
        // for i in 0..256 {
        //     if let Some(sb) = sig.subpacket(i as u8) {
        //         eprintln!("  {:?}", sb);
        //     }
        // }

        assert_eq!(sig.signature_creation_time(),
                   Some(time::Tm::from_pgp(1515886658)));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(
                           time::Tm::from_pgp(1515886658))
                   }));

        assert_eq!(sig.reason_for_revocation(),
                   Some((ReasonForRevocation::Unspecified,
                         &b"Forgot to set a sig expiration."[..])));
        assert_eq!(sig.subpacket(SubpacketTag::ReasonForRevocation),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::ReasonForRevocation,
                       value: SubpacketValue::ReasonForRevocation {
                           code: ReasonForRevocation::Unspecified,
                           reason: &b"Forgot to set a sig expiration."[..],
                       },
                   }));
    }


    // Test #5
    if let Some(&Packet::Signature(ref sig)) = pile.children().nth(7) {
        // The only thing interesting about this signature is that it
        // has multiple notations.

        assert_eq!(sig.signature_creation_time(),
                   Some(time::Tm::from_pgp(1515791467)));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(
                           time::Tm::from_pgp(1515791467))
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
    if let Some(&Packet::Signature(ref sig)) = pile.children().nth(8) {
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

        assert_eq!(sig.signature_creation_time(),
                   Some(time::Tm::from_pgp(1515791223)));
        assert_eq!(sig.subpacket(SubpacketTag::SignatureCreationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::SignatureCreationTime,
                       value: SubpacketValue::SignatureCreationTime(
                           time::Tm::from_pgp(1515791223))
                   }));

        assert_eq!(sig.trust_signature(), Some((2, 120)));
        assert_eq!(sig.subpacket(SubpacketTag::TrustSignature),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::TrustSignature,
                       value: SubpacketValue::TrustSignature {
                           level: 2,
                           trust: 120,
                       },
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
    if let Some(&Packet::Signature(ref sig)) = pile.children().nth(11) {
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

        assert_eq!(sig.key_expiration_time(),
                   Some(time::Duration::from_pgp(63072000)));
        assert_eq!(sig.subpacket(SubpacketTag::KeyExpirationTime),
                   Some(Subpacket {
                       critical: false,
                       tag: SubpacketTag::KeyExpirationTime,
                       value: SubpacketValue::KeyExpirationTime(
                           time::Duration::from_pgp(63072000))
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

//     for (i, p) in pile.children().enumerate() {
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
