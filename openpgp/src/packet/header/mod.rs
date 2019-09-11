//! OpenPGP Header.

use crate::{
    Error,
    Result,
};
use crate::packet::tag::Tag;
pub use crate::packet::BodyLength;
pub use crate::packet::ctb::{self, CTB};

/// An OpenPGP packet's header.
#[derive(Clone, Debug)]
pub struct Header {
    /// The packet's CTB.
    ctb: CTB,
    /// The packet's length.
    length: BodyLength,
}

impl Header {
    /// Creates a new header.
    pub fn new(ctb: CTB, length: BodyLength) -> Self {
        Header { ctb, length }
    }

    /// Returns the packet's CTB.
    pub fn ctb(&self) -> &CTB {
        &self.ctb
    }

    /// Returns the packet's length.
    pub fn length(&self) -> &BodyLength {
        &self.length
    }

    /// Syntax checks the header.
    ///
    /// A header is consider invalid if:
    ///
    ///   - The tag is Tag::Reserved.
    ///   - The tag is unknown (if future_compatible is false).
    ///   - The [length encoding] is invalid for the packet.
    ///   - The lengths are unreasonable for a packet (e.g., a
    ///     PKESK or SKESK larger than 10 kb).
    ///
    /// [length encoding]: https://tools.ietf.org/html/rfc4880#section-4.2.2.4
    ///
    /// This function does not check the packet's content.
    // Note: To check the packet's content, use
    //       `PacketParser::plausible`.
    pub fn valid(&self, future_compatible: bool) -> Result<()> {
        let tag = self.ctb.tag();

        // Reserved packets are never valid.
        if tag == Tag::Reserved {
            return Err(Error::UnsupportedPacketType(tag).into());
        }

        // Unknown packets are not valid unless we want future
        // compatibility.
        if ! future_compatible
            && (destructures_to!(Tag::Unknown(_) = tag)
                || destructures_to!(Tag::Private(_) = tag))
        {
            return Err(Error::UnsupportedPacketType(tag).into());
        }

        // An implementation MAY use Partial Body Lengths for data
        // packets, be they literal, compressed, or encrypted.  The
        // first partial length MUST be at least 512 octets long.
        // Partial Body Lengths MUST NOT be used for any other packet
        // types.
        //
        // https://tools.ietf.org/html/rfc4880#section-4.2.2.4
        if tag == Tag::Literal || tag == Tag::CompressedData
            || tag == Tag::SED || tag == Tag::SEIP
            || tag == Tag::AED
        {
            // Data packet.
            match self.length {
                BodyLength::Indeterminate => (),
                BodyLength::Partial(l) => {
                    if l < 512 {
                        return Err(Error::MalformedPacket(
                            format!("Partial body length must be \
                                     at least 512 (got: {})",
                                    l)).into());
                    }
                }
                BodyLength::Full(l) => {
                    // In the following block cipher length checks, we
                    // conservatively assume a block size of 8 bytes,
                    // because Twofish, TripleDES, IDEA, and CAST-5
                    // have a block size of 64 bits.
                    if tag == Tag::SED && (l < (8       // Random block.
                                                + 2     // Quickcheck bytes.
                                                + 6)) { // Smallest literal.
                        return Err(Error::MalformedPacket(
                            format!("{} packet's length must be \
                                     at least 16 bytes in length (got: {})",
                                    tag, l)).into());
                    } else if tag == Tag::SEIP
                        && (l < (1       // Version.
                                 + 8     // Random block.
                                 + 2     // Quickcheck bytes.
                                 + 6     // Smallest literal.
                                 + 20))  // MDC packet.
                    {
                        return Err(Error::MalformedPacket(
                            format!("{} packet's length minus 1 must be \
                                     at least 37 bytes in length (got: {})",
                                    tag, l)).into());
                    } else if tag == Tag::CompressedData && l == 0 {
                        // One byte header.
                        return Err(Error::MalformedPacket(
                            format!("{} packet's length must be \
                                     at least 1 byte (got ({})",
                                    tag, l)).into());
                    } else if tag == Tag::Literal && l < 6 {
                        // Smallest literal packet consists of 6 octets.
                        return Err(Error::MalformedPacket(
                            format!("{} packet's length must be \
                                     at least 6 bytes (got: ({})",
                                    tag, l)).into());
                    }
                }
            }
        } else {
            // Non-data packet.
            match self.length {
                BodyLength::Indeterminate =>
                    return Err(Error::MalformedPacket(
                        format!("Indeterminite length encoding \
                                 not allowed for {} packets",
                                tag)).into()),
                BodyLength::Partial(_) =>
                    return Err(Error::MalformedPacket(
                        format!("Partial Body Chunking not allowed \
                                 for {} packets",
                                tag)).into()),
                BodyLength::Full(l) => {
                    let valid = match tag {
                        Tag::Signature =>
                            // A V3 signature is 19 bytes plus the
                            // MPIs.  A V4 is 10 bytes plus the hash
                            // areas and the MPIs.
                            10 <= l
                            && l < (10  // Header, fixed sized fields.
                                    + 2 * 64 * 1024 // Hashed & Unhashed areas.
                                    + 64 * 1024 // MPIs.
                                   ),
                        Tag::SKESK =>
                            // 2 bytes of fixed header.  An s2k
                            // specification (at least 1 byte), an
                            // optional encryption session key.
                            3 <= l && l < 10 * 1024,
                        Tag::PKESK =>
                            // 10 bytes of fixed header, plus the
                            // encrypted session key.
                            10 < l && l < 10 * 1024,
                        Tag::OnePassSig if ! future_compatible => l == 13,
                        Tag::OnePassSig => l < 1024,
                        Tag::PublicKey | Tag::PublicSubkey
                            | Tag::SecretKey | Tag::SecretSubkey =>
                            // A V3 key is 8 bytes of fixed header
                            // plus MPIs.  A V4 key is 6 bytes of
                            // fixed headers plus MPIs.
                            6 < l && l < 1024 * 1024,
                        Tag::Trust => true,
                        Tag::UserID =>
                            // Avoid insane user ids.
                            l < 32 * 1024,
                        Tag::UserAttribute =>
                            // The header is at least 2 bytes.
                            2 <= l,
                        Tag::MDC => l == 20,

                        Tag::Literal | Tag::CompressedData
                            | Tag::SED | Tag::SEIP | Tag::AED =>
                            unreachable!("handled in the data-packet branch"),
                        Tag::Unknown(_) | Tag::Private(_) => true,

                        Tag::Marker => l == 3,
                        Tag::Reserved => true,
                    };

                    if ! valid {
                        return Err(Error::MalformedPacket(
                            format!("Invalid size ({} bytes) for a {} packet",
                                    l, tag)).into())
                    }
                }
            }
        }

        Ok(())
    }
}
