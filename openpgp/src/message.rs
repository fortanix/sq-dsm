use std::fmt;
use std::path::Path;
use std::iter;

use Result;
use Error;
use Tag;
use Packet;
use PacketPile;
use Message;

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Message")
            .field("pile", &self.pile)
            .finish()
    }
}

// This is a helper function to signal that an `PacketPile` is not a
// `Message`.
macro_rules! bad {
    ($msg:expr) => ({
        return Err(Error::MalformedMessage(
            format!("Invalid OpenPGP message: {}", $msg.to_string())
                .into()).into())
    });
}

// The grammar for an encrypt part is:
//
//   ESK :- Public-Key Encrypted Session Key Packet |
//          Symmetric-Key Encrypted Session Key Packet.
//
//   ESK Sequence :- ESK | ESK Sequence, ESK.
//
//   Encrypted Data :- Symmetrically Encrypted Data Packet |
//         Symmetrically Encrypted Integrity Protected Data Packet
//
//   Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
//
// See https://tools.ietf.org/html/rfc4880#section-11.3
//
// In other words: zero or more ESKs followed by exactly one SEIP or
// SED packet.
fn is_encrypted_part<'a, I>(mut po: Option<&'a Packet>, mut iter: I,
                            depth: usize)
    -> Result<()>
    where I: Iterator<Item=&'a Packet>
{
    if po.is_none() {
        po = iter.next();
    }

    while let Some(p) = po {
        // We match by tag so that we correctly handle Unknown
        // packets.
        match p.tag() {
            Tag::PKESK | Tag::SKESK => (),

            tag @ Tag::SEIP | tag @ Tag::SED => {
                // This has to be the last packet.
                let tail : Vec<&Packet> = iter.collect();
                if tail.len() > 0 {
                    bad!(format!(
                        "{} should be the last packet in an encrypted part, \
                         but followed by {} packets ({:?}).",
                        tag, tail.len(),
                        tail.iter().map(|p| p.tag()).collect::<Vec<Tag>>()));
                }

                // XXX: We assume that if a SEIP or SED packet has a
                // body, then the body is encrypted.
                if p.body.is_some() {
                    return Ok(());
                } else if let Some(ref children) = p.children {
                    return is_message(None, children.children(), depth + 1);
                } else {
                    bad!("an encrypted part cannot be empty.");
                }
            },

            tag @ _ =>
                bad!(format!("while parsing an encrypted part: \
                              unexpected packet ({})",
                             tag)),
        }

        po = iter.next();
    }

    bad!("encrypted part missing a SEIP or SED packet.");
}

fn is_one_pass_signed_part<'a, I>(mut po: Option<&'a Packet>, mut iter: I,
                                  depth: usize)
    -> Result<()>
    where I: Iterator<Item=&'a Packet>
{
    if po.is_none() {
        po = iter.next();
    }

    let mut ops = 0;
    let mut saw_message = false;

    while let Some(p) = po {
        // We match by tag so that we correctly handle Unknown
        // packets.
        match p.tag() {
            Tag::OnePassSig => {
                if saw_message {
                    bad!("One Pass Signature packet should not follow \
                          a message.");
                }
                ops += 1;
            },
            Tag::Signature => {
                if !saw_message {
                    bad!("Signature packet encountered \
                          before a signed message.");
                }
                if ops == 0 {
                    bad!("Unbalanced signature: more Signature than \
                          One Pass Signature packets.");
                }
                ops -= 1;
            }
            _ => {
                if saw_message {
                    bad!("A signature is only allowed over a single message.");
                }
                saw_message = true;
                is_message(Some(p), iter::empty(), depth + 1)?
            },
        }

        po = iter.next();
    }

    if !(ops == 0 && saw_message) {
        bad!(format!("Unbalanced signature: missing {} signature packets",
                     ops));
    }

    Ok(())
}

fn is_message<'a, I>(mut po: Option<&'a Packet>, mut iter: I, depth: usize)
    -> Result<()>
    where I: Iterator<Item=&'a Packet>
{
    if po.is_none() {
        po = iter.next();
    }

    let tag = po.and_then(|p| Some(p.tag()));

    match tag {
        None =>
            bad!("an empty message is not a valid OpenPGP message."),

        Some(Tag::PublicKey) =>
            bad!("it appears to be a TPK."),

        Some(Tag::SecretKey) =>
            bad!("it appears to be a TSK."),

        Some(Tag::PKESK) | Some(Tag::SKESK)
            | Some(Tag::SEIP) | Some(Tag::SED) =>
            is_encrypted_part(po, iter, depth + 1),

        Some(Tag::OnePassSig) =>
            is_one_pass_signed_part(po, iter, depth + 1),

        Some(Tag::Signature) => {
            // Signature Packet, OpenPGP Message
            is_message(None, iter, depth + 1)
        },

        Some(Tag::CompressedData) => {
            if iter.next().is_some() {
                bad!("a compressed packet may not be \
                      followed by another packet.");
            }

            let p = po.unwrap();
            if p.body.is_some() {
                // XXX: The body is still compressed.  Assume it is
                // okay.
                Ok(())
            } else if let Some(ref children) = p.children {
                is_message(None, children.children(), depth + 1)
            } else {
                bad!("empty compressed data packet.");
            }
        },

        Some(Tag::Literal) => {
            if iter.next().is_some() {
                bad!("a literal packet may not be \
                      followed by another packet.");
            }

            Ok(())
        },

        _ => {
            bad!(format!("{:?} is invalid.", tag));
        },
    }
}

impl Message {
    /// Converts the `PacketPile` to a `Message`.
    ///
    /// Converting a `PacketPile` to a `Message` doesn't change the
    /// packets; it asserts that the packet sequence is an optionally
    /// encrypted, optionally signed, optionally compressed literal
    /// data packet.  The exact grammar is defined in [Section 11.3 of
    /// RFC 4880].
    ///
    /// Caveats: this function assumes that any still encrypted parts
    /// or still compressed parts are valid messages.
    ///
    ///   [Section 11.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-11.3
    pub fn from_packet_pile(pile: PacketPile) -> Result<Self> {
        is_message(None, pile.children(), 0)
            .and_then(|_| Ok(Message { pile: pile } ))
    }

    /// Converts the vector of `Packets` to a `Message`.
    ///
    /// See [`Message::from_packets`] for more details.
    ///
    ///   [`Message::from_packets`]: #method.from_packet_pile
    pub fn from_packets(packets: Vec<Packet>) -> Result<Self> {
        Self::from_packet_pile(PacketPile::from_packets(packets))
    }

    /// Reads a `Message` from the specified file.
    ///
    /// See [`Message::from_packets`] for more details.
    ///
    ///   [`Message::from_packets`]: #method.from_packet_pile
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_packet_pile(PacketPile::from_file(path)?)
    }

    /// Converts the `Message` to a `PacketPile`.
    pub fn to_packet_pile(self) -> PacketPile {
        self.pile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use HashAlgorithm;
    use CompressionAlgorithm;
    use SymmetricAlgorithm;
    use PublicKeyAlgorithm;
    use SignatureType;
    use S2K;
    use MPIs;
    use CompressedData;
    use Literal;
    use OnePassSig;
    use Signature;
    use SKESK;
    use PKESK;
    use SEIP;
    use KeyID;
    use Container;

    #[test]
    fn basic() {
        // Empty.
        // => bad.
        let message = Message::from_packets(vec![]);
        assert!(message.is_err(), "{:?}", message);

        // 0: Literal
        // => good.
        let mut packets = Vec::new();
        packets.push(Literal::new('t').body(b"data".to_vec()).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);
    }

    #[test]
    fn compressed_part() {
        // 0: CompressedData
        //  0: Literal
        // => good.
        let mut packets = Vec::new();
        packets.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(Literal::new('t').body(b"inner".to_vec()).to_packet())
                .to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);

        // 0: CompressedData
        //  0: Literal
        //  1: Literal
        // => bad.
        let mut packets = Vec::new();
        packets.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(Literal::new('t').body(b"inner one".to_vec()).to_packet())
                .push(Literal::new('t').body(b"inner two".to_vec()).to_packet())
                .to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_err(), "{:?}", message);

        // 0: CompressedData
        //  0: Literal
        // 1: Literal
        // => bad.
        let mut packets = Vec::new();
        packets.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(Literal::new('t').body(b"inner".to_vec()).to_packet())
                .to_packet());
        packets.push(Literal::new('t').body(b"outer".to_vec()).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_err(), "{:?}", message);

        // 0: CompressedData
        //  0: CompressedData
        //   0: Literal
        // => good.
        let mut packets = Vec::new();
        packets.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(Literal::new('t').body(b"inner".to_vec())
                            .to_packet())
                      .to_packet())
                .to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);
    }

    #[test]
    fn one_pass_sig_part() {
        // 0: OnePassSig
        // => bad.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_err(), "{:?}", message);

        // 0: OnePassSig
        // 1: Literal
        // => bad.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_err(), "{:?}", message);

        // 0: OnePassSig
        // 1: Literal
        // 2: Signature
        // => good.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);

        // 0: OnePassSig
        // 1: Literal
        // 2: Signature
        // 3: Signature
        // => bad.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_err(), "{:?}", message);

        // 0: OnePassSig
        // 1: OnePassSig
        // 2: Literal
        // 3: Signature
        // 4: Signature
        // => good.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);

        // 0: OnePassSig
        // 1: OnePassSig
        // 2: Literal
        // 3: Literal
        // 4: Signature
        // 5: Signature
        // => bad.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_err(), "{:?}", message);

        // 0: OnePassSig
        // 1: OnePassSig
        // 2: CompressedData
        //  0: Literal
        // 3: Signature
        // 4: Signature
        // => good.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(Literal::new('t').body(b"inner".to_vec()).to_packet())
                .to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);
    }

    #[test]
    fn signature_part() {
        // 0: Signature
        // => bad.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(Signature::new(SignatureType::Binary).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_err(), "{:?}", message);

        // 0: Signature
        // 1: Literal
        // => good.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);

        // 0: Signature
        // 1: Signature
        // 2: Literal
        // => good.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);
    }

    #[test]
    fn encrypted_part() {
        // There are no simple constructors for SEIP packets: they are
        // interleaved with SK-ESK and PK-ESK packets.  And, the
        // session key needs to be managed.  Instead, we use some
        // internal iterfaces to progressively build up more
        // complicated messages.

        // 0: SK-ESK
        // => bad.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(SKESK::new(SymmetricAlgorithm::AES256,
                                S2K::Simple { hash: HashAlgorithm::SHA256 },
                                &b"12345678"[..],
                                &b"12345678"[..]).unwrap().to_packet());
        let message = Message::from_packets(packets.clone());
        assert!(message.is_err(), "{:?}", message);

        // 0: SK-ESK
        // 1: Literal
        // => bad.
        packets.push(Literal::new('t').body(b"inner".to_vec()).to_packet());

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::SKESK, Tag::Literal ]);

        let message = Message::from_packets(packets.clone());
        assert!(message.is_err(), "{:?}", message);

        // 0: SK-ESK
        // 1: SEIP
        //  0: Literal
        // => good.
        let mut seip = SEIP {
            common: Default::default(),
            version: 0
        };
        seip.common.children = Some(Container::new());
        seip.common.children.as_mut().unwrap().push(
            Literal::new('t').body(b"inner".to_vec()).to_packet());
        packets[1] = Packet::SEIP(seip);

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::SKESK, Tag::SEIP ]);

        let message = Message::from_packets(packets.clone());
        assert!(message.is_ok(), "{:#?}", message);

        // 0: SK-ESK
        // 1: SEIP
        //  0: Literal
        // 2: SK-ESK
        // => bad.
        let skesk = packets[0].clone();
        packets.push(skesk);

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::SKESK, Tag::SEIP, Tag::SKESK ]);

        let message = Message::from_packets(packets.clone());
        assert!(message.is_err(), "{:#?}", message);

        // 0: SK-ESK
        // 1: SK-ESK
        // 2: SEIP
        //  0: Literal
        // => good.
        packets.swap(1, 2);

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::SKESK, Tag::SKESK, Tag::SEIP ]);

        let message = Message::from_packets(packets.clone());
        assert!(message.is_ok(), "{:#?}", message);

        // 0: SK-ESK
        // 1: SK-ESK
        // 2: SEIP
        //  0: Literal
        // 3: SEIP
        //  0: Literal
        // => bad.
        let seip = packets[2].clone();
        packets.push(seip);

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::SKESK, Tag::SKESK, Tag::SEIP, Tag::SEIP ]);

        let message = Message::from_packets(packets.clone());
        assert!(message.is_err(), "{:#?}", message);

        // 0: SK-ESK
        // 1: SK-ESK
        // 2: SEIP
        //  0: Literal
        // 3: Literal
        // => bad.
        packets[3]
            = packets[3].children.as_mut().unwrap().packets.pop().unwrap();

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::SKESK, Tag::SKESK, Tag::SEIP, Tag::Literal ]);

        let message = Message::from_packets(packets.clone());
        assert!(message.is_err(), "{:#?}", message);

        // 0: SK-ESK
        // 1: SK-ESK
        // 2: SEIP
        //  0: Literal
        //  1: Literal
        // => bad.
        packets.remove(3);
        packets[2].children.as_mut().unwrap().push(
            Literal::new('t').body(b"inner two".to_vec()).to_packet());

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::SKESK, Tag::SKESK, Tag::SEIP ]);

        let message = Message::from_packets(packets.clone());
        assert!(message.is_err(), "{:#?}", message);

        // 0: SK-ESK
        // 2: PK-ESK
        // 1: SK-ESK
        // 2: SEIP
        //  0: Literal
        // => good.
        packets[2].children.as_mut().unwrap().packets.pop().unwrap();

        packets.insert(
            1,
            Packet::PKESK(PKESK {
                common: Default::default(),
                version: 0,
                recipient: KeyID::from_hex("0000111122223333").unwrap(),
                pk_algo: PublicKeyAlgorithm::RSAEncrypt,
                esk: MPIs::empty()
            }));

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::SKESK, Tag::PKESK, Tag::SKESK, Tag::SEIP ]);

        let message = Message::from_packets(packets.clone());
        assert!(message.is_ok(), "{:#?}", message);
    }
}
