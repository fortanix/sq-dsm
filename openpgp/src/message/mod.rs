use std::fmt;
use std::path::Path;

use Result;
use Error;
use Packet;
use PacketPile;
use Message;

mod lexer;
mod grammar;

use self::lexer::Lexer;
use self::grammar::MessageParser;

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Message")
            .field("pile", &self.pile)
            .finish()
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
        let r = MessageParser::new().parse(Lexer::from_packet_pile(&pile)?);
        match r {
            Ok(_) => Ok(Message { pile: pile }),
            /// We really want to squash the lexer's error: it is an
            /// internal detail that may change, and meaningless even
            /// to an immediate user of this crate.
            Err(err) => Err(Error::MalformedMessage(
                format!("Invalid OpenPGP message: {:?}", err).into()).into())
        }
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

    use constants::DataFormat::Text;
    use HashAlgorithm;
    use CompressionAlgorithm;
    use SymmetricAlgorithm;
    use PublicKeyAlgorithm;
    use SignatureType;
    use s2k::S2K;
    use mpis::MPIs;
    use Tag;
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
    fn tokens() {
        use self::lexer::{Token, Lexer};
        use self::lexer::Token::*;
        use self::grammar::MessageParser;

        struct TestVector<'a> {
            s: &'a [Token],
            result: bool,
        }

        let test_vectors = [
            TestVector {
                s: &[Literal][..],
                result: true,
            },
            TestVector {
                s: &[CompressedData, Literal, Pop],
                result: true,
            },
            TestVector {
                s: &[CompressedData, CompressedData, Literal,
                     Pop, Pop],
                result: true,
            },
            TestVector {
                s: &[SEIP, Literal, Pop],
                result: true,
            },
            TestVector {
                s: &[CompressedData, SEIP, Literal, Pop, Pop],
                result: true,
            },
            TestVector {
                s: &[CompressedData, SEIP, CompressedData, Literal,
                     Pop, Pop, Pop],
                result: true,
            },
            TestVector {
                s: &[SEIP, Pop],
                result: false,
            },
            TestVector {
                s: &[SKESK, SEIP, Literal, Pop],
                result: true,
            },
            TestVector {
                s: &[PKESK, SEIP, Literal, Pop],
                result: true,
            },
            TestVector {
                s: &[SKESK, SKESK, SEIP, Literal, Pop],
                result: true,
            },

            TestVector {
                s: &[OPS, Literal, SIG],
                result: true,
            },
            TestVector {
                s: &[OPS, OPS, Literal, SIG, SIG],
                result: true,
            },
            TestVector {
                s: &[OPS, OPS, Literal, SIG],
                result: false,
            },
            TestVector {
                s: &[OPS, OPS, SEIP, OPS, SEIP, Literal, Pop,
                     SIG, Pop, SIG, SIG],
                result: true,
            },

            TestVector {
                s: &[CompressedData, OpaqueContent],
                result: false,
            },
            TestVector {
                s: &[CompressedData, OpaqueContent, Pop],
                result: true,
            },
            TestVector {
                s: &[CompressedData, CompressedData, OpaqueContent, Pop, Pop],
                result: true,
            },
            TestVector {
                s: &[SEIP, CompressedData, OpaqueContent, Pop, Pop],
                result: true,
            },
            TestVector {
                s: &[SEIP, OpaqueContent, Pop],
                result: true,
            },
        ];

        for v in test_vectors.into_iter() {
            eprintln!("Parsing: {:?}", v.s);
            match MessageParser::new().parse(Lexer::from_tokens(v.s))
            {
                Ok(r) => {
                    println!("Parsed as {:?} {}",
                             r,
                             if v.result { "(expected)" }
                             else { "UNEXPECTED!" });
                    assert!(v.result);
                },
                Err(e) => {
                    println!("Parse error: {:?} {}",
                             e,
                             if v.result { "UNEXPECTED!" }
                             else { "(expected)" });
                    assert!(! v.result);
                }
            }
        }
    }

    #[test]
    fn basic() {
        // Empty.
        // => bad.
        let message = Message::from_packets(vec![]);
        assert!(message.is_err(), "{:?}", message);

        // 0: Literal
        // => good.
        let mut packets = Vec::new();
        packets.push(Literal::new(Text).body(b"data".to_vec()).to_packet());

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
                .push(Literal::new(Text).body(b"inner".to_vec()).to_packet())
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
                .push(Literal::new(Text).body(b"inner one".to_vec()).to_packet())
                .push(Literal::new(Text).body(b"inner two".to_vec()).to_packet())
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
                .push(Literal::new(Text).body(b"inner".to_vec()).to_packet())
                .to_packet());
        packets.push(Literal::new(Text).body(b"outer".to_vec()).to_packet());

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
                      .push(Literal::new(Text).body(b"inner".to_vec())
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
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_err(), "{:?}", message);

        // 0: OnePassSig
        // 1: Literal
        // 2: Signature
        // => good.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(OnePassSig::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());
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
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());
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
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());
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
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());
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
                .push(Literal::new(Text).body(b"inner".to_vec()).to_packet())
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
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());

        let message = Message::from_packets(packets);
        assert!(message.is_ok(), "{:?}", message);

        // 0: Signature
        // 1: Signature
        // 2: Literal
        // => good.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Signature::new(SignatureType::Binary).to_packet());
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());

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
        packets.push(Literal::new(Text).body(b"inner".to_vec()).to_packet());

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
            Literal::new(Text).body(b"inner".to_vec()).to_packet());
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
            Literal::new(Text).body(b"inner two".to_vec()).to_packet());

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
