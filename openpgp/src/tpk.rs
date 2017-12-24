//! Transferable public keys.

use std::io;
use std::path::Path;
use std::fs::File;

use super::{Packet, Message, Signature, Key, UserID, Fingerprint};
use super::parse::PacketParser;

/// A transferable public key (TPK).
///
/// A TPK (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
#[derive(Debug)]
pub struct TPK {
    primary: Key,
    userids: Vec<UserIDBinding>,
    subkeys: Vec<SubkeyBinding>,
}

#[derive(Debug)]
pub struct SubkeyBinding {
    subkey: Key,
    signatures: Vec<Signature>,
}

#[derive(Debug)]
pub struct UserIDBinding {
    userid: UserID,
    signatures: Vec<Signature>,
}

// We use a state machine to extract a TPK from an OpenPGP message.
// These are the states.
#[derive(Debug)]
enum TPKParserState {
    Start,
    TPK,
    UserID(UserIDBinding),
    Subkey(SubkeyBinding),
    End,
}

struct TPKParser {
    state: TPKParserState,
    primary: Option<Key>,
    userids: Vec<UserIDBinding>,
    subkeys: Vec<SubkeyBinding>,
}

impl TPKParser {
    // Initializes a parser.
    fn new() -> TPKParser {
        TPKParser {
            state: TPKParserState::Start,
            primary: None,
            userids: vec![],
            subkeys: vec![],
        }
    }

    // Parses the next packet in the packet stream.
    fn parse(mut self, p: Packet) -> Self {
        self.state = match { self.state } {
            TPKParserState::Start => {
                /* Find the first public key packet.  */
                match p {
                    Packet::PublicKey(pk) => {
                        self.primary = Some(pk);
                        TPKParserState::TPK
                    },
                    _ => TPKParserState::Start,
                }
            },
            TPKParserState::TPK => {
                /* Find user id, or subkey packets.  */
                match p {
                    Packet::PublicKey(_pk) => {
                        TPKParserState::End
                    },
                    Packet::UserID(uid) => {
                        TPKParserState::UserID(
                            UserIDBinding{userid: uid, signatures: vec![]})
                    },
                    Packet::PublicSubkey(key) => {
                        TPKParserState::Subkey(
                            SubkeyBinding{subkey: key, signatures: vec![]})
                    },
                    _ => TPKParserState::TPK,
                }
            },
            TPKParserState::UserID(mut u) => {
                /* Find signature packets.  */
                match p {
                    Packet::PublicKey(_pk) => {
                        TPKParserState::End
                    },
                    Packet::UserID(uid) => {
                        self.userids.push(u);
                        TPKParserState::UserID(
                            UserIDBinding{userid: uid, signatures: vec![]})
                    },
                    Packet::PublicSubkey(key) => {
                        self.userids.push(u);
                        TPKParserState::Subkey(
                            SubkeyBinding{subkey: key, signatures: vec![]})
                    },
                    Packet::Signature(sig) => {
                        u.signatures.push(sig);
                        TPKParserState::UserID(u)
                    },
                    _ => TPKParserState::UserID(u),
                }
            },
            TPKParserState::Subkey(mut s) => {
                /* Find signature packets.  */
                match p {
                    Packet::PublicKey(_pk) => {
                        TPKParserState::End
                    },
                    Packet::UserID(uid) => {
                        self.subkeys.push(s);
                        TPKParserState::UserID(
                            UserIDBinding{userid: uid, signatures: vec![]})
                    },
                    Packet::PublicSubkey(key) => {
                        self.subkeys.push(s);
                        TPKParserState::Subkey(
                            SubkeyBinding{subkey: key, signatures: vec![]})
                    },
                    Packet::Signature(sig) => {
                        s.signatures.push(sig);
                        TPKParserState::Subkey(s)
                    },
                    _ => TPKParserState::Subkey(s),
                }
            },
            TPKParserState::End => TPKParserState::End,
        };

        self
    }

    // Returns whatever TPK was found.
    fn finish(self) -> Result<TPK> {
        let mut tpk = if let Some(p) = self.primary {
            TPK {
                primary: p,
                userids: self.userids,
                subkeys: self.subkeys
            }
        } else {
            return Err(Error::NoKeyFound);
        };

        match self.state {
            TPKParserState::UserID(u) => {
                tpk.userids.push(u);
                Ok(tpk)
            },
            TPKParserState::Subkey(s) => {
                tpk.subkeys.push(s);
                Ok(tpk)
            },
            TPKParserState::End => Ok(tpk),
            _ => Err(Error::NoKeyFound),
        }.and_then(|tpk| tpk.canonicalize())
    }
}

impl TPK {
    /// Returns the first TPK found in the packet stream.
    pub fn from_packet_parser(mut pp: PacketParser) -> Result<Self> {
        let mut parser = TPKParser::new();
        loop {
            let (packet, _, ppo, _) = pp.next()?;
            parser = parser.parse(packet);
            match parser.state {
                TPKParserState::End => break,
                _ => true,
            };

            if ppo.is_none() {
                break;
            }
            pp = ppo.unwrap();
        }

        parser.finish()
    }

    /// Returns the first TPK encountered in the reader.
    pub fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        let ppo = PacketParser::from_reader(reader)
            .map_err(|e| Error::IoError(e))?;
        if let Some(pp) = ppo {
            TPK::from_packet_parser(pp)
        } else {
            TPKParser::new().finish()
        }
    }

    /// Returns the first TPK encountered in the file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_reader(File::open(path)?)
    }

    /// Returns the first TPK found in `m`.
    pub fn from_message(m: Message) -> Result<Self> {
        let mut parser = TPKParser::new();
        for p in m.into_children() {
            parser = parser.parse(p);
            match parser.state {
                TPKParserState::End => break,
                _ => true,
            };
        }

        parser.finish()
    }

    /// Returns the first TPK found in `buf`.
    ///
    /// `buf` must be an OpenPGP encoded message.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let ppo = PacketParser::from_bytes(buf)
            .map_err(|e| Error::IoError(e))?;
        if let Some(pp) = ppo {
            TPK::from_packet_parser(pp)
        } else {
            TPKParser::new().finish()
        }
    }

    fn canonicalize(mut self) -> Result<Self> {
        // Sanity checks.

        // - One or more User ID packets.
        if self.userids.len() == 0 {
            return Err(Error::NoUserId);
        }

        // Drop user ids.
        self.userids.retain(|userid| {
            // XXX Check binding signature.
            userid.signatures.len() > 0
        });

        // Drop invalid subkeys.
        self.subkeys.retain(|subkey| {
            // XXX Check binding signature.
            subkey.signatures.len() > 0
        });

        // XXX Do some more canonicalization.

        Ok(self)
    }

    /// Returns the fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.primary.fingerprint()
    }

    /// Serialize the transferable public key into an OpenPGP message.
    pub fn to_message(self) -> Message {
        let mut p : Vec<Packet> = Vec::new();

        p.push(Packet::PublicKey(self.primary));

        for u in self.userids.into_iter() {
            p.push(Packet::UserID(u.userid));
            for s in u.signatures.into_iter() {
                p.push(Packet::Signature(s));
            }
        }

        let subkeys = self.subkeys;
        for k in subkeys.into_iter() {
            p.push(Packet::PublicSubkey(k.subkey));
            for s in k.signatures.into_iter() {
                p.push(Packet::Signature(s));
            }
        }

        Message::from_packets(p)
    }
}

/// Results for TPK.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Errors returned from the key routines.
#[derive(Debug)]
pub enum Error {
    /// No key found in OpenPGP message.
    NoKeyFound,
    /// No user id found.
    NoUserId,
    /// An `io::Error` occured.
    IoError(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

#[cfg(test)]
mod test {
    use super::{Error, TPK, Message, Result};

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../tests/data/keys/", $x)) };
    }

    macro_rules! assert_match {
        ( $error: pat = $expr:expr ) => {
            let x = $expr;
            if let $error = x {
                /* Pass.  */
            } else {
                panic!("Expected {}, got {:?}.", stringify!($error), x);
            }
        };
    }

    fn parse_tpk(data: &[u8], as_message: bool) -> Result<TPK> {
        if as_message {
            let m = Message::from_bytes(data).unwrap();
            TPK::from_message(m)
        } else {
            TPK::from_bytes(data)
        }
    }

    #[test]
    fn broken() {
        for i in 0..2 {
            let tpk = parse_tpk(bytes!("testy-broken-no-pk.pgp"),
                                i == 0);
            assert_match!(Err(Error::NoKeyFound) = tpk);

            let tpk = parse_tpk(bytes!("testy-broken-no-uid.pgp"),
                                i == 0);
            assert_match!(Err(Error::NoUserId) = tpk);

            // We have:
            //
            //   [ pk, user id, sig, subkey ]
            let tpk = parse_tpk(bytes!("testy-broken-no-sig-on-subkey.pgp"),
                                i == 0).unwrap();
            eprintln!("{:?}", tpk);
            assert_eq!(tpk.primary.creation_time, 1511355130);
            assert_eq!(tpk.userids.len(), 1);
            assert_eq!(tpk.userids[0].userid.value,
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].signatures.len(), 1);
            assert_eq!(tpk.userids[0].signatures[0].hash_prefix,
                       [ 0xc6, 0x8f ]);
            assert_eq!(tpk.subkeys.len(), 0);
        }
    }

    #[test]
    fn basics() {
        for i in 0..2 {
            let tpk = parse_tpk(bytes!("testy.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.creation_time, 1511355130);
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(tpk.userids.len(), 1, "number of userids");
            assert_eq!(tpk.userids[0].userid.value,
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].signatures.len(), 1);
            assert_eq!(tpk.userids[0].signatures[0].hash_prefix,
                       [ 0xc6, 0x8f ]);

            assert_eq!(tpk.subkeys.len(), 1, "number of subkeys");
            assert_eq!(tpk.subkeys[0].subkey.creation_time, 1511355130);
            assert_eq!(tpk.subkeys[0].signatures[0].hash_prefix,
                       [ 0xb7, 0xb9 ]);

            let tpk = parse_tpk(bytes!("testy-no-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.creation_time, 1511355130);
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(tpk.userids.len(), 1, "number of userids");
            assert_eq!(tpk.userids[0].userid.value,
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].signatures.len(), 1);
            assert_eq!(tpk.userids[0].signatures[0].hash_prefix,
                       [ 0xc6, 0x8f ]);

            assert_eq!(tpk.subkeys.len(), 0, "number of subkeys");
        }
    }
}
