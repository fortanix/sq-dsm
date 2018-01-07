//! Transferable public keys.

use std::io;
use std::cmp::Ordering;
use std::path::Path;
use std::fs::File;

use super::{Packet, Message, Signature, Key, UserID, Fingerprint, Tag};
use super::parse::PacketParser;
use super::serialize::{signature_serialize};

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
    userids: Vec<UserIDBinding>,
    subkeys: Vec<SubkeyBinding>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SubkeyBinding {
    subkey: Key,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.  (In general, this will only be by
    // designated revokers.)
    certifications: Vec<Signature>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserIDBinding {
    userid: UserID,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.
    certifications: Vec<Signature>,
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
                            UserIDBinding{
                                userid: uid,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::PublicSubkey(key) => {
                        TPKParserState::Subkey(
                            SubkeyBinding{
                                subkey: key,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
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
                            UserIDBinding{
                                userid: uid,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::PublicSubkey(key) => {
                        self.userids.push(u);
                        TPKParserState::Subkey(
                            SubkeyBinding{
                                subkey: key,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::Signature(sig) => {
                        let primary = self.primary.as_ref().unwrap();
                        let selfsig = if let Some((_critical, issuer))
                                = sig.issuer_fingerprint() {
                            issuer == primary.fingerprint()
                        } else if let Some((_critical, issuer))
                                = sig.issuer() {
                            issuer == primary.keyid()
                        } else {
                            // No issuer.  XXX: Assume its a 3rd party
                            // cert.  But, we should really just try
                            // to reorder it.
                            false
                        };
                        if selfsig {
                            u.selfsigs.push(sig);
                        } else {
                            u.certifications.push(sig);
                        }
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
                            UserIDBinding{
                                userid: uid,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::PublicSubkey(key) => {
                        self.subkeys.push(s);
                        TPKParserState::Subkey(
                            SubkeyBinding{
                                subkey: key,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::Signature(sig) => {
                        let primary = self.primary.as_ref().unwrap();
                        let selfsig = if let Some((_critical, issuer))
                                = sig.issuer_fingerprint() {
                            issuer == primary.fingerprint()
                        } else if let Some((_critical, issuer))
                                = sig.issuer() {
                            issuer == primary.keyid()
                        } else {
                            // No issuer.  XXX: Assume its a 3rd party
                            // cert.  But, we should really just try
                            // to reorder it.
                            false
                        };
                        if selfsig {
                            s.selfsigs.push(sig);
                        } else {
                            s.certifications.push(sig);
                        }

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
        // Helper functions.

        // Compare the creation time of two signatures.  Order them so
        // that the more recent signature is first.
        fn sig_cmp(a: &Signature, b: &Signature) -> Ordering {
            b.signature_creation_time().cmp(&a.signature_creation_time())
        }

        // Turn a signature into a key for use by dedup.
        fn sig_key(a: &mut Signature) -> Box<[u8]> {
            let mut bytes = Vec::new();
            // Serializing to a vector won't fail.
            signature_serialize(&mut bytes, a).unwrap();
            return bytes.into_boxed_slice();
        }


        // Sanity checks.

        // - One or more User ID packets.
        if self.userids.len() == 0 {
            return Err(Error::NoUserId);
        }

        // Drop invalid user ids.
        self.userids.retain(|userid| {
            // XXX Check binding signature.
            userid.selfsigs.len() > 0
        });

        // XXX: Drop invalid self-signatures.

        // Sort the signatures so that the current valid
        // self-signature is first.
        for userid in &mut self.userids {
            userid.selfsigs.sort_by(sig_cmp);
            userid.selfsigs.dedup_by_key(sig_key);

            // There is no need to sort the certifications, but we do
            // want to remove dups and sorting is a prerequisite.
            userid.certifications.sort_by(sig_cmp);
            userid.certifications.dedup_by_key(sig_key);
        }

        // First, we sort the bindings lexographically by user id in
        // preparation for a dedup.
        //
        // Note: we cannot do the final sort here, because a user ID
        // might appear multiple times, sometimes being marked as
        // primary and sometimes not, for example.  In such a case,
        // one copy might be sorted to the front and the other to the
        // back, and the following dedup wouldn't combine the user
        // ids!
        self.userids.sort_by(|a, b| a.userid.value.cmp(&b.userid.value));

        // Then, we dedup them.
        self.userids.dedup_by(|a, b| {
            if a.userid == b.userid {
                // Merge the content of duplicate user ids.

                // Recall: if a and b are equal, a will be dropped.
                b.selfsigs.append(&mut a.selfsigs);
                b.selfsigs.sort_by(sig_cmp);
                b.selfsigs.dedup_by_key(sig_key);

                b.certifications.append(&mut a.certifications);
                b.certifications.sort_by(sig_cmp);
                b.certifications.dedup_by_key(sig_key);

                true
            } else {
                false
            }
        });

        // Now, resort using the information provided in the self-sig.
        //
        // Recall: we know that there are no duplicates, and that
        // self-signatures have been sorted.
        //
        // Order by:
        //
        //  - Whether the User IDs are marked as primary.
        //
        //  - The timestamp (reversed).
        //
        //  - The User IDs' lexographical order.
        //
        // Note: Comparing the lexographical order of the serialized form
        // is useless since that will be the same as the User IDs'
        // lexographical order.
        self.userids.sort_by(|a, b| {
            // Compare their primary status.
            let a_primary = a.selfsigs[0].primary_userid();
            let b_primary = b.selfsigs[0].primary_userid();

            if a_primary.is_some() && b_primary.is_none() {
                return Ordering::Less;
            } else if a_primary.is_none() && b_primary.is_some() {
                return Ordering::Greater;
            } else if a_primary.is_some() && b_primary.is_some() {
                // Both are marked as primary.  Fallback to the date.
                let a_timestamp
                    = a.selfsigs[0].signature_creation_time().unwrap_or(0);
                let b_timestamp
                    = b.selfsigs[0].signature_creation_time().unwrap_or(0);
                // We want the more recent date first.
                let cmp = b_timestamp.cmp(&a_timestamp);
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }

            // Fallback to a lexicographical comparison.
            a.userid.value.cmp(&b.userid.value)
        });


        // Drop invalid subkeys.
        self.subkeys.retain(|subkey| {
            // XXX Check binding signature.
            subkey.selfsigs.len() > 0
        });

        // XXX: Drop invalid self-signatures / see if they are just
        // out of place.

        // Sort the signatures so that the current valid
        // self-signature is first.
        for subkey in &mut self.subkeys {
            subkey.selfsigs.sort_by(sig_cmp);
            subkey.selfsigs.dedup_by_key(sig_key);

            // There is no need to sort the certifications, but we do
            // want to remove dups and sorting is a prerequisite.
            subkey.certifications.sort_by(sig_cmp);
            subkey.certifications.dedup_by_key(sig_key);
        }

        // Sort the subkeys in preparation for a dedup.  As for the
        // user ids, we can't do the final sort here, because we rely
        // on the self-signatures.
        self.subkeys.sort_by(|a, b| a.subkey.mpis.cmp(&b.subkey.mpis));

        // And, dedup them.
        self.subkeys.dedup_by(|a, b| {
            if a.subkey == b.subkey {
                // Recall: if a and b are equal, a will be dropped.
                b.selfsigs.append(&mut a.selfsigs);
                b.selfsigs.sort_by(sig_cmp);
                b.selfsigs.dedup_by_key(sig_key);

                b.certifications.append(&mut a.certifications);
                b.certifications.sort_by(sig_cmp);
                b.certifications.dedup_by_key(sig_key);

                true
            } else {
                false
            }
        });

        self.subkeys.sort_by(|a, b| {
            // Features.
            let a_features = a.selfsigs[0].features().unwrap_or(Vec::new());
            let b_features = b.selfsigs[0].features().unwrap_or(Vec::new());
            let cmp = a_features.cmp(&b_features);
            if cmp != Ordering::Equal {
                return cmp;
            }

            // Creation time (more recent first).
            let cmp = b.subkey.creation_time.cmp(&a.subkey.creation_time);
            if cmp != Ordering::Equal {
                return cmp;
            }

            // Fallback to the lexicographical comparison.
            a.subkey.mpis.cmp(&b.subkey.mpis)
        });


        // XXX Do some more canonicalization.

        // Collect revocation certs and designated revocation certs.

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
            for s in u.selfsigs.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in u.certifications.into_iter() {
                p.push(Packet::Signature(s));
            }
        }

        let subkeys = self.subkeys;
        for k in subkeys.into_iter() {
            p.push(Packet::PublicSubkey(k.subkey));
            for s in k.selfsigs.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in k.certifications.into_iter() {
                p.push(Packet::Signature(s));
            }
        }

        Message::from_packets(p)
    }

    /// Serialize the TPK.
    pub fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        use super::serialize::*;
        key_serialize(o, &self.primary, Tag::PublicKey)?;

        for u in self.userids.iter() {
            userid_serialize(o, &u.userid)?;
            for s in u.selfsigs.iter() {
                signature_serialize(o, s)?;
            }
            for s in u.certifications.iter() {
                signature_serialize(o, s)?;
            }
        }

        for k in self.subkeys.iter() {
            key_serialize(o, &k.subkey, Tag::PublicSubkey)?;
            for s in k.selfsigs.iter() {
                signature_serialize(o, s)?;
            }
            for s in k.certifications.iter() {
                signature_serialize(o, s)?;
            }
        }
        Ok(())
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
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix,
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
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix,
                       [ 0xc6, 0x8f ]);

            assert_eq!(tpk.subkeys.len(), 1, "number of subkeys");
            assert_eq!(tpk.subkeys[0].subkey.creation_time, 1511355130);
            assert_eq!(tpk.subkeys[0].selfsigs[0].hash_prefix,
                       [ 0xb7, 0xb9 ]);

            let tpk = parse_tpk(bytes!("testy-no-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.creation_time, 1511355130);
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(tpk.userids.len(), 1, "number of userids");
            assert_eq!(tpk.userids[0].userid.value,
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix,
                       [ 0xc6, 0x8f ]);

            assert_eq!(tpk.subkeys.len(), 0, "number of subkeys");
        }
    }
}
