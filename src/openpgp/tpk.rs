use io;

use openpgp;
use super::Packet;

/// A transferable public key (TPK).
///
/// A TPK (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
#[derive(Debug)]
pub struct TPK {
    primary: openpgp::Key,
    userids: Vec<UserIDBinding>,
    subkeys: Vec<SubkeyBinding>,
}

#[derive(Debug)]
pub struct SubkeyBinding {
    subkey: openpgp::Key,
    signatures: Vec<openpgp::Signature>,
}

#[derive(Debug)]
pub struct UserIDBinding {
    userid: openpgp::UserID,
    signatures: Vec<openpgp::Signature>,
}

#[derive(Debug)]
enum States {
    Start,
    TPK,
    UserID(UserIDBinding),
    Subkey(SubkeyBinding),
    End,
}

impl TPK {
    /// Returns the first TPK found in `m`.
    pub fn from_message(m: openpgp::Message) -> Result<Self> {
        let mut state = States::Start;
        let mut primary = None;
        let mut userids = vec![];
        let mut subkeys = vec![];
        for p in m.into_iter() {
            state = match state {
                States::Start => {
                    /* Find the first public key packet.  */
                    match p {
                        Packet::PublicKey(pk) => {
                            primary = Some(pk);
                            States::TPK
                        },
                        _ => States::Start,
                    }
                },
                States::TPK => {
                    /* Find user id, or subkey packets.  */
                    match p {
                        Packet::PublicKey(_pk) => {
                            States::End
                        },
                        Packet::UserID(uid) => {
                            States::UserID(UserIDBinding{userid: uid, signatures: vec![]})
                        },
                        Packet::PublicSubkey(key) => {
                            States::Subkey(SubkeyBinding{subkey: key, signatures: vec![]})
                        },
                        _ => States::TPK,
                    }
                },
                States::UserID(mut u) => {
                    /* Find signature packets.  */
                    match p {
                        Packet::PublicKey(_pk) => {
                            States::End
                        },
                        Packet::UserID(uid) => {
                            userids.push(u);
                            States::UserID(UserIDBinding{userid: uid, signatures: vec![]})
                        },
                        Packet::PublicSubkey(key) => {
                            userids.push(u);
                            States::Subkey(SubkeyBinding{subkey: key, signatures: vec![]})
                        },
                        Packet::Signature(sig) => {
                            u.signatures.push(sig);
                            States::UserID(u)
                        },
                        _ => States::UserID(u),
                    }
                },
                States::Subkey(mut s) => {
                    /* Find signature packets.  */
                    match p {
                        Packet::PublicKey(_pk) => {
                            States::End
                        },
                        Packet::UserID(uid) => {
                            subkeys.push(s);
                            States::UserID(UserIDBinding{userid: uid, signatures: vec![]})
                        },
                        Packet::PublicSubkey(key) => {
                            subkeys.push(s);
                            States::Subkey(SubkeyBinding{subkey: key, signatures: vec![]})
                        },
                        Packet::Signature(sig) => {
                            s.signatures.push(sig);
                            States::Subkey(s)
                        },
                        _ => States::Subkey(s),
                    }
                },
                States::End => break,
            };
        }

        let mut tpk = if let Some(p) = primary {
            TPK{primary: p, userids: userids, subkeys: subkeys}
        } else {
            return Err(Error::NoKeyFound);
        };

        match state {
            States::UserID(u) => {
                tpk.userids.push(u);
                Ok(tpk)
            },
            States::Subkey(s) => {
                tpk.subkeys.push(s);
                Ok(tpk)
            },
            States::End => Ok(tpk),
            _ => Err(Error::NoKeyFound),
        }.and_then(|tpk| tpk.canonicalize())
    }

    /// Returns the first TPK found in `buf`.
    ///
    /// `buf` must be an OpenPGP encoded message.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        openpgp::Message::from_bytes(buf)
            .map_err(|e| Error::IoError(e))
            .and_then(Self::from_message)
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

    /// Serialize the transferable public key into an OpenPGP message.
    pub fn to_message(self) -> openpgp::Message {
        let mut p : Vec<openpgp::Packet> = Vec::new();

        p.push(openpgp::Packet::PublicKey(self.primary));

        for u in self.userids.into_iter() {
            p.push(openpgp::Packet::UserID(u.userid));
            for s in u.signatures.into_iter() {
                p.push(openpgp::Packet::Signature(s));
            }
        }

        let subkeys = self.subkeys;
        for k in subkeys.into_iter() {
            p.push(openpgp::Packet::PublicSubkey(k.subkey));
            for s in k.signatures.into_iter() {
                p.push(openpgp::Packet::Signature(s));
            }
        }

        openpgp::Message::from_packets(p)
    }
}

type Result<T> = ::std::result::Result<T, Error>;

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
    use super::{Error, TPK, openpgp};

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../tests/data/keys/", $x)) };
    }

    #[test]
    fn broken() {
        let m = openpgp::Message::from_bytes(bytes!("testy-broken-no-pk.pgp")).unwrap();
        if let Err(Error::NoKeyFound) = TPK::from_message(m) {
            /* Pass.  */
        } else {
            panic!("Expected error, got none.");
        }

        let m = openpgp::Message::from_bytes(bytes!("testy-broken-no-uid.pgp")).unwrap();
        if let Err(Error::NoUserId) = TPK::from_message(m) {
            /* Pass.  */
        } else {
            panic!("Expected error, got none.");
        }

        let m = openpgp::Message::from_bytes(bytes!("testy-broken-no-sig-on-subkey.pgp")).unwrap();
        let tpk = TPK::from_message(m).unwrap();
        assert_eq!(tpk.subkeys.len(), 0);
    }

    #[test]
    fn basics() {
        let m = openpgp::Message::from_bytes(bytes!("testy.pgp")).unwrap();
        let orig_dbg = format!("{:?}", m);
        let tpk = TPK::from_message(m).unwrap();
        //println!("{:?}", tpk);

        assert_eq!(tpk.userids.len(), 1, "number of userids");
        // XXX .value is private
        //assert_eq!(tpk.userids[0].userid.value, "Testy McTestface <testy@example.org>");
        assert_eq!(tpk.subkeys.len(), 1, "number of subkeys");

        // XXX Messages cannot be compared.
        assert_eq!(format!("{:?}", tpk.to_message()), orig_dbg);

        let m = openpgp::Message::from_bytes(bytes!("testy-no-subkey.pgp")).unwrap();
        let orig_dbg = format!("{:?}", m);
        let tpk = TPK::from_message(m).unwrap();

        assert_eq!(tpk.userids.len(), 1, "number of userids");
        assert_eq!(tpk.subkeys.len(), 0, "number of subkeys");
        // XXX Messages cannot be compared.
        assert_eq!(format!("{:?}", tpk.to_message()), orig_dbg);
    }
}
