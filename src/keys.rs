use super::openpgp;
use super::openpgp::Packet;

/// This represents a transferable public key (see [RFC 4880, section
/// 11.1](https://tools.ietf.org/html/rfc4880#section-11.1)).
#[derive(Debug)]
pub struct TPK {
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
    /// Return the first transferable public key found in `m`.
    pub fn from_message(m: openpgp::Message) -> Option<Self> {
        let mut state = States::Start;
        let mut tpk = TPK { userids: vec![], subkeys: vec![] };
        for p in m.into_iter() {
            state = match state {
                States::Start => {
                    /* Find the first public key packet.  */
                    match p {
                        Packet::PublicKey(pk) => {
                            tpk.subkeys.push(SubkeyBinding{subkey: pk, signatures: vec![]});
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
                            tpk.userids.push(u);
                            States::UserID(UserIDBinding{userid: uid, signatures: vec![]})
                        },
                        Packet::PublicSubkey(key) => {
                            tpk.userids.push(u);
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
                            tpk.subkeys.push(s);
                            States::UserID(UserIDBinding{userid: uid, signatures: vec![]})
                        },
                        Packet::PublicSubkey(key) => {
                            tpk.subkeys.push(s);
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

        match state {
            States::UserID(u) => {
                tpk.userids.push(u);
                Some(tpk)
            },
            States::Subkey(s) => {
                tpk.subkeys.push(s);
                Some(tpk)
            },
            States::End => Some(tpk),
            _ => None,
        }.and_then(|tpk| tpk.canonicalize())
    }

    fn canonicalize(self) -> Option<Self> {
        // Sanity checks.

        // - One or more User ID packets.
        if self.userids.len() == 0 {
            return None;
        }

        // - After each Subkey packet, one Signature packet.
        for subkey in self.subkeys.iter().skip(1) {
            if subkey.signatures.len() == 0 {
                return None;
            }
        }

        // XXX Do some canonicalization.

        Some(self)
    }
}

#[cfg(test)]
mod test {
    use super::TPK;
    use super::openpgp;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../tests/data/keys/", $x)) };
    }

    #[test]
    fn broken() {
        let m = openpgp::Message::from_bytes(bytes!("testy-broken-no-pk.pgp")).unwrap();
        let tpk = TPK::from_message(m);
        assert!(tpk.is_none());

        let m = openpgp::Message::from_bytes(bytes!("testy-broken-no-uid.pgp")).unwrap();
        let tpk = TPK::from_message(m);
        assert!(tpk.is_none());

        let m = openpgp::Message::from_bytes(bytes!("testy-broken-no-sig-on-subkey.pgp")).unwrap();
        let tpk = TPK::from_message(m);
        assert!(tpk.is_none());
    }

    #[test]
    fn basics() {
        let m = openpgp::Message::from_bytes(bytes!("testy.pgp")).unwrap();
        let tpk = TPK::from_message(m).unwrap();
        //println!("{:?}", tpk);

        assert_eq!(tpk.userids.len(), 1, "number of userids");
        // XXX .value is private
        //assert_eq!(tpk.userids[0].userid.value, "Testy McTestface <testy@example.org>");
        assert_eq!(tpk.subkeys.len(), 2, "number of subkeys");

        let m = openpgp::Message::from_bytes(bytes!("testy-no-subkey.pgp")).unwrap();
        let tpk = TPK::from_message(m).unwrap();

        assert_eq!(tpk.userids.len(), 1, "number of userids");
        assert_eq!(tpk.subkeys.len(), 1, "number of subkeys");
    }
}
