//! Transferable public keys.

use failure;
use std::io;
use std::cmp::Ordering;
use std::path::Path;
use std::fs::File;
use std::slice;
use std::mem;
use std::iter;
use std::fmt;

use IterError;

use super::{TPK, Packet, Message, Signature, Key, UserID, UserAttribute,
            Fingerprint, Tag};
use super::parse::PacketParser;
use super::serialize::{Serialize, SerializeKey};

const TRACE : bool = false;

#[derive(Debug, Clone, PartialEq)]
pub struct SubkeyBinding {
    subkey: Key,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.  (In general, this will only be by
    // designated revokers.)
    certifications: Vec<Signature>,
}

impl SubkeyBinding {
    pub fn subkey(&self) -> &Key {
        &self.subkey
    }

    pub fn selfsigs(&self) -> slice::Iter<Signature> {
        self.selfsigs.iter()
    }

    pub fn certifications(&self) -> slice::Iter<Signature> {
        self.certifications.iter()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserIDBinding {
    userid: UserID,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.
    certifications: Vec<Signature>,
}

impl UserIDBinding {
    pub fn userid(&self) -> &UserID {
        &self.userid
    }

    pub fn selfsigs(&self) -> slice::Iter<Signature> {
        self.selfsigs.iter()
    }

    pub fn certifications(&self) -> slice::Iter<Signature> {
        self.certifications.iter()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UserAttributeBinding {
    user_attribute: UserAttribute,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.
    certifications: Vec<Signature>,
}

impl UserAttributeBinding {
    pub fn user_attribute(&self) -> &UserAttribute {
        &self.user_attribute
    }

    pub fn selfsigs(&self) -> slice::Iter<Signature> {
        self.selfsigs.iter()
    }

    pub fn certifications(&self) -> slice::Iter<Signature> {
        self.certifications.iter()
    }
}

// We use a state machine to extract a TPK from an OpenPGP message.
// These are the states.
enum TPKParserState {
    Start,
    TPK,
    UserID(UserIDBinding),
    UserAttribute(UserAttributeBinding),
    Subkey(SubkeyBinding),
    End,
}

impl fmt::Debug for TPKParserState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &TPKParserState::Start => f.debug_struct("Start").finish(),
            &TPKParserState::TPK => f.debug_struct("TPK").finish(),
            &TPKParserState::UserID(ref binding) =>
                f.debug_struct("UserID")
                .field("userid", &binding.userid)
                .field("self-sigs", &binding.selfsigs.len())
                .field("certifications", &binding.certifications.len())
                .finish(),
            &TPKParserState::UserAttribute(ref binding) =>
                f.debug_struct("UserAttribute")
                .field("userid", &binding.user_attribute)
                .field("self-sigs", &binding.selfsigs.len())
                .field("certifications", &binding.certifications.len())
                .finish(),
            &TPKParserState::Subkey(ref binding) =>
                f.debug_struct("Subkey")
                .field("subkey", &binding.subkey)
                .field("self-sigs", &binding.selfsigs.len())
                .field("certifications", &binding.certifications.len())
                .finish(),
            &TPKParserState::End => f.debug_struct("End").finish(),
        }
    }
}

pub struct TPKParser<I: iter::Iterator<Item=Packet>> {
    packet_iter: Option<I>,

    state: TPKParserState,
    primary: Option<Key>,
    userids: Vec<UserIDBinding>,
    user_attributes: Vec<UserAttributeBinding>,
    subkeys: Vec<SubkeyBinding>,
}

impl<I: iter::Iterator<Item=Packet>> Default for TPKParser<I> {
    fn default() -> Self {
        TPKParser {
            packet_iter: None,
            state: TPKParserState::Start,
            primary: None,
            userids: vec![],
            user_attributes: vec![],
            subkeys: vec![],
        }
    }
}

impl<I: iter::Iterator<Item=Packet> + IterError> TPKParser<I> {
    /// Returns any pending error.
    ///
    /// This interface is useful, because using an iterator, the
    /// caller cannot distinguish between no more items and an error.
    pub fn error(&mut self) -> Option<failure::Error> {
        if let &mut Some(ref mut i) = &mut self.packet_iter {
            i.error()
        } else {
            None
        }
    }
}

pub struct KeyIter<'a> {
    tpk: &'a TPK,
    primary: bool,
    subkey_iter: slice::Iter<'a, SubkeyBinding>,
}

impl<'a> Iterator for KeyIter<'a> {
    type Item = &'a Key;

    fn next(&mut self) -> Option<Self::Item> {
        if ! self.primary {
            self.primary = true;
            Some(self.tpk.primary())
        } else {
            self.subkey_iter.next().map(|sk_binding| &sk_binding.subkey)
        }
    }
}

impl<I: iter::Iterator<Item=Packet>> TPKParser<I> {
    /// Initializes a parser.
    pub fn new(iter: I) -> Self {
        let mut parser : Self = Default::default();
        parser.packet_iter = Some(iter);
        parser
    }

    // Resets the parser so that it starts parsing a new packet.
    //
    // Returns the old state.  Note: the packet iterator is preserved.
    fn reset(&mut self) -> Self {
        // We need to preserve `packet_iter`.
        let mut orig = mem::replace(self, Default::default());
        self.packet_iter = orig.packet_iter.take();
        orig
    }

    // Parses the next packet in the packet stream.  If th
    fn parse(&mut self, p: Packet) -> Option<TPK> {
        let mut result : Option<TPK> = None;

        if TRACE {
            eprintln!("TPKParser::parse(packet: {:?}): current state: {:?}",
                      p.tag(), self.state);
        }

        self.state = match mem::replace(&mut self.state, TPKParserState::End) {
            TPKParserState::Start => {
                // Skip packets until we find a public key packet.
                match p {
                    Packet::PublicKey(pk) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found primary key: {}.",
                                      pk.fingerprint());
                        }

                        self.primary = Some(pk);
                        TPKParserState::TPK
                    },
                    _ => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Skipping {:?} \
                                       which is unexpected in this state.",
                                      p.tag());
                        }

                        TPKParserState::Start
                    },
                }
            },
            TPKParserState::TPK => {
                /* Find user id, user attribute, or subkey packets.  */
                match p {
                    Packet::PublicKey(pk) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found primary key: {}.",
                                      pk.fingerprint());
                        }

                        result = self.tpk(Some(pk));
                        TPKParserState::TPK
                    },
                    Packet::UserID(uid) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found user id: {}.",
                                      String::from_utf8_lossy(&uid.value[..]));
                        }

                        TPKParserState::UserID(
                            UserIDBinding{
                                userid: uid,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::UserAttribute(attribute) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found user attribute.");
                        }

                        TPKParserState::UserAttribute(
                            UserAttributeBinding{
                                user_attribute: attribute,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::PublicSubkey(key) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found subkey {}.",
                                      key.fingerprint());
                        }

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
                // Collect signatures.  If we encounter a user id,
                // user attribute or subkey packet, then wrap up the
                // binding for this user id.
                match p {
                    Packet::PublicKey(pk) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found primary key: {}.",
                                      pk.fingerprint());
                        }

                        self.userids.push(u);
                        result = self.tpk(Some(pk));
                        TPKParserState::TPK
                    },
                    Packet::UserID(uid) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found user id: {}.",
                                      String::from_utf8_lossy(&uid.value[..]));
                        }

                        self.userids.push(u);
                        TPKParserState::UserID(
                            UserIDBinding{
                                userid: uid,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::UserAttribute(attribute) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found user attribute.");
                        }

                        self.userids.push(u);
                        TPKParserState::UserAttribute(
                            UserAttributeBinding{
                                user_attribute: attribute,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::PublicSubkey(key) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found subkey {}.",
                                      key.fingerprint());
                        }

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
                        let selfsig = if let Some(issuer)
                                = sig.issuer_fingerprint() {
                            issuer == primary.fingerprint()
                        } else if let Some(issuer) = sig.issuer() {
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
            TPKParserState::UserAttribute(mut u) => {
                // Collect signatures.  If we encounter a user id,
                // user attribute or subkey packet, then wrap up the
                // binding for this user attribute.
                match p {
                    Packet::PublicKey(pk) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found primary key: {}.",
                                      pk.fingerprint());
                        }

                        self.user_attributes.push(u);
                        result = self.tpk(Some(pk));
                        TPKParserState::TPK
                    },
                    Packet::UserID(uid) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found user id: {}.",
                                      String::from_utf8_lossy(&uid.value[..]));
                        }

                        self.user_attributes.push(u);
                        TPKParserState::UserID(
                            UserIDBinding{
                                userid: uid,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::UserAttribute(attribute) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found user attribute.");
                        }

                        self.user_attributes.push(u);
                        TPKParserState::UserAttribute(
                            UserAttributeBinding{
                                user_attribute: attribute,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::PublicSubkey(key) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found subkey {}.",
                                      key.fingerprint());
                        }

                        self.user_attributes.push(u);
                        TPKParserState::Subkey(
                            SubkeyBinding{
                                subkey: key,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::Signature(sig) => {
                        let primary = self.primary.as_ref().unwrap();
                        let selfsig = if let Some(issuer)
                                = sig.issuer_fingerprint() {
                            issuer == primary.fingerprint()
                        } else if let Some(issuer) = sig.issuer() {
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
                        TPKParserState::UserAttribute(u)
                    },
                    _ => TPKParserState::UserAttribute(u),
                }
            },
            TPKParserState::Subkey(mut s) => {
                // Collect signatures.  If we encounter a user id,
                // user attribute or subkey packet, then wrap up the
                // binding for this subkey.
                match p {
                    Packet::PublicKey(pk) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found primary key: {}.",
                                      pk.fingerprint());
                        }

                        self.subkeys.push(s);
                        result = self.tpk(Some(pk));
                        TPKParserState::TPK
                    },
                    Packet::UserID(uid) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found user id: {}.",
                                      String::from_utf8_lossy(&uid.value[..]));
                        }

                        self.subkeys.push(s);
                        TPKParserState::UserID(
                            UserIDBinding{
                                userid: uid,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::UserAttribute(attribute) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found user attribute.");
                        }

                        self.subkeys.push(s);
                        TPKParserState::UserAttribute(
                            UserAttributeBinding{
                                user_attribute: attribute,
                                selfsigs: vec![],
                                certifications: vec![],
                            })
                    },
                    Packet::PublicSubkey(key) => {
                        if TRACE {
                            eprintln!("TPKParser::parse: Found subkey {}.",
                                      key.fingerprint());
                        }

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
                        let selfsig = if let Some(issuer)
                                = sig.issuer_fingerprint() {
                            issuer == primary.fingerprint()
                        } else if let Some(issuer) = sig.issuer() {
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
            TPKParserState::End => {
                // We've reach the EOF.  There is nothing to do.
                TPKParserState::End
            }
        };

        if TRACE {
            eprintln!("TPKParser::parse => new state: {:?}, result: {:?}",
                      self.state,
                      result.as_ref().map(|tpk| tpk.primary().fingerprint()));
        }

        result
    }

    // Finalizes the current TPK and returns it.  Sets the parse up to
    // begin parsing the next TPK.
    fn tpk(&mut self, pk: Option<Key>) -> Option<TPK> {
        let mut orig = self.reset();

        let mut tpk = if let Some(pk) = orig.primary.take() {
            TPK {
                primary: pk,
                userids: orig.userids,
                user_attributes: orig.user_attributes,
                subkeys: orig.subkeys
            }
        } else {
            return None;
        };

        let tpko = match orig.state {
            TPKParserState::UserID(u) => {
                tpk.userids.push(u);
                Some(tpk)
            },
            TPKParserState::UserAttribute(u) => {
                tpk.user_attributes.push(u);
                Some(tpk)
            },
            TPKParserState::Subkey(s) => {
                tpk.subkeys.push(s);
                Some(tpk)
            },
            TPKParserState::End =>
                Some(tpk),
            _ => None,
        }.and_then(|tpk| Some(tpk.canonicalize()));

        self.primary = pk;

        tpko
    }
}

impl<I: iter::Iterator<Item=Packet>> Iterator for TPKParser<I> {
    type Item = TPK;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut i) = self.packet_iter.take() {
            while let Some(packet) = i.next() {
                if let Some(tpk) = self.parse(packet) {
                    if TRACE {
                        eprintln!("TPKParser::next => {}",
                                  tpk.primary().fingerprint());
                    }
                    self.packet_iter = Some(i);
                    return Some(tpk);
                }
            }
        }

        if TRACE {
            eprintln!("TPKParser::next: EOF.");
        }
        return self.tpk(None);
    }
}

impl TPK {
    pub fn primary(&self) -> &Key {
        &self.primary
    }

    pub fn userids(&self) -> slice::Iter<UserIDBinding> {
        self.userids.iter()
    }

    pub fn user_attributes(&self) -> slice::Iter<UserAttributeBinding> {
        self.user_attributes.iter()
    }

    pub fn subkeys(&self) -> slice::Iter<SubkeyBinding> {
        self.subkeys.iter()
    }

    pub fn keys(&self) -> KeyIter {
        KeyIter {
            tpk: self,
            primary: false,
            subkey_iter: self.subkeys()
        }
    }

    /// Returns the first TPK found in the packet stream.
    pub fn from_packet_parser(pp: PacketParser) -> Result<Self> {
        let mut parser = TPKParser::new(pp.into_iter());
        if let Some(tpk) = parser.next() {
            if let Some(err) = parser.error() {
                Err(err)
            } else {
                Ok(tpk)
            }
        } else {
            Err(Error::NoKeyFound.into())
        }
    }

    /// Returns the first TPK encountered in the reader.
    pub fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        let ppo = PacketParser::from_reader(reader)?;
        if let Some(pp) = ppo {
            TPK::from_packet_parser(pp)
        } else {
            Err(Error::NoKeyFound.into())
        }
    }

    /// Returns the first TPK encountered in the file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_reader(File::open(path)?)
    }

    /// Returns the first TPK found in `m`.
    pub fn from_message(m: Message) -> Result<Self> {
        let mut i = TPKParser::new(m.into_children());
        if let Some(tpk) = i.next() {
            Ok(tpk)
        } else {
            Err(Error::NoKeyFound.into())
        }
    }

    /// Returns the first TPK found in `buf`.
    ///
    /// `buf` must be an OpenPGP encoded message.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let ppo = PacketParser::from_bytes(buf)?;
        if let Some(pp) = ppo {
            TPK::from_packet_parser(pp)
        } else {
            Err(Error::NoKeyFound.into())
        }
    }

    fn canonicalize(mut self) -> Self {
        // Helper functions.

        // Compare the creation time of two signatures.  Order them so
        // that the more recent signature is first.
        fn sig_cmp(a: &Signature, b: &Signature) -> Ordering {
            b.signature_creation_time().cmp(&a.signature_creation_time())
        }

        // Turn a signature into a key for use by dedup.
        fn sig_key(a: &mut Signature) -> Box<[u8]> {
            a.to_vec().into_boxed_slice()
        }


        // Sanity checks.

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


        // Drop invalid user attributes.
        self.user_attributes.retain(|a| {
            // XXX Check binding signature.
            a.selfsigs.len() > 0
        });

        // XXX: Drop invalid self-signatures / see if they are just
        // out of place.

        // Sort the signatures so that the current valid
        // self-signature is first.
        for attribute in &mut self.user_attributes {
            attribute.selfsigs.sort_by(sig_cmp);
            attribute.selfsigs.dedup_by_key(sig_key);

            // There is no need to sort the certifications, but we do
            // want to remove dups and sorting is a prerequisite.
            attribute.certifications.sort_by(sig_cmp);
            attribute.certifications.dedup_by_key(sig_key);
        }

        // Sort the user attributes in preparation for a dedup.  As
        // for the user ids, we can't do the final sort here, because
        // we rely on the self-signatures.
        self.user_attributes.sort_by(
            |a, b| a.user_attribute.value.cmp(&b.user_attribute.value));

        // And, dedup them.
        self.user_attributes.dedup_by(|a, b| {
            if a.user_attribute == b.user_attribute {
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

        self.user_attributes.sort_by(|a, b| {
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
            a.user_attribute.value.cmp(&b.user_attribute.value)
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
            let a_features = a.selfsigs[0].features().unwrap_or(b"");
            let b_features = b.selfsigs[0].features().unwrap_or(b"");
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

        self
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

        for u in self.user_attributes.into_iter() {
            p.push(Packet::UserAttribute(u.user_attribute));
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
        self.primary.serialize(o, Tag::PublicKey)?;

        for u in self.userids.iter() {
            u.userid.serialize(o)?;
            for s in u.selfsigs.iter() {
                s.serialize(o)?;
            }
            for s in u.certifications.iter() {
                s.serialize(o)?;
            }
        }

        for u in self.user_attributes.iter() {
            u.user_attribute.serialize(o)?;
            for s in u.selfsigs.iter() {
                s.serialize(o)?;
            }
            for s in u.certifications.iter() {
                s.serialize(o)?;
            }
        }

        for k in self.subkeys.iter() {
            k.subkey.serialize(o, Tag::PublicSubkey)?;
            for s in k.selfsigs.iter() {
                s.serialize(o)?;
            }
            for s in k.certifications.iter() {
                s.serialize(o)?;
            }
        }
        Ok(())
    }

    /// Merges `other` into `self`.
    ///
    /// If `other` is a different key, then nothing is merged into
    /// `self`, but `self` is still canonicalized.
    pub fn merge(mut self, mut other: TPK) -> Result<Self> {
        if self.primary != other.primary {
            // The primary key is not the same.  There is nothing to
            // do.
            return Ok(self.canonicalize());
        }

        self.userids.append(&mut other.userids);
        self.user_attributes.append(&mut other.user_attributes);
        self.subkeys.append(&mut other.subkeys);

        Ok(self.canonicalize())
    }

    /// Checks whether at least one of this key's user ids (not user
    /// attributes!) is signed by 'other'.
    pub fn is_signed_by(&self, other: &TPK) -> bool {
        let fp = other.fingerprint();
        for userid in self.userids.iter() {
            for sig in userid.certifications.iter() {
                if let Some(issuer) = sig.issuer_fingerprint() {
                    if issuer == fp {
                        return true
                    }
                }
            }
        }
        return false
    }
}

/// Results for TPK.
pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Fail, Debug)]
/// Errors returned from the key routines.
pub enum Error {
    #[fail(display = "No key found")]
    /// No key found in OpenPGP message.
    NoKeyFound,
    #[fail(display = "No UID found")]
    /// No user id found.
    NoUserId,
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

    #[test]
    fn key_iter_test() {
        let key = TPK::from_bytes(bytes!("neal.pgp")).unwrap();
        assert_eq!(1 + key.subkeys().count(),
                   key.keys().count());
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
            assert_match!(Error::NoKeyFound
                          = tpk.err().unwrap().downcast::<Error>().unwrap());

            // According to 4880, a TPK must have a UserID.  But, we
            // don't require it.
            let tpk = parse_tpk(bytes!("testy-broken-no-uid.pgp"),
                                i == 0);
            assert!(tpk.is_ok());

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
            assert_eq!(tpk.user_attributes.len(), 0);
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

            assert_eq!(tpk.user_attributes.len(), 0);

            assert_eq!(tpk.subkeys.len(), 1, "number of subkeys");
            assert_eq!(tpk.subkeys[0].subkey.creation_time, 1511355130);
            assert_eq!(tpk.subkeys[0].selfsigs[0].hash_prefix,
                       [ 0xb7, 0xb9 ]);

            let tpk = parse_tpk(bytes!("testy-no-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.creation_time, 1511355130);
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(tpk.user_attributes.len(), 0);

            assert_eq!(tpk.userids.len(), 1, "number of userids");
            assert_eq!(tpk.userids[0].userid.value,
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix,
                       [ 0xc6, 0x8f ]);

            assert_eq!(tpk.subkeys.len(), 0, "number of subkeys");
        }
    }

    #[test]
    fn merge() {
        let tpk_base = TPK::from_bytes(bytes!("bannon-base.gpg")).unwrap();

        // When we merge it with itself, we should get the exact same
        // thing.
        let merged = tpk_base.clone().merge(tpk_base.clone()).unwrap();
        assert_eq!(tpk_base, merged);

        let tpk_add_uid_1
            = TPK::from_bytes(bytes!("bannon-add-uid-1-whitehouse.gov.gpg"))
                .unwrap();
        let tpk_add_uid_2
            = TPK::from_bytes(bytes!("bannon-add-uid-2-fox.com.gpg"))
                .unwrap();
        // Duplicate user id, but with a different self-sig.
        let tpk_add_uid_3
            = TPK::from_bytes(bytes!("bannon-add-uid-3-whitehouse.gov-dup.gpg"))
                .unwrap();

        let tpk_all_uids
            = TPK::from_bytes(bytes!("bannon-all-uids.gpg"))
            .unwrap();
        // We have four User ID packets, but one has the same User ID,
        // just with a different self-signature.
        assert_eq!(tpk_all_uids.userids.len(), 3);

        // Merge in order.
        let merged = tpk_base.clone().merge(tpk_add_uid_1.clone()).unwrap()
            .merge(tpk_add_uid_2.clone()).unwrap()
            .merge(tpk_add_uid_3.clone()).unwrap();
        assert_eq!(tpk_all_uids, merged);

        // Merge in reverse order.
        let merged = tpk_base.clone()
            .merge(tpk_add_uid_3.clone()).unwrap()
            .merge(tpk_add_uid_2.clone()).unwrap()
            .merge(tpk_add_uid_1.clone()).unwrap();
        assert_eq!(tpk_all_uids, merged);

        let tpk_add_subkey_1
            = TPK::from_bytes(bytes!("bannon-add-subkey-1.gpg")).unwrap();
        let tpk_add_subkey_2
            = TPK::from_bytes(bytes!("bannon-add-subkey-2.gpg")).unwrap();
        let tpk_add_subkey_3
            = TPK::from_bytes(bytes!("bannon-add-subkey-3.gpg")).unwrap();

        let tpk_all_subkeys
            = TPK::from_bytes(bytes!("bannon-all-subkeys.gpg")).unwrap();

        // Merge the first user, then the second, then the third.
        let merged = tpk_base.clone().merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap();
        assert_eq!(tpk_all_subkeys, merged);

        // Merge the third user, then the second, then the first.
        let merged = tpk_base.clone().merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap();
        assert_eq!(tpk_all_subkeys, merged);

        // Merge alot.
        let merged = tpk_base.clone()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap();
        assert_eq!(tpk_all_subkeys, merged);

        let tpk_all
            = TPK::from_bytes(bytes!("bannon-all-uids-subkeys.gpg"))
            .unwrap();

        // Merge all the subkeys with all the uids.
        let merged = tpk_all_subkeys.clone()
            .merge(tpk_all_uids.clone()).unwrap();
        assert_eq!(tpk_all, merged);

        // Merge all uids with all the subkeys.
        let merged = tpk_all_uids.clone()
            .merge(tpk_all_subkeys.clone()).unwrap();
        assert_eq!(tpk_all, merged);

        // All the subkeys and the uids in a mixed up order.
        let merged = tpk_base.clone()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_uid_2.clone()).unwrap()
            .merge(tpk_add_uid_1.clone()).unwrap()
            .merge(tpk_add_subkey_3.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_uid_3.clone()).unwrap()
            .merge(tpk_add_subkey_2.clone()).unwrap()
            .merge(tpk_add_subkey_1.clone()).unwrap()
            .merge(tpk_add_uid_2.clone()).unwrap();
        assert_eq!(tpk_all, merged);

        // Certifications.
        let tpk_donald_signs_base
            = TPK::from_bytes(bytes!("bannon-the-donald-signs-base.gpg"))
            .unwrap();
        let tpk_donald_signs_all
            = TPK::from_bytes(bytes!("bannon-the-donald-signs-all-uids.gpg"))
            .unwrap();
        let tpk_ivanka_signs_base
            = TPK::from_bytes(bytes!("bannon-ivanka-signs-base.gpg"))
            .unwrap();
        let tpk_ivanka_signs_all
            = TPK::from_bytes(bytes!("bannon-ivanka-signs-all-uids.gpg"))
            .unwrap();

        assert!(tpk_donald_signs_base.userids.len() == 1);
        assert!(tpk_donald_signs_base.userids[0].selfsigs.len() == 1);
        assert!(tpk_base.userids[0].certifications.len() == 0);
        assert!(tpk_donald_signs_base.userids[0].certifications.len() == 1);

        let merged = tpk_donald_signs_base.clone()
            .merge(tpk_ivanka_signs_base.clone()).unwrap();
        assert!(merged.userids.len() == 1);
        assert!(merged.userids[0].selfsigs.len() == 1);
        assert!(merged.userids[0].certifications.len() == 2);

        let merged = tpk_donald_signs_base.clone()
            .merge(tpk_donald_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].selfsigs.len() == 1);
        // There should be two certifications from the Donald on the
        // first user id.
        assert!(merged.userids[0].certifications.len() == 2);
        assert!(merged.userids[1].certifications.len() == 1);
        assert!(merged.userids[2].certifications.len() == 1);

        let merged = tpk_donald_signs_base.clone()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_ivanka_signs_base.clone()).unwrap()
            .merge(tpk_ivanka_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].selfsigs.len() == 1);
        // There should be two certifications from each of the Donald
        // and Ivanka on the first user id, and one each on the rest.
        assert!(merged.userids[0].certifications.len() == 4);
        assert!(merged.userids[1].certifications.len() == 2);
        assert!(merged.userids[2].certifications.len() == 2);

        // Same as above, but redundant.
        let merged = tpk_donald_signs_base.clone()
            .merge(tpk_ivanka_signs_base.clone()).unwrap()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_ivanka_signs_all.clone()).unwrap()
            .merge(tpk_ivanka_signs_base.clone()).unwrap()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_donald_signs_all.clone()).unwrap()
            .merge(tpk_ivanka_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].selfsigs.len() == 1);
        // There should be two certifications from each of the Donald
        // and Ivanka on the first user id, and one each on the rest.
        assert!(merged.userids[0].certifications.len() == 4);
        assert!(merged.userids[1].certifications.len() == 2);
        assert!(merged.userids[2].certifications.len() == 2);
    }
}
