//! Transferable public keys.

use std::io;
use std::cmp::Ordering;
use std::path::Path;
use std::fs::File;
use std::slice;
use std::mem;
use std::fmt;
use std::vec;
use time;

use {
    Error,
    Result,
    Tag,
    Signature,
    Key,
    UserID,
    UserAttribute,
    Packet,
    PacketPile,
    TPK,
    Fingerprint,
};
use parse::{PacketParserResult, PacketParser};
use serialize::{Serialize, SerializeKey};

const TRACE : bool = false;

/// A subkey and any associated signatures.
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
    /// The key.
    pub fn subkey(&self) -> &Key {
        &self.subkey
    }

    /// The self-signatures.
    ///
    /// All self-signatures have been validated, and the newest
    /// self-signature is first.
    pub fn selfsigs(&self) -> slice::Iter<Signature> {
        self.selfsigs.iter()
    }

    /// Any third-party certifications.
    ///
    /// The signatures have *not* been validated.
    pub fn certifications(&self) -> slice::Iter<Signature> {
        self.certifications.iter()
    }
}

/// A User ID and any associated signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct UserIDBinding {
    userid: UserID,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.
    certifications: Vec<Signature>,
}

impl UserIDBinding {
    /// The User ID.
    pub fn userid(&self) -> &UserID {
        &self.userid
    }

    /// The self-signatures.
    ///
    /// The self-signatures have been validated, and the newest
    /// self-signature is first.
    pub fn selfsigs(&self) -> slice::Iter<Signature> {
        self.selfsigs.iter()
    }

    /// Any third-party certifications.
    ///
    /// The signatures have *not* been validated.
    pub fn certifications(&self) -> slice::Iter<Signature> {
        self.certifications.iter()
    }
}

/// A User Attribute and any associated signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct UserAttributeBinding {
    user_attribute: UserAttribute,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.
    certifications: Vec<Signature>,
}

impl UserAttributeBinding {
    /// The User attribute.
    pub fn user_attribute(&self) -> &UserAttribute {
        &self.user_attribute
    }

    /// The self-signatures.
    ///
    /// The self-signatures have been validated, and the newest
    /// self-signature is first.
    pub fn selfsigs(&self) -> slice::Iter<Signature> {
        self.selfsigs.iter()
    }

    /// Any third-party certifications.
    ///
    /// The signatures have *not* been validated.
    pub fn certifications(&self) -> slice::Iter<Signature> {
        self.certifications.iter()
    }
}

/// An iterator over all `Key`s (both the primary key and any subkeys)
/// in a TPK.
///
/// Returned by TPK::keys().
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

// We use a state machine to extract a TPK from a sequence of OpenPGP
// packets.  These are the states.
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

// A TPKParser can read packets from either an Iterator or a
// PacketParser.  Ideally, we would just take an iterator, but we
// want to be able to handle errors, which iterators hide.
enum PacketSource<'a, I: Iterator<Item=Packet>> {
    EOF,
    PacketParser(PacketParser<'a>),
    Iter(I),
}

/// An iterator over a sequence of TPKs (e.g., an OpenPGP keyring).
///
/// The source of packets can either be a `PacketParser` or an
/// iterator over `Packet`s.  (In the latter case, the underlying
/// parser is not able to propagate errors.  Thus, this is only
/// appropriate for in-memory structures, like a vector of `Packet`s
/// or a `PacketPile`.)
///
/// # Example
///
/// ```rust
/// # extern crate openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{PacketParserResult, PacketParser};
/// use openpgp::tpk::TPKParser;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
/// #     let ppr = PacketParser::from_bytes(&b""[..])?;
/// for tpko in TPKParser::from_packet_parser(ppr) {
///     match tpko {
///         Ok(tpk) => {
///             println!("Key: {}", tpk.primary());
///             for binding in tpk.userids() {
///                 println!("User ID: {}", binding.userid());
///             }
///         }
///         Err(err) => {
///             eprintln!("Error reading keyring: {}", err);
///         }
///     }
/// }
/// #     Ok(())
/// # }
/// ```
pub struct TPKParser<'a, I: Iterator<Item=Packet>> {
    source: PacketSource<'a, I>,

    state: TPKParserState,
    primary: Option<Key>,
    userids: Vec<UserIDBinding>,
    user_attributes: Vec<UserAttributeBinding>,
    subkeys: Vec<SubkeyBinding>,

    saw_error: bool,

    filter: Vec<Box<Fn(&TPK, bool) -> bool + 'a>>,
}

impl<'a, I: Iterator<Item=Packet>> Default for TPKParser<'a, I> {
    fn default() -> Self {
        TPKParser {
            source: PacketSource::EOF,
            state: TPKParserState::Start,
            primary: None,
            userids: vec![],
            user_attributes: vec![],
            subkeys: vec![],
            saw_error: false,
            filter: vec![],
        }
    }
}

// When using a `PacketParser`, we never use the `Iter` variant.
// Nevertheless, we need to provide a concrete type.
// vec::IntoIter<Packet> is about as good as any other.
impl<'a> TPKParser<'a, vec::IntoIter<Packet>> {
    /// Initializes a `TPKParser` from a `PacketParser`.
    pub fn from_packet_parser(ppr: PacketParserResult<'a>) -> Self {
        let mut parser : Self = Default::default();
        if let PacketParserResult::Some(pp) = ppr {
            parser.source = PacketSource::PacketParser(pp);
        }
        parser
    }

    /// Initializes a `TPKParser` from a `Read`er.
    pub fn from_reader<R: 'a + io::Read>(reader: R) -> Result<Self> {
        Ok(Self::from_packet_parser(PacketParser::from_reader(reader)?))
    }

    /// Initializes a `TPKParser` from a `File`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self::from_packet_parser(PacketParser::from_file(path)?))
    }

    /// Initializes a `TPKParser` from a byte string.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self> {
        Ok(Self::from_packet_parser(PacketParser::from_bytes(data)?))
    }
}

impl<'a, I: Iterator<Item=Packet>> TPKParser<'a, I> {
    /// Initializes a TPKParser from an iterator over Packets.
    pub fn from_iter(iter: I) -> Self {
        let mut parser : Self = Default::default();
        parser.source = PacketSource::Iter(iter);
        parser
    }

    /// Filters the TPKs prior to validation.
    ///
    /// By default, the `TPKParser` only returns valdiated `TPK`s.
    /// Checking that a `TPK`'s self-signatures are valid, however, is
    /// computationally expensive, and not always necessary.  For
    /// example, when looking for a small number of `TPK`s in a large
    /// keyring, most `TPK`s can be immediately discarded.  That is,
    /// it is more efficient to filter, validate, and double check,
    /// than to validate and filter.  (It is necessary to double
    /// check, because the check might have been on an invalid part.
    /// For example, if searching for a key with a particular key ID,
    /// a matching subkey might not have any self signatures.)
    ///
    /// If the `TPKParser` gave out unvalidated `TPK`s, and provided
    /// an interface to validate them, then the caller could implement
    /// this first-validate-double-check pattern.  Giving out
    /// unvalidated `TPK`s, however, is too dangerous: inevitably, a
    /// `TPK` will be used without having been validated in a context
    /// where it should have been.
    ///
    /// This function avoids this class of bugs while still providing
    /// a mechanism to filter `TPK`s prior to validation: the caller
    /// provides a callback, that is invoked on the *unvalidated*
    /// `TPK`.  If the callback returns `true`, then the parser
    /// validates the `TPK`, and invokes the callback *a second time*
    /// to make sure the `TPK` is really wanted.  If the callback
    /// returns false, then the `TPK` is skipped.
    ///
    /// Note: calling this function multiple times on a single
    /// `TPKParser` will install multiple filters.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::parse::PacketParser;
    /// use openpgp::tpk::TPKParser;
    /// use openpgp::TPK;
    /// use openpgp::KeyID;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// #     let ppr = PacketParser::from_bytes(&b""[..])?;
    /// #     let some_keyid = KeyID::from_hex("C2B819056C652598").unwrap();
    /// for tpkr in TPKParser::from_packet_parser(ppr)
    ///     .unvalidated_tpk_filter(|tpk, _| {
    ///         if tpk.primary().keyid() == some_keyid {
    ///             return true;
    ///         }
    ///         for binding in tpk.subkeys() {
    ///             if binding.subkey().keyid() == some_keyid {
    ///                 return true;
    ///             }
    ///         }
    ///         false
    ///     })
    /// {
    ///     match tpkr {
    ///         Ok(tpk) => {
    ///             // The TPK contains the subkey.
    ///         }
    ///         Err(err) => {
    ///             eprintln!("Error reading keyring: {}", err);
    ///         }
    ///     }
    /// }
    /// #     Ok(())
    /// # }
    /// ```
    pub fn unvalidated_tpk_filter<F: 'a>(mut self, filter: F) -> Self
        where F: Fn(&TPK, bool) -> bool
    {
        self.filter.push(Box::new(filter));
        self
    }

    // Resets the parser so that it starts parsing a new packet.
    //
    // Returns the old state.  Note: the packet iterator is preserved.
    fn reset(&mut self) -> Self {
        // We need to preserve `source`.
        let mut orig = mem::replace(self, Default::default());
        self.source = mem::replace(&mut orig.source, PacketSource::EOF);
        orig
    }

    // Parses the next packet in the packet stream.
    //
    // If we complete parsing a TPK, returns the TPK.  Otherwise,
    // returns None.
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
                    Packet::PublicKey(pk) | Packet::SecretKey(pk) => {
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
                    Packet::PublicSubkey(key) | Packet::SecretSubkey(key)=> {
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
                    Packet::PublicSubkey(key) | Packet::SecretSubkey(key) => {
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
                    Packet::PublicSubkey(key) | Packet::SecretSubkey(key) => {
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
                    Packet::PublicSubkey(key) | Packet::SecretSubkey(key) => {
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

    // Finalizes the current TPK and returns it.  Sets the parser up to
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
            TPKParserState::TPK => {
                Some(tpk)
            },
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
        }.and_then(|tpk| {
            for filter in &self.filter {
                if !filter(&tpk, false) {
                    return None;
                }
            }

            let tpk = tpk.canonicalize();

            // Make sure it is still okay.
            for filter in &self.filter {
                if !filter(&tpk, true) {
                    return None;
                }
            }

            Some(tpk)
        });

        self.primary = pk;

        tpko
    }
}

impl<'a, I: Iterator<Item=Packet>> Iterator for TPKParser<'a, I> {
    type Item = Result<TPK>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.saw_error {
            return None;
        }

        loop {
            match mem::replace(&mut self.source, PacketSource::EOF) {
                PacketSource::EOF => {
                    if TRACE {
                        eprintln!("TPKParser::next: EOF.");
                    }

                    return self.tpk(None).map(|tpk| Ok(tpk));
                },
                PacketSource::PacketParser(pp) => {
                    match pp.next() {
                        Ok((packet, _, ppr, _)) => {
                            if let PacketParserResult::Some(pp) = ppr {
                                self.source = PacketSource::PacketParser(pp);
                            }

                            if let Some(tpk) = self.parse(packet) {
                                if TRACE {
                                    eprintln!("TPKParser::next => {}",
                                              tpk.primary().fingerprint());
                                }
                                return Some(Ok(tpk));
                            }
                        },
                        Err(err) => {
                            self.saw_error = true;
                            return Some(Err(err));
                        }
                    }
                },
                PacketSource::Iter(mut iter) => {
                    match iter.next() {
                        Some(packet) => {
                            self.source = PacketSource::Iter(iter);
                            if let Some(tpk) = self.parse(packet) {
                                if TRACE {
                                    eprintln!("TPKParser::next => {}",
                                              tpk.primary().fingerprint());
                                }
                                return Some(Ok(tpk));
                            }
                        },
                        None => {
                            return self.tpk(None).map(|tpk| Ok(tpk));
                        }
                    }
                },
            }
        }
    }
}

impl fmt::Display for TPK {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.primary.fingerprint())
    }
}

impl TPK {
    /// Returns a reference to the primary key.
    pub fn primary(&self) -> &Key {
        &self.primary
    }

    #[cfg(test)]
    pub fn primary_mut(&mut self) -> &mut Key {
        &mut self.primary
    }

    /// Returns an iterator over the TPK's valid `UserIDBinding`s.
    ///
    /// A valid `UserIDBinding` has at least one good self-signature.
    pub fn userids(&self) -> slice::Iter<UserIDBinding> {
        self.userids.iter()
    }

    /// Returns an iterator over the TPK's valid `UserAttributeBinding`s.
    ///
    /// A valid `UserIDAttributeBinding` has at least one good
    /// self-signature.
    pub fn user_attributes(&self) -> slice::Iter<UserAttributeBinding> {
        self.user_attributes.iter()
    }

    /// Returns an iterator over the TPK's valid subkeys.
    ///
    /// A valid `SubkeyBinding` has at least one good self-signature.
    pub fn subkeys(&self) -> slice::Iter<SubkeyBinding> {
        self.subkeys.iter()
    }

    /// Returns an iterator over all of the TPK's valid keys.
    ///
    /// That is, this returns an iterator over the primary key and any
    /// subkeys.  Note: since a primary key is different from a
    /// binding, the iterator is over `Key`s and not `SubkeyBindings`.
    ///
    /// A valid `Key` has at least one good self-signature.
    pub fn keys(&self) -> KeyIter {
        KeyIter {
            tpk: self,
            primary: false,
            subkey_iter: self.subkeys()
        }
    }

    /// Returns the first TPK found in the packet stream.
    pub fn from_packet_parser(ppr: PacketParserResult) -> Result<Self> {
        let mut parser = TPKParser::from_packet_parser(ppr);
        if let Some(tpk_result) = parser.next() {
            tpk_result
        } else {
            Err(Error::MalformedTPK("No data".into()).into())
        }
    }

    /// Returns the first TPK encountered in the reader.
    pub fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        TPK::from_packet_parser(PacketParser::from_reader(reader)?)
    }

    /// Returns the first TPK encountered in the file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_reader(File::open(path)?)
    }

    /// Returns the first TPK found in the `PacketPile`.
    pub fn from_packet_pile(p: PacketPile) -> Result<Self> {
        let mut i = TPKParser::from_iter(p.into_children());
        match i.next() {
            Some(Ok(tpk)) => Ok(tpk),
            Some(Err(err)) => Err(err),
            None => Err(Error::MalformedTPK("No data".into()).into()),
        }
    }

    /// Returns the first TPK found in `buf`.
    ///
    /// `buf` must be an OpenPGP-encoded message.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        TPK::from_packet_parser(PacketParser::from_bytes(buf)?)
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

        // Fallback time.
        let time_zero = time::at_utc(time::Timespec::new(0, 0));


        // The very first thing that we do is verify the
        // self-signatures.  There are a few things that we need to be
        // aware of:
        //
        //  - Signature may be invalid.  These should be dropped.
        //
        //  - Signature may be out of order.  These should be
        //    reordered so that we have the latest self-signature and
        //    we don't drop a userid or subkey that is actually
        //    valid.

        // Collect bad signatures here.  Below, we'll test whether
        // they are just out of order by checking them against all
        // userids and subkeys.
        let mut bad = Vec::new();

        for binding in self.userids.iter_mut() {
            for sig in mem::replace(&mut binding.selfsigs, Vec::new())
                .into_iter()
            {
                if let Ok(true) = sig.verify_userid_binding(
                    &self.primary, &self.primary, &binding.userid) {
                    binding.selfsigs.push(sig);
                } else {
                    if TRACE {
                        eprintln!("Sig {:02X}{:02X}, type = {} \
                                   doesn't belong to user id \"{}\"",
                                  sig.hash_prefix[0], sig.hash_prefix[1],
                                  sig.sigtype, binding.userid);
                    }
                    bad.push(sig);
                }
            }
        }

        for binding in self.user_attributes.iter_mut() {
            for sig in mem::replace(&mut binding.selfsigs, Vec::new())
                .into_iter()
            {
                if let Ok(true) = sig.verify_user_attribute_binding(
                    &self.primary, &self.primary, &binding.user_attribute) {
                    binding.selfsigs.push(sig);
                } else {
                    if TRACE {
                        eprintln!("Sig {:02X}{:02X}, type = {} \
                                   doesn't belong to user attribute",
                                  sig.hash_prefix[0], sig.hash_prefix[1],
                                  sig.sigtype);
                    }
                    bad.push(sig);
                }
            }
        }

        for binding in self.subkeys.iter_mut() {
            for sig in mem::replace(&mut binding.selfsigs, Vec::new())
                .into_iter()
            {
                if let Ok(true) = sig.verify_subkey_binding(
                    &self.primary, &self.primary, &binding.subkey) {
                    binding.selfsigs.push(sig);
                } else {
                    if TRACE {
                        eprintln!("Sig {:02X}{:02X}, type = {} \
                                   doesn't belong to subkey {}",
                                  sig.hash_prefix[0], sig.hash_prefix[1],
                                  sig.sigtype, binding.subkey.keyid());
                    }
                    bad.push(sig);
                }
            }
        }

        // See if the signatures that didn't validate are just out of
        // place.
        'outer: for sig in mem::replace(&mut bad, Vec::new()) {
            for binding in self.userids.iter_mut() {
                if let Ok(true) = sig.verify_userid_binding(
                    &self.primary, &self.primary, &binding.userid) {
                    if TRACE {
                        eprintln!("Sig {:02X}{:02X} was out of place. \
                                   Belongs to: {} / \"{:?}\".",
                                  sig.hash_prefix[0], sig.hash_prefix[1],
                                  self.primary.keyid(), binding.userid);
                    }

                    binding.selfsigs.push(sig);
                    continue 'outer;
                }
            }

            for binding in self.user_attributes.iter_mut() {
                if let Ok(true) = sig.verify_user_attribute_binding(
                    &self.primary, &self.primary, &binding.user_attribute) {
                    if TRACE {
                        eprintln!("Sig {:02X}{:02X} was out of place. \
                                   Belongs to: {}'s user attribute.",
                                  sig.hash_prefix[0], sig.hash_prefix[1],
                                  self.primary.keyid());
                    }

                    binding.selfsigs.push(sig);
                    continue 'outer;
                }
            }

            for binding in self.subkeys.iter_mut() {
                if let Ok(true) = sig.verify_subkey_binding(
                    &self.primary, &self.primary, &binding.subkey) {
                    if TRACE {
                        eprintln!("Sig {:02X}{:02X} was out of place. \
                                   Belongs to: {} / {}.",
                                  sig.hash_prefix[0], sig.hash_prefix[1],
                                  self.primary.keyid(),
                                  binding.subkey.keyid());
                    }

                    binding.selfsigs.push(sig);
                    continue 'outer;
                }
            }

            bad.push(sig);
        }

        if bad.len() > 0 && TRACE {
            eprintln!("{}: ignoring {} bad self-signatures",
                      self.primary.keyid(), bad.len());
        }

        // Only keep user ids / user attributes / subkeys with at
        // least one valid self-signature.
        self.userids.retain(|userid| {
            userid.selfsigs.len() > 0
        });

        self.user_attributes.retain(|ua| {
            ua.selfsigs.len() > 0
        });

        self.subkeys.retain(|subkey| {
            subkey.selfsigs.len() > 0
        });


        // Sanity checks.

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
                    = a.selfsigs[0].signature_creation_time()
                    .unwrap_or(time_zero);
                let b_timestamp
                    = b.selfsigs[0].signature_creation_time()
                    .unwrap_or(time_zero);
                // We want the more recent date first.
                let cmp = b_timestamp.cmp(&a_timestamp);
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }

            // Fallback to a lexicographical comparison.
            a.userid.value.cmp(&b.userid.value)
        });


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
                    = a.selfsigs[0].signature_creation_time()
                    .unwrap_or(time_zero);
                let b_timestamp
                    = b.selfsigs[0].signature_creation_time()
                    .unwrap_or(time_zero);
                // We want the more recent date first.
                let cmp = b_timestamp.cmp(&a_timestamp);
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }

            // Fallback to a lexicographical comparison.
            a.user_attribute.value.cmp(&b.user_attribute.value)
        });


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

    /// Returns the TPK's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.primary.fingerprint()
    }

    /// Converts the TPK into a `PacketPile`.
    pub fn to_packet_pile(self) -> PacketPile {
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

        PacketPile::from_packets(p)
    }

    /// Serializes the TPK.
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
}

#[cfg(test)]
mod test {
    use super::*;

    use KeyID;

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
            let pile = PacketPile::from_bytes(data).unwrap();
            TPK::from_packet_pile(pile)
        } else {
            TPK::from_bytes(data)
        }
    }

    #[test]
    fn broken() {
        use conversions::Time;
        for i in 0..2 {
            let tpk = parse_tpk(bytes!("testy-broken-no-pk.pgp"),
                                i == 0);
            assert_match!(Error::MalformedTPK(_)
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
            assert_eq!(tpk.primary.creation_time.to_pgp().unwrap(), 1511355130);
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
        use conversions::Time;
        for i in 0..2 {
            let tpk = parse_tpk(bytes!("testy.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.creation_time.to_pgp().unwrap(), 1511355130);
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
            assert_eq!(tpk.subkeys[0].subkey.creation_time.to_pgp().unwrap(),
                       1511355130);
            assert_eq!(tpk.subkeys[0].selfsigs[0].hash_prefix,
                       [ 0xb7, 0xb9 ]);

            let tpk = parse_tpk(bytes!("testy-no-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.creation_time.to_pgp().unwrap(), 1511355130);
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
    fn only_a_public_key() {
        // Make sure the TPK parser can parse a key that just consists
        // of a public key---no signatures, no user ids, nothing.
        let tpk = TPK::from_bytes(bytes!("testy-only-a-pk.pgp")).unwrap();
        assert_eq!(tpk.userids.len(), 0);
        assert_eq!(tpk.user_attributes.len(), 0);
        assert_eq!(tpk.subkeys.len(), 0);
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

    #[test]
    fn key_iter_test() {
        let key = TPK::from_bytes(bytes!("neal.pgp")).unwrap();
        assert_eq!(1 + key.subkeys().count(),
                   key.keys().count());
    }

    #[test]
    fn out_of_order_self_sigs_test() {
        // neal-out-of-order.pgp contains all of the self-signatures,
        // but some are out of order.  The canonicalization step
        // should reorder them.
        //
        // original order/new order:
        //
        //  1/ 1. pk
        //  2/ 2. user id #1: neal@walfield.org (good)
        //  3/ 3. sig over user ID #1
        //
        //  4/ 4. user id #2: neal@gnupg.org (good)
        //  5/ 7. sig over user ID #3
        //  6/ 5. sig over user ID #2
        //
        //  7/ 6. user id #3: neal@g10code.com (bad)
        //
        //  8/ 8. user ID #4: neal@pep.foundation (bad)
        //  9/11. sig over user ID #5
        //
        // 10/10. user id #5: neal@pep-project.org (bad)
        // 11/ 9. sig over user ID #4
        //
        // 12/12. user ID #6: neal@sequoia-pgp.org (good)
        // 13/13. sig over user ID #6
        //
        // ----------------------------------------------
        //
        // 14/14. signing subkey #1: 7223B56678E02528 (good)
        // 15/15. sig over subkey #1
        // 16/16. sig over subkey #1
        //
        // 17/17. encryption subkey #2: C2B819056C652598 (good)
        // 18/18. sig over subkey #2
        // 19/21. sig over subkey #3
        // 20/22. sig over subkey #3
        //
        // 21/20. auth subkey #3: A3506AFB820ABD08 (bad)
        // 22/19. sig over subkey #2

        let tpk = TPK::from_bytes(bytes!("neal-sigs-out-of-order.pgp")).unwrap();

        let mut userids = tpk.userids()
            .map(|u| String::from_utf8_lossy(&u.userid.value[..]).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "Neal H. Walfield <neal@g10code.com>",
                      "Neal H. Walfield <neal@gnupg.org>",
                      "Neal H. Walfield <neal@pep-project.org>",
                      "Neal H. Walfield <neal@pep.foundation>",
                      "Neal H. Walfield <neal@sequoia-pgp.org>",
                      "Neal H. Walfield <neal@walfield.org>",
                   ][..]);

        let mut subkeys = tpk.subkeys()
            .map(|sk| Some(sk.subkey.keyid()))
            .collect::<Vec<Option<KeyID>>>();
        subkeys.sort();
        assert_eq!(subkeys,
                   &[ KeyID::from_hex(&"7223B56678E02528"[..]),
                      KeyID::from_hex(&"A3506AFB820ABD08"[..]),
                      KeyID::from_hex(&"C2B819056C652598"[..]),
                   ][..]);

        // DKG's key has all of the self-signatures moved to the last
        // subkey; all user ids/user attributes/subkeys have nothing.
        let tpk = TPK::from_bytes(bytes!("dkg-sigs-out-of-order.pgp")).unwrap();

        let mut userids = tpk.userids()
            .map(|u| String::from_utf8_lossy(&u.userid.value[..]).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "Daniel Kahn Gillmor <dkg-debian.org@fifthhorseman.net>",
                      "Daniel Kahn Gillmor <dkg@aclu.org>",
                      "Daniel Kahn Gillmor <dkg@astro.columbia.edu>",
                      "Daniel Kahn Gillmor <dkg@debian.org>",
                      "Daniel Kahn Gillmor <dkg@fifthhorseman.net>",
                      "Daniel Kahn Gillmor <dkg@openflows.com>",
                   ][..]);

        assert_eq!(tpk.user_attributes.len(), 1);

        let mut subkeys = tpk.subkeys()
            .map(|sk| Some(sk.subkey.keyid()))
            .collect::<Vec<Option<KeyID>>>();
        subkeys.sort();
        assert_eq!(subkeys,
                   &[ KeyID::from_hex(&"1075 8EBD BD7C FAB5"[..]),
                      KeyID::from_hex(&"1258 68EA 4BFA 08E4"[..]),
                      KeyID::from_hex(&"1498 ADC6 C192 3237"[..]),
                      KeyID::from_hex(&"24EC FF5A FF68 370A"[..]),
                      KeyID::from_hex(&"3714 7292 14D5 DA70"[..]),
                      KeyID::from_hex(&"3B7A A7F0 14E6 9B5A"[..]),
                      KeyID::from_hex(&"5B58 DCF9 C341 6611"[..]),
                      KeyID::from_hex(&"A524 01B1 1BFD FA5C"[..]),
                      KeyID::from_hex(&"A70A 96E1 439E A852"[..]),
                      KeyID::from_hex(&"C61B D3EC 2148 4CFF"[..]),
                      KeyID::from_hex(&"CAEF A883 2167 5333"[..]),
                      KeyID::from_hex(&"DC10 4C4E 0CA7 57FB"[..]),
                      KeyID::from_hex(&"E3A3 2229 449B 0350"[..]),
                   ][..]);

    }
}
