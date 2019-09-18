use std::io;
use std::mem;
use std::vec;
use std::path::Path;

use lalrpop_util::ParseError;

use crate::{
    Error,
    Fingerprint,
    KeyID,
    packet::Tag,
    packet::Signature,
    Packet,
    parse::{
        Parse,
        PacketParserResult,
        PacketParser
    },
    Result,
    tpk::ComponentBinding,
    TPK,
};

mod low_level;
use low_level::{
    Lexer,
    TPKParser as TPKLowLevelParser,
    TPKParserError,
    Token,
    parse_error_downcast,
};

use super::TRACE;

/// Whether a packet sequence is a valid key ring.
#[derive(Debug)]
pub enum KeyringValidity {
    /// The packet sequence is a valid key ring.
    Keyring,
    /// The packet sequence is a valid key ring prefix.
    KeyringPrefix,
    /// The packet sequence is definitely not a key ring.
    Error(failure::Error),
}

impl KeyringValidity {
    /// Returns whether the packet sequence is a valid key ring.
    ///
    /// Note: a `KeyringValidator` will only return this after
    /// `KeyringValidator::finish` has been called.
    pub fn is_keyring(&self) -> bool {
        if let KeyringValidity::Keyring = self {
            true
        } else {
            false
        }
    }

    /// Returns whether the packet sequence is a valid Keyring prefix.
    ///
    /// Note: a `KeyringValidator` will only return this before
    /// `KeyringValidator::finish` has been called.
    pub fn is_keyring_prefix(&self) -> bool {
        if let KeyringValidity::KeyringPrefix = self {
            true
        } else {
            false
        }
    }

    /// Returns whether the packet sequence is definitely not a valid
    /// key ring.
    pub fn is_err(&self) -> bool {
        if let KeyringValidity::Error(_) = self {
            true
        } else {
            false
        }
    }
}

/// Used to help validate that a packet sequence is a valid key ring.
#[derive(Debug)]
pub struct KeyringValidator {
    tokens: Vec<Token>,
    n_keys: usize,
    n_packets: usize,
    finished: bool,

    // If we know that the packet sequence is invalid.
    error: Option<TPKParserError>,
}

impl Default for KeyringValidator {
    fn default() -> Self {
        KeyringValidator::new()
    }
}

impl KeyringValidator {
    /// Instantiates a new `KeyringValidator`.
    pub fn new() -> Self {
        KeyringValidator {
            tokens: vec![],
            n_keys: 0,
            n_packets: 0,
            finished: false,
            error: None,
        }
    }

    /// Returns whether the packet sequence is a valid keyring.
    ///
    /// Note: a `KeyringValidator` will only return this after
    /// `KeyringValidator::finish` has been called.
    pub fn is_keyring(&self) -> bool {
        self.check().is_keyring()
    }

    /// Returns whether the packet sequence forms a valid keyring
    /// prefix.
    ///
    /// Note: a `KeyringValidator` will only return this before
    /// `KeyringValidator::finish` has been called.
    pub fn is_keyring_prefix(&self) -> bool {
        self.check().is_keyring_prefix()
    }

    /// Returns whether the packet sequence is definitely not a valid
    /// keyring.
    pub fn is_err(&self) -> bool {
        self.check().is_err()
    }

    /// Add the token `token` to the token stream.
    pub fn push_token(&mut self, token: Token) {
        assert!(!self.finished);

        if self.error.is_some() {
            return;
        }

        match token {
            Token::PublicKey(_) | Token::SecretKey(_) => {
                self.tokens.clear();
                self.n_keys += 1;
            },
            _ => (),
        }

        self.n_packets += 1;
        if destructures_to!(Token::Signature(None) = &token)
            && destructures_to!(Some(Token::Signature(None)) = self.tokens.last())
        {
            // Compress multiple signatures in a row.  This is
            // essential for dealing with flooded keys.
        } else {
            self.tokens.push(token);
        }
    }

    /// Add a packet of type `tag` to the token stream.
    pub fn push(&mut self, tag: Tag) {
        let token = match tag {
            Tag::PublicKey => Token::PublicKey(None),
            Tag::SecretKey => Token::SecretKey(None),
            Tag::PublicSubkey => Token::PublicSubkey(None),
            Tag::SecretSubkey => Token::SecretSubkey(None),
            Tag::UserID => Token::UserID(None),
            Tag::UserAttribute => Token::UserAttribute(None),
            Tag::Signature => Token::Signature(None),
            Tag::Trust => Token::Trust(None),
            _ => {
                // Unknown token.
                self.error = Some(TPKParserError::OpenPGP(
                    Error::MalformedMessage(
                        format!("Invalid TPK: {:?} packet (at {}) not expected",
                                tag, self.n_packets).into())));
                self.tokens.clear();
                return;
            }
        };

        self.push_token(token)
    }

    /// Note that the entire message has been seen.
    ///
    /// This function may only be called once.
    ///
    /// Once called, this function will no longer return
    /// `KeyringValidity::KeyringPrefix`.
    pub fn finish(&mut self) {
        assert!(!self.finished);
        self.finished = true;
    }

    /// Returns whether the token stream corresponds to a valid
    /// keyring.
    ///
    /// This returns a tri-state: if the packet sequence is a valid
    /// Keyring, it returns KeyringValidity::Keyring, if the packet sequence is
    /// invalid, then it returns KeyringValidity::Error.  If the packet
    /// sequence could be valid, then it returns
    /// KeyringValidity::KeyringPrefix.
    ///
    /// Note: if KeyringValidator::finish() *hasn't* been called, then
    /// this function will only ever return either
    /// KeyringValidity::KeyringPrefix or KeyringValidity::Error.  Once
    /// KeyringValidity::finish() has been called, then only
    /// KeyringValidity::Keyring or KeyringValidity::Bad will be called.
    pub fn check(&self) -> KeyringValidity {
        if let Some(ref err) = self.error {
            return KeyringValidity::Error((*err).clone().into());
        }

        let r = TPKLowLevelParser::new().parse(
            Lexer::from_tokens(&self.tokens));

        if self.finished {
            match r {
                Ok(_) => KeyringValidity::Keyring,
                Err(err) =>
                    KeyringValidity::Error(
                        TPKParserError::Parser(parse_error_downcast(err)).into()),
            }
        } else {
            match r {
                Ok(_) => KeyringValidity::KeyringPrefix,
                Err(ParseError::UnrecognizedEOF { .. }) =>
                    KeyringValidity::KeyringPrefix,
                Err(err) =>
                    KeyringValidity::Error(
                        TPKParserError::Parser(parse_error_downcast(err)).into()),
            }
        }
    }
}

/// Whether a packet sequence is a valid TPK.
#[derive(Debug)]
pub enum TPKValidity {
    /// The packet sequence is a valid TPK.
    TPK,
    /// The packet sequence is a valid TPK prefix.
    TPKPrefix,
    /// The packet sequence is definitely not a TPK.
    Error(failure::Error),
}

impl TPKValidity {
    /// Returns whether the packet sequence is a valid TPK.
    ///
    /// Note: a `TPKValidator` will only return this after
    /// `TPKValidator::finish` has been called.
    pub fn is_tpk(&self) -> bool {
        if let TPKValidity::TPK = self {
            true
        } else {
            false
        }
    }

    /// Returns whether the packet sequence is a valid TPK prefix.
    ///
    /// Note: a `TPKValidator` will only return this before
    /// `TPKValidator::finish` has been called.
    pub fn is_tpk_prefix(&self) -> bool {
        if let TPKValidity::TPKPrefix = self {
            true
        } else {
            false
        }
    }

    /// Returns whether the packet sequence is definitely not a valid
    /// TPK.
    pub fn is_err(&self) -> bool {
        if let TPKValidity::Error(_) = self {
            true
        } else {
            false
        }
    }
}

/// Used to help validate that a packet sequence is a valid TPK.
#[derive(Debug)]
pub struct TPKValidator(KeyringValidator);

impl Default for TPKValidator {
    fn default() -> Self {
        TPKValidator::new()
    }
}

impl TPKValidator {
    /// Instantiates a new `TPKValidator`.
    pub fn new() -> Self {
        TPKValidator(Default::default())
    }

    /// Returns whether the packet sequence is a valid TPK.
    ///
    /// Note: a `TPKValidator` will only return this after
    /// `TPKValidator::finish` has been called.
    pub fn is_tpk(&self) -> bool {
        self.check().is_tpk()
    }

    /// Returns whether the packet sequence forms a valid TPK
    /// prefix.
    ///
    /// Note: a `TPKValidator` will only return this before
    /// `TPKValidator::finish` has been called.
    pub fn is_tpk_prefix(&self) -> bool {
        self.check().is_tpk_prefix()
    }

    /// Returns whether the packet sequence is definitely not a valid
    /// TPK.
    pub fn is_err(&self) -> bool {
        self.check().is_err()
    }

    /// Add the token `token` to the token stream.
    pub fn push_token(&mut self, token: Token) {
        self.0.push_token(token)
    }

    /// Add a packet of type `tag` to the token stream.
    pub fn push(&mut self, tag: Tag) {
        self.0.push(tag)
    }

    /// Note that the entire message has been seen.
    ///
    /// This function may only be called once.
    ///
    /// Once called, this function will no longer return
    /// `TPKValidity::TPKPrefix`.
    pub fn finish(&mut self) {
        self.0.finish()
    }

    /// Returns whether the token stream corresponds to a valid
    /// TPK.
    ///
    /// This returns a tri-state: if the packet sequence is a valid
    /// TPK, it returns TPKValidity::TPK, if the packet sequence is
    /// invalid, then it returns TPKValidity::Error.  If the packet
    /// sequence could be valid, then it returns
    /// TPKValidity::TPKPrefix.
    ///
    /// Note: if TPKValidator::finish() *hasn't* been called, then
    /// this function will only ever return either
    /// TPKValidity::TPKPrefix or TPKValidity::Error.  Once
    /// TPKValidity::finish() has been called, then only
    /// TPKValidity::TPK or TPKValidity::Bad will be called.
    pub fn check(&self) -> TPKValidity {
        if self.0.n_keys > 1 {
            return TPKValidity::Error(Error::MalformedMessage(
                    "More than one key found, this is a keyring".into()).into());
        }

        match self.0.check() {
            KeyringValidity::Keyring => TPKValidity::TPK,
            KeyringValidity::KeyringPrefix => TPKValidity::TPKPrefix,
            KeyringValidity::Error(e) => TPKValidity::Error(e),
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
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{Parse, PacketParserResult, PacketParser};
/// use openpgp::tpk::TPKParser;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
/// #     let ppr = PacketParser::from_bytes(b"")?;
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
    packets: Vec<Packet>,
    saw_error: bool,
    filter: Vec<Box<Fn(&TPK, bool) -> bool + 'a>>,
}

impl<'a, I: Iterator<Item=Packet>> Default for TPKParser<'a, I> {
    fn default() -> Self {
        TPKParser {
            source: PacketSource::EOF,
            packets: vec![],
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
}

impl<'a> Parse<'a, TPKParser<'a, vec::IntoIter<Packet>>>
    for TPKParser<'a, vec::IntoIter<Packet>>
{
    /// Initializes a `TPKParser` from a `Read`er.
    fn from_reader<R: 'a + io::Read>(reader: R) -> Result<Self> {
        Ok(Self::from_packet_parser(PacketParser::from_reader(reader)?))
    }

    /// Initializes a `TPKParser` from a `File`.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Ok(Self::from_packet_parser(PacketParser::from_file(path)?))
    }

    /// Initializes a `TPKParser` from a byte string.
    fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D) -> Result<Self> {
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
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::parse::{Parse, PacketParser};
    /// use openpgp::tpk::TPKParser;
    /// use openpgp::TPK;
    /// use openpgp::KeyID;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// #     let ppr = PacketParser::from_bytes(b"")?;
    /// #     let some_keyid = KeyID::from_hex("C2B819056C652598").unwrap();
    /// for tpkr in TPKParser::from_packet_parser(ppr)
    ///     .unvalidated_tpk_filter(|tpk, _| {
    ///         if tpk.primary().keyid() == some_keyid {
    ///             return true;
    ///         }
    ///         for binding in tpk.subkeys() {
    ///             if binding.key().keyid() == some_keyid {
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

    // Parses the next packet in the packet stream.
    //
    // If we complete parsing a TPK, returns the TPK.  Otherwise,
    // returns None.
    fn parse(&mut self, p: Packet) -> Result<Option<TPK>> {
        if self.packets.len() > 0 {
            match p.tag() {
                Tag::PublicKey | Tag::SecretKey => {
                    return self.tpk(Some(p));
                },
                _ => {},
            }
        }

        self.packets.push(p);
        Ok(None)
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

    // Finalizes the current TPK and returns it.  Sets the parser up to
    // begin parsing the next TPK.
    fn tpk(&mut self, pk: Option<Packet>) -> Result<Option<TPK>> {
        let orig = self.reset();

        if let Some(pk) = pk {
            self.packets.push(pk);
        }

        let packets = orig.packets.len();
        let tokens = orig.packets
            .into_iter()
            .filter_map(|p| p.into())
            .collect::<Vec<Token>>();
        if tokens.len() != packets {
            // There was at least one packet that doesn't belong in a
            // TPK.  Fail now.
            return Err(Error::UnsupportedTPK(
                "Packet sequence includes non-TPK packets.".into()).into());
        }

        let tpko = match TPKLowLevelParser::new()
            .parse(Lexer::from_tokens(&tokens))
        {
            Ok(tpko) => tpko,
            Err(e) => return Err(
                low_level::parse_error_to_openpgp_error(
                    low_level::parse_error_downcast(e)).into()),
        }.and_then(|tpk| {
            for filter in &self.filter {
                if !filter(&tpk, true) {
                    return None;
                }
            }

            Some(tpk)
        }).and_then(|mut tpk| {
            fn split_sigs<C>(primary: &Fingerprint, primary_keyid: &KeyID,
                             b: &mut ComponentBinding<C>)
            {
                let mut selfsigs = vec![];
                let mut certifications = vec![];
                let mut self_revs = vec![];
                let mut other_revs = vec![];

                for sig in mem::replace(&mut b.certifications, vec![]) {
                    match sig {
                        Signature::V4(sig) => {
                            let typ = sig.typ();

                            let is_selfsig =
                                sig.issuer_fingerprint()
                                .map(|fp| fp == *primary)
                                .unwrap_or(false)
                                || sig.issuer()
                                .map(|keyid| keyid == *primary_keyid)
                                .unwrap_or(false);

                            use crate::SignatureType::*;
                            if typ == KeyRevocation
                                || typ == SubkeyRevocation
                                || typ == CertificateRevocation
                            {
                                if is_selfsig {
                                    self_revs.push(sig.into());
                                } else {
                                    other_revs.push(sig.into());
                                }
                            } else {
                                if is_selfsig {
                                    selfsigs.push(sig.into());
                                } else {
                                    certifications.push(sig.into());
                                }
                            }
                        },
                    }
                }

                b.selfsigs = selfsigs;
                b.certifications = certifications;
                b.self_revocations = self_revs;
                b.other_revocations = other_revs;
            }

            let primary_fp = tpk.primary().fingerprint();
            let primary_keyid = primary_fp.to_keyid();

            // The parser puts all of the signatures on the
            // certifications field.  Split them now.

            split_sigs(&primary_fp, &primary_keyid, &mut tpk.primary);

            for b in tpk.userids.iter_mut() {
                split_sigs(&primary_fp, &primary_keyid, b);
            }
            for b in tpk.user_attributes.iter_mut() {
                split_sigs(&primary_fp, &primary_keyid, b);
            }
            for b in tpk.subkeys.iter_mut() {
                split_sigs(&primary_fp, &primary_keyid, b);
            }

            let tpk = tpk.canonicalize();

            // Make sure it is still wanted.
            for filter in &self.filter {
                if !filter(&tpk, true) {
                    return None;
                }
            }

            Some(tpk)
        });

        Ok(tpko)
    }
}

impl<'a, I: Iterator<Item=Packet>> Iterator for TPKParser<'a, I> {
    type Item = Result<TPK>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match mem::replace(&mut self.source, PacketSource::EOF) {
                PacketSource::EOF => {
                    if TRACE {
                        eprintln!("TPKParser::next: EOF.");
                    }

                    if self.packets.len() == 0 {
                        return None;
                    }
                    match self.tpk(None) {
                        Ok(Some(tpk)) => return Some(Ok(tpk)),
                        Ok(None) => return None,
                        Err(err) => return Some(Err(err)),
                    }
                },
                PacketSource::PacketParser(pp) => {
                    match pp.next() {
                        Ok((packet, ppr)) => {
                            if let PacketParserResult::Some(pp) = ppr {
                                self.source = PacketSource::PacketParser(pp);
                            }

                            match self.parse(packet) {
                                Ok(Some(tpk)) => return Some(Ok(tpk)),
                                Ok(None) => (),
                                Err(err) => return Some(Err(err)),
                            }
                        },
                        Err(err) => {
                            self.saw_error = true;
                            return Some(Err(err));
                        }
                    }
                },
                PacketSource::Iter(mut iter) => {
                    let r = match iter.next() {
                        Some(packet) => {
                            self.source = PacketSource::Iter(iter);
                            self.parse(packet)
                        }
                        None if self.packets.len() == 0 => Ok(None),
                        None => self.tpk(None),
                    };

                    match r {
                        Ok(Some(tpk)) => {
                            if TRACE {
                                eprintln!("TPKParser::next => {}",
                                          tpk.primary().fingerprint());
                            }
                            return Some(Ok(tpk));
                        }
                        Ok(None) => (),
                        Err(err) => return Some(Err(err)),
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tokens() {
        use crate::tpk::parser::low_level::lexer::{Token, Lexer};
        use crate::tpk::parser::low_level::lexer::Token::*;
        use crate::tpk::parser::low_level::TPKParser;

        struct TestVector<'a> {
            s: &'a [Token],
            result: bool,
        }

        let test_vectors = [
            TestVector {
                s: &[ PublicKey(None) ],
                result: true,
            },
            TestVector {
                s: &[ SecretKey(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None) ],
                result: true,
            },

            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     UserID(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     UserID(None), Signature(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     UserAttribute(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     UserAttribute(None), Signature(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     PublicSubkey(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     PublicSubkey(None), Signature(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     SecretSubkey(None) ],
                result: true,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                     SecretSubkey(None), Signature(None) ],
                result: true,
            },

            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      UserID(None), Signature(None),
                        Signature(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      UserAttribute(None), Signature(None),
                      Signature(None), Signature(None),
                      SecretSubkey(None), Signature(None),
                      UserID(None),
                      UserAttribute(None), Signature(None),
                        Signature(None), Signature(None),
                ],
                result: true,
            },

            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                      PublicKey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
            TestVector {
                s: &[ PublicKey(None), Signature(None), Signature(None),
                      SecretKey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
            TestVector {
                s: &[ SecretKey(None), Signature(None), Signature(None),
                      SecretKey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
            TestVector {
                s: &[ SecretKey(None), Signature(None), Signature(None),
                      PublicKey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
            TestVector {
                s: &[ SecretSubkey(None), Signature(None), Signature(None),
                      PublicSubkey(None), Signature(None), Signature(None),
                ],
                result: false,
            },
        ];

        for v in test_vectors.into_iter() {
            if v.result {
                let mut l = TPKValidator::new();
                for token in v.s.into_iter() {
                    l.push_token((*token).clone());
                    assert_match!(TPKValidity::TPKPrefix = l.check());
                }

                l.finish();
                assert_match!(TPKValidity::TPK = l.check());
            }

            match TPKParser::new().parse(Lexer::from_tokens(v.s)) {
                Ok(r) => assert!(v.result, "Parsing: {:?} => {:?}", v.s, r),
                Err(e) => assert!(! v.result, "Parsing: {:?} => {:?}", v.s, e),
            }
        }
    }
}
