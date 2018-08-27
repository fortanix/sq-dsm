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
use failure;

use {
    Error,
    Result,
    Tag,
    Signature,
    Key,
    UserID,
    UserAttribute,
    Unknown,
    Packet,
    PacketPile,
    TPK,
    Fingerprint,
    TSK,
};
use parse::{PacketParserResult, PacketParser};
use serialize::{Serialize, SerializeKey};

mod lexer;
mod grammar;
mod builder;

use self::lexer::Lexer;
pub use self::lexer::Token;
pub use self::builder::{TPKBuilder, CipherSuite};

use lalrpop_util::ParseError;

use self::grammar::TPKParser as TPKLowLevelParser;

// Converts a ParseError<usize, Token, Error> to a
// ParseError<usize, Tag, Error>.
//
// Justification: a Token is a tuple containing a Tag and a Packet.
// This function essentially drops the Packet.  Dropping the packet is
// necessary, because packets are not async, but Fail, which we want
// to convert ParseErrors to, is.  Since we don't need the packet in
// general anyways, changing the Token to a Tag is a simple and
// sufficient fix.  Unfortunately, this conversion is a bit ugly and
// will break if lalrpop ever extends ParseError.
fn parse_error_downcast(e: ParseError<usize, Token, Error>)
    -> ParseError<usize, Tag, Error>
{
    match e {
        ParseError::UnrecognizedToken {
            token: Some((start, t, end)),
            expected,
        } => ParseError::UnrecognizedToken {
            token: Some((start, t.into(), end)),
            expected,
        },
        ParseError::UnrecognizedToken {
            token: None,
            expected,
        } => ParseError::UnrecognizedToken {
            token: None,
            expected,
        },

        ParseError::ExtraToken {
            token: (start, t, end),
        } => ParseError::ExtraToken {
            token: (start, t.into(), end),
        },

        ParseError::InvalidToken { location }
        => ParseError::InvalidToken { location },

        ParseError::User { error }
        => ParseError::User { error },
    }
}

fn parse_error_to_openpgp_error(e: ParseError<usize, Tag, Error>) -> Error
{
    match e {
        ParseError::User { error } => error,
        e => Error::MalformedTPK(format!("{}", e)),
    }
}

/// Errors that TPKValidator::check may return.
#[derive(Debug, Clone)]
pub enum TPKParserError {
    /// A parser error.
    Parser(ParseError<usize, Tag, Error>),
    /// An OpenPGP error.
    OpenPGP(Error),
}

impl From<TPKParserError> for failure::Error {
    fn from(err: TPKParserError) -> Self {
        match err {
            TPKParserError::Parser(p) => p.into(),
            TPKParserError::OpenPGP(p) => p.into(),
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
pub struct TPKValidator {
    tokens: Vec<Token>,
    finished: bool,

    // If we know that the packet sequence is invalid.
    error: Option<TPKParserError>,
}

impl Default for TPKValidator {
    fn default() -> Self {
        TPKValidator::new()
    }
}

impl TPKValidator {
    /// Instantiates a new `TPKValidator`.
    pub fn new() -> Self {
        TPKValidator {
            tokens: vec![],
            finished: false,
            error: None,
        }
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
        assert!(!self.finished);

        if self.error.is_some() {
            return;
        }

        self.tokens.push(token);
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
            _ => {
                // Unknown token.
                self.error = Some(TPKParserError::OpenPGP(
                    Error::MalformedMessage(
                        format!("Invalid OpenPGP message: unexpected packet: {:?}",
                                tag).into())));
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
    /// `TPKValidity::TPKPrefix`.
    pub fn finish(&mut self) {
        assert!(!self.finished);
        self.finished = true;
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
        if let Some(ref err) = self.error {
            return TPKValidity::Error((*err).clone().into());
        }

        let r = TPKLowLevelParser::new().parse(
            Lexer::from_tokens(&self.tokens[..]));

        if self.finished {
            match r {
                Ok(_) => TPKValidity::TPK,
                Err(err) =>
                    TPKValidity::Error(
                        TPKParserError::Parser(parse_error_downcast(err)).into()),
            }
        } else {
            match r {
                Ok(_) => TPKValidity::TPKPrefix,
                Err(ParseError::UnrecognizedToken { token: None, .. }) =>
                    TPKValidity::TPKPrefix,
                Err(err) =>
                    TPKValidity::Error(
                        TPKParserError::Parser(parse_error_downcast(err)).into()),
            }
        }
    }
}

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
    /// Creates a new subkey binding signature. The subkey can be used for
    /// encrypting transport and expires in three years.
    pub fn new(subkey: Key, primary_key: &Key) -> Result<Self> {
        use subpacket::KeyFlags;
        use constants::HashAlgorithm;
        use SignatureType;
        use SecretKey;

        let mut sig = Signature::new(SignatureType::SubkeyBinding);

        sig.set_key_flags(&KeyFlags::default().set_encrypt_for_transport(true))?;
        sig.set_signature_creation_time(time::now())?;
        sig.set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?;
        sig.set_issuer_fingerprint(primary_key.fingerprint())?;
        sig.set_issuer(primary_key.fingerprint().to_keyid())?;

        let mut hash = HashAlgorithm::SHA512.context()?;

        primary_key.hash(&mut hash);
        subkey.hash(&mut hash);

        match primary_key.secret {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_hash(primary_key, mpis, HashAlgorithm::SHA512, hash)?;
            }
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation("Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation("No secret key".into()).into());
            }
        }

        Ok(SubkeyBinding{
            subkey: subkey,
            selfsigs: vec![sig],
            certifications: vec![],
        })
    }

    /// The key.
    pub fn subkey(&self) -> &Key {
        &self.subkey
    }

    /// Returns the most recent binding signature.
    pub fn binding_signature(&self) -> &Signature {
        &self.selfsigs[0]
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
    /// Creates a new self-signature binding `uid` to `key`, certified by `signer`. The signature
    /// asserts that the bound key can sign and certify and expires in three years.
    pub fn new(key: &Key, uid: UserID, signer: &Key) -> Result<Self> {
        use subpacket::KeyFlags;
        use constants::HashAlgorithm;
        use SignatureType;
        use SecretKey;

        let mut sig = Signature::new(SignatureType::PositiveCertificate);

        sig.set_key_flags(&KeyFlags::default().set_certify(true).set_sign(true))?;
        sig.set_signature_creation_time(time::now())?;
        sig.set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?;
        sig.set_issuer_fingerprint(signer.fingerprint())?;
        sig.set_issuer(signer.fingerprint().to_keyid())?;
        sig.set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?;

        let mut hash = HashAlgorithm::SHA512.context()?;

        key.hash(&mut hash);
        uid.hash(&mut hash);

        match signer.secret {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                sig.sign_hash(signer, mpis, HashAlgorithm::SHA512, hash)?;
            }
            Some(SecretKey::Encrypted{ .. }) => {
                return Err(Error::InvalidOperation("Secret key is encrypted".into()).into());
            }
            None => {
                return Err(Error::InvalidOperation("No secret key".into()).into());
            }
        }

        Ok(UserIDBinding{
            userid: uid,
            selfsigs: vec![sig],
            certifications: vec![],
        })
    }

    /// Returns the user id certified by this binding.
    pub fn userid(&self) -> &UserID {
        &self.userid
    }

    /// Returns the most recent binding signature.
    pub fn binding_signature(&self) -> &Signature {
        &self.selfsigs[0]
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

    /// Returns the most recent binding signature.
    pub fn binding_signature(&self) -> &Signature {
        &self.selfsigs[0]
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
pub struct UnknownBinding {
    unknown: Unknown,

    sigs: Vec<Signature>,
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
            .parse(Lexer::from_tokens(&tokens[..]))
        {
            Ok(tpko) => tpko,
            Err(e) => return Err(
                parse_error_to_openpgp_error(
                    parse_error_downcast(e)).into()),
        }.and_then(|tpk| {
            for filter in &self.filter {
                if !filter(&tpk, true) {
                    return None;
                }
            }

            Some(tpk)
        }).and_then(|mut tpk| {
            fn split_sigs(primary: &Fingerprint, sigs: Vec<Signature>)
                          -> (Vec<Signature>, Vec<Signature>)
            {
                let mut selfsigs = vec![];
                let mut certifications = vec![];

                let primary_keyid = primary.to_keyid();

                for sig in sigs.into_iter() {
                    let is_selfsig =
                        sig.issuer_fingerprint()
                            .map(|fp| fp == *primary)
                            .unwrap_or(false)
                        || sig.issuer()
                            .map(|keyid| keyid == primary_keyid)
                            .unwrap_or(false);

                    if is_selfsig {
                        selfsigs.push(sig);
                    } else {
                        certifications.push(sig);
                    }
                }

                (selfsigs, certifications)
            }

            // The parser puts all of the signatures on the
            // certifications.  Split them now.
            let primary_fp = tpk.primary.fingerprint();

            let (selfsigs, certifications)
                = split_sigs(
                    &primary_fp,
                    mem::replace(&mut tpk.primary_certifications, vec![]));
            tpk.primary_selfsigs = selfsigs;
            tpk.primary_certifications = certifications;

            for mut b in tpk.userids.iter_mut() {
                let (selfsigs, certifications)
                    = split_sigs(&primary_fp,
                                 mem::replace(&mut b.certifications, vec![]));
                b.selfsigs = selfsigs;
                b.certifications = certifications;
            }
            for mut b in tpk.user_attributes.iter_mut() {
                let (selfsigs, certifications)
                    = split_sigs(&primary_fp,
                                 mem::replace(&mut b.certifications, vec![]));
                b.selfsigs = selfsigs;
                b.certifications = certifications;
            }
            for mut b in tpk.subkeys.iter_mut() {
                let (selfsigs, certifications)
                    = split_sigs(&primary_fp,
                                 mem::replace(&mut b.certifications, vec![]));
                b.selfsigs = selfsigs;
                b.certifications = certifications;
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
                        Ok(((packet, _), (ppr, _))) => {
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

    /// Returns the signature carrying the primary keys' flags.
    pub fn primary_key_signature(&self) -> Option<&Signature> {
        self.userids.get(0).map(|uid| &uid.selfsigs[0])
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

        for sig in mem::replace(&mut self.primary_selfsigs, Vec::new())
            .into_iter()
        {
            if let Ok(true) = sig.verify_primary_key_binding(&self.primary,
                                                             &self.primary) {
                self.primary_selfsigs.push(sig);
            } else {
                bad.push(sig);
            }
        }

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
            if let Ok(true) = sig.verify_primary_key_binding(&self.primary,
                                                             &self.primary) {
                    if TRACE {
                        eprintln!("Sig {:02X}{:02X} was out of place. \
                                   Belongs to primary key: {}.",
                                  sig.hash_prefix[0], sig.hash_prefix[1],
                                  self.primary.keyid());
                    }
                self.primary_selfsigs.push(sig);
                continue 'outer;
            }

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
            let a_features = a.selfsigs[0].features();
            let b_features = b.selfsigs[0].features();
            let cmp = a_features.as_slice().cmp(b_features.as_slice());
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

        // In case we have subkeys bound to the primary, it must be certification capable.
        if ! self.subkeys.is_empty() {
            let pk_can_certify = self.userids.last()
                .map(|uid| uid.binding_signature().key_flags().can_certify())
                .unwrap_or(false);

            if ! pk_can_certify {
                // Primary not certification capable, all binding sigs are invalid.
                self.subkeys.clear();
            }
        }

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

    /// Cast the public key into a secret key that allows using the secret parts of the containing
    /// keys.
    pub fn into_tsk(self) -> TSK {
        TSK::from_tpk(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use KeyID;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../tests/data/keys/", $x)) };
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
    fn tokens() {
        use self::lexer::{Token, Lexer};
        use self::lexer::Token::*;
        use self::grammar::TPKParser;

        struct TestVector<'a> {
            s: &'a [Token],
            result: bool,
        }

        let test_vectors = [
            TestVector {
                s: &[ PublicKey(None) ][..],
                result: true,
            },
            TestVector {
                s: &[ SecretKey(None) ][..],
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
                   &[ KeyID::from_hex(&"7223B56678E02528"[..]).ok(),
                      KeyID::from_hex(&"A3506AFB820ABD08"[..]).ok(),
                      KeyID::from_hex(&"C2B819056C652598"[..]).ok(),
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
                   &[ KeyID::from_hex(&"1075 8EBD BD7C FAB5"[..]).ok(),
                      KeyID::from_hex(&"1258 68EA 4BFA 08E4"[..]).ok(),
                      KeyID::from_hex(&"1498 ADC6 C192 3237"[..]).ok(),
                      KeyID::from_hex(&"24EC FF5A FF68 370A"[..]).ok(),
                      KeyID::from_hex(&"3714 7292 14D5 DA70"[..]).ok(),
                      KeyID::from_hex(&"3B7A A7F0 14E6 9B5A"[..]).ok(),
                      KeyID::from_hex(&"5B58 DCF9 C341 6611"[..]).ok(),
                      KeyID::from_hex(&"A524 01B1 1BFD FA5C"[..]).ok(),
                      KeyID::from_hex(&"A70A 96E1 439E A852"[..]).ok(),
                      KeyID::from_hex(&"C61B D3EC 2148 4CFF"[..]).ok(),
                      KeyID::from_hex(&"CAEF A883 2167 5333"[..]).ok(),
                      KeyID::from_hex(&"DC10 4C4E 0CA7 57FB"[..]).ok(),
                      KeyID::from_hex(&"E3A3 2229 449B 0350"[..]).ok(),
                   ][..]);

    }

    // lutz's key is a v3 key.
    //
    // dkg's includes some v3 signatures.
    #[test]
    fn v3_packets() {
        let dkg = bytes!("dkg.gpg");
        let lutz = bytes!("lutz.gpg");

        // v3 primary keys are not supported.
        let tpk = TPK::from_bytes(lutz);
        assert_match!(Error::UnsupportedTPK(_)
                      = tpk.err().unwrap().downcast::<Error>().unwrap());

        let tpk = TPK::from_bytes(dkg);
        assert!(tpk.is_ok(), "dkg.gpg: {:?}", tpk);
    }

    #[test]
    fn keyring_with_v3_public_keys() {
        let dkg = bytes!("dkg.gpg");
        let lutz = bytes!("lutz.gpg");

        let tpk = TPK::from_bytes(dkg);
        assert!(tpk.is_ok(), "dkg.gpg: {:?}", tpk);

        // Key ring with two good keys
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&dkg[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, true ]);

        // Key ring with a good key, and a bad key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, false ]);

        // Key ring with a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ false, true ]);

        // Key ring with a good key, a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, false, true ]);

        // Key ring with a good key, a bad key, and a bad key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&lutz[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, false, false ]);

        // Key ring with a good key, a bad key, a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let tpks = TPKParser::from_bytes(&combined[..]).unwrap()
            .map(|tpkr| tpkr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(tpks, &[ true, false, false, true ]);
    }
}
