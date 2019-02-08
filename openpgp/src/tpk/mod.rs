//! Transferable public keys.

use std::io;
use std::cmp::Ordering;
use std::path::Path;
use std::slice;
use std::mem;
use std::fmt;
use std::vec;
use time;
use failure;

use {
    crypto::{Hash, Signer},
    Error,
    Result,
    RevocationStatus,
    SignatureType,
    HashAlgorithm,
    packet::Tag,
    packet::signature::{self, Signature},
    packet::Key,
    packet::UserID,
    packet::UserAttribute,
    packet::Unknown,
    packet::KeyFlags,
    Packet,
    PacketPile,
    TPK,
    Fingerprint,
    TSK,
};
use parse::{Parse, PacketParserResult, PacketParser};
use serialize::{Serialize, SerializeInto, SerializeKey};
use conversions::Time;
use constants::ReasonForRevocation;

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
                Err(ParseError::UnrecognizedToken { token: None, .. }) =>
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

const TRACE : bool = false;

/// Compare the creation time of two signatures.  Order them so
/// that the more recent signature is first.
fn canonical_signature_order(a: Option<time::Tm>, b: Option<time::Tm>) -> Ordering {
    match (a,b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(ref a), Some(ref b)) => a.cmp(b),
    }
}

/// Returns the first signature with creation time not less than `t`.
fn greatest_lower_bound<'a>(t: time::Tm, sigs: &'a [Signature])
    -> Option<&'a Signature>
{
    let idx = sigs
        .binary_search_by(|s| {
            canonical_signature_order(s.signature_creation_time(), Some(t))
        });

    match idx {
        Ok(i) => sigs.get(i),
        Err(0) => None,
        Err(i) => sigs.get(i - 1),
    }
}

/// Returns true if latest revocation signature in `revs` is newer than the
/// latest self signature in sigs. Signatures _must_ be sorted by
/// `canonical_signature_order`.
///
/// Signatures are expected to have the right signature types and be
/// cryptographically sound.
fn active_revocation(sigs: &[Signature], revs: &[Signature], t: time::Tm)
    -> bool
{
    let sig = greatest_lower_bound(t, sigs);
    let rev = greatest_lower_bound(t, revs);

    match (sig, rev) {
        (None, Some(_)) => true,
        (Some(_), None) => false,
        (None, None) => false,
        (Some(ref sig), Some(ref revc)) => {
            canonical_signature_order(
                sig.signature_creation_time(),
                revc.signature_creation_time()) != Ordering::Greater
        }
    }
}

/// A subkey and any associated signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct SubkeyBinding {
    subkey: Key,

    // Self signatures.
    selfsigs: Vec<Signature>,

    // Third-party certifications.  (In general, this will only be by
    // designated revokers.)
    certifications: Vec<Signature>,

    // Self revocations.
    self_revocations: Vec<Signature>,

    // Third-party revocations (e.g., designated revokers).
    other_revocations: Vec<Signature>,
}

impl SubkeyBinding {
    /// Creates a new subkey binding signature certified by
    /// `signer`. The subkey can be used for encrypting transport and
    /// expires in three years.
    pub fn new(subkey: Key, primary_key: &Key, signer: &mut Signer)
               -> Result<Self> {
        use packet::KeyFlags;
        use constants::HashAlgorithm;
        use SignatureType;

        let sig = signature::Builder::new(SignatureType::SubkeyBinding)
            .set_key_flags(&KeyFlags::default().set_encrypt_for_transport(true))?
            .set_signature_creation_time(time::now().canonicalize())?
            .set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().fingerprint().to_keyid())?
            .sign_subkey_binding(signer,
                                 primary_key, &subkey,
                                 HashAlgorithm::SHA512)?;

        Ok(SubkeyBinding{
            subkey: subkey,
            selfsigs: vec![sig],
            certifications: vec![],
            self_revocations: vec![],
            other_revocations: vec![],
        })
    }

    /// The key.
    pub fn subkey(&self) -> &Key {
        &self.subkey
    }

    /// Returns the most recent binding signature.
    ///
    /// This will never return a revocation certificate.
    ///
    /// Normally, we ignore subkeys that don't have a binding
    /// signature.  However, if there is a valid revocation
    /// certificate for the subkey, we keep it.  In such cases, this
    /// function will return None.
    pub fn binding_signature(&self) -> Option<&Signature> {
        self.selfsigs.last()
    }

    /// The self-signatures.
    ///
    /// All self-signatures have been validated, and the newest
    /// self-signature is first.
    pub fn selfsigs(&self) -> &[Signature] {
        &self.selfsigs
    }

    /// Any third-party certifications.
    ///
    /// The signatures have *not* been validated.
    pub fn certifications(&self) -> &[Signature] {
        &self.certifications
    }

    /// Revocations issued by the key itself.
    ///
    /// The revocations have been validated, and the newest is first.
    pub fn self_revocations(&self) -> &[Signature] {
        &self.self_revocations
    }

    /// Revocations issued by other keys.
    ///
    /// The revocations have *not* been validated.
    pub fn other_revocations(&self) -> &[Signature] {
        &self.other_revocations
    }

    /// Returns the subkey's revocation status.
    ///
    /// Note: this only returns whether the subkey is revoked.  If you
    /// want to know whether the key, subkey, etc., is revoked, then
    /// you need to query them separately.
    pub fn revoked<T>(&self, t: T) -> RevocationStatus
        where T: Into<Option<time::Tm>>
    {
        let t = t.into().unwrap_or_else(time::now_utc);
        let has_self_revs =
            active_revocation(&self.selfsigs,
                              &self.self_revocations, t);

        if has_self_revs {
            return RevocationStatus::Revoked(&self.self_revocations);
        }

        let has_other_revs =
            active_revocation(&self.selfsigs,
                              &self.other_revocations, t);

        if has_other_revs {
            RevocationStatus::CouldBe(&self.other_revocations)
        } else {
            RevocationStatus::NotAsFarAsWeKnow
        }
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

    // Self revocations.
    self_revocations: Vec<Signature>,

    // Third-party revocations (e.g., designated revokers).
    other_revocations: Vec<Signature>,
}

impl UserIDBinding {
    /// Creates a new self-signature binding `uid` to `key`, certified by `signer`. The signature
    /// asserts that the bound key can sign and certify and expires in three years.
    pub fn new(key: &Key, uid: UserID, signer: &mut Signer) -> Result<Self> {
        use packet::KeyFlags;
        use constants::HashAlgorithm;
        use SignatureType;

        let sig = signature::Builder::new(SignatureType::PositiveCertificate)
            .set_key_flags(&KeyFlags::default().set_certify(true).set_sign(true))?
            .set_signature_creation_time(time::now().canonicalize())?
            .set_key_expiration_time(Some(time::Duration::weeks(3 * 52)))?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().fingerprint().to_keyid())?
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512])?
            .sign_userid_binding(signer, key, &uid, HashAlgorithm::SHA512)?;

        Ok(UserIDBinding{
            userid: uid,
            selfsigs: vec![sig],
            certifications: vec![],
            self_revocations: vec![],
            other_revocations: vec![],
        })
    }

    /// Returns the user id certified by this binding.
    pub fn userid(&self) -> &UserID {
        &self.userid
    }

    /// Returns the most recent binding signature.
    ///
    /// This will never return a revocation certificate.
    ///
    /// Normally, we ignore user ids that don't have a binding
    /// signature.  However, if there is a valid revocation
    /// certificate for the user id, we keep it.  In such cases, this
    /// function will return None.
    pub fn binding_signature(&self) -> Option<&Signature> {
        self.selfsigs.last()
    }

    /// The self-signatures.
    ///
    /// The self-signatures have been validated, and the newest
    /// self-signature is first.
    pub fn selfsigs(&self) -> &[Signature] {
        &self.selfsigs
    }

    /// Any third-party certifications.
    ///
    /// The signatures have *not* been validated.
    pub fn certifications(&self) -> &[Signature] {
        &self.certifications
    }

    /// Revocations issued by the key itself.
    ///
    /// The revocations have been validated, and the newest is first.
    pub fn self_revocations(&self) -> &[Signature] {
        &self.self_revocations
    }

    /// Revocations issued by other keys.
    ///
    /// The revocations have *not* been validated.
    pub fn other_revocations(&self) -> &[Signature] {
        &self.other_revocations
    }

    /// Returns the user id's revocation status at time `t`. If `t` is None,
    /// the current time is used.
    ///
    /// Note: this only returns whether the user id is revoked.  If
    /// you want to know whether the key, subkey, etc., is revoked,
    /// then you need to query them separately.
    pub fn revoked<T>(&self, t: T) -> RevocationStatus
        where T: Into<Option<time::Tm>>
    {
        let t = t.into().unwrap_or_else(time::now_utc);
        let has_self_revs =
            active_revocation(&self.selfsigs,
                              &self.self_revocations, t);

        if has_self_revs {
            return RevocationStatus::Revoked(&self.self_revocations);
        }

        let has_other_revs =
            active_revocation(&self.selfsigs,
                              &self.other_revocations, t);

        if has_other_revs {
            RevocationStatus::CouldBe(&self.other_revocations)
        } else {
            RevocationStatus::NotAsFarAsWeKnow
        }
    }

    /// Returns a revocation certificate for the user id.
    pub fn revoke(&self, signer: &mut Signer,
                  code: ReasonForRevocation, reason: &[u8])
        -> Result<Signature>
    {
        let key = signer.public().clone();

        signature::Builder::new(SignatureType::CertificateRevocation)
            .set_signature_creation_time(time::now_utc())?
            .set_issuer_fingerprint(signer.public().fingerprint())?
            .set_issuer(signer.public().keyid())?
            .set_reason_for_revocation(code, reason)?
            .sign_userid_binding(signer, &key, self.userid(), HashAlgorithm::SHA512)
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

    // Self revocations.
    self_revocations: Vec<Signature>,

    // Third-party revocations (e.g., designated revokers).
    other_revocations: Vec<Signature>,
}

impl UserAttributeBinding {
    /// The User attribute.
    pub fn user_attribute(&self) -> &UserAttribute {
        &self.user_attribute
    }

    /// Returns the most recent binding signature.
    ///
    /// This will never return a revocation certificate.
    ///
    /// Normally, we ignore user attributes that don't have a binding
    /// signature.  However, if there is a valid revocation
    /// certificate for the user attribute, we keep it.  In such
    /// cases, this function will return None.
    pub fn binding_signature(&self) -> Option<&Signature> {
        self.selfsigs.last()
    }

    /// The self-signatures.
    ///
    /// The self-signatures have been validated, and the newest
    /// self-signature is first.
    pub fn selfsigs(&self) -> &[Signature] {
        &self.selfsigs
    }

    /// Any third-party certifications.
    ///
    /// The signatures have *not* been validated.
    pub fn certifications(&self) -> &[Signature] {
        &self.certifications
    }

    /// Revocations issued by the key itself.
    ///
    /// The revocations have been validated, and the newest is first.
    pub fn self_revocations(&self) -> &[Signature] {
        &self.self_revocations
    }

    /// Revocations issued by other keys.
    ///
    /// The revocations have *not* been validated.
    pub fn other_revocations(&self) -> &[Signature] {
        &self.other_revocations
    }

    /// Returns the `UserAttribute`'s revocation status.
    ///
    /// Note: this only returns whether the user attribute is revoked.
    /// If you want to know whether the key, subkey, etc., is revoked,
    /// then you need to query them separately.
    pub fn revoked<T>(&self, t: T) -> RevocationStatus
        where T: Into<Option<time::Tm>>
    {
        let t = t.into().unwrap_or_else(time::now_utc);
        let has_self_revs =
            active_revocation(&self.selfsigs,
                              &self.self_revocations, t);

        if has_self_revs {
            return RevocationStatus::Revoked(&self.self_revocations);
        }

        let has_other_revs =
            active_revocation(&self.selfsigs,
                              &self.other_revocations, t);

        if has_other_revs {
            RevocationStatus::CouldBe(&self.other_revocations)
        } else {
            RevocationStatus::NotAsFarAsWeKnow
        }
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
    subkey_iter: SubkeyBindingIter<'a>,
}

impl<'a> Iterator for KeyIter<'a> {
    type Item = (Option<&'a Signature>, RevocationStatus<'a>, &'a Key);

    fn next(&mut self) -> Option<Self::Item> {
        if ! self.primary {
            self.primary = true;
            Some((self.tpk.primary_key_signature(),
                  self.tpk.revoked(None),
                  self.tpk.primary()))
        } else {
            self.subkey_iter.next()
                .map(|sk_binding| (sk_binding.binding_signature(),
                                   sk_binding.revoked(None),
                                   &sk_binding.subkey,))
        }
    }
}

impl<'a> ExactSizeIterator for KeyIter<'a> {
    fn len(&self) -> usize { 1 + self.subkey_iter.len() }
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
    fn from_bytes(data: &'a [u8]) -> Result<Self> {
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
            .parse(Lexer::from_tokens(&tokens))
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
                          -> (Vec<Signature>, Vec<Signature>,
                              Vec<Signature>, Vec<Signature>)
            {
                let mut selfsigs = vec![];
                let mut certifications = vec![];
                let mut self_revs = vec![];
                let mut other_revs = vec![];

                let primary_keyid = primary.to_keyid();

                for sig in sigs.into_iter() {
                    let sigtype = sig.sigtype();

                    let is_selfsig =
                        sig.issuer_fingerprint()
                            .map(|fp| fp == *primary)
                            .unwrap_or(false)
                        || sig.issuer()
                            .map(|keyid| keyid == primary_keyid)
                            .unwrap_or(false);

                    if sigtype == SignatureType::KeyRevocation
                        || sigtype == SignatureType::SubkeyRevocation
                        || sigtype == SignatureType::CertificateRevocation
                    {
                        if is_selfsig {
                            self_revs.push(sig);
                        } else {
                            other_revs.push(sig);
                        }
                    } else {
                        if is_selfsig {
                            selfsigs.push(sig);
                        } else {
                            certifications.push(sig);
                        }
                    }
                }

                (selfsigs, certifications, self_revs, other_revs)
            }

            let primary_fp = tpk.primary().fingerprint();

            // The parser puts all of the signatures on the
            // certifications field.  Split them now.

            let (selfsigs, certifications, self_revs, other_revs)
                = split_sigs(
                    &primary_fp,
                    mem::replace(&mut tpk.primary_certifications, vec![]));
            tpk.primary_selfsigs = selfsigs;
            tpk.primary_certifications = certifications;
            tpk.primary_self_revocations = self_revs;
            tpk.primary_other_revocations = other_revs;

            for mut b in tpk.userids.iter_mut() {
                let (selfsigs, certifications, self_revs, other_revs)
                    = split_sigs(&primary_fp,
                                 mem::replace(&mut b.certifications, vec![]));
                b.selfsigs = selfsigs;
                b.certifications = certifications;
                b.self_revocations = self_revs;
                b.other_revocations = other_revs;
            }
            for mut b in tpk.user_attributes.iter_mut() {
                let (selfsigs, certifications, self_revs, other_revs)
                    = split_sigs(&primary_fp,
                                 mem::replace(&mut b.certifications, vec![]));
                b.selfsigs = selfsigs;
                b.certifications = certifications;
                b.self_revocations = self_revs;
                b.other_revocations = other_revs;
            }
            for mut b in tpk.subkeys.iter_mut() {
                let (selfsigs, certifications, self_revs, other_revs)
                    = split_sigs(&primary_fp,
                                 mem::replace(&mut b.certifications, vec![]));
                b.selfsigs = selfsigs;
                b.certifications = certifications;
                b.self_revocations = self_revs;
                b.other_revocations = other_revs;
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

impl fmt::Display for TPK {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.primary().fingerprint())
    }
}

/// An iterator over `UserIDBinding`s.
pub struct UserIDBindingIter<'a> {
    iter: slice::Iter<'a, UserIDBinding>,
}

impl<'a> Iterator for UserIDBindingIter<'a> {
    type Item = &'a UserIDBinding;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<'a> ExactSizeIterator for UserIDBindingIter<'a> {
    fn len(&self) -> usize { self.iter.len() }
}

/// An iterator over `UserAttributeBinding`s.
pub struct UserAttributeBindingIter<'a> {
    iter: slice::Iter<'a, UserAttributeBinding>,
}

impl<'a> Iterator for UserAttributeBindingIter<'a> {
    type Item = &'a UserAttributeBinding;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<'a> ExactSizeIterator for UserAttributeBindingIter<'a> {
    fn len(&self) -> usize { self.iter.len() }
}

/// An iterator over `SubkeyBinding`s.
pub struct SubkeyBindingIter<'a> {
    iter: slice::Iter<'a, SubkeyBinding>,
}

impl<'a> Iterator for SubkeyBindingIter<'a> {
    type Item = &'a SubkeyBinding;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

impl<'a> ExactSizeIterator for SubkeyBindingIter<'a> {
    fn len(&self) -> usize { self.iter.len() }
}


impl<'a> Parse<'a, TPK> for TPK {
    /// Returns the first TPK encountered in the reader.
    fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        TPK::from_packet_parser(PacketParser::from_reader(reader)?)
    }

    /// Returns the first TPK encountered in the file.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        TPK::from_packet_parser(PacketParser::from_file(path)?)
    }

    /// Returns the first TPK found in `buf`.
    ///
    /// `buf` must be an OpenPGP-encoded message.
    fn from_bytes(buf: &[u8]) -> Result<Self> {
        TPK::from_packet_parser(PacketParser::from_bytes(buf)?)
    }
}

impl TPK {
    /// Returns a reference to the primary key.
    pub fn primary(&self) -> &Key {
        &self.primary
    }

    #[cfg(test)]
    pub(crate) fn primary_mut(&mut self) -> &mut Key {
        &mut self.primary
    }

    /// Returns the primary key's current self-signature and, if it
    /// belong to a user id, a reference to the `UserIDBinding`.
    ///
    /// Normally, the primary key's current self-signature is the
    /// primary user id's newest, non-revoked self-signature.
    /// However, if all user ids are revoked and there is a direct
    /// signature, that is returned.  If there is no direct signature,
    /// then we return the newest self-signature on the most recently
    /// revoked user id (i.e., the binding signature that was last
    /// valid).  If there are no user ids at all and no direct
    /// signatures, then we return None.
    pub fn primary_key_signature_full(&self)
        -> Option<(Option<&UserIDBinding>, &Signature)>
    {
        // 1. Self-signature from a non-revoked UserID.
        if let Some(userid) = self.userids.get(0) {
            if userid.self_revocations.len() == 0 {
                return Some((Some(&userid), userid.selfsigs.last().unwrap()));
            }
        }

        // 2. Direct signature.
        if let Some(sig) = self.primary_selfsigs.last() {
            return Some((None, sig));
        }

        // 3. Treat User IDs as if they were not revoked.
        if let Some(userid) = self.userids.get(0) {
            return Some((Some(&userid), &userid.selfsigs.last().unwrap()));
        }

        // 4. No user ids and no direct signatures.
        None
    }

    /// Returns the primary key's current self-signature.
    ///
    /// This function is identical to
    /// `TPK::primary_key_signature_full()`, but it doesn't return the
    /// `UserIDBinding`.
    pub fn primary_key_signature(&self) -> Option<&Signature> {
        if let Some((_, sig)) = self.primary_key_signature_full() {
            Some(sig)
        } else {
            None
        }
    }

    /// The self-signatures.
    ///
    /// All self-signatures have been validated, and the newest
    /// self-signature is first.
    pub fn selfsigs(&self) -> &[Signature] {
        &self.primary_selfsigs
    }

    /// Any third-party certifications.
    ///
    /// The signatures have *not* been validated.
    pub fn certifications(&self) -> &[Signature] {
        &self.primary_certifications
    }

    /// Revocations issued by the key itself.primary_
    ///
    /// The revocations have been validated, and the newest is first.
    pub fn self_revocations(&self) -> &[Signature] {
        &self.primary_self_revocations
    }

    /// Revocations issued by other keys.
    ///
    /// The revocations have *not* been validated.
    pub fn other_revocations(&self) -> &[Signature] {
        &self.primary_other_revocations
    }

    /// Returns the TPK's revocation status.
    ///
    /// Note: this only returns whether the primary key is revoked.  If you
    /// want to know whether a subkey, user id, etc., is revoked, then
    /// you need to query them separately.
    pub fn revoked<T>(&self, t: T) -> RevocationStatus
        where T: Into<Option<time::Tm>>
    {
        let t = t.into().unwrap_or_else(time::now_utc);
        let has_self_revs =
            active_revocation(&self.primary_selfsigs,
                              &self.primary_self_revocations, t);

        if has_self_revs {
            return RevocationStatus::Revoked(&self.primary_self_revocations);
        }

        let has_other_revs =
            active_revocation(&self.primary_selfsigs,
                              &self.primary_other_revocations, t);

        if has_other_revs {
            RevocationStatus::CouldBe(&self.primary_other_revocations)
        } else {
            RevocationStatus::NotAsFarAsWeKnow
        }
    }

    /// Returns a revocation certificate for the TPK.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::RevocationStatus;
    /// use openpgp::constants::{ReasonForRevocation, SignatureType};
    /// use openpgp::tpk::{CipherSuite, TPKBuilder};
    /// use openpgp::crypto::KeyPair;
    /// use openpgp::parse::Parse;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()>
    /// # {
    /// let (tpk, _) = TPKBuilder::default()
    ///     .set_cipher_suite(CipherSuite::Cv25519)
    ///     .generate()?;
    /// assert_eq!(RevocationStatus::NotAsFarAsWeKnow, tpk.revoked(None));
    ///
    /// let mut keypair = tpk.primary().clone().into_keypair()?;
    /// let sig = tpk.revoke(&mut keypair, ReasonForRevocation::KeyCompromised,
    ///                      b"It was the maid :/")?;
    /// assert_eq!(sig.sigtype(), SignatureType::KeyRevocation);
    ///
    /// let tpk = tpk.merge_packets(vec![sig.clone().into()])?;
    /// assert_eq!(RevocationStatus::Revoked(&[sig]), tpk.revoked(None));
    /// # Ok(())
    /// # }
    pub fn revoke(&self, primary_signer: &mut Signer,
                  code: ReasonForRevocation, reason: &[u8])
        -> Result<Signature>
    {
        if primary_signer.public().fingerprint() != self.fingerprint() {
            return Err(Error::InvalidArgument(
                "signer is not the primary key".into()).into());
        }

        // Recompute the signature.
        let hash_algo = HashAlgorithm::SHA512;
        let mut hash = hash_algo.context()?;
        let pair = self.primary();
        pair.hash(&mut hash);

        signature::Builder::new(SignatureType::KeyRevocation)
            .set_signature_creation_time(time::now_utc())?
            .set_issuer_fingerprint(self.primary().fingerprint())?
            .set_issuer(self.primary().keyid())?
            .set_reason_for_revocation(code, reason)?
            .sign_hash(primary_signer, hash_algo, hash)
    }

    /// Revokes the TPK.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::RevocationStatus;
    /// use openpgp::constants::{ReasonForRevocation, SignatureType};
    /// use openpgp::tpk::{CipherSuite, TPKBuilder};
    /// use openpgp::crypto::KeyPair;
    /// use openpgp::parse::Parse;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()>
    /// # {
    /// let (mut tpk, _) = TPKBuilder::default()
    ///     .set_cipher_suite(CipherSuite::Cv25519)
    ///     .generate()?;
    /// assert_eq!(RevocationStatus::NotAsFarAsWeKnow, tpk.revoked(None));
    ///
    /// let mut keypair = tpk.primary().clone().into_keypair()?;
    /// let tpk = tpk.revoke_in_place(&mut keypair,
    ///                               ReasonForRevocation::KeyCompromised,
    ///                               b"It was the maid :/")?;
    /// if let RevocationStatus::Revoked(sigs) = tpk.revoked(None) {
    ///     assert_eq!(sigs.len(), 1);
    ///     assert_eq!(sigs[0].sigtype(), SignatureType::KeyRevocation);
    ///     assert_eq!(sigs[0].reason_for_revocation(),
    ///                Some((ReasonForRevocation::KeyCompromised,
    ///                      "It was the maid :/".as_bytes())));
    /// } else {
    ///     unreachable!()
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn revoke_in_place(self, primary_signer: &mut Signer,
                           code: ReasonForRevocation, reason: &[u8])
        -> Result<TPK>
    {
        let sig = self.revoke(primary_signer, code, reason)?;
        self.merge_packets(vec![sig.into()])
    }

    /// Returns whether or not the TPK has expired.
    pub fn expired(&self) -> bool {
        if let Some(sig) = self.primary_key_signature() {
            sig.key_expired(self.primary())
        } else {
            false
        }
    }

    /// Returns whether or not the key is expired at the given time.
    pub fn expired_at(&self, tm: time::Tm) -> bool {
        if let Some(sig) = self.primary_key_signature() {
            sig.key_expired_at(self.primary(), tm)
        } else {
            false
        }
    }

    /// Returns whether or not the TPK is alive.
    pub fn alive(&self) -> bool {
        if let Some(sig) = self.primary_key_signature() {
            sig.key_alive(self.primary())
        } else {
            false
        }
    }

    /// Returns whether or not the key is alive at the given time.
    pub fn alive_at(&self, tm: time::Tm) -> bool {
        if let Some(sig) = self.primary_key_signature() {
            sig.key_alive_at(self.primary(), tm)
        } else {
            false
        }
    }

    /// Sets the key to expire in delta seconds.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    ///
    /// This function exists to facilitate testing, which is why it is
    /// not exported.
    fn set_expiry_as_of(self, primary_signer: &mut Signer,
                        expiration: Option<time::Duration>,
                        now: time::Tm)
        -> Result<TPK>
    {
        let sig = {
            let (userid, template) = self
                .primary_key_signature_full()
                .ok_or(Error::MalformedTPK("No self-signature".into()))?;

            // Recompute the signature.
            let hash_algo = HashAlgorithm::SHA512;
            let mut hash = hash_algo.context()?;

            self.primary().hash(&mut hash);
            if let Some(userid) = userid {
                userid.userid().hash(&mut hash);
            } else {
                assert_eq!(template.sigtype(), SignatureType::DirectKey);
            }

            // Generate the signature.
            signature::Builder::from(template.clone())
                .set_key_expiration_time(expiration)?
                .set_signature_creation_time(now)?
                .sign_hash(primary_signer, hash_algo, hash)?
        };

        self.merge_packets(vec![sig.into()])
    }

    /// Sets the key to expire in delta.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    pub fn set_expiry(self, primary_signer: &mut Signer,
                      expiration: Option<time::Duration>)
        -> Result<TPK>
    {
        self.set_expiry_as_of(primary_signer, expiration, time::now())
    }

    /// Returns an iterator over the TPK's valid `UserIDBinding`s.
    ///
    /// The primary user id is returned first.  A valid
    /// `UserIDBinding` has at least one good self-signature.
    pub fn userids(&self) -> UserIDBindingIter {
        UserIDBindingIter { iter: self.userids.iter() }
    }

    /// Returns an iterator over the TPK's valid `UserAttributeBinding`s.
    ///
    /// A valid `UserIDAttributeBinding` has at least one good
    /// self-signature.
    pub fn user_attributes(&self) -> UserAttributeBindingIter {
        UserAttributeBindingIter { iter: self.user_attributes.iter() }
    }

    /// Returns an iterator over the TPK's valid subkeys.
    ///
    /// A valid `SubkeyBinding` has at least one good self-signature.
    pub fn subkeys(&self) -> SubkeyBindingIter {
        SubkeyBindingIter { iter: self.subkeys.iter() }
    }

    /// Returns an iterator over all of the TPK's valid keys.
    ///
    /// That is, this returns an iterator over the primary key and any
    /// subkeys, along with the corresponding signatures.
    ///
    /// Note: since a primary key is different from a binding, the
    /// iterator is over `Key`s and not `SubkeyBindings`.
    /// Furthermore, the primary key has no binding signature.  Here,
    /// the signature carrying the primary key's key flags is
    /// returned.  There are corner cases where no such signature
    /// exists (e.g. partial TPKs), therefore this iterator may return
    /// `None` for the primary key's signature.
    ///
    /// A valid `Key` has at least one good self-signature.
    pub fn keys(&self) -> KeyIter {
        KeyIter {
            tpk: self,
            primary: false,
            subkey_iter: self.subkeys()
        }
    }

    /// Returns all unrevoked (sub)keys that have all capabilities in `cap` and
    /// are valid `now`. If `now` is `None` the current time is used.
    ///
    /// Keys are sorted by creation time (newest first). If the primary key
    /// qualifies it will always be last. Using the first key should suffice
    /// for most use cases.
    pub fn select_keys<'a, T>(&'a self, cap: KeyFlags, now: T)
        -> Vec<&'a Key>
        where T: Into<Option<time::Tm>> {
            use std::slice;
            use std::iter;
            use std::borrow::Borrow;

        fn is_usable<S>(key: &Key, mut bindings: slice::Iter<S>, now: time::Tm,
                        cap: &KeyFlags) -> bool where S: Borrow<Signature> {
            let key_now_valid = *key.creation_time() < now;
            let sig_now_valid = bindings.clone().any(|sig| {
                sig.borrow().signature_alive_at(now)
            });
            let right_caps = bindings.any(|sig| {
                *cap <= sig.borrow().key_flags()
            });

            key_now_valid && sig_now_valid && right_caps
        }
        let now = now.into().unwrap_or_else(time::now);

        if self.revoked(now) == RevocationStatus::NotAsFarAsWeKnow {
            let prim_sigs = match self.primary_key_signature_full() {
                None => Vec::default(),
                Some((None, sig)) => vec![sig],
                Some((Some(uid), sig)) =>
                    uid.selfsigs().iter().chain(iter::once(sig)).collect(),
            };
            let prim = Some(&self.primary)
                .filter(|k| is_usable(k, prim_sigs.iter(), now, &cap));
            let mut ret = self.subkeys
                .iter()
                .filter(|sb| {
                    sb.revoked(None) == RevocationStatus::NotAsFarAsWeKnow &&
                        is_usable(sb.subkey(), sb.selfsigs().iter(), now, &cap)
                })
                .map(|sb| sb.subkey())
                .collect::<Vec<_>>();

            ret.sort_by(|a,b| b.creation_time().cmp(a.creation_time()));
            ret.extend(prim);

            ret
        } else {
            Vec::default()
        }
    }

    /// Returns all unrevoked (sub)keys that have the signing
    /// capability and are valid `now`. If `now` is `None` the current
    /// time is used.
    ///
    /// Keys are sorted by creation time (newest first). If the
    /// primary key qualifies it will always be last. Using the first
    /// key should suffice for most use cases.
    pub fn select_signing_keys<'a, T>(&'a self, now: T) -> Vec<&'a Key>
        where T: Into<Option<time::Tm>>
    {
        self.select_keys(KeyFlags::default().set_sign(true), now)
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

    /// Returns the first TPK found in the `PacketPile`.
    pub fn from_packet_pile(p: PacketPile) -> Result<Self> {
        let mut i = TPKParser::from_iter(p.into_children());
        match i.next() {
            Some(Ok(tpk)) => Ok(tpk),
            Some(Err(err)) => Err(err),
            None => Err(Error::MalformedTPK("No data".into()).into()),
        }
    }

    fn canonicalize(mut self) -> Self {
        // Helper functions.
        // Turn a signature into a key for use by dedup.
        fn sig_key(a: &mut Signature) -> Box<[u8]> {
            a.to_vec().expect("XXX: this better not fail")
                .into_boxed_slice()
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

        // We collect bad signatures here in self.bad.  Below, we'll
        // test whether they are just out of order by checking them
        // against all userids and subkeys.  Furthermore, this may be
        // a partial TPK that is merged into an older copy.

        // desc: a description of the component
        // binding: the binding to check
        // sigs: a vector of sigs in $binding to check
        // verify_method: the method to call on a signature to verify it
        // verify_args: additional arguments to pass to verify_method
        macro_rules! check {
            ($desc:expr, $binding:expr, $sigs:ident,
             $verify_method:ident, $($verify_args:expr),*) => ({
                for sig in mem::replace(&mut $binding.$sigs, Vec::new())
                    .into_iter()
                {
                    if let Ok(true) = sig.$verify_method(&self.primary,
                                                         &self.primary,
                                                         $($verify_args),*) {
                        $binding.$sigs.push(sig);
                    } else {
                        if TRACE {
                            eprintln!("Sig {:02X}{:02X}, type = {} \
                                       doesn't belong to {}",
                                      sig.hash_prefix()[0], sig.hash_prefix()[1],
                                      sig.sigtype(), $desc);
                        }

                        self.bad.push(sig);
                    }
                }
            });
            ($desc:expr, $binding:expr, $sigs:ident,
             $verify_method:ident) => ({
                check!($desc, $binding, $sigs, $verify_method,)
            });
        }

        check!("primary key",
               self, primary_selfsigs, verify_primary_key_binding);
        check!("primary key",
               self, primary_self_revocations, verify_primary_key_revocation);

        for binding in self.userids.iter_mut() {
            check!(format!("userid \"{}\"",
                           String::from_utf8_lossy(binding.userid.userid())),
                   binding, selfsigs, verify_userid_binding,
                   &binding.userid);
            check!(format!("userid \"{}\"",
                           String::from_utf8_lossy(binding.userid.userid())),
                   binding, self_revocations, verify_userid_revocation,
                   &binding.userid);
        }

        for binding in self.user_attributes.iter_mut() {
            check!("user attribute",
                   binding, selfsigs, verify_user_attribute_binding,
                   &binding.user_attribute);
            check!("user attribute",
                   binding, self_revocations, verify_user_attribute_revocation,
                   &binding.user_attribute);
        }

        for binding in self.subkeys.iter_mut() {
            check!(format!("subkey {}", binding.subkey.keyid()),
                   binding, selfsigs, verify_subkey_binding,
                   &binding.subkey);
            check!(format!("subkey {}", binding.subkey.keyid()),
                   binding, self_revocations, verify_subkey_revocation,
                   &binding.subkey);
        }

        // See if the signatures that didn't validate are just out of
        // place.

        'outer: for sig in mem::replace(&mut self.bad, Vec::new()) {
            macro_rules! check_one {
                ($desc:expr, $sigs:expr, $sig:expr,
                 $verify_method:ident, $($verify_args:expr),*) => ({
                     if let Ok(true)
                         = $sig.$verify_method(&self.primary,
                                               &self.primary,
                                               $($verify_args),*)
                     {
                         if TRACE {
                             eprintln!("Sig {:02X}{:02X}, {:?} \
                                        was out of place.  Belongs to {}.",
                                       $sig.hash_prefix()[0],
                                       $sig.hash_prefix()[1],
                                       $sig.sigtype(), $desc);
                         }

                         $sigs.push($sig);
                         continue 'outer;
                     }
                 });
                ($desc:expr, $sigs:expr, $sig:expr,
                 $verify_method:ident) => ({
                    check_one!($desc, $sigs, $sig, $verify_method,)
                });
            }

            check_one!("primary key", self.primary_selfsigs, sig,
                       verify_primary_key_binding);
            check_one!("primary key", self.primary_self_revocations, sig,
                       verify_primary_key_revocation);

            for binding in self.userids.iter_mut() {
                check_one!(format!("userid \"{}\"",
                                   String::from_utf8_lossy(
                                       binding.userid.userid())),
                           binding.selfsigs, sig,
                           verify_userid_binding, &binding.userid);
                check_one!(format!("userid \"{}\"",
                                   String::from_utf8_lossy(
                                       binding.userid.userid())),
                           binding.self_revocations, sig,
                           verify_userid_revocation, &binding.userid);
            }

            for binding in self.user_attributes.iter_mut() {
                check_one!("user attribute",
                           binding.selfsigs, sig,
                           verify_user_attribute_binding,
                           &binding.user_attribute);
                check_one!("user attribute",
                           binding.self_revocations, sig,
                           verify_user_attribute_revocation,
                           &binding.user_attribute);
            }

            for binding in self.subkeys.iter_mut() {
                check_one!(format!("subkey {}", binding.subkey.keyid()),
                           binding.selfsigs, sig,
                           verify_subkey_binding, &binding.subkey);
                check_one!(format!("subkey {}", binding.subkey.keyid()),
                           binding.self_revocations, sig,
                           verify_subkey_revocation, &binding.subkey);
            }

            // Keep them for later.
            if TRACE {
                eprintln!("Self-sig {:02X}{:02X}, {:?} doesn't belong \
                           to any known component or is bad.",
                          sig.hash_prefix()[0], sig.hash_prefix()[1],
                          sig.sigtype());
            }
            self.bad.push(sig);
        }

        if self.bad.len() > 0 && TRACE {
            eprintln!("{}: ignoring {} bad self-signatures",
                      self.primary().keyid(), self.bad.len());
        }

        // Only keep user ids / user attributes / subkeys with at
        // least one valid self-signature or self-revocation.
        self.userids.retain(|userid| {
            userid.selfsigs.len() > 0 || userid.self_revocations.len() > 0
        });

        self.user_attributes.retain(|ua| {
            ua.selfsigs.len() > 0 || ua.self_revocations.len() > 0
        });

        self.subkeys.retain(|subkey| {
            subkey.selfsigs.len() > 0 || subkey.self_revocations.len() > 0
        });

        fn sig_cmp(a: &Signature, b: &Signature) -> Ordering {
            canonical_signature_order(a.signature_creation_time(),
                                      b.signature_creation_time())
        }

        // Sort and dedup the primary key's signatures.
        self.primary_selfsigs.sort_by(sig_cmp);
        self.primary_selfsigs.dedup_by_key(sig_key);

        // There is no need to sort the certifications, but we do
        // want to remove dups and sorting is a prerequisite.
        self.primary_certifications.sort_by(sig_cmp);
        self.primary_certifications.dedup_by_key(sig_key);

        self.primary_self_revocations.sort_by(sig_cmp);
        self.primary_self_revocations.dedup_by_key(sig_key);

        self.primary_other_revocations.sort_by(sig_cmp);
        self.primary_other_revocations.dedup_by_key(sig_key);

        self.bad.sort_by(sig_cmp);
        self.bad.dedup_by_key(sig_key);


        // Sort the signatures so that the current valid
        // self-signature is first.
        for userid in &mut self.userids {
            userid.selfsigs.sort_by(sig_cmp);
            userid.selfsigs.dedup_by_key(sig_key);

            // There is no need to sort the certifications, but we do
            // want to remove dups and sorting is a prerequisite.
            userid.certifications.sort_by(sig_cmp);
            userid.certifications.dedup_by_key(sig_key);

            userid.self_revocations.sort_by(sig_cmp);
            userid.self_revocations.dedup_by_key(sig_key);

            userid.other_revocations.sort_by(sig_cmp);
            userid.other_revocations.dedup_by_key(sig_key);
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
        self.userids.sort_by(|a, b| a.userid.userid().cmp(&b.userid.userid()));

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

                b.self_revocations.append(&mut a.self_revocations);
                b.self_revocations.sort_by(sig_cmp);
                b.self_revocations.dedup_by_key(sig_key);

                b.other_revocations.append(&mut a.self_revocations);
                b.other_revocations.sort_by(sig_cmp);
                b.other_revocations.dedup_by_key(sig_key);

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
            // Compare their revocation status.  Components known be
            // revoked come last.
            let a_revoked = a.self_revocations.len() > 0;
            let b_revoked = b.self_revocations.len() > 0;

            if a_revoked && ! b_revoked {
                return Ordering::Greater;
            }
            if ! a_revoked && b_revoked {
                return Ordering::Less;
            }

            let a_selfsig = a.binding_signature();
            let b_selfsig = b.binding_signature();

            if a_revoked && b_revoked {
                // Both are revoked.

                // Sort user ids that have at least one self signature
                // towards the front.
                if a_selfsig.is_some() && b_selfsig.is_none() {
                    return Ordering::Less;
                }
                if a_selfsig.is_none() && b_selfsig.is_some() {
                    return Ordering::Greater;
                }

                // Sort by reversed revocation time (i.e., most
                // recently revoked user id first).
                let cmp = b.self_revocations[0].signature_creation_time().cmp(
                    &a.self_revocations[0].signature_creation_time());
                if cmp != Ordering::Equal {
                    return cmp;
                }

                // They were revoked at the same time.  This is
                // unlikely.  We just need to do something
                // deterministic.
            }

            // Compare their primary status.
            let a_primary =
                a_selfsig.map(|sig| sig.primary_userid()).unwrap_or(None);
            let b_primary =
                b_selfsig.map(|sig| sig.primary_userid()).unwrap_or(None);

            if a_primary.is_some() && b_primary.is_none() {
                return Ordering::Less;
            } else if a_primary.is_none() && b_primary.is_some() {
                return Ordering::Greater;
            } else if a_primary.is_some() && b_primary.is_some() {
                // Both are marked as primary.  Fallback to the date.
                let mut a_timestamp = time_zero;
                if let Some(sig) = a_selfsig {
                    if let Some(ts) = sig.signature_creation_time() {
                        a_timestamp = ts;
                    }
                }
                let mut b_timestamp = time_zero;
                if let Some(sig) = a_selfsig {
                    if let Some(ts) = sig.signature_creation_time() {
                        b_timestamp = ts;
                    }
                }

                // We want the more recent date first.
                let cmp = b_timestamp.cmp(&a_timestamp);
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }

            // Fallback to a lexicographical comparison.
            a.userid.userid().cmp(&b.userid.userid())
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

            attribute.self_revocations.sort_by(sig_cmp);
            attribute.self_revocations.dedup_by_key(sig_key);

            attribute.other_revocations.sort_by(sig_cmp);
            attribute.other_revocations.dedup_by_key(sig_key);
        }

        // Sort the user attributes in preparation for a dedup.  As
        // for the user ids, we can't do the final sort here, because
        // we rely on the self-signatures.
        self.user_attributes.sort_by(
            |a, b| a.user_attribute.user_attribute()
                .cmp(&b.user_attribute.user_attribute()));

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

                b.self_revocations.append(&mut a.self_revocations);
                b.self_revocations.sort_by(sig_cmp);
                b.self_revocations.dedup_by_key(sig_key);

                b.other_revocations.append(&mut a.self_revocations);
                b.other_revocations.sort_by(sig_cmp);
                b.other_revocations.dedup_by_key(sig_key);

                true
            } else {
                false
            }
        });

        self.user_attributes.sort_by(|a, b| {
            // Compare their revocation status.  Components known be
            // revoked come last.
            let a_revoked = a.self_revocations.len() > 0;
            let b_revoked = b.self_revocations.len() > 0;

            if a_revoked && ! b_revoked {
                return Ordering::Greater;
            }
            if ! a_revoked && b_revoked {
                return Ordering::Less;
            }

            let a_selfsig = a.binding_signature();
            let b_selfsig = b.binding_signature();

            if a_revoked && b_revoked {
                // Both are revoked.

                // Sort user attributes that have at least one self
                // signature towards the front.
                if a_selfsig.is_some() && b_selfsig.is_none() {
                    return Ordering::Less;
                }
                if a_selfsig.is_none() && b_selfsig.is_some() {
                    return Ordering::Greater;
                }

                // Sort by reversed revocation time (i.e., most
                // recently revoked user attribute first).
                let cmp = b.self_revocations[0].signature_creation_time().cmp(
                    &a.self_revocations[0].signature_creation_time());
                if cmp != Ordering::Equal {
                    return cmp;
                }

                // They were revoked at the same time.  This is
                // unlikely.  We just need to do something
                // deterministic.
            }

            // Compare their primary status.
            let a_primary =
                a_selfsig.map(|sig| sig.primary_userid()).unwrap_or(None);
            let b_primary =
                b_selfsig.map(|sig| sig.primary_userid()).unwrap_or(None);

            if a_primary.is_some() && b_primary.is_none() {
                return Ordering::Less;
            } else if a_primary.is_none() && b_primary.is_some() {
                return Ordering::Greater;
            } else if a_primary.is_some() && b_primary.is_some() {
                // Both are marked as primary.  Fallback to the date.
                let mut a_timestamp = time_zero;
                if let Some(sig) = a_selfsig {
                    if let Some(ts) = sig.signature_creation_time() {
                        a_timestamp = ts;
                    }
                }
                let mut b_timestamp = time_zero;
                if let Some(sig) = a_selfsig {
                    if let Some(ts) = sig.signature_creation_time() {
                        b_timestamp = ts;
                    }
                }

                // We want the more recent date first.
                let cmp = b_timestamp.cmp(&a_timestamp);
                if cmp != Ordering::Equal {
                    return cmp;
                }
            }

            // Fallback to a lexicographical comparison.
            a.user_attribute.user_attribute()
                .cmp(&b.user_attribute.user_attribute())
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

            subkey.self_revocations.sort_by(sig_cmp);
            subkey.self_revocations.dedup_by_key(sig_key);

            subkey.other_revocations.sort_by(sig_cmp);
            subkey.other_revocations.dedup_by_key(sig_key);
        }

        // Sort the subkeys in preparation for a dedup.  As for the
        // user ids, we can't do the final sort here, because we rely
        // on the self-signatures.
        self.subkeys.sort_by(
            |a, b| Key::public_cmp(&a.subkey, &b.subkey));

        // And, dedup them.
        //
        // If the public keys match, but only one of them has a secret
        // key, then merge the key and keep the secret key.
        self.subkeys.dedup_by(|a, b| {
            if Key::public_cmp(&a.subkey, &b.subkey) == Ordering::Equal
                && (a.subkey.secret() == b.subkey.secret()
                    || a.subkey.secret().is_none()
                    || b.subkey.secret().is_none())
            {
                // Recall: if a and b are equal, a will be dropped.
                if b.subkey.secret().is_none() && a.subkey.secret().is_some() {
                    b.subkey.set_secret(a.subkey.set_secret(None));
                }

                b.selfsigs.append(&mut a.selfsigs);
                b.selfsigs.sort_by(sig_cmp);
                b.selfsigs.dedup_by_key(sig_key);

                b.certifications.append(&mut a.certifications);
                b.certifications.sort_by(sig_cmp);
                b.certifications.dedup_by_key(sig_key);

                b.self_revocations.append(&mut a.self_revocations);
                b.self_revocations.sort_by(sig_cmp);
                b.self_revocations.dedup_by_key(sig_key);

                b.other_revocations.append(&mut a.self_revocations);
                b.other_revocations.sort_by(sig_cmp);
                b.other_revocations.dedup_by_key(sig_key);

                true
            } else {
                false
            }
        });

        self.subkeys.sort_by(|a, b| {
            // Compare their revocation status.  Components known to be
            // revoked come last.
            let a_revoked = a.self_revocations.len() > 0;
            let b_revoked = b.self_revocations.len() > 0;

            if a_revoked && ! b_revoked {
                return Ordering::Greater;
            }
            if ! a_revoked && b_revoked {
                return Ordering::Less;
            }

            let a_selfsig = a.binding_signature();
            let b_selfsig = b.binding_signature();

            if a_revoked && b_revoked {
                // Both are revoked.

                // Sort keys that have at least one self signature
                // towards the front.
                if a_selfsig.is_some() && b_selfsig.is_none() {
                    return Ordering::Less;
                }
                if a_selfsig.is_none() && b_selfsig.is_some() {
                    return Ordering::Greater;
                }

                // Sort by reversed revocation time (i.e., most
                // recently revoked key first).
                let cmp = b.self_revocations[0].signature_creation_time().cmp(
                    &a.self_revocations[0].signature_creation_time());
                if cmp != Ordering::Equal {
                    return cmp;
                }

                // They were revoked at the same time.  This is
                // unlikely.  We just need to do something
                // deterministic.
            }

            // Features.
            let a_features =
                a_selfsig.map(|sig| sig.features()).unwrap_or(Default::default());
            let b_features =
                b_selfsig.map(|sig| sig.features()).unwrap_or(Default::default());

            let cmp = a_features.as_vec().cmp(&b_features.as_vec());
            if cmp != Ordering::Equal {
                return cmp;
            }

            // Creation time (more recent first).
            let cmp = b.subkey.creation_time().cmp(&a.subkey.creation_time());
            if cmp != Ordering::Equal {
                return cmp;
            }

            // Fallback to the lexicographical comparison.
            a.subkey.mpis().cmp(&b.subkey.mpis())
        });

        // In case we have subkeys bound to the primary, it must be
        // certification capable.
        if ! self.subkeys.is_empty() {
            let pk_can_certify =
                self.primary_key_signature()
                .map(|sig| sig.key_flags().can_certify())
                .unwrap_or(true);

            if ! pk_can_certify {
                // Primary not certification capable, all binding sigs
                // are invalid.
                self.subkeys.clear();
            }
        }


        // XXX: Check if the sigs in other_sigs issuer are actually
        // designated revokers for this key (listed in a "Revocation
        // Key" subpacket in *any* non-revoked self-signature).  Only
        // if that is the case should a sig be considered a potential
        // revocation.  (This applies to
        // self.primary_other_revocations as well as
        // self.userids().other_revocations, etc.)  If not, put the
        // sig on the bad list.
        //
        // Note: just because the TPK doesn't indicate that a key is a
        // designed revoker doesn't mean that it isn't---we might just
        // be missing the signature.  In other words, this is a policy
        // decision, but given how easy it could be to create rouge
        // revocations, is probably the better to reject such
        // signatures than to keep them around and have many keys
        // being shown as "potentially revoked".

        // XXX Do some more canonicalization.

        self
    }

    /// Returns the TPK's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.primary().fingerprint()
    }

    /// Converts the TPK into a sequence of packets.
    ///
    /// This method discards an invalid components and bad signatures.
    pub fn into_packets(self) -> Vec<Packet> {
        let mut p : Vec<Packet> = Vec::new();

        p.push(Packet::PublicKey(self.primary));

        for s in self.primary_selfsigs.into_iter() {
            p.push(Packet::Signature(s));
        }
        for s in self.primary_self_revocations.into_iter() {
            p.push(Packet::Signature(s));
        }
        for s in self.primary_certifications.into_iter() {
            p.push(Packet::Signature(s));
        }
        for s in self.primary_other_revocations.into_iter() {
            p.push(Packet::Signature(s));
        }

        for u in self.userids.into_iter() {
            p.push(Packet::UserID(u.userid));
            for s in u.self_revocations.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in u.selfsigs.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in u.other_revocations.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in u.certifications.into_iter() {
                p.push(Packet::Signature(s));
            }
        }

        for u in self.user_attributes.into_iter() {
            p.push(Packet::UserAttribute(u.user_attribute));
            for s in u.self_revocations.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in u.selfsigs.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in u.other_revocations.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in u.certifications.into_iter() {
                p.push(Packet::Signature(s));
            }
        }

        let subkeys = self.subkeys;
        for k in subkeys.into_iter() {
            p.push(Packet::PublicSubkey(k.subkey));
            for s in k.self_revocations.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in k.selfsigs.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in k.other_revocations.into_iter() {
                p.push(Packet::Signature(s));
            }
            for s in k.certifications.into_iter() {
                p.push(Packet::Signature(s));
            }
        }

        p
    }

    /// Converts the TPK into a `PacketPile`.
    ///
    /// This method discards an invalid components and bad signatures.
    pub fn into_packet_pile(self) -> PacketPile {
        PacketPile::from(self.into_packets())
    }

    /// Merges `other` into `self`.
    ///
    /// If `other` is a different key, then nothing is merged into
    /// `self`, but `self` is still canonicalized.
    pub fn merge(mut self, mut other: TPK) -> Result<Self> {
        if self.primary().fingerprint() != other.primary().fingerprint() {
            // The primary key is not the same.  There is nothing to
            // do.
            return Err(Error::InvalidArgument(
                "Primary key mismatch".into()).into());
        }

        if self.primary.secret().is_none() && other.primary.secret().is_some() {
            self.primary.set_secret(other.primary.set_secret(None));
        }

        self.primary_selfsigs.append(
            &mut other.primary_selfsigs);
        self.primary_certifications.append(
            &mut other.primary_certifications);
        self.primary_self_revocations.append(
            &mut other.primary_self_revocations);
        self.primary_other_revocations.append(
            &mut other.primary_other_revocations);

        self.userids.append(&mut other.userids);
        self.user_attributes.append(&mut other.user_attributes);
        self.subkeys.append(&mut other.subkeys);
        self.bad.append(&mut other.bad);

        Ok(self.canonicalize())
    }

    /// Adds packets to the TPK.
    ///
    /// This recanonicalizes the TPK.  If the packets are invalid,
    /// they are dropped.
    pub fn merge_packets(self, mut packets: Vec<Packet>) -> Result<Self> {
        let mut combined = self.into_packets();
        combined.append(&mut packets);
        TPK::from_packet_pile(PacketPile::from(combined))
    }

    /// Cast the public key into a secret key that allows using the secret
    /// parts of the containing keys.
    pub fn into_tsk(self) -> TSK {
        TSK::from_tpk(self)
    }

    /// Cast the public key into a secret key that allows using the secret
    /// parts of the containing keys. Only packets for which `filter` returns
    /// true are included in the TSK.
    pub fn filter_into_tsk<F: Fn(&Packet) -> bool>(self, f: F) -> Result<TSK> {
        let pkts = self.into_packet_pile().into_children().filter(f).collect::<Vec<_>>();
        let pile = PacketPile::from(pkts);

        Ok(TSK::from_tpk(TPK::from_packet_pile(pile)?))
    }

    /// Returns whether at least one of the keys includes a secret
    /// part.
    pub fn is_tsk(&self) -> bool {
        if self.primary().secret().is_some() {
            return true;
        }
        self.subkeys().any(|sk| {
            sk.binding_signature().is_some() && sk.subkey().secret().is_some()
        })
    }
}

impl Serialize for TPK {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        self.primary().serialize(o, Tag::PublicKey)?;

        for s in self.primary_selfsigs.iter() {
            s.serialize(o)?;
        }
        for s in self.primary_self_revocations.iter() {
            s.serialize(o)?;
        }
        for s in self.primary_certifications.iter() {
            s.serialize(o)?;
        }
        for s in self.primary_other_revocations.iter() {
            s.serialize(o)?;
        }

        for u in self.userids.iter() {
            u.userid.serialize(o)?;
            for s in u.self_revocations() {
                s.serialize(o)?;
            }
            for s in u.selfsigs.iter() {
                s.serialize(o)?;
            }
            for s in u.other_revocations() {
                s.serialize(o)?;
            }
            for s in u.certifications.iter() {
                s.serialize(o)?;
            }
        }

        for u in self.user_attributes.iter() {
            u.user_attribute.serialize(o)?;
            for s in u.self_revocations() {
                s.serialize(o)?;
            }
            for s in u.selfsigs.iter() {
                s.serialize(o)?;
            }
            for s in u.other_revocations() {
                s.serialize(o)?;
            }
            for s in u.certifications.iter() {
                s.serialize(o)?;
            }
        }

        for k in self.subkeys.iter() {
            k.subkey.serialize(o, Tag::PublicSubkey)?;
            for s in k.self_revocations() {
                s.serialize(o)?;
            }
            for s in k.selfsigs.iter() {
                s.serialize(o)?;
            }
            for s in k.other_revocations() {
                s.serialize(o)?;
            }
            for s in k.certifications.iter() {
                s.serialize(o)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crypto::KeyPair;
    use super::*;

    use KeyID;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../tests/data/keys/", $x)) };
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
            assert_eq!(tpk.primary.creation_time().to_pgp().unwrap(), 1511355130);
            assert_eq!(tpk.userids.len(), 1);
            assert_eq!(tpk.userids[0].userid.userid(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix(),
                       &[ 0xc6, 0x8f ]);
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
            assert_eq!(tpk.primary.creation_time().to_pgp().unwrap(), 1511355130);
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(tpk.userids.len(), 1, "number of userids");
            assert_eq!(tpk.userids[0].userid.userid(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix(),
                       &[ 0xc6, 0x8f ]);

            assert_eq!(tpk.user_attributes.len(), 0);

            assert_eq!(tpk.subkeys.len(), 1, "number of subkeys");
            assert_eq!(tpk.subkeys[0].subkey.creation_time().to_pgp().unwrap(),
                       1511355130);
            assert_eq!(tpk.subkeys[0].selfsigs[0].hash_prefix(),
                       &[ 0xb7, 0xb9 ]);

            let tpk = parse_tpk(bytes!("testy-no-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(tpk.primary.creation_time().to_pgp().unwrap(), 1511355130);
            assert_eq!(tpk.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(tpk.user_attributes.len(), 0);

            assert_eq!(tpk.userids.len(), 1, "number of userids");
            assert_eq!(tpk.userids[0].userid.userid(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(tpk.userids[0].selfsigs.len(), 1);
            assert_eq!(tpk.userids[0].selfsigs[0].hash_prefix(),
                       &[ 0xc6, 0x8f ]);

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
            .map(|u| String::from_utf8_lossy(u.userid.userid()).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "Neal H. Walfield <neal@g10code.com>",
                      "Neal H. Walfield <neal@gnupg.org>",
                      "Neal H. Walfield <neal@pep-project.org>",
                      "Neal H. Walfield <neal@pep.foundation>",
                      "Neal H. Walfield <neal@sequoia-pgp.org>",
                      "Neal H. Walfield <neal@walfield.org>",
                   ]);

        let mut subkeys = tpk.subkeys()
            .map(|sk| Some(sk.subkey.keyid()))
            .collect::<Vec<Option<KeyID>>>();
        subkeys.sort();
        assert_eq!(subkeys,
                   &[ KeyID::from_hex("7223B56678E02528").ok(),
                      KeyID::from_hex("A3506AFB820ABD08").ok(),
                      KeyID::from_hex("C2B819056C652598").ok(),
                   ]);

        // DKG's key has all of the self-signatures moved to the last
        // subkey; all user ids/user attributes/subkeys have nothing.
        let tpk = TPK::from_bytes(bytes!("dkg-sigs-out-of-order.pgp")).unwrap();

        let mut userids = tpk.userids()
            .map(|u| String::from_utf8_lossy(u.userid.userid()).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "Daniel Kahn Gillmor <dkg-debian.org@fifthhorseman.net>",
                      "Daniel Kahn Gillmor <dkg@aclu.org>",
                      "Daniel Kahn Gillmor <dkg@astro.columbia.edu>",
                      "Daniel Kahn Gillmor <dkg@debian.org>",
                      "Daniel Kahn Gillmor <dkg@fifthhorseman.net>",
                      "Daniel Kahn Gillmor <dkg@openflows.com>",
                   ]);

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
                   ]);

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
        assert_match!(Error::MalformedTPK(_)
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

    #[test]
    fn merge_with_incomplete_update() {
        let tpk = TPK::from_bytes(bytes!("about-to-expire.expired.pgp"))
            .unwrap();
        assert!(tpk.primary_key_signature().unwrap()
                .key_expired(tpk.primary()));

        let update = TPK::from_bytes(bytes!("about-to-expire.update-no-uid.pgp"))
            .unwrap();
        let tpk = tpk.merge(update).unwrap();
        assert!(! tpk.primary_key_signature().unwrap()
                .key_expired(tpk.primary()));
    }

    #[test]
    fn packet_pile_roundtrip() {
        // Make sure TPK::from_packet_pile(TPK::to_packet_pile(tpk))
        // does a clean round trip.

        let tpk = TPK::from_bytes(bytes!("already-revoked.pgp")).unwrap();
        let tpk2
            = TPK::from_packet_pile(tpk.clone().into_packet_pile()).unwrap();
        assert_eq!(tpk, tpk2);

        let tpk = TPK::from_bytes(
            bytes!("already-revoked-direct-revocation.pgp")).unwrap();
        let tpk2
            = TPK::from_packet_pile(tpk.clone().into_packet_pile()).unwrap();
        assert_eq!(tpk, tpk2);

        let tpk = TPK::from_bytes(
            bytes!("already-revoked-userid-revocation.pgp")).unwrap();
        let tpk2
            = TPK::from_packet_pile(tpk.clone().into_packet_pile()).unwrap();
        assert_eq!(tpk, tpk2);

        let tpk = TPK::from_bytes(
            bytes!("already-revoked-subkey-revocation.pgp")).unwrap();
        let tpk2
            = TPK::from_packet_pile(tpk.clone().into_packet_pile()).unwrap();
        assert_eq!(tpk, tpk2);
    }

    #[test]
    fn merge_packets() {
        use armor;

        // Merge the revocation certificate into the TPK and make sure
        // it shows up.
        let tpk = TPK::from_bytes(bytes!("already-revoked.pgp")).unwrap();

        let rev = bytes!("already-revoked.rev");
        let rev = PacketPile::from_reader(armor::Reader::new(&rev[..], None))
            .unwrap();

        let rev : Vec<Packet> = rev.into_children().collect();
        assert_eq!(rev.len(), 1);
        assert_eq!(rev[0].tag(), Tag::Signature);

        let packets_pre_merge = tpk.clone().into_packets().len();
        let tpk = tpk.merge_packets(rev).unwrap();
        let packets_post_merge = tpk.clone().into_packets().len();
        assert_eq!(packets_post_merge, packets_pre_merge + 1);
    }

    #[test]
    fn set_expiry() {
        let now = time::now_utc();

        let (tsk, _) = TSK::new(Some("Test".into())).unwrap();
        let tpk = tsk.into_tpk();
        let expiry_orig = tpk.primary_key_signature().unwrap()
            .key_expiration_time()
            .expect("Keys expire by default.");

        let mut keypair = tpk.primary().clone().into_keypair().unwrap();

        // Clear the expiration.
        let tpk = tpk.set_expiry_as_of(
            &mut keypair,
            None,
            now + time::Duration::seconds(10)).unwrap();
        {
            let expiry = tpk.primary_key_signature().unwrap()
                .key_expiration_time();
            assert_eq!(expiry, None);
        }

        // Shorten the expiry.  (The default expiration should be at
        // least a few weeks, so removing an hour should still keep us
        // over 0.)
        let expiry_expected = expiry_orig - time::Duration::hours(1);
        assert!(expiry_expected > time::Duration::seconds(0));

        let tpk = tpk.set_expiry_as_of(
            &mut keypair,
            Some(expiry_expected),
            now + time::Duration::seconds(20)).unwrap();
        {
            let expiry = tpk.primary_key_signature().unwrap()
                .key_expiration_time();
            assert_eq!(expiry.unwrap(), expiry_expected);
        }
    }

    #[test]
    fn direct_key_sig() {
        use constants::SignatureType;
        // XXX: testing sequoia against itself isn't optimal, but I couldn't
        // find a tool to generate direct key signatures :-(

        let (tpk1, _) = TPKBuilder::default().generate().unwrap();
        let mut buf = Vec::default();

        tpk1.serialize(&mut buf).unwrap();
        let tpk2 = TPK::from_bytes(&buf).unwrap();

        assert_eq!(tpk2.primary_key_signature().unwrap().sigtype(), SignatureType::DirectKey);
        assert_eq!(tpk2.userids().count(), 0);
    }

    #[test]
    fn revoked() {
        fn check(tpk: &TPK, direct_revoked: bool,
                 userid_revoked: bool, subkey_revoked: bool) {
            // If we have a user id---even if it is revoked---we have
            // a primary key signature.
            let sigtype = tpk.primary_key_signature().unwrap().sigtype();
            assert_eq!(sigtype, SignatureType::PositiveCertificate,
                       "{:#?}", tpk);

            let revoked = tpk.revoked(None);
            if direct_revoked {
                assert_match!(RevocationStatus::Revoked(_) = revoked,
                              "{:#?}", tpk);
            } else {
                assert_eq!(revoked, RevocationStatus::NotAsFarAsWeKnow,
                           "{:#?}", tpk);
            }

            for userid in tpk.userids() {
                let sigtype = userid.binding_signature().unwrap().sigtype();
                assert_eq!(sigtype, SignatureType::PositiveCertificate,
                           "{:#?}", tpk);

                let revoked = userid.revoked(None);
                if userid_revoked {
                    assert_match!(RevocationStatus::Revoked(_) = revoked);
                } else {
                    assert_eq!(RevocationStatus::NotAsFarAsWeKnow, revoked,
                               "{:#?}", tpk);
                }
            }

            for subkey in tpk.subkeys() {
                let sigtype = subkey.binding_signature().unwrap().sigtype();
                assert_eq!(sigtype, SignatureType::SubkeyBinding,
                           "{:#?}", tpk);

                let revoked = subkey.revoked(None);
                if subkey_revoked {
                    assert_match!(RevocationStatus::Revoked(_) = revoked);
                } else {
                    assert_eq!(RevocationStatus::NotAsFarAsWeKnow, revoked,
                               "{:#?}", tpk);
                }
            }
        }

        let tpk = TPK::from_bytes(bytes!("already-revoked.pgp")).unwrap();
        check(&tpk, false, false, false);

        let d = TPK::from_bytes(
            bytes!("already-revoked-direct-revocation.pgp")).unwrap();
        check(&d, true, false, false);

        check(&tpk.clone().merge(d.clone()).unwrap(), true, false, false);
        // Make sure the merge order does not matter.
        check(&d.clone().merge(tpk.clone()).unwrap(), true, false, false);

        let u = TPK::from_bytes(
            bytes!("already-revoked-userid-revocation.pgp")).unwrap();
        check(&u, false, true, false);

        check(&tpk.clone().merge(u.clone()).unwrap(), false, true, false);
        check(&u.clone().merge(tpk.clone()).unwrap(), false, true, false);

        let k = TPK::from_bytes(
            bytes!("already-revoked-subkey-revocation.pgp")).unwrap();
        check(&k, false, false, true);

        check(&tpk.clone().merge(k.clone()).unwrap(), false, false, true);
        check(&k.clone().merge(tpk.clone()).unwrap(), false, false, true);

        // direct and user id revocation.
        check(&d.clone().merge(u.clone()).unwrap(), true, true, false);
        check(&u.clone().merge(d.clone()).unwrap(), true, true, false);

        // direct and subkey revocation.
        check(&d.clone().merge(k.clone()).unwrap(), true, false, true);
        check(&k.clone().merge(d.clone()).unwrap(), true, false, true);

        // user id and subkey revocation.
        check(&u.clone().merge(k.clone()).unwrap(), false, true, true);
        check(&k.clone().merge(u.clone()).unwrap(), false, true, true);

        // direct, user id and subkey revocation.
        check(&d.clone().merge(u.clone().merge(k.clone()).unwrap()).unwrap(),
              true, true, true);
        check(&d.clone().merge(k.clone().merge(u.clone()).unwrap()).unwrap(),
              true, true, true);
    }

    #[test]
    fn revoke() {
        let (tsk, _) = TSK::new(Some("Test".into())).unwrap();
        let tpk = tsk.into_tpk();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow, tpk.revoked(None));

        let mut keypair = tpk.primary().clone().into_keypair().unwrap();
        let sig = tpk.revoke(&mut keypair,
                             ReasonForRevocation::KeyCompromised,
                             b"It was the maid :/").unwrap();
        assert_eq!(sig.sigtype(), SignatureType::KeyRevocation);

        let tpk = tpk.merge_packets(vec![sig.into()]).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = tpk.revoked(None));
    }

    #[test]
    fn revoke_uid() {
        use std::{thread, time};

        let (tpk, _) = TPKBuilder::default()
            .add_userid("Test1")
            .add_userid("Test2")
            .generate().unwrap();

        thread::sleep(time::Duration::from_secs(2));
        let sig = {
            let uid = tpk.userids().skip(1).next().unwrap();
            assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revoked(None));

            let mut keypair = tpk.primary().clone().into_keypair().unwrap();
            uid.revoke(&mut keypair,
                       ReasonForRevocation::UIDRetired,
                       b"It was the maid :/").unwrap()
        };
        assert_eq!(sig.sigtype(), SignatureType::CertificateRevocation);
        let tpk = tpk.merge_packets(vec![sig.into()]).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow, tpk.revoked(None));

        let uid = tpk.userids().skip(1).next().unwrap();
        assert_match!(RevocationStatus::Revoked(_) = uid.revoked(None));
    }

    #[test]
    fn revoked_time() {
        use packet::Features;
        use packet::key::SecretKey;
        use constants::Curve;
        use rand::{thread_rng, Rng, distributions::Open01};
        /*
         * t1: 1st binding sig ctime
         * t2: rev sig ctime
         * t3: 2nd binding sig ctime
         *
         * [0,t1): invalid, but not revoked
         * [t1,t2): valid
         * [t2,t3): revoked
         * [t3,inf): valid again
         */
        let t1 = time::strptime("2000-1-1", "%F").unwrap();
        let t2 = time::strptime("2001-1-1", "%F").unwrap();
        let t3 = time::strptime("2002-1-1", "%F").unwrap();
        let key = Key::generate_ecc(true, Curve::Ed25519).unwrap();
        let (bind1, rev, bind2) = {
            let mpis = match key.secret() {
                Some(SecretKey::Unencrypted{ ref mpis }) => mpis,
                _ => unreachable!(),
            };
            let bind1 = signature::Builder::new(SignatureType::DirectKey)
                .set_features(&Features::sequoia()).unwrap()
                .set_key_flags(&KeyFlags::default()).unwrap()
                .set_signature_creation_time(t1).unwrap()
                .set_key_expiration_time(Some(time::Duration::weeks(10 * 52))).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.fingerprint().to_keyid()).unwrap()
                .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                .sign_primary_key_binding(
                    &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
                    HashAlgorithm::SHA512).unwrap();

            let rev = signature::Builder::new(SignatureType::KeyRevocation)
                .set_signature_creation_time(t2).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.fingerprint().to_keyid()).unwrap()
                .sign_primary_key_binding(
                    &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
                    HashAlgorithm::SHA512).unwrap();

            let bind2 = signature::Builder::new(SignatureType::DirectKey)
                .set_features(&Features::sequoia()).unwrap()
                .set_key_flags(&KeyFlags::default()).unwrap()
                .set_signature_creation_time(t3).unwrap()
                .set_key_expiration_time(Some(time::Duration::weeks(10 * 52))).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.fingerprint().to_keyid()).unwrap()
                .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                .sign_primary_key_binding(
                    &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
                    HashAlgorithm::SHA512).unwrap();

            (bind1, rev, bind2)
        };
        let tpk = TPK::from_packet_pile(PacketPile::from(vec![
            key.into_packet(Tag::PublicKey).unwrap(),
            bind1.into(),
            bind2.into(),
            rev.into()
        ])).unwrap();

        let f1: f32 = thread_rng().sample(Open01);
        let f2: f32 = thread_rng().sample(Open01);
        let f3: f32 = thread_rng().sample(Open01);
        let te1 = t1 - time::Duration::days((300.0 * f1) as i64);
        let t12 = t1 + time::Duration::days((300.0 * f2) as i64);
        let t23 = t2 + time::Duration::days((300.0 * f3) as i64);
        assert_eq!(tpk.revoked(te1), RevocationStatus::NotAsFarAsWeKnow);
        assert_eq!(tpk.revoked(t12), RevocationStatus::NotAsFarAsWeKnow);
        match tpk.revoked(t23) {
            RevocationStatus::Revoked(_) => {}
            _ => unreachable!(),
        }
        assert_eq!(tpk.revoked(time::now_utc()), RevocationStatus::NotAsFarAsWeKnow);
    }

    #[test]
    fn unrevoked() {
        let tpk = TPK::from_bytes(bytes!("un-revoked-userid.pgp")).unwrap();

        for uid in tpk.userids() {
            assert_eq!(uid.revoked(None), RevocationStatus::NotAsFarAsWeKnow);
        }
    }

    #[test]
    fn tsk_filter() {
        let (tpk, _) = TPKBuilder::default()
            .add_signing_subkey()
            .add_encryption_subkey()
            .generate().unwrap();

        assert!(!tpk.subkeys.is_empty());

        // filter subkeys
        let tsk = tpk.filter_into_tsk(|pkt| {
            match pkt {
                &Packet::PublicSubkey(_) | &Packet::SecretSubkey(_) => false,
                _ => true
            }
        }).unwrap();

        assert!(tsk.tpk().subkeys.is_empty());
    }

    #[test]
    fn is_tsk() {
        let tpk = TPK::from_bytes(
            bytes!("already-revoked.pgp")).unwrap();
        assert!(! tpk.is_tsk());

        let tpk = TPK::from_bytes(
            bytes!("already-revoked-private.pgp")).unwrap();
        assert!(tpk.is_tsk());
    }

    #[test]
    fn export_only_exports_public_key() {
        let tpk = TPK::from_bytes(
            bytes!("testy-new-private.pgp")).unwrap();
        assert!(tpk.is_tsk());

        let mut v = Vec::new();
        tpk.serialize(&mut v).unwrap();
        let tpk = TPK::from_bytes(&v).unwrap();
        assert!(! tpk.is_tsk());
    }

    #[test]
    fn select_no_keys() {
        let (tpk, _) = TPKBuilder::default()
            .generate().unwrap();
        let flags = KeyFlags::default().set_encrypt_for_transport(true);

        assert!(tpk.select_keys(flags, None).is_empty());
    }

    #[test]
    fn select_valid_and_right_flags() {
        let (tpk, _) = TPKBuilder::default()
            .add_encryption_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_encrypt_for_transport(true);

        assert_eq!(tpk.select_keys(flags, None).len(), 1);
    }

    #[test]
    fn select_valid_and_wrong_flags() {
        let (tpk, _) = TPKBuilder::default()
            .add_encryption_subkey()
            .add_signing_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_encrypt_for_transport(true);

        assert_eq!(tpk.select_keys(flags, None).len(), 1);
    }

    #[test]
    fn select_invalid_and_right_flags() {
        let (tpk, _) = TPKBuilder::default()
            .add_encryption_subkey()
            .generate().unwrap();
        let mut now = time::now();
        let flags = KeyFlags::default().set_encrypt_for_transport(true);

        now.tm_year -= 1;
        assert_eq!(tpk.select_keys(flags, now).len(), 0);
    }

    #[test]
    fn select_primary() {
        let (tpk, _) = TPKBuilder::default()
            .add_certification_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_certify(true);

        assert_eq!(tpk.select_keys(flags, None).len(), 2);
    }

    // Make sure that when merging two TPKs, the primary key and
    // subkeys with and without a private key are merged.
    #[test]
    fn public_private_merge() {
        let (tsk, _) = TSK::new(Some("foo@example.com".into())).unwrap();
        // tsk is now a tpk, but it still has its private bits.
        let tsk = tsk.into_tpk();
        assert!(tsk.primary.secret().is_some());
        assert!(tsk.is_tsk());
        let subkey_count = tsk.subkeys().len();
        assert!(subkey_count > 0);
        assert!(tsk.subkeys().all(|k| k.subkey.secret().is_some()));

        // This will write out the tsk as a tpk, i.e., without any
        // private bits.
        let mut tpk_bytes = Vec::new();
        tsk.serialize(&mut tpk_bytes).unwrap();

        // Reading it back in, the private bits have been stripped.
        let tpk = TPK::from_bytes(&tpk_bytes[..]).unwrap();
        assert!(tpk.primary.secret().is_none());
        assert!(!tpk.is_tsk());
        assert!(tpk.subkeys().all(|k| k.subkey.secret().is_none()));

        let merge1 = tpk.clone().merge(tsk.clone()).unwrap();
        assert!(merge1.is_tsk());
        assert!(merge1.primary.secret().is_some());
        assert_eq!(merge1.subkeys().len(), subkey_count);
        assert!(merge1.subkeys().all(|k| k.subkey.secret().is_some()));

        let merge2 = tsk.clone().merge(tpk.clone()).unwrap();
        assert!(merge2.is_tsk());
        assert!(merge2.primary.secret().is_some());
        assert_eq!(merge2.subkeys().len(), subkey_count);
        assert!(merge2.subkeys().all(|k| k.subkey.secret().is_some()));
    }

    #[test]
    fn issue_120() {
        let tpk = b"
-----BEGIN PGP ARMORED FILE-----

xcBNBFoVcvoBCACykTKOJddF8SSUAfCDHk86cNTaYnjCoy72rMgWJsrMLnz/V16B
J9M7l6nrQ0JMnH2Du02A3w+kNb5q97IZ/M6NkqOOl7uqjyRGPV+XKwt0G5mN/ovg
8630BZAYS3QzavYf3tni9aikiGH+zTFX5pynTNfYRXNBof3Xfzl92yad2bIt4ITD
NfKPvHRko/tqWbclzzEn72gGVggt1/k/0dKhfsGzNogHxg4GIQ/jR/XcqbDFR3RC
/JJjnTOUPGsC1y82Xlu8udWBVn5mlDyxkad5laUpWWg17anvczEAyx4TTOVItLSu
43iPdKHSs9vMXWYID0bg913VusZ2Ofv690nDABEBAAHNJFRlc3R5IE1jVGVzdGZh
Y2UgPHRlc3R5QGV4YW1wbGUub3JnPsLAlAQTAQgAPhYhBD6Id8h3J0aSl1GJ9dA/
b4ZSJv6LBQJaFXL6AhsDBQkDwmcABQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJ
ENA/b4ZSJv6Lxo8H/1XMt+Nqa6e0SG/up3ypKe5nplA0p/9j/s2EIsP8S8uPUd+c
WS17XOmPwkNDmHeL3J6hzwL74NlYSLEtyf7WoOV74xAKQA9WkqaKPHCtpll8aFWA
ktQDLWTPeKuUuSlobAoRtO17ZmheSQzmm7JYt4Ahkxt3agqGT05OsaAey6nIKqpq
ArokvdHTZ7AFZeSJIWmuCoT9M1lo3LAtLnRGOhBMJ5dDIeOwflJwNBXlJVi4mDPK
+fumV0MbSPvZd1/ivFjSpQyudWWtv1R1nAK7+a4CPTGxPvAQkLtRsL/V+Q7F3BJG
jAn4QVx8p4t3NOPuNgcoZpLBE3sc4Nfs5/CphMLHwE0EWhVy+gEIALSpjYD+tuWC
rj6FGP6crQjQzVlH+7axoM1ooTwiPs4fzzt2iLw3CJyDUviM5F9ZBQTei635RsAR
a/CJTSQYAEU5yXXxhoe0OtwnuvsBSvVT7Fox3pkfNTQmwMvkEbodhfKpqBbDKCL8
f5A8Bb7aISsLf0XRHWDkHVqlz8LnOR3f44wEWiTeIxLc8S1QtwX/ExyW47oPsjs9
ShCmwfSpcngH/vGBRTO7WeI54xcAtKSm/20B/MgrUl5qFo17kUWot2C6KjuZKkHk
3WZmJwQz+6rTB11w4AXt8vKkptYQCkfat2FydGpgRO5dVg6aWNJefOJNkC7MmlzC
ZrrAK8FJ6jcAEQEAAcLAdgQYAQgAIBYhBD6Id8h3J0aSl1GJ9dA/b4ZSJv6LBQJa
FXL6AhsMAAoJENA/b4ZSJv6Lt7kH/jPr5wg8lcamuLj4lydYiLttvvTtDTlD1TL+
IfwVARB/ruoerlEDr0zX1t3DCEcvJDiZfOqJbXtHt70+7NzFXrYxfaNFmikMgSQT
XqHrMQho4qpseVOeJPWGzGOcrxCdw/ZgrWbkDlAU5KaIvk+M4wFPivjbtW2Ro2/F
J4I/ZHhJlIPmM+hUErHC103b08pBENXDQlXDma7LijH5kWhyfF2Ji7Ft0EjghBaW
AeGalQHjc5kAZu5R76Mwt06MEQ/HL1pIvufTFxkr/SzIv8Ih7Kexb0IrybmfD351
Pu1xwz57O4zo1VYf6TqHJzVC3OMvMUM2hhdecMUe5x6GorNaj6g=
=1Vzu
-----END PGP ARMORED FILE-----
";
        assert!(TPK::from_bytes(tpk).is_err());
    }

    #[test]
    fn missing_uids() {
        let (tpk, _) = TPKBuilder::default()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .add_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();
        assert_eq!(tpk.subkeys().len(), 2);
        let pile = tpk
            .into_packet_pile()
            .into_children()
            .filter(|pkt| {
                match pkt {
                    &Packet::PublicKey(_) | &Packet::PublicSubkey(_) => true,
                    &Packet::Signature(ref sig) => {
                        sig.sigtype() == SignatureType::DirectKey
                            || sig.sigtype() == SignatureType::SubkeyBinding
                    }
                    e => {
                        eprintln!("{:?}", e);
                        false
                    }
                }
            })
        .collect::<Vec<_>>();
        eprintln!("parse back");
        let tpk = TPK::from_packet_pile(PacketPile::from(pile)).unwrap();

        assert_eq!(tpk.subkeys().len(), 2);
    }
}
