//! Streaming packet serialization.
//!
//! This is the preferred interface to generate OpenPGP messages.  It
//! takes advantage of OpenPGP's streaming nature to avoid unnecessary
//! buffering.  This interface provides a convenient, yet low-level
//! way to sign or encrypt.
//!
//! See the [encryption example].
//!
//! [encryption example]: struct.Encryptor.html#example

use std::fmt;
use std::io::{self, Write};
use std::time::SystemTime;

use crate::{
    crypto,
    Error,
    Fingerprint,
    HashAlgorithm,
    KeyID,
    Result,
    crypto::Password,
    crypto::SessionKey,
    packet::prelude::*,
    packet::signature,
    packet::key::{
        PublicParts,
        UnspecifiedRole,
    },
    cert::prelude::*,
};
use crate::packet::header::CTB;
use crate::packet::header::BodyLength;
use super::{
    PartialBodyFilter,
    Marshal,
    writer,
};
use crate::types::{
    AEADAlgorithm,
    CompressionAlgorithm,
    DataFormat,
    SignatureType,
    SymmetricAlgorithm,
};

/// Cookie must be public because the writers are.
#[doc(hidden)]
#[derive(Debug)]
pub struct Cookie {
    pub(crate) // For padding.rs
    level: usize,
    private: Private,
}

#[derive(Debug)]
enum Private {
    Nothing,
    Signer,
}

impl Cookie {
    pub(crate) // For padding.rs
    fn new(level: usize) -> Self {
        Cookie {
            level: level,
            private: Private::Nothing,
        }
    }
}

impl Default for Cookie {
    fn default() -> Self {
        Cookie::new(0)
    }
}

/// Streams an OpenPGP message.
///
/// Wraps a `std::io::Write`r for use with the streaming subsystem.
pub struct Message {
}

impl Message {
    /// Streams an OpenPGP message.
    pub fn new<'a, W: 'a + io::Write>(w: W) -> writer::Stack<'a, Cookie> {
        writer::Generic::new(w, Cookie::new(0))
    }
}

impl<'a> From<&'a mut dyn io::Write> for writer::Stack<'a, Cookie> {
    fn from(w: &'a mut dyn io::Write) -> Self {
        writer::Generic::new(w, Cookie::new(0))
    }
}


/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
///
/// # Example
///
/// ```
/// extern crate sequoia_openpgp as openpgp;
/// use std::io::Write;
/// use openpgp::packet::Tag;
/// use openpgp::serialize::stream::{Message, ArbitraryWriter};
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let mut o = vec![];
/// {
///     let mut w = ArbitraryWriter::new(Message::new(&mut o), Tag::Literal)?;
///     w.write_all(b"t")?;                   // type
///     w.write_all(b"\x00")?;                // filename length
///     w.write_all(b"\x00\x00\x00\x00")?;    // date
///     w.write_all(b"Hello world.")?;        // body
/// }
/// assert_eq!(b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.", o.as_slice());
/// # Ok(())
/// # }
pub struct ArbitraryWriter<'a> {
    inner: writer::BoxStack<'a, Cookie>,
}

impl<'a> ArbitraryWriter<'a> {
    /// Creates a new writer with the given tag.
    pub fn new(mut inner: writer::Stack<'a, Cookie>, tag: Tag)
               -> Result<writer::Stack<'a, Cookie>> {
        let level = inner.as_ref().cookie_ref().level + 1;
        CTB::new(tag).serialize(&mut inner)?;
        Ok(writer::Stack::from(Box::new(ArbitraryWriter {
            inner: PartialBodyFilter::new(inner, Cookie::new(level)).into()
        })))
    }
}

impl<'a> fmt::Debug for ArbitraryWriter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ArbitraryWriter")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a> Write for ArbitraryWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> writer::Stackable<'a, Cookie> for ArbitraryWriter<'a> {
    fn into_inner(self: Box<Self>) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        Box::new(self.inner).into_inner()
    }
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_mut())
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        self.inner.cookie_set(cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        self.inner.cookie_ref()
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        self.inner.cookie_mut()
    }
    fn position(&self) -> u64 {
        self.inner.position()
    }
}

/// Signs a packet stream.
///
/// For every signing key, a signer writes a one-pass-signature
/// packet, then hashes and emits the data stream, then for every key
/// writes a signature packet.
pub struct Signer<'a> {
    // The underlying writer.
    //
    // Because this writer implements `Drop`, we cannot move the inner
    // writer out of this writer.  We therefore wrap it with `Option`
    // so that we can `take()` it.
    //
    // Furthermore, the LiteralWriter will pop us off the stack, and
    // take our inner reader.  If that happens, we only update the
    // digests.
    inner: Option<writer::BoxStack<'a, Cookie>>,
    signers: Vec<Box<dyn crypto::Signer + 'a>>,
    intended_recipients: Vec<Fingerprint>,
    detached: bool,
    creation_time: Option<SystemTime>,
    hash: crypto::hash::Context,
    cookie: Cookie,
    position: u64,
}

impl<'a> Signer<'a> {
    /// Creates a signer.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate sequoia_openpgp as openpgp;
    /// use std::io::{Read, Write};
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// let p = &StandardPolicy::new();
    ///
    /// # let tsk = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])
    /// #     .unwrap();
    /// # let keypair = tsk.keys().with_policy(p, None).alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().mark_parts_secret().unwrap().into_keypair().unwrap();
    /// # f(tsk, keypair).unwrap();
    /// # fn f(cert: Cert, mut signing_keypair: KeyPair)
    /// #      -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let mut o = vec![];
    /// {
    ///     let message = Message::new(&mut o);
    ///     let signer = Signer::new(message, signing_keypair).build()?;
    ///     let mut ls = LiteralWriter::new(signer).build()?;
    ///     ls.write_all(b"Make it so, number one!")?;
    ///     ls.finalize()?;
    /// }
    ///
    /// // Now check the signature.
    /// struct Helper<'a>(&'a openpgp::Cert);
    /// impl<'a> VerificationHelper for Helper<'a> {
    ///     fn get_public_keys(&mut self, _: &[openpgp::KeyHandle])
    ///                        -> openpgp::Result<Vec<openpgp::Cert>> {
    ///         Ok(vec![self.0.clone()])
    ///     }
    ///
    ///     fn check(&mut self, structure: MessageStructure)
    ///              -> openpgp::Result<()> {
    ///         if let MessageLayer::SignatureGroup { ref results } =
    ///             structure.iter().nth(0).unwrap()
    ///         {
    ///             results.get(0).unwrap().as_ref().unwrap();
    ///             Ok(())
    ///         } else { panic!() }
    ///     }
    /// }
    ///
    /// let mut verifier = Verifier::from_bytes(p, &o, Helper(&cert), None)?;
    ///
    /// let mut message = String::new();
    /// verifier.read_to_string(&mut message)?;
    /// assert_eq!(&message, "Make it so, number one!");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<S>(inner: writer::Stack<'a, Cookie>, signer: S) -> Self
        where S: crypto::Signer + 'a
    {
        let inner = writer::BoxStack::from(inner);
        let level = inner.cookie_ref().level + 1;
        Signer {
            inner: Some(inner),
            signers: vec![Box::new(signer)],
            intended_recipients: Vec::new(),
            detached: false,
            creation_time: None,
            hash: HashAlgorithm::default().context().unwrap(),
            cookie: Cookie {
                level: level,
                private: Private::Signer,
            },
            position: 0,
        }
    }

    /// Sets the hash algorithm to use for the signatures.
    pub fn hash_algo(mut self, algo: HashAlgorithm) -> Result<Self> {
        self.hash = algo.context()?;
        Ok(self)
    }

    /// Adds an additional signer.
    pub fn add_signer<S>(mut self, signer: S) -> Self
        where S: crypto::Signer + 'a
    {
        self.signers.push(Box::new(signer));
        self
    }

    /// Adds an intended recipient.
    ///
    /// This signer emits signatures indicating the intended
    /// recipients of the encryption container containing the
    /// signature.  This prevents forwarding a signed message using a
    /// different encryption context.
    pub fn add_intended_recipient(mut self, recipient: &Cert) -> Self {
        self.intended_recipients.push(recipient.fingerprint());
        self
    }

    /// Creates a signer for a detached signature.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate sequoia_openpgp as openpgp;
    /// use std::io::{Read, Write};
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// use sequoia_openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let tsk = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])
    /// #     .unwrap();
    /// # let keypair
    /// #     = tsk.keys().with_policy(p, None).alive().revoked(false).for_signing()
    /// #           .nth(0).unwrap()
    /// #           .key().clone().mark_parts_secret().unwrap().into_keypair()
    /// #           .unwrap();
    /// # f(tsk, keypair).unwrap();
    /// # fn f(cert: Cert, mut signing_keypair: KeyPair)
    /// #      -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let mut o = vec![];
    /// {
    ///     let message = Message::new(&mut o);
    ///     let mut signer =
    ///         Signer::new(message, signing_keypair).detached().build()?;
    ///     signer.write_all(b"Make it so, number one!")?;
    ///     // In reality, just io::copy() the file to be signed.
    ///     signer.finalize()?;
    /// }
    ///
    /// // Now check the signature.
    /// struct Helper<'a>(&'a openpgp::Cert);
    /// impl<'a> VerificationHelper for Helper<'a> {
    ///     fn get_public_keys(&mut self, _: &[openpgp::KeyHandle])
    ///                        -> openpgp::Result<Vec<openpgp::Cert>> {
    ///         Ok(vec![self.0.clone()])
    ///     }
    ///
    ///     fn check(&mut self, structure: MessageStructure)
    ///              -> openpgp::Result<()> {
    ///         if let MessageLayer::SignatureGroup { ref results } =
    ///             structure.iter().nth(0).unwrap()
    ///         {
    ///             results.get(0).unwrap().as_ref().unwrap();
    ///             Ok(())
    ///         } else { panic!() }
    ///     }
    /// }
    ///
    /// let mut verifier =
    ///     DetachedVerifier::from_bytes(p, &o, b"Make it so, number one!",
    ///                                  Helper(&cert), None)?;
    ///
    /// let mut message = String::new();
    /// verifier.read_to_string(&mut message)?;
    /// assert_eq!(&message, "Make it so, number one!");
    /// # Ok(())
    /// # }
    /// ```
    pub fn detached(mut self) -> Self {
        self.detached = true;
        self
    }

    /// Sets the signature's creation time to `time`.
    ///
    /// Note: it is up to the caller to make sure the signing keys are
    /// actually valid as of `time`.
    pub fn creation_time(mut self, creation_time: SystemTime) -> Self {
        self.creation_time = Some(creation_time);
        self
    }

    /// Finalizes the signer, returning the writer stack.
    pub fn build(mut self) -> Result<writer::Stack<'a, Cookie>>
    {
        assert!(self.signers.len() > 0, "The constructor adds a signer.");
        assert!(self.inner.is_some(), "The constructor adds an inner writer.");

        if ! self.detached {
            // For every key we collected, build and emit a one pass
            // signature packet.
            for (i, keypair) in self.signers.iter().enumerate() {
                let key = keypair.public();
                let mut ops = OnePassSig3::new(SignatureType::Binary);
                ops.set_pk_algo(key.pk_algo());
                ops.set_hash_algo(self.hash.algo());
                ops.set_issuer(key.keyid());
                ops.set_last(i == self.signers.len() - 1);
                Packet::OnePassSig(ops.into())
                    .serialize(self.inner.as_mut().unwrap())?;
            }
        }

        Ok(writer::Stack::from(Box::new(self)))
    }

    fn emit_signatures(&mut self) -> Result<()> {
        if let Some(ref mut sink) = self.inner {
            // Emit the signatures in reverse, so that the
            // one-pass-signature and signature packets "bracket" the
            // message.
            for signer in self.signers.iter_mut() {
                // Part of the signature packet is hashed in,
                // therefore we need to clone the hash.
                let hash = self.hash.clone();

                // Make and hash a signature packet.
                let mut sig = signature::Builder::new(SignatureType::Binary)
                    .set_signature_creation_time(
                        self.creation_time
                            .unwrap_or_else(SystemTime::now))?
                    .set_issuer_fingerprint(signer.public().fingerprint())?
                    // GnuPG up to (and including) 2.2.8 requires the
                    // Issuer subpacket to be present.
                    .set_issuer(signer.public().keyid())?;

                if ! self.intended_recipients.is_empty() {
                    sig = sig.set_intended_recipients(
                        self.intended_recipients.clone())?;
                }

                // Compute the signature.
                let sig = sig.sign_hash(signer.as_mut(), hash)?;

                // And emit the packet.
                Packet::Signature(sig).serialize(sink)?;
            }
        }
        Ok(())
    }
}

impl<'a> Drop for Signer<'a> {
    fn drop(&mut self) {
        let _ = self.emit_signatures();
    }
}

impl<'a> fmt::Debug for Signer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Signer")
            .field("inner", &self.inner)
            .field("cookie", &self.cookie)
            .finish()
    }
}

impl<'a> Write for Signer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = match self.inner.as_mut() {
            // If we are creating a normal signature, pass data
            // through.
            Some(ref mut w) if ! self.detached => w.write(buf),
            // If we are creating a detached signature, just hash all
            // bytes.
            Some(_) => Ok(buf.len()),
            // When we are popped off the stack, we have no inner
            // writer.  Just hash all bytes.
            None => Ok(buf.len()),
        };

        if let Ok(amount) = written {
            self.hash.update(&buf[..amount]);
            self.position += amount as u64;
        }

        written
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(ref mut w) => w.flush(),
            // When we are popped off the stack, we have no inner
            // writer.  Just do nothing.
            None => Ok(()),
        }
    }
}

impl<'a> writer::Stackable<'a, Cookie> for Signer<'a> {
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        Ok(self.inner.take())
    }
    fn mount(&mut self, new: writer::BoxStack<'a, Cookie>) {
        self.inner = Some(new);
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        self.inner.as_ref().map(|r| r.as_ref())
    }
    fn into_inner(mut self: Box<Self>)
                  -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        self.emit_signatures()?;
        Ok(self.inner.take())
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        ::std::mem::replace(&mut self.cookie, cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        &self.cookie
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        &mut self.cookie
    }
    fn position(&self) -> u64 {
        self.position
    }
}


/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
///
/// # Example
///
/// ```
/// extern crate sequoia_openpgp as openpgp;
/// use std::io::Write;
/// use openpgp::serialize::stream::{Message, LiteralWriter};
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
///
/// let mut o = vec![];
/// {
///     let message = Message::new(&mut o);
///     let mut w = LiteralWriter::new(message).build()?;
///     w.write_all(b"Hello world.")?;
///     w.finalize()?;
/// }
/// assert_eq!(b"\xcb\x12b\x00\x00\x00\x00\x00Hello world.", o.as_slice());
/// # Ok(())
/// # }
/// ```
pub struct LiteralWriter<'a> {
    template: Literal,
    inner: writer::BoxStack<'a, Cookie>,
    signature_writer: Option<writer::BoxStack<'a, Cookie>>,
}

impl<'a> LiteralWriter<'a> {
    /// Creates a new literal writer.
    pub fn new(inner: writer::Stack<'a, Cookie>) -> Self {
        LiteralWriter {
            template: Literal::new(DataFormat::default()),
            inner: writer::BoxStack::from(inner),
            signature_writer: None,
        }
    }

    /// Sets the data format.
    pub fn format(mut self, format: DataFormat) -> Self {
        self.template.set_format(format);
        self
    }

    /// Sets the filename.
    ///
    /// The standard does not specify the encoding.  Filenames must
    /// not be longer than 255 bytes.
    pub fn filename<B: AsRef<[u8]>>(mut self, filename: B) -> Result<Self> {
        self.template.set_filename(filename.as_ref())?;
        Ok(self)
    }

    /// Sets the data format.
    pub fn date(mut self, timestamp: SystemTime) -> Result<Self>
    {
        self.template.set_date(Some(timestamp))?;
        Ok(self)
    }

    /// Finalizes the literal writer, returning the writer stack.
    ///
    /// `format`, `filename`, and `date` will be emitted as part of
    /// the literal packets headers.  Note that these headers will not
    /// be authenticated by signatures (but will be authenticated by a
    /// SEIP/MDC container), and are therefore unreliable and should
    /// not be trusted.
    pub fn build(mut self) -> Result<writer::Stack<'a, Cookie>> {
        let level = self.inner.cookie_ref().level + 1;

        // For historical reasons, signatures over literal data
        // packets only include the body without metadata or framing.
        // Therefore, we check whether the writer is a
        // Signer, and if so, we pop it off the stack and
        // store it in 'self.signature_writer'.
        let signer_above =
            if let &Cookie {
                private: Private::Signer{..},
                ..
            } = self.inner.cookie_ref() {
                true
            } else {
                false
            };

        if signer_above {
            let stack = self.inner.pop()?;
            // We know a signer has an inner stackable.
            let stack = stack.unwrap();
            self.signature_writer = Some(self.inner);
            self.inner = stack;
        }

        // Not hashed by the signature_writer (see above).
        CTB::new(Tag::Literal).serialize(&mut self.inner)?;

        // Neither is any framing added by the PartialBodyFilter.
        self.inner
            = PartialBodyFilter::new(writer::Stack::from(self.inner),
                                     Cookie::new(level)).into();

        // Nor the headers.
        self.template.serialize_headers(&mut self.inner, false)?;

        Ok(writer::Stack::from(Box::new(self)))
    }
}

impl<'a> fmt::Debug for LiteralWriter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LiteralWriter")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a> Write for LiteralWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf);

        // Any successful written bytes needs to be hashed too.
        if let (&Ok(ref amount), &mut Some(ref mut sig))
            = (&written, &mut self.signature_writer) {
                sig.write_all(&buf[..*amount])?;
            };
        written
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> writer::Stackable<'a, Cookie> for LiteralWriter<'a> {
    fn into_inner(mut self: Box<Self>)
                  -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        let signer = self.signature_writer.take();
        let stack = self.inner
            .into_inner()?.unwrap(); // Peel off the PartialBodyFilter.

        if let Some(mut signer) = signer {
            // We stashed away a Signer.  Reattach it to the
            // stack and return it.
            signer.mount(stack);
            Ok(Some(signer))
        } else {
            Ok(Some(stack))
        }
    }

    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_mut())
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        self.inner.cookie_set(cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        self.inner.cookie_ref()
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        self.inner.cookie_mut()
    }
    fn position(&self) -> u64 {
        self.inner.position()
    }
}

/// Compresses a packet stream.
///
/// Writes a compressed data packet containing all packets written to
/// this writer.
///
/// # Example
///
/// ```
/// extern crate sequoia_openpgp as openpgp;
/// use std::io::Write;
/// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
/// use openpgp::types::CompressionAlgorithm;
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
///
/// let mut o = vec![];
/// {
///     let message = Message::new(&mut o);
///     let w = Compressor::new(message)
///         .algo(CompressionAlgorithm::Uncompressed).build()?;
///     let mut w = LiteralWriter::new(w).build()?;
///     w.write_all(b"Hello world.")?;
///     w.finalize()?;
/// }
/// assert_eq!(b"\xc8\x15\x00\xcb\x12b\x00\x00\x00\x00\x00Hello world.",
///            o.as_slice());
/// # Ok(())
/// # }
pub struct Compressor<'a> {
    algo: CompressionAlgorithm,
    level: writer::CompressionLevel,
    inner: writer::BoxStack<'a, Cookie>,
}

impl<'a> Compressor<'a> {
    /// Creates a new compressor using the given algorithm.
    ///
    /// Passing `None` to `compression_level` selects the default
    /// compression level.
    pub fn new(inner: writer::Stack<'a, Cookie>) -> Self {
        Self {
            algo: Default::default(),
            level: Default::default(),
            inner: inner.into(),
        }
    }

    /// Sets the compression algorithm.
    pub fn algo(mut self, algo: CompressionAlgorithm) -> Self {
        self.algo = algo;
        self
    }

    /// Sets the compression level.
    pub fn level(mut self, level: writer::CompressionLevel) -> Self {
        self.level = level;
        self
    }

    /// Finalizes the literal writer, returning the writer stack.
    ///
    /// `format`, `filename`, and `date` will be emitted as part of
    /// the literal packets headers.  Note that these headers will not
    /// be authenticated by signatures (but will be authenticated by a
    /// SEIP/MDC container), and are therefore unreliable and should
    /// not be trusted.
    pub fn build(mut self) -> Result<writer::Stack<'a, Cookie>> {
        let level = self.inner.cookie_ref().level + 1;

        // Packet header.
        CTB::new(Tag::CompressedData).serialize(&mut self.inner)?;
        let inner: writer::Stack<'a, Cookie>
            = PartialBodyFilter::new(writer::Stack::from(self.inner),
                                     Cookie::new(level));

        Self::new_naked(inner, self.algo, self.level, level)
    }


    /// Creates a new compressor using the given algorithm.
    pub(crate) // For CompressedData::serialize.
    fn new_naked(mut inner: writer::Stack<'a, Cookie>,
                 algo: CompressionAlgorithm,
                 compression_level: writer::CompressionLevel,
                 level: usize)
                 -> Result<writer::Stack<'a, Cookie>>
    {
        // Compressed data header.
        inner.as_mut().write_u8(algo.into())?;

        // Create an appropriate filter.
        let inner: writer::Stack<'a, Cookie> = match algo {
            CompressionAlgorithm::Uncompressed => {
                // Avoid warning about unused value if compiled
                // without any compression support.
                let _ = compression_level;
                writer::Identity::new(inner, Cookie::new(level))
            },
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zip =>
                writer::ZIP::new(inner, Cookie::new(level), compression_level),
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zlib =>
                writer::ZLIB::new(inner, Cookie::new(level), compression_level),
            #[cfg(feature = "compression-bzip2")]
            CompressionAlgorithm::BZip2 =>
                writer::BZ::new(inner, Cookie::new(level), compression_level),
            a =>
                return Err(Error::UnsupportedCompressionAlgorithm(a).into()),
        };

        Ok(writer::Stack::from(Box::new(Self {
            algo,
            level: compression_level,
            inner: inner.into(),
        })))
    }
}

impl<'a> fmt::Debug for Compressor<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Compressor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a> io::Write for Compressor<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> writer::Stackable<'a, Cookie> for Compressor<'a> {
    fn into_inner(self: Box<Self>) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        Box::new(self.inner).into_inner()?.unwrap().into_inner()
    }
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_mut())
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        self.inner.cookie_set(cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        self.inner.cookie_ref()
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        self.inner.cookie_mut()
    }
    fn position(&self) -> u64 {
        self.inner.position()
    }
}

/// A recipient of an encrypted message.
#[derive(Debug)]
pub struct Recipient<'a> {
    keyid: KeyID,
    key: &'a Key<PublicParts, UnspecifiedRole>,
}

impl<'a> From<&'a Key<PublicParts, UnspecifiedRole>> for Recipient<'a> {
    fn from(key: &'a Key<PublicParts, UnspecifiedRole>) -> Self {
        Self::new(key.keyid(), key)
    }
}

impl<'a> Recipient<'a> {
    /// Creates a new recipient with an explicit recipient keyid.
    pub fn new<P, R>(keyid: KeyID, key: &'a Key<P, R>) -> Recipient<'a>
        where P: key::KeyParts,
              R: key::KeyRole,
    {
        Recipient {
            keyid,
            key: key.mark_parts_public_ref().mark_role_unspecified_ref(),
        }
    }

    /// Gets the KeyID.
    pub fn keyid(&self) -> &KeyID {
        &self.keyid
    }

    /// Sets the KeyID.
    pub fn set_keyid(&mut self, keyid: KeyID) -> KeyID {
        std::mem::replace(&mut self.keyid, keyid)
    }
}

/// Encrypts a packet stream.
pub struct Encryptor<'a> {
    inner: Option<writer::BoxStack<'a, Cookie>>,
    recipients: Vec<Recipient<'a>>,
    passwords: Vec<Password>,
    sym_algo: SymmetricAlgorithm,
    aead_algo: Option<AEADAlgorithm>,
    hash: crypto::hash::Context,
    cookie: Cookie,
}

impl<'a> Encryptor<'a> {
    /// Creates a new encryptor.
    ///
    /// The stream will be encrypted using a generated session key,
    /// which will be encrypted using the given passwords, and all
    /// encryption-capable subkeys of the given Certs.
    ///
    /// Unless otherwise specified, the stream is encrypted using
    /// AES256.  If `aead_algo` is `None`, a `SEIP` packet is emitted,
    /// otherwise the given AEAD algorithm is used.
    ///
    /// Key preferences of the recipients are not honored.
    ///
    /// # Example
    ///
    /// ```
    /// use std::io::Write;
    /// extern crate sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::types::KeyFlags;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::Result;
    /// # use openpgp::parse::Parse;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      mQENBFpxtsABCADZcBa1Q3ZLZnju18o0+t8LoQuIIeyeUQ0H45y6xUqyrD5HSkVM
    /// #    VGQs6IHLq70mAizBJ4VznUVqVOh/NhOlapXi6/TKpjHvttdg45o6Pgqa0Kx64luT
    /// #    ZY+TEKyILcdBdhr3CzsEILnQst5jadgMvU9fnT/EkJIvxtWPlUzU5R7nnALO626x
    /// #    2M5Pj3k0h3ZNHMmYQQtReX/RP/xUh2SfOYG6i/MCclIlee8BXHB9k0bW2NAX2W7H
    /// #    rLDGPm1LzmyqxFGDvDvfPlYZ5nN2cbGsv3w75LDzv75kMhVnkZsrUjnHjVRzFq7q
    /// #    fSIpxlvJMEMKSIJ/TFztQoOBO5OlBb5qzYPpABEBAAG0F+G8iM+BzrnPg8+Ezr/P
    /// #    hM6tzrvOt8+CiQFUBBMBCAA+FiEEfcpYtU6xQxad3uFfJH9tq8hJFP4FAlpxtsAC
    /// #    GwMFCQPCZwAFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQJH9tq8hJFP49hgf+
    /// #    IKvec0RkD9EHSLFc6AKDm/knaI4AIH0isZTz9jRCF8H/j3h8QVUE+/0jtCcyvR6F
    /// #    TGVSfO3pelDPYGIjDFI3aA6H/UlhZWzYRXZ+QQRrV0zwvLna3XjiW8ib3Ky+5bpQ
    /// #    0uVeee30u+U3SnaCL9QB4+UvwVvAxRuk49Z0Q8TsRrQyQNYpeZDN7uNrvA134cf6
    /// #    6pLUvzPG4lMLIvSXFuHou704EhT7NS3wAzFtjMrsLLieVqtbEi/kBaJTQSZQwjVB
    /// #    sE/Z8lp1heKw/33Br3cB63n4cTf0FdoFywDBhCAMU7fKboU5xBpm5bQJ4ck6j6w+
    /// #    BKG1FiQRR6PCUeb6GjxVOrkBDQRacbbAAQgAw538MMb/pRdpt7PTgBCedw+rU9fh
    /// #    onZYKwmCO7wz5VrVf8zIVvWKxhX6fBTSAy8mxaYbeL/3woQ9Leuo8f0PQNs9zw1N
    /// #    mdH+cnm2KQmL9l7/HQKMLgEAu/0C/q7ii/j8OMYitaMUyrwy+OzW3nCal/uJHIfj
    /// #    bdKx29MbKgF/zaBs8mhTvf/Tu0rIVNDPEicwijDEolGSGebZxdGdHJA31uayMHDK
    /// #    /mwySJViMZ8b+Lzc/dRgNbQoY6yjsjso7U9OZpQK1fooHOSQS6iLsSSsZLcGPD+7
    /// #    m7j3jwq68SIJPMsu0O8hdjFWL4Cfj815CwptAxRGkp00CIusAabO7m8DzwARAQAB
    /// #    iQE2BBgBCAAgFiEEfcpYtU6xQxad3uFfJH9tq8hJFP4FAlpxtsACGwwACgkQJH9t
    /// #    q8hJFP5rmQgAoYOUXolTiQmWipJTdMG/VZ5X7mL8JiBWAQ11K1o01cZCMlziyHnJ
    /// #    xJ6Mqjb6wAFpYBtqysJG/vfjc/XEoKgfFs7+zcuEnt41xJQ6tl/L0VTxs+tEwjZu
    /// #    Rp/owB9GCkqN9+xNEnlH77TLW1UisW+l0F8CJ2WFOj4lk9rcXcLlEdGmXfWIlVCb
    /// #    2/o0DD+HDNsF8nWHpDEy0mcajkgIUTvXQaDXKbccX6Wgep8dyBP7YucGmRPd9Z6H
    /// #    bGeT3KvlJlH5kthQ9shsmT14gYwGMR6rKpNUXmlpetkjqUK7pGVaHGgJWUZ9QPGU
    /// #    awwPdWWvZSyXJAPZ9lC5sTKwMJDwIxILug==
    /// #    =lAie
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// ).unwrap();
    ///
    /// // Build a vector of recipients to hand to Encryptor.
    /// let recipient =
    ///     cert.keys().with_policy(p, None).alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption()
    ///     .map(|ka| ka.key().into())
    ///     .nth(0).unwrap();
    ///
    /// let mut o = vec![];
    /// let message = Message::new(&mut o);
    /// let encryptor =
    ///     Encryptor::for_recipient(message, recipient)
    ///         .build().expect("Failed to create encryptor");
    /// let mut w = LiteralWriter::new(encryptor).build()?;
    /// w.write_all(b"Hello world.")?;
    /// w.finalize()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn for_recipient(inner: writer::Stack<'a, Cookie>,
                         recipient: Recipient<'a>) -> Self {
        Self {
            inner: Some(inner.into()),
            recipients: vec![recipient],
            passwords: Vec::new(),
            sym_algo: Default::default(),
            aead_algo: Default::default(),
            hash: HashAlgorithm::SHA1.context().unwrap(),
            cookie: Default::default(), // Will be fixed in build.
        }
    }

    /// Creates a new encryptor.
    ///
    /// The stream will be encrypted using a generated session key,
    /// which will be encrypted using the given passwords, and all
    /// encryption-capable subkeys of the given Certs.
    ///
    /// Unless otherwise specified, the stream is encrypted using
    /// AES256.  If `aead_algo` is `None`, a `SEIP` packet is emitted,
    /// otherwise the given AEAD algorithm is used.
    ///
    /// Key preferences of the recipients are not honored.
    ///
    /// # Example
    ///
    /// ```
    /// use std::io::Write;
    /// extern crate sequoia_openpgp as openpgp;
    /// use openpgp::types::KeyFlags;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    /// # use openpgp::Result;
    /// # use openpgp::parse::Parse;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let mut o = vec![];
    /// let message = Message::new(&mut o);
    /// let encryptor =
    ///     Encryptor::with_password(message, "совершенно секретно".into())
    ///         .build().expect("Failed to create encryptor");
    /// let mut w = LiteralWriter::new(encryptor).build()?;
    /// w.write_all(b"Hello world.")?;
    /// w.finalize()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_password(inner: writer::Stack<'a, Cookie>,
                         password: Password) -> Self {
        Self {
            inner: Some(inner.into()),
            recipients: Vec::new(),
            passwords: vec![password],
            sym_algo: Default::default(),
            aead_algo: Default::default(),
            hash: HashAlgorithm::SHA1.context().unwrap(),
            cookie: Default::default(), // Will be fixed in build.
        }
    }

    /// Adds a recipient.
    pub fn add_recipient(mut self, recipient: Recipient<'a>) -> Self {
        self.recipients.push(recipient);
        self
    }

    /// Adds a password.
    pub fn add_password(mut self, password: Password) -> Self {
        self.passwords.push(password);
        self
    }

    /// Sets the symmetric algorithm to use.
    pub fn sym_algo(mut self, algo: SymmetricAlgorithm) -> Self {
        self.sym_algo = algo;
        self
    }

    /// Enables AEAD and sets the AEAD algorithm to use.
    ///
    /// This feature is [experimental](../../index.html#experimental-features).
    pub fn aead_algo(mut self, algo: AEADAlgorithm) -> Self {
        self.aead_algo = Some(algo);
        self
    }

    // The default chunk size.
    //
    // A page, 3 per mille overhead.
    const AEAD_CHUNK_SIZE : usize = 4096;

    /// Finalizes the encryptor, returning the writer stack.
    pub fn build(mut self) -> Result<writer::Stack<'a, Cookie>> {
        assert!(self.recipients.len() + self.passwords.len() > 0,
                "The constructors add at least one recipient or password");

        struct AEADParameters {
            algo: AEADAlgorithm,
            chunk_size: usize,
            nonce: Box<[u8]>,
        }

        let aead = if let Some(algo) = self.aead_algo {
            let mut nonce = vec![0; algo.iv_size()?];
            crypto::random(&mut nonce);
            Some(AEADParameters {
                algo: algo,
                chunk_size: Self::AEAD_CHUNK_SIZE,
                nonce: nonce.into_boxed_slice(),
            })
        } else {
            None
        };

        let mut inner = self.inner.take().expect("Added in constructors");
        let level = inner.as_ref().cookie_ref().level + 1;

        // Generate a session key.
        let sk = SessionKey::new(self.sym_algo.key_size()?);

        // Write the PKESK packet(s).
        for recipient in self.recipients.iter() {
            let mut pkesk =
                PKESK3::for_recipient(self.sym_algo, &sk, recipient.key)?;
            pkesk.set_recipient(recipient.keyid.clone());
            Packet::PKESK(pkesk.into()).serialize(&mut inner)?;
        }

        // Write the SKESK packet(s).
        for password in self.passwords.iter() {
            if let Some(aead) = aead.as_ref() {
                let skesk = SKESK5::with_password(self.sym_algo, aead.algo,
                                                  Default::default(),
                                                  &sk, password).unwrap();
                Packet::SKESK(skesk.into()).serialize(&mut inner)?;
            } else {
                let skesk = SKESK4::with_password(self.sym_algo,
                                                  Default::default(),
                                                  &sk, password).unwrap();
                Packet::SKESK(skesk.into()).serialize(&mut inner)?;
            }
        }

        if let Some(aead) = aead {
            // Write the AED packet.
            CTB::new(Tag::AED).serialize(&mut inner)?;
            let mut inner = PartialBodyFilter::new(writer::Stack::from(inner),
                                                   Cookie::new(level));
            let aed = AED1::new(self.sym_algo, aead.algo, aead.chunk_size, aead.nonce)?;
            aed.serialize_headers(&mut inner)?;

            writer::AEADEncryptor::new(
                inner.into(),
                Cookie::new(level),
                aed.symmetric_algo(),
                aed.aead(),
                aed.chunk_size(),
                aed.iv(),
                &sk,
            )
        } else {
            // Write the SEIP packet.
            CTB::new(Tag::SEIP).serialize(&mut inner)?;
            let mut inner = PartialBodyFilter::new(writer::Stack::from(inner),
                                                   Cookie::new(level));
            inner.write_all(&[1])?; // Version.

            // Install encryptor.
            self.inner = Some(writer::Encryptor::new(
                inner.into(),
                Cookie::new(level),
                self.sym_algo,
                &sk,
            )?.into());
            self.cookie = Cookie::new(level);

            // Write the initialization vector, and the quick-check
            // bytes.  The hash for the MDC must include the
            // initialization vector, hence we must write this to
            // self after installing the encryptor at self.inner.
            let mut iv = vec![0; self.sym_algo.block_size()?];
            crypto::random(&mut iv);
            self.write_all(&iv)?;
            self.write_all(&iv[iv.len() - 2..])?;

            Ok(writer::Stack::from(Box::new(self)))
        }
    }

    /// Emits the MDC packet and recovers the original writer.
    fn emit_mdc(&mut self) -> Result<writer::BoxStack<'a, Cookie>> {
        if let Some(mut w) = self.inner.take() {
            // Write the MDC, which must be the last packet inside the
            // encrypted packet stream.  The hash includes the MDC's
            // CTB and length octet.
            let mut header = Vec::new();
            CTB::new(Tag::MDC).serialize(&mut header)?;
            BodyLength::Full(20).serialize(&mut header)?;

            self.hash.update(&header);
            Packet::MDC(MDC::from(self.hash.clone())).serialize(&mut w)?;

            // Now recover the original writer.  First, strip the
            // Encryptor.
            let w = w.into_inner()?.unwrap();
            // And the partial body filter.
            let w = w.into_inner()?.unwrap();

            Ok(w)
        } else {
            Err(Error::InvalidOperation(
                "Inner writer already taken".into()).into())
        }
    }
}

impl<'a> Drop for Encryptor<'a> {
    fn drop(&mut self) {
        let _ = self.emit_mdc();
    }
}

impl<'a> fmt::Debug for Encryptor<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a> Write for Encryptor<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = match self.inner.as_mut() {
            Some(ref mut w) => w.write(buf),
            None => Ok(buf.len()),
        };
        if let Ok(amount) = written {
            self.hash.update(&buf[..amount]);
        }
        written
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(ref mut w) => w.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> writer::Stackable<'a, Cookie> for Encryptor<'a> {
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        self.inner.as_ref().map(|r| r.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn into_inner(mut self: Box<Self>) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        Ok(Some(self.emit_mdc()?))
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        ::std::mem::replace(&mut self.cookie, cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        &self.cookie
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        &mut self.cookie
    }
    fn position(&self) -> u64 {
        self.inner.as_ref().map(|i| i.position()).unwrap_or(0)
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use crate::{Packet, PacketPile, packet::CompressedData};
    use crate::parse::{Parse, PacketParserResult, PacketParser};
    use super::*;
    use crate::types::DataFormat::Text as T;
    use crate::policy::Policy;
    use crate::policy::StandardPolicy as P;

    #[test]
    fn arbitrary() {
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let mut ustr = ArbitraryWriter::new(m, Tag::Literal).unwrap();
            ustr.write_all(b"t").unwrap(); // type
            ustr.write_all(b"\x00").unwrap(); // fn length
            ustr.write_all(b"\x00\x00\x00\x00").unwrap(); // date
            ustr.write_all(b"Hello world.").unwrap(); // body
        }

        let mut pp = PacketParser::from_bytes(&o).unwrap().unwrap();
        if let Packet::Literal(ref l) = pp.packet {
                assert_eq!(l.format(), DataFormat::Text);
                assert_eq!(l.filename(), None);
                assert_eq!(l.date(), None);
        } else {
            panic!("Unexpected packet type.");
        }

        let mut body = vec![];
        pp.read_to_end(&mut body).unwrap();
        assert_eq!(&body, b"Hello world.");

        // Make sure it is the only packet.
        let (_, ppr) = pp.recurse().unwrap();
        assert!(ppr.is_none());
    }

    // Create some crazy nesting structures, serialize the messages,
    // reparse them, and make sure we get the same result.
    #[test]
    fn stream_0() {
        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "one (3 bytes)" })
        //  2: Literal(Literal { body: "two (3 bytes)" })
        // 2: Literal(Literal { body: "three (5 bytes)" })
        let mut one = Literal::new(T);
        one.set_body(b"one".to_vec());
        let mut two = Literal::new(T);
        two.set_body(b"two".to_vec());
        let mut three = Literal::new(T);
        three.set_body(b"three".to_vec());
        let mut reference = Vec::new();
        reference.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(one.into())
                .push(two.into())
                .into());
        reference.push(three.into());

        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c = Compressor::new(m)
                .algo(CompressionAlgorithm::Uncompressed).build().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "one").unwrap();
            let c = ls.finalize_one().unwrap().unwrap(); // Pop the LiteralWriter.
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "two").unwrap();
            let c = ls.finalize_one().unwrap().unwrap(); // Pop the LiteralWriter.
            let c = c.finalize_one().unwrap().unwrap(); // Pop the Compressor.
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "three").unwrap();
        }

        let pile = PacketPile::from(reference);
        let pile2 = PacketPile::from_bytes(&o).unwrap();
        if pile != pile2 {
            eprintln!("REFERENCE...");
            pile.pretty_print();
            eprintln!("REPARSED...");
            pile2.pretty_print();
            panic!("Reparsed packet does not match reference packet!");
        }
    }

    // Create some crazy nesting structures, serialize the messages,
    // reparse them, and make sure we get the same result.
    #[test]
    fn stream_1() {
        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: CompressedData(CompressedData { algo: 0 })
        //   1: Literal(Literal { body: "one (3 bytes)" })
        //   2: Literal(Literal { body: "two (3 bytes)" })
        //  2: CompressedData(CompressedData { algo: 0 })
        //   1: Literal(Literal { body: "three (5 bytes)" })
        //   2: Literal(Literal { body: "four (4 bytes)" })
        let mut one = Literal::new(T);
        one.set_body(b"one".to_vec());
        let mut two = Literal::new(T);
        two.set_body(b"two".to_vec());
        let mut three = Literal::new(T);
        three.set_body(b"three".to_vec());
        let mut four = Literal::new(T);
        four.set_body(b"four".to_vec());
        let mut reference = Vec::new();
        reference.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(one.into())
                      .push(two.into())
                      .into())
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(three.into())
                      .push(four.into())
                      .into())
                .into());

        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c0 = Compressor::new(m)
                .algo(CompressionAlgorithm::Uncompressed).build().unwrap();
            let c = Compressor::new(c0)
                .algo(CompressionAlgorithm::Uncompressed).build().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "one").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "two").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let c0 = c.finalize_one().unwrap().unwrap();
            let c = Compressor::new(c0)
                .algo(CompressionAlgorithm::Uncompressed).build().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "three").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "four").unwrap();
        }

        let pile = PacketPile::from(reference);
        let pile2 = PacketPile::from_bytes(&o).unwrap();
        if pile != pile2 {
            eprintln!("REFERENCE...");
            pile.pretty_print();
            eprintln!("REPARSED...");
            pile2.pretty_print();
            panic!("Reparsed packet does not match reference packet!");
        }
    }

    #[cfg(feature = "compression-bzip2")]
    #[test]
    fn stream_big() {
        let zeros = vec![0; 1024 * 1024 * 4];
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c = Compressor::new(m)
                .algo(CompressionAlgorithm::BZip2).build().unwrap();
            let mut ls = LiteralWriter::new(c).build().unwrap();
            // Write 64 megabytes of zeroes.
            for _ in 0 .. 16 {
                ls.write_all(&zeros).unwrap();
            }
        }
        assert!(o.len() < 1024);
    }

    #[test]
    fn signature() {
        let p = &P::new();
        use crate::crypto::KeyPair;
        use std::collections::HashMap;
        use crate::Fingerprint;

        let mut keys: HashMap<Fingerprint, key::UnspecifiedPublic> = HashMap::new();
        for tsk in &[
            Cert::from_bytes(crate::tests::key("testy-private.pgp")).unwrap(),
            Cert::from_bytes(crate::tests::key("testy-new-private.pgp")).unwrap(),
        ] {
            for key in tsk.keys().with_policy(p, crate::frozen_time())
                .for_signing().map(|ka| ka.key())
            {
                keys.insert(key.fingerprint(), key.clone());
            }
        }

        let mut o = vec![];
        {
            let mut signers = keys.iter().map(|(_, key)| {
                key.clone().mark_parts_secret().unwrap().into_keypair()
                    .expect("expected unencrypted secret key")
            }).collect::<Vec<KeyPair>>();

            let m = Message::new(&mut o);
            let mut signer = Signer::new(m, signers.pop().unwrap());
            for s in signers.into_iter() {
                signer = signer.add_signer(s);
            }
            let signer = signer.build().unwrap();
            let mut ls = LiteralWriter::new(signer).build().unwrap();
            ls.write_all(b"Tis, tis, tis.  Tis is important.").unwrap();
            let _ = ls.finalize().unwrap();
        }

        let mut ppr = PacketParser::from_bytes(&o).unwrap();
        let mut good = 0;
        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(ref sig) = pp.packet {
                let key = keys.get(&sig.issuer_fingerprint().unwrap())
                    .unwrap();
                sig.verify(key).unwrap();
                good += 1;
            }

            // Get the next packet.
            ppr = pp.recurse().unwrap().1;
        }
        assert_eq!(good, 2);
    }

    #[test]
    fn encryptor() {
        let passwords: [Password; 2] = ["streng geheim".into(),
                                        "top secret".into()];
        let message = b"Hello world.";

        // Write a simple encrypted message...
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let encryptor = Encryptor::with_password(m, passwords[0].clone())
                .add_password(passwords[1].clone())
                .build().unwrap();
            let mut literal = LiteralWriter::new(encryptor).build()
                .unwrap();
            literal.write_all(message).unwrap();
        }

        // ... and recover it...
        #[derive(Debug, PartialEq)]
        enum State {
            Start,
            Decrypted(Vec<(SymmetricAlgorithm, SessionKey)>),
            Deciphered,
            MDC,
            Done,
        }

        // ... with every password.
        for password in &passwords {
            let mut state = State::Start;
            let mut ppr = PacketParser::from_bytes(&o).unwrap();
            while let PacketParserResult::Some(mut pp) = ppr {
                state = match state {
                    // Look for the SKESK packet.
                    State::Start =>
                        if let Packet::SKESK(ref skesk) = pp.packet {
                            match skesk.decrypt(password) {
                                Ok((algo, key))
                                    => State::Decrypted(
                                        vec![(algo, key)]),
                                Err(e) =>
                                    panic!("Decryption failed: {}", e),
                            }
                        } else {
                            panic!("Unexpected packet: {:?}", pp.packet)
                        },

                    // Look for the SEIP packet.
                    State::Decrypted(mut keys) =>
                        match pp.packet {
                            Packet::SEIP(_) =>
                                loop {
                                    if let Some((algo, key)) = keys.pop() {
                                        let r = pp.decrypt(algo, &key);
                                        if r.is_ok() {
                                            break State::Deciphered;
                                        }
                                    } else {
                                        panic!("seip decryption failed");
                                    }
                                },
                            Packet::SKESK(ref skesk) =>
                                match skesk.decrypt(password) {
                                    Ok((algo, key)) => {
                                        keys.push((algo, key));
                                        State::Decrypted(keys)
                                    },
                                    Err(e) =>
                                        panic!("Decryption failed: {}", e),
                                },
                            _ =>
                                panic!("Unexpected packet: {:?}", pp.packet),
                        },

                    // Look for the literal data packet.
                    State::Deciphered =>
                        if let Packet::Literal(_) = pp.packet {
                            let mut body = Vec::new();
                            pp.read_to_end(&mut body).unwrap();
                            assert_eq!(&body, message);
                            State::MDC
                        } else {
                            panic!("Unexpected packet: {:?}", pp.packet)
                        },

                    // Look for the MDC packet.
                    State::MDC =>
                        if let Packet::MDC(ref mdc) = pp.packet {
                            assert_eq!(mdc.digest(), mdc.computed_digest());
                            State::Done
                        } else {
                            panic!("Unexpected packet: {:?}", pp.packet)
                        },

                    State::Done =>
                        panic!("Unexpected packet: {:?}", pp.packet),
                };

                // Next?
                ppr = pp.recurse().unwrap().1;
            }
            assert_eq!(state, State::Done);
        }
    }

    #[test]
    fn aead_messages() {
        // AEAD data is of the form:
        //
        //   [ chunk1 ][ tag1 ] ... [ chunkN ][ tagN ][ tag ]
        //
        // All chunks are the same size except for the last chunk, which may
        // be shorter.
        //
        // In `Decryptor::read_helper`, we read a chunk and a tag worth of
        // data at a time.  Because only the last chunk can be shorter, if
        // the amount read is less than `chunk_size + tag_size`, then we know
        // that we've read the last chunk.
        //
        // Unfortunately, this is not sufficient: if the last chunk is
        // `chunk_size - tag size` bytes large, then when we read it, we'll
        // read `chunk_size + tag_size` bytes, because we'll have also read
        // the final tag!
        //
        // Make sure we handle this situation correctly.

        use std::cmp;

        use crate::parse::{
            stream::{
                Decryptor,
                DecryptionHelper,
                VerificationHelper,
                MessageStructure,
            },
        };
        use crate::cert::prelude::*;
        use crate::serialize::stream::{LiteralWriter, Message};

        let (tsk, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_transport_encryption_subkey()
            .generate().unwrap();

        struct Helper<'a> {
            policy: &'a dyn Policy,
            tsk: &'a Cert,
        };
        impl<'a> VerificationHelper for Helper<'a> {
            fn get_public_keys(&mut self, _ids: &[crate::KeyHandle])
                               -> Result<Vec<Cert>> {
                Ok(Vec::new())
            }
            fn check(&mut self, _structure: MessageStructure) -> Result<()> {
                Ok(())
            }
        }
        impl<'a> DecryptionHelper for Helper<'a> {
            fn decrypt<D>(&mut self, pkesks: &[PKESK], _skesks: &[SKESK],
                          sym_algo: Option<SymmetricAlgorithm>,
                          mut decrypt: D) -> Result<Option<crate::Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> Result<()>
            {
                let mut keypair = self.tsk.keys().with_policy(self.policy, None)
                    .for_transport_encryption()
                    .map(|ka| ka.key()).next().unwrap()
                    .clone().mark_parts_secret().unwrap()
                    .into_keypair().unwrap();
                pkesks[0].decrypt(&mut keypair, sym_algo)
                    .and_then(|(algo, session_key)| decrypt(algo, &session_key))
                    .map(|_| None)
            }
        }

        let p = &P::new();

        for chunks in 0..3 {
            for msg_len in
                      cmp::max(24, chunks * Encryptor::AEAD_CHUNK_SIZE) - 24
                          ..chunks * Encryptor::AEAD_CHUNK_SIZE + 24
            {
                eprintln!("Encrypting message of size: {}", msg_len);

                let mut content : Vec<u8> = Vec::new();
                for i in 0..msg_len {
                    content.push(b'0' + ((i % 10) as u8));
                }

                let mut msg = vec![];
                {
                    let m = Message::new(&mut msg);
                    let recipient = tsk
                        .keys().with_policy(p, None)
                        .for_storage_encryption().for_transport_encryption()
                        .nth(0).unwrap().key().into();
                    let encryptor = Encryptor::for_recipient(m, recipient)
                        .aead_algo(AEADAlgorithm::EAX)
                        .build().unwrap();
                    let mut literal = LiteralWriter::new(encryptor).build()
                        .unwrap();
                    literal.write_all(&content).unwrap();
                    // literal.finalize().unwrap();
                }

                for &read_len in &[
                    37,
                    Encryptor::AEAD_CHUNK_SIZE - 1,
                    Encryptor::AEAD_CHUNK_SIZE,
                    100 * Encryptor::AEAD_CHUNK_SIZE
                ] {
                    for &do_err in &[ false, true ] {
                        let mut msg = msg.clone();
                        if do_err {
                            let l = msg.len() - 1;
                            if msg[l] == 0 {
                                msg[l] = 1;
                            } else {
                                msg[l] = 0;
                            }
                        }

                        let h = Helper { policy: p, tsk: &tsk };
                        // Note: a corrupted message is only guaranteed
                        // to error out before it returns EOF.
                        let mut v = match Decryptor::from_bytes(p, &msg, h, None) {
                            Ok(v) => v,
                            Err(_) if do_err => continue,
                            Err(err) => panic!("Decrypting message: {}", err),
                        };

                        let mut buffer = Vec::new();
                        buffer.resize(read_len, 0);

                        let mut decrypted_content = Vec::new();
                        loop {
                            match v.read(&mut buffer[..read_len]) {
                                Ok(0) if do_err =>
                                    panic!("Expected an error, got EOF"),
                                Ok(0) => break,
                                Ok(len) =>
                                    decrypted_content.extend_from_slice(
                                        &buffer[..len]),
                                Err(_) if do_err => break,
                                Err(err) =>
                                    panic!("Decrypting data: {:?}", err),
                            }
                        }

                        if do_err {
                            // If we get an error once, we should get
                            // one again.
                            for _ in 0..3 {
                                assert!(v.read(&mut buffer[..read_len]).is_err());
                            }
                        }

                        // We only corrupted the final tag, so we
                        // should get all of the content.
                        assert_eq!(msg_len, decrypted_content.len());
                        assert_eq!(content, decrypted_content);
                    }
                }
            }
        }
    }

    #[test]
    fn signature_at_time() {
        // Generates a signature with a specific Signature Creation
        // Time.
        use crate::cert::prelude::*;
        use crate::serialize::stream::{LiteralWriter, Message};
        use crate::crypto::KeyPair;

        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();

        // What we're going to sign with.
        let ka = cert.keys().with_policy(p, None).for_signing().nth(0).unwrap();

        // A timestamp later than the key's creation.
        let timestamp = ka.key().creation_time()
            + std::time::Duration::from_secs(14 * 24 * 60 * 60);
        assert!(ka.key().creation_time() < timestamp);

        let mut o = vec![];
        {
            let signer_keypair : KeyPair =
                ka.key().clone().mark_parts_secret().unwrap().into_keypair()
                    .expect("expected unencrypted secret key");

            let m = Message::new(&mut o);
            let signer = Signer::new(m, signer_keypair);
            let signer = signer.creation_time(timestamp);
            let signer = signer.build().unwrap();

            let mut ls = LiteralWriter::new(signer).build().unwrap();
            ls.write_all(b"Tis, tis, tis.  Tis is important.").unwrap();
            let signer = ls.finalize_one().unwrap().unwrap();
            let _ = signer.finalize_one().unwrap().unwrap();
        }

        let mut ppr = PacketParser::from_bytes(&o).unwrap();
        let mut good = 0;
        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(ref sig) = pp.packet {
                assert_eq!(sig.signature_creation_time(), Some(timestamp));
                sig.verify(ka.key()).unwrap();
                good += 1;
            }

            // Get the next packet.
            ppr = pp.recurse().unwrap().1;
        }
        assert_eq!(good, 1);
    }
}
