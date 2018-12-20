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
use std::iter;
use time;
use nettle::{Hash, Yarrow};

use {
    crypto,
    Error,
    Fingerprint,
    HashAlgorithm,
    packet::Key,
    packet::Literal,
    packet::MDC,
    packet::AED,
    packet::OnePassSig,
    packet::PKESK,
    Result,
    crypto::Password,
    crypto::SessionKey,
    packet::SKESK4,
    packet::SKESK5,
    packet::signature::{self, Signature},
    packet::Tag,
    TPK,
};
use packet::ctb::CTB;
use packet::BodyLength;
use super::{
    PartialBodyFilter,
    Serialize,
    writer,
};
use constants::{
    AEADAlgorithm,
    CompressionAlgorithm,
    DataFormat,
    SignatureType,
    SymmetricAlgorithm,
};
use conversions::Time;

/// Cookie must be public because the writers are.
#[doc(hidden)]
#[derive(Debug)]
pub struct Cookie {
    level: usize,
    private: Private,
}

#[derive(Debug)]
enum Private {
    Nothing,
    Signer,
}

impl Cookie {
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

impl<'a> From<&'a mut io::Write> for writer::Stack<'a, Cookie> {
    fn from(w: &'a mut io::Write) -> Self {
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
        unimplemented!()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unimplemented!()
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        self.inner.inner_ref()
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        self.inner.inner_mut()
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
    signers: Vec<&'a mut dyn crypto::Signer>,
    intended_recipients: Option<Vec<Fingerprint>>,
    detached: bool,
    hash: Box<Hash>,
    cookie: Cookie,
}

impl<'a> Signer<'a> {
    /// Creates a signer.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate sequoia_openpgp as openpgp;
    /// use std::io::Write;
    /// use openpgp::constants::DataFormat;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::{Result, TPK};
    /// # use openpgp::packet::key::SecretKey;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # let tsk = TPK::from_bytes(include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp"))
    /// #     .unwrap();
    /// # let key = tsk.select_signing_keys(None)[0];
    /// # let sec = match key.secret() {
    /// #     Some(SecretKey::Unencrypted { ref mpis }) => mpis,
    /// #     _ => unreachable!(),
    /// # };
    /// # let keypair = KeyPair::new(key.clone(), sec.clone()).unwrap();
    /// # f(keypair).unwrap();
    /// # fn f(mut signing_keypair: KeyPair) -> Result<()> {
    ///
    /// let mut o = vec![];
    /// {
    ///     let message = Message::new(&mut o);
    ///     let signer = Signer::new(message, vec![&mut signing_keypair])?;
    ///     let mut ls = LiteralWriter::new(signer, DataFormat::Text, None, None)?;
    ///     ls.write_all(b"Make it so, number one!")?;
    ///     ls.finalize()?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(inner: writer::Stack<'a, Cookie>,
               signers: Vec<&'a mut dyn crypto::Signer>)
               -> Result<writer::Stack<'a, Cookie>> {
        Self::make(inner, signers, None, false)
    }

    /// Creates a signer with intended recipients.
    ///
    /// This signer emits signatures indicating the intended
    /// recipients of the encryption container containing the
    /// signature.  This prevents forwarding a signed message using a
    /// different encryption context.
    pub fn with_intended_recipients(inner: writer::Stack<'a, Cookie>,
                                    signers: Vec<&'a mut dyn crypto::Signer>,
                                    recipients: &[&'a TPK])
                                    -> Result<writer::Stack<'a, Cookie>> {
        Self::make(inner, signers,
                   Some(recipients.iter().map(|r| r.fingerprint()).collect()),
                   false)
    }

    /// Creates a signer for a detached signature.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate sequoia_openpgp as openpgp;
    /// use std::io::Write;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::{Result, TPK};
    /// # use openpgp::packet::key::SecretKey;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # let tsk = TPK::from_bytes(include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp"))
    /// #     .unwrap();
    /// # let key = tsk.select_signing_keys(None)[0];
    /// # let sec = match key.secret() {
    /// #     Some(SecretKey::Unencrypted { ref mpis }) => mpis,
    /// #     _ => unreachable!(),
    /// # };
    /// # let keypair = KeyPair::new(key.clone(), sec.clone()).unwrap();
    /// # f(keypair).unwrap();
    /// # fn f(mut signing_keypair: KeyPair) -> Result<()> {
    ///
    /// let mut o = vec![];
    /// {
    ///     let message = Message::new(&mut o);
    ///     let mut signer = Signer::detached(message, vec![&mut signing_keypair])?;
    ///     signer.write_all(b"Make it so, number one!")?;
    ///     // In reality, just io::copy() the file to be signed.
    ///     signer.finalize()?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn detached(inner: writer::Stack<'a, Cookie>,
                    signers: Vec<&'a mut dyn crypto::Signer>)
                    -> Result<writer::Stack<'a, Cookie>> {
        Self::make(inner, signers, None, true)
    }

    fn make(inner: writer::Stack<'a, Cookie>,
            signers: Vec<&'a mut dyn crypto::Signer>,
            intended_recipients: Option<Vec<Fingerprint>>, detached: bool)
            -> Result<writer::Stack<'a, Cookie>> {
        let mut inner = writer::BoxStack::from(inner);
        // Just always use SHA512.
        let hash_algo = HashAlgorithm::SHA512;

        if signers.len() == 0 {
            return Err(Error::InvalidArgument(
                "No signing keys given".into()).into());
        }

        if ! detached {
            // For every key we collected, build and emit a one pass
            // signature packet.
            for (i, keypair) in signers.iter().enumerate() {
                let key = keypair.public();
                let mut ops = OnePassSig::new(SignatureType::Binary);
                ops.set_pk_algo(key.pk_algo());
                ops.set_hash_algo(hash_algo);
                ops.set_issuer(key.fingerprint().to_keyid());
                ops.set_last(i == signers.len() - 1);
                ops.serialize(&mut inner)?;
            }
        }

        let level = inner.cookie_ref().level + 1;
        Ok(writer::Stack::from(Box::new(Signer {
            inner: Some(inner),
            signers: signers,
            intended_recipients: intended_recipients,
            detached: detached,
            hash: hash_algo.context()?,
            cookie: Cookie {
                level: level,
                private: Private::Signer,
            },
        })))
    }

    fn emit_signatures(&mut self) -> Result<()> {
        if let Some(ref mut sink) = self.inner {
            // Emit the signatures in reverse, so that the
            // one-pass-signature and signature packets "bracket" the
            // message.
            for signer in self.signers.iter_mut() {
                // Part of the signature packet is hashed in,
                // therefore we need to clone the hash.
                let mut hash = self.hash.clone();

                // Make and hash a signature packet.
                let mut sig = signature::Builder::new(SignatureType::Binary);
                sig.set_signature_creation_time(time::now().canonicalize())?;
                sig.set_issuer_fingerprint(signer.public().fingerprint())?;
                // GnuPG up to (and including) 2.2.8 requires the
                // Issuer subpacket to be present.
                sig.set_issuer(signer.public().keyid())?;

                if let Some(ref ir) = self.intended_recipients {
                    sig.set_intended_recipients(ir.clone())?;
                }

                // Compute the signature.
                let sig = sig.sign_hash(*signer, HashAlgorithm::SHA512, hash)?;

                // And emit the packet.
                sig.serialize(sink)?;
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
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        if let Some(ref i) = self.inner {
            Some(i)
        } else {
            None
        }
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
/// use openpgp::constants::DataFormat;
/// use openpgp::serialize::stream::{Message, LiteralWriter};
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
///
/// let mut o = vec![];
/// {
///     let message = Message::new(&mut o);
///     let mut w = LiteralWriter::new(message, DataFormat::Text, None, None)?;
///     w.write_all(b"Hello world.")?;
///     w.finalize()?;
/// }
/// assert_eq!(b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.", o.as_slice());
/// # Ok(())
/// # }
/// ```
pub struct LiteralWriter<'a> {
    inner: writer::BoxStack<'a, Cookie>,
    signature_writer: Option<writer::BoxStack<'a, Cookie>>,
}

impl<'a> LiteralWriter<'a> {
    /// Creates a new literal writer.
    ///
    /// `format`, `filename`, and `date` will be emitted as part of
    /// the literal packets headers.  Note that these headers will not
    /// be authenticated by signatures (but will be authenticated by a
    /// SEIP/MDC container), and are therefore unreliable and should
    /// not be trusted.
    ///
    /// If `date` is `None`, then the earliest representable time will
    /// be used as a dummy value.
    pub fn new(inner: writer::Stack<'a, Cookie>,
               format: DataFormat,
               filename: Option<&[u8]>,
               date: Option<time::Tm>)
               -> Result<writer::Stack<'a, Cookie>> {
        let mut inner = writer::BoxStack::from(inner);
        let level = inner.cookie_ref().level + 1;

        let mut template = Literal::new(format);
        template.set_date(date);

        if let Some(f) = filename {
            template.set_filename_from_bytes(f)?;
        }

        // For historical reasons, signatures over literal data
        // packets only include the body without metadata or framing.
        // Therefore, we check whether the writer is a
        // Signer, and if so, we pop it off the stack and
        // store it in 'self.signature_writer'.
        let signer_above =
            if let &Cookie {
                private: Private::Signer{..},
                ..
            } = inner.cookie_ref() {
                true
            } else {
                false
            };

        let mut signature_writer = None;
        if signer_above {
            let stack = inner.pop()?;
            // We know a signer has an inner stackable.
            let stack = stack.unwrap();
            signature_writer = Some(inner);
            inner = stack;
        }

        // Not hashed by the signature_writer (see above).
        CTB::new(Tag::Literal).serialize(&mut inner)?;

        // Neither is any framing added by the PartialBodyFilter.
        let mut inner
            = PartialBodyFilter::new(writer::Stack::from(inner), Cookie::new(level));

        // Nor the headers.
        template.serialize_headers(&mut inner, false)?;

        Ok(writer::Stack::from(Box::new(Self {
            inner: inner.into(),
            signature_writer: signature_writer,
        })))
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
        unimplemented!()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unimplemented!()
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        self.inner.inner_ref()
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        self.inner.inner_mut()
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
/// use openpgp::constants::DataFormat;
/// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
/// use openpgp::constants::CompressionAlgorithm;
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
///
/// let mut o = vec![];
/// {
///     let message = Message::new(&mut o);
///     let w = Compressor::new(message,
///                             CompressionAlgorithm::Uncompressed)?;
///     let mut w = LiteralWriter::new(w, DataFormat::Text, None, None)?;
///     w.write_all(b"Hello world.")?;
///     w.finalize()?;
/// }
/// assert_eq!(b"\xc8\x15\x00\xcb\x12t\x00\x00\x00\x00\x00Hello world.",
///            o.as_slice());
/// # Ok(())
/// # }
pub struct Compressor<'a> {
    inner: writer::BoxStack<'a, Cookie>,
}

impl<'a> Compressor<'a> {
    /// Creates a new compressor using the given algorithm.
    pub fn new(inner: writer::Stack<'a, Cookie>, algo: CompressionAlgorithm)
               -> Result<writer::Stack<'a, Cookie>> {
        let mut inner = writer::BoxStack::from(inner);
        let level = inner.cookie_ref().level + 1;

        // Packet header.
        CTB::new(Tag::CompressedData).serialize(&mut inner)?;

        let mut inner: writer::Stack<'a, Cookie>
            = PartialBodyFilter::new(writer::Stack::from(inner),
                                     Cookie::new(level));

        // Compressed data header.
        inner.as_mut().write_u8(algo.into())?;

        // Create an appropriate filter.
        let inner: writer::Stack<'a, Cookie> = match algo {
            CompressionAlgorithm::Uncompressed =>
                writer::Identity::new(inner, Cookie::new(level)),
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zip =>
                writer::ZIP::new(inner, Cookie::new(level)),
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zlib =>
                writer::ZLIB::new(inner, Cookie::new(level)),
            #[cfg(feature = "compression-bzip2")]
            CompressionAlgorithm::BZip2 =>
                writer::BZ::new(inner, Cookie::new(level)),
            _ => unimplemented!(),
        };

        Ok(writer::Stack::from(Box::new(Self{inner: inner.into()})))
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
        unimplemented!()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unimplemented!()
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        self.inner.inner_ref()
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        self.inner.inner_mut()
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
}

/// Encrypts a packet stream.
pub struct Encryptor<'a> {
    inner: Option<writer::BoxStack<'a, Cookie>>,
    hash: Box<Hash>,
    cookie: Cookie,
}

/// Specifies whether to encrypt for archival purposes or for
/// transport.
pub enum EncryptionMode {
    /// Encrypt data for long-term storage.
    ///
    /// This should be used for things that should be decryptable for
    /// a long period of time, e.g. backups, archives, etc.
    AtRest,

    /// Encrypt data for transport.
    ///
    /// This should be used to protect a message in transit.  The
    /// recipient is expected to take additional steps if she wants to
    /// be able to decrypt it later on, e.g. store the decrypted
    /// session key, or re-encrypt the session key with a different
    /// key.
    ForTransport,
}

impl<'a> Encryptor<'a> {
    /// Creates a new encryptor.
    ///
    /// The stream will be encrypted using a generated session key,
    /// which will be encrypted using the given passwords, and all
    /// encryption-capable subkeys of the given TPKs.
    ///
    /// The stream is encrypted using AES256, regardless of any key
    /// preferences.
    ///
    /// # Example
    ///
    /// ```
    /// use std::io::Write;
    /// #[macro_use] extern crate sequoia_openpgp as openpgp; // For armored!
    /// use openpgp::constants::DataFormat;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, EncryptionMode, LiteralWriter,
    /// };
    /// # use openpgp::Result;
    /// # use openpgp::parse::Parse;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let tpk = openpgp::TPK::from_reader(armored!(
    /// #   // We do some acrobatics here to abbreviate the TPK.
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
    /// )).unwrap();
    ///
    /// let mut o = vec![];
    /// let message = Message::new(&mut o);
    /// let encryptor = Encryptor::new(message,
    ///                                &[&"совершенно секретно".into()],
    ///                                &[&tpk],
    ///                                EncryptionMode::AtRest)
    ///     .expect("Failed to create encryptor");
    /// let mut w = LiteralWriter::new(encryptor, DataFormat::Text, None, None)?;
    /// w.write_all(b"Hello world.")?;
    /// w.finalize()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(mut inner: writer::Stack<'a, Cookie>,
               passwords: &[&Password], tpks: &[&TPK],
               encryption_mode: EncryptionMode)
               -> Result<writer::Stack<'a, Cookie>> {
        if tpks.len() + passwords.len() == 0 {
            return Err(Error::InvalidArgument(
                "Neither recipient keys nor passwords given".into()).into());
        }

        let mut rng = Yarrow::default();

        struct AEADParameters {
            algo: AEADAlgorithm,
            chunk_size: usize,
            nonce: Box<[u8]>,
        }

        // Use AEAD if there are TPKs and all of them support AEAD.
        let aead = if tpks.len() > 0 && tpks.iter().all(|t| {
            t.primary_key_signature().map(|s| s.features().supports_aead())
                .unwrap_or(false)
        }) {
            let mut nonce = vec![0; AEADAlgorithm::EAX.iv_size()?];
            rng.random(&mut nonce);
            Some(AEADParameters {
                algo: AEADAlgorithm::EAX, // Must implement EAX.
                chunk_size: 4096, // A page, 3 per mille overhead.
                nonce: nonce.into_boxed_slice(),
            })
        } else {
            None
        };

        let level = inner.as_ref().cookie_ref().level + 1;
        let algo = SymmetricAlgorithm::AES256;

        // Generate a session key.
        let sk = SessionKey::new(&mut rng, algo.key_size().unwrap());

        // Write the PKESK packet(s).
        for tpk in tpks {
            // We need to find all applicable encryption (sub)keys.
            let can_encrypt = |key: &Key, sig: Option<&Signature>| -> bool {
                if let Some(sig) = sig {
                    (match encryption_mode {
                        EncryptionMode::AtRest =>
                            sig.key_flags().can_encrypt_at_rest(),
                        EncryptionMode::ForTransport =>
                            sig.key_flags().can_encrypt_for_transport(),
                    }
                     // Check expiry.
                     && sig.signature_alive()
                     && sig.key_alive(key))
                } else {
                    false
                }
            };

            // Gather all encryption-capable subkeys.
            let subkeys = tpk.subkeys().filter_map(|skb| {
                let key = skb.subkey();
                if can_encrypt(key, skb.binding_signature()) {
                    Some(key)
                } else {
                    None
                }
            });

            // Check if the primary key is encryption-capable.
            let primary_can_encrypt =
                can_encrypt(tpk.primary(), tpk.primary_key_signature());

            // If the primary key is encryption-capable, prepend to
            // subkeys via iterator magic.
            let keys =
                iter::once(tpk.primary())
                .filter(|_| primary_can_encrypt)
                .chain(subkeys);

            let mut count = 0;
            for key in keys {
                if let Ok(pkesk) = PKESK::new(algo, &sk, key) {
                    pkesk.serialize(&mut inner)?;
                    count += 1;
                }
            }

            if count == 0 {
                return Err(Error::InvalidOperation(
                    format!("Key {} has no suitable encryption subkey",
                            tpk)).into());
            }
        }

        // Write the SKESK packet(s).
        for password in passwords {
            if let Some(aead) = aead.as_ref() {
                let skesk = SKESK5::with_password(algo, aead.algo,
                                                  Default::default(),
                                                  &sk, password).unwrap();
                skesk.serialize(&mut inner)?;
            } else {
                let skesk = SKESK4::with_password(algo, Default::default(),
                                                  &sk, password).unwrap();
                skesk.serialize(&mut inner)?;
            }
        }

        let encryptor = if let Some(aead) = aead {
            // Write the AED packet.
            CTB::new(Tag::AED).serialize(&mut inner)?;
            let mut inner = PartialBodyFilter::new(inner, Cookie::new(level));
            let aed = AED::new(algo, aead.algo, aead.chunk_size, aead.nonce)?;
            aed.serialize_headers(&mut inner)?;

            writer::AEADEncryptor::new(
                inner.into(),
                Cookie::new(level),
                aed.cipher(),
                aed.aead(),
                aed.chunk_size(),
                aed.iv(),
                &sk,
            )?
        } else {
            // Write the SEIP packet.
            CTB::new(Tag::SEIP).serialize(&mut inner)?;
            let mut inner = PartialBodyFilter::new(inner, Cookie::new(level));
            inner.write_all(&[1])?; // Version.

            let encryptor = writer::Encryptor::new(
                inner.into(),
                Cookie::new(level),
                algo,
                &sk,
            )?;

            // The hash for the MDC must include the initialization
            // vector, hence we build the object here.
            let mut encryptor = writer::Stack::from(Box::new(Self{
                inner: Some(encryptor.into()),
                hash: HashAlgorithm::SHA1.context().unwrap(),
                cookie: Cookie::new(level),
            }));

            // Write the initialization vector, and the quick-check bytes.
            let mut iv = vec![0; algo.block_size().unwrap()];
            rng.random(&mut iv);
            encryptor.write_all(&iv)?;
            encryptor.write_all(&iv[iv.len() - 2..])?;

            encryptor
        };

        Ok(encryptor)
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
            MDC::new(&mut self.hash).serialize(&mut w)?;

            // Now recover the original writer.  First, strip the
            // Encryptor.
            let mut w = w.into_inner()?.unwrap();
            // And the partial body filter.
            let mut w = w.into_inner()?.unwrap();

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
        unimplemented!()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unimplemented!()
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        if let Some(ref i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
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
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use {Packet, PacketPile, packet::CompressedData};
    use parse::{Parse, PacketParserResult, PacketParser};
    use super::*;
    use constants::DataFormat::Text as T;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../tests/data/", $x)) };
    }

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
                .push(one.to_packet())
                .push(two.to_packet())
                .to_packet());
        reference.push(three.to_packet());

        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c = Compressor::new(
                m, CompressionAlgorithm::Uncompressed).unwrap();
            let mut ls = LiteralWriter::new(c, T, None, None).unwrap();
            write!(ls, "one").unwrap();
            let c = ls.finalize_one().unwrap().unwrap(); // Pop the LiteralWriter.
            let mut ls = LiteralWriter::new(c, T, None, None).unwrap();
            write!(ls, "two").unwrap();
            let c = ls.finalize_one().unwrap().unwrap(); // Pop the LiteralWriter.
            let c = c.finalize_one().unwrap().unwrap(); // Pop the Compressor.
            let mut ls = LiteralWriter::new(c, T, None, None).unwrap();
            write!(ls, "three").unwrap();
        }

        let pile = PacketPile::from_packets(reference);
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
                      .push(one.to_packet())
                      .push(two.to_packet())
                      .to_packet())
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(three.to_packet())
                      .push(four.to_packet())
                      .to_packet())
                .to_packet());

        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c0 = Compressor::new(
                m, CompressionAlgorithm::Uncompressed).unwrap();
            let c = Compressor::new(
                c0, CompressionAlgorithm::Uncompressed).unwrap();
            let mut ls = LiteralWriter::new(c, T, None, None).unwrap();
            write!(ls, "one").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let mut ls = LiteralWriter::new(c, T, None, None).unwrap();
            write!(ls, "two").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let c0 = c.finalize_one().unwrap().unwrap();
            let c = Compressor::new(
                c0, CompressionAlgorithm::Uncompressed).unwrap();
            let mut ls = LiteralWriter::new(c, T, None, None).unwrap();
            write!(ls, "three").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let mut ls = LiteralWriter::new(c, T, None, None).unwrap();
            write!(ls, "four").unwrap();
        }

        let pile = PacketPile::from_packets(reference);
        let pile2 = PacketPile::from_bytes(&o).unwrap();
        if pile != pile2 {
            eprintln!("REFERENCE...");
            pile.pretty_print();
            eprintln!("REPARSED...");
            pile2.pretty_print();
            panic!("Reparsed packet does not match reference packet!");
        }
    }

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn stream_big() {
        let zeros = vec![0; 1024 * 1024 * 4];
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c = Compressor::new(m,
                                    CompressionAlgorithm::BZip2).unwrap();
            let mut ls = LiteralWriter::new(c, T, None, None).unwrap();
            // Write 64 megabytes of zeroes.
            for _ in 0 .. 16 {
                ls.write_all(&zeros).unwrap();
            }
        }
        assert!(o.len() < 1024);
    }

    #[test]
    fn signature() {
        use crypto::KeyPair;
        use packet::KeyFlags;
        use packet::key::SecretKey;
        use std::collections::HashMap;
        use Fingerprint;

        let mut keys: HashMap<Fingerprint, Key> = HashMap::new();
        for tsk in &[
            TPK::from_bytes(bytes!("keys/testy-private.pgp")).unwrap(),
            TPK::from_bytes(bytes!("keys/testy-new-private.pgp")).unwrap(),
        ] {
            for key in tsk.select_keys(
                KeyFlags::default().set_sign(true), None)
            {
                keys.insert(key.fingerprint(), key.clone());
            }
        }

        let mut o = vec![];
        {
            let mut signers = keys.iter().map(|(_, key)| {
                match key.secret() {
                    Some(SecretKey::Unencrypted { ref mpis }) =>
                        KeyPair::new(key.clone(), mpis.clone()).unwrap(),
                    s =>
                        panic!("expected unencrypted secret key, got: {:?}", s),
                }
            }).collect::<Vec<KeyPair>>();

            let m = Message::new(&mut o);
            let signer = Signer::new(
                m,
                signers.iter_mut()
                    .map(|s| -> &mut dyn crypto::Signer {s})
                    .collect())
                .unwrap();
            let mut ls = LiteralWriter::new(signer, T, None, None).unwrap();
            ls.write_all(b"Tis, tis, tis.  Tis is important.").unwrap();
            let signer = ls.finalize_one().unwrap().unwrap();
            let _ = signer.finalize_one().unwrap().unwrap();
        }

        let mut ppr = PacketParser::from_bytes(&o).unwrap();
        let mut good = 0;
        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(ref sig) = pp.packet {
                let key = keys.get(&sig.issuer_fingerprint().unwrap())
                    .unwrap();
                let result = sig.verify(key).unwrap();
                assert!(result);
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
            let encryptor = Encryptor::new(
                m, &passwords.iter().collect::<Vec<&Password>>(),
                &[], EncryptionMode::ForTransport)
                .unwrap();
            let mut literal = LiteralWriter::new(encryptor, DataFormat::Binary,
                                                 None, None)
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
                            assert_eq!(mdc.hash(), mdc.computed_hash());
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
}
