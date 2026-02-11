//! Streaming packet serialization.
//!
//! This interface provides a convenient way to create signed and/or
//! encrypted OpenPGP messages (see [Section 10.3 of RFC 9580]) and is
//! the preferred interface to generate messages using Sequoia.  It
//! takes advantage of OpenPGP's streaming nature to avoid unnecessary
//! buffering.
//!
//!   [Section 10.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3
//!
//! To use this interface, a sink implementing [`io::Write`] is
//! wrapped by [`Message::new`] returning a streaming [`Message`].
//! The writer stack is a structure to compose filters that create the
//! desired message structure.  There are a number of filters that can
//! be freely combined:
//!
//!   - [`Armorer`] applies ASCII-Armor to the stream,
//!   - [`Encryptor`] encrypts data fed into it,
//!   - [`Compressor`] compresses data,
//!   - [`Padder`] pads data,
//!   - [`Signer`] signs data,
//!   - [`LiteralWriter`] wraps literal data (i.e. the payload) into
//!     a literal data packet,
//!   - and finally, [`ArbitraryWriter`] can be used to create
//!     arbitrary packets for testing purposes.
//!
//!   [`io::Write`]: std::io::Write
//!   [`Message::new`]: Message::new()
//!   [`Padder`]: padding::Padder
//!
//! The most common structure is an optionally encrypted, optionally
//! compressed, and optionally signed message.  This structure is
//! [supported] by all OpenPGP implementations, and applications
//! should only create messages of that structure to increase
//! compatibility.  See the example below on how to create this
//! structure.  This is a sketch of such a message:
//!
//! ```text
//! [ encryption layer: [ compression layer: [ signature group: [ literal data ]]]]
//! ```
//!
//!   [supported]: https://tests.sequoia-pgp.org/#Unusual_Message_Structure
//!
//! # Examples
//!
//! This example demonstrates how to create the simplest possible
//! OpenPGP message (see [Section 10.3 of RFC 9580]) containing just a
//! literal data packet (see [Section 5.9 of RFC 9580]):
//!
//!   [Section 5.9 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.9
//!
//! ```
//! # fn main() -> sequoia_openpgp::Result<()> {
//! use std::io::Write;
//! use sequoia_openpgp as openpgp;
//! use openpgp::serialize::stream::{Message, LiteralWriter};
//!
//! let mut sink = vec![];
//! {
//!     let message = Message::new(&mut sink);
//!     let mut message = LiteralWriter::new(message).build()?;
//!     message.write_all(b"Hello world.")?;
//!     message.finalize()?;
//! }
//! assert_eq!(b"\xcb\x12b\x00\x00\x00\x00\x00Hello world.", sink.as_slice());
//! # Ok(()) }
//! ```
//!
//! This example demonstrates how to create the most common OpenPGP
//! message structure (see [Section 10.3 of RFC 9580]).  The plaintext
//! is first signed, then padded, encrypted, and finally ASCII armored.
//!
//! ```
//! # fn main() -> sequoia_openpgp::Result<()> {
//! use std::io::Write;
//! use sequoia_openpgp as openpgp;
//! use openpgp::policy::StandardPolicy;
//! use openpgp::cert::prelude::*;
//! use openpgp::serialize::stream::{
//!     Message, Armorer, Encryptor, Signer, LiteralWriter, padding::Padder,
//! };
//! # use openpgp::parse::Parse;
//!
//! let p = &StandardPolicy::new();
//!
//! let sender: Cert = // ...
//! #     Cert::from_bytes(&include_bytes!(
//! #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
//! let signing_keypair = sender.keys().secret()
//!     .with_policy(p, None).supported().alive().revoked(false).for_signing()
//!     .nth(0).unwrap()
//!     .key().clone().into_keypair()?;
//!
//! let recipient: Cert = // ...
//! #     sender.clone();
//! // Note: One certificate may contain several suitable encryption keys.
//! let recipients =
//!     recipient.keys().with_policy(p, None).supported().alive().revoked(false)
//!     // Or `for_storage_encryption()`, for data at rest.
//!     .for_transport_encryption();
//!
//! # let mut sink = vec![];
//! let message = Message::new(&mut sink);
//! let message = Armorer::new(message).build()?;
//! let message = Encryptor::for_recipients(message, recipients).build()?;
//! // Reduce metadata leakage by concealing the message size.
//! let message = Padder::new(message).build()?;
//! let message = Signer::new(message, signing_keypair)?
//!     // Prevent Surreptitious Forwarding.
//!     .add_intended_recipient(&recipient)
//!     .build()?;
//! let mut message = LiteralWriter::new(message).build()?;
//! message.write_all(b"Hello world.")?;
//! message.finalize()?;
//! # Ok(()) }
//! ```

use std::fmt;
use std::io::{self, Write};
use std::time::SystemTime;

use crate::{
    armor,
    crypto,
    Error,
    Fingerprint,
    HashAlgorithm,
    KeyHandle,
    Profile,
    Result,
    crypto::Password,
    crypto::SessionKey,
    packet::prelude::*,
    packet::signature,
    packet::key,
    cert::prelude::*,
};
use crate::packet::header::CTB;
use crate::packet::header::BodyLength;
use crate::parse::HashingMode;
use super::{
    Marshal,
};
use crate::types::{
    AEADAlgorithm,
    CompressionAlgorithm,
    CompressionLevel,
    DataFormat,
    Features,
    SignatureType,
    SymmetricAlgorithm,
};

pub(crate) mod writer;
pub mod padding;
mod partial_body;
use partial_body::PartialBodyFilter;
mod dash_escape;
use dash_escape::DashEscapeFilter;
mod trim_whitespace;
use trim_whitespace::TrailingWSFilter;


/// Cookie must be public because the writers are.
#[derive(Debug)]
struct Cookie {
    level: usize,
    private: Private,
}

impl Cookie {
    /// Sets the private data part of the cookie.
    pub fn set_private(mut self, p: Private) -> Self {
        self.private = p;
        self
    }
}

/// An enum to store writer-specific data.
#[derive(Debug)]
enum Private {
    Nothing,
    Signer,
    Armorer {
        set_profile: Option<Profile>,
    },
    Encryptor {
        profile: Profile,
    },
}

impl Cookie {
    fn new(level: usize) -> Self {
        Cookie {
            level,
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
/// Wraps an [`io::Write`]r for use with the streaming subsystem.  The
/// `Message` is a stack of filters that create the desired message
/// structure.  Literal data must be framed using the
/// [`LiteralWriter`] filter.  Once all the has been written, the
/// `Message` must be finalized using [`Message::finalize`].
///
///   [`io::Write`]: std::io::Write
///   [`Message::finalize`]: Message::finalize()
#[derive(Debug)]
pub struct Message<'a>(writer::BoxStack<'a, Cookie>);
assert_send_and_sync!(Message<'_>);

impl<'a> Message<'a> {
    /// Starts streaming an OpenPGP message.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// # let mut sink = vec![]; // Vec<u8> implements io::Write.
    /// let message = Message::new(&mut sink);
    /// // Construct the writer stack here.
    /// let mut message = LiteralWriter::new(message).build()?;
    /// // Write literal data to `message` here.
    /// // ...
    /// // Finalize the message.
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn new<W: 'a + io::Write + Send + Sync>(w: W) -> Message<'a> {
        writer::Generic::new(w, Cookie::new(0))
    }

    /// Finalizes the topmost writer, returning the underlying writer.
    ///
    /// Finalizes the topmost writer, i.e. flushes any buffered data,
    /// and pops it of the stack.  This allows for fine-grained
    /// control of the resulting message, but must be done with great
    /// care.  If done improperly, the resulting message may be
    /// malformed.
    ///
    /// # Examples
    ///
    /// This demonstrates how to create a compressed, signed message
    /// from a detached signature.
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use std::convert::TryFrom;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::packet::{Packet, Signature, one_pass_sig::OnePassSig3};
    /// # use openpgp::parse::Parse;
    /// use openpgp::serialize::Serialize;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    ///
    /// let data: &[u8] = // ...
    /// # &include_bytes!(
    /// # "../../tests/data/messages/a-cypherpunks-manifesto.txt")[..];
    /// let sig: Signature = // ...
    /// # if let Packet::Signature(s) = Packet::from_bytes(&include_bytes!(
    /// # "../../tests/data/messages/a-cypherpunks-manifesto.txt.ed25519.sig")[..])?
    /// # { s } else { panic!() };
    ///
    /// # let mut sink = vec![]; // Vec<u8> implements io::Write.
    /// let message = Message::new(&mut sink);
    /// let mut message = Compressor::new(message).build()?;
    ///
    /// // First, write a one-pass-signature packet.
    /// Packet::from(OnePassSig3::try_from(&sig)?)
    ///     .serialize(&mut message)?;
    ///
    /// // Then, add the literal data.
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(data)?;
    ///
    /// // Finally, pop the `LiteralWriter` off the stack to write the
    /// // signature.
    /// let mut message = message.finalize_one()?.unwrap();
    /// Packet::from(sig).serialize(&mut message)?;
    ///
    /// // Finalize the message.
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn finalize_one(self) -> Result<Option<Message<'a>>> {
        Ok(self.0.into_inner()?.map(|bs| Self::from(bs)))
    }

    /// Finalizes the message.
    ///
    /// Finalizes all writers on the stack, flushing any buffered
    /// data.
    ///
    /// # Note
    ///
    /// Failing to finalize the message may result in corrupted
    /// messages.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// # let mut sink = vec![]; // Vec<u8> implements io::Write.
    /// let message = Message::new(&mut sink);
    /// // Construct the writer stack here.
    /// let mut message = LiteralWriter::new(message).build()?;
    /// // Write literal data to `message` here.
    /// // ...
    /// // Finalize the message.
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn finalize(self) -> Result<()> {
        let mut stack = self;
        while let Some(s) = stack.finalize_one()? {
            stack = s;
        }
        Ok(())
    }
}

impl<'a> From<&'a mut (dyn io::Write + Send + Sync)> for Message<'a> {
    fn from(w: &'a mut (dyn io::Write + Send + Sync)) -> Self {
        writer::Generic::new(w, Cookie::new(0))
    }
}


/// Applies ASCII Armor to the message.
///
/// ASCII armored data (see [Section 6 of RFC 9580]) is a OpenPGP data
/// stream that has been base64-encoded and decorated with a header,
/// footer, and optional headers representing key-value pairs.  It can
/// be safely transmitted over protocols that can only transmit
/// printable characters, and can be handled by end users (e.g. copied
/// and pasted).
///
///   [Section 6 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-6
pub struct Armorer<'a> {
    kind: armor::Kind,
    headers: Vec<(String, String)>,
    inner: Message<'a>,
}
assert_send_and_sync!(Armorer<'_>);

impl<'a> Armorer<'a> {
    /// Creates a new armoring filter.
    ///
    /// By default, the type of the armored data is set to
    /// [`armor::Kind`]`::Message`.  To change it, use
    /// [`Armorer::kind`].  To add headers to the armor, use
    /// [`Armorer::add_header`].
    ///
    ///   [`armor::Kind`]: crate::armor::Kind
    ///   [`Armorer::kind`]: Armorer::kind()
    ///   [`Armorer::add_header`]: Armorer::add_header()
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Armorer, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Armorer::new(message)
    ///         // Customize the `Armorer` here.
    ///         .build()?;
    ///     let mut message = LiteralWriter::new(message).build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!("-----BEGIN PGP MESSAGE-----\n\
    ///             \n\
    ///             yxJiAAAAAABIZWxsbyB3b3JsZC4=\n\
    ///             =6nHv\n\
    ///             -----END PGP MESSAGE-----\n",
    ///            std::str::from_utf8(&sink)?);
    /// # Ok(()) }
    pub fn new(inner: Message<'a>) -> Self {
        Self {
            kind: armor::Kind::Message,
            headers: Vec::with_capacity(0),
            inner,
        }
    }

    /// Changes the kind of armoring.
    ///
    /// The armor header and footer changes depending on the type of
    /// wrapped data.  See [`armor::Kind`] for the possible values.
    ///
    ///   [`armor::Kind`]: crate::armor::Kind
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::armor;
    /// use openpgp::serialize::stream::{Message, Armorer, Signer};
    /// # use sequoia_openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    /// # let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair
    /// #     = cert.keys().secret()
    /// #           .with_policy(p, None).alive().revoked(false).for_signing()
    /// #           .nth(0).unwrap()
    /// #           .key().clone().into_keypair()?;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Armorer::new(message)
    ///         .kind(armor::Kind::Signature)
    ///         .build()?;
    ///     let mut signer = Signer::new(message, signing_keypair)?
    ///         .detached()
    ///         .build()?;
    ///
    ///     // Write the data directly to the `Signer`.
    ///     signer.write_all(b"Make it so, number one!")?;
    ///     // In reality, just io::copy() the file to be signed.
    ///     signer.finalize()?;
    /// }
    ///
    /// assert!(std::str::from_utf8(&sink)?
    ///         .starts_with("-----BEGIN PGP SIGNATURE-----\n"));
    /// # Ok(()) }
    pub fn kind(mut self, kind: armor::Kind) -> Self {
        self.kind = kind;
        self
    }

    /// Adds a header to the armor block.
    ///
    /// There are a number of defined armor header keys (see [Section
    /// 6 of RFC 9580]), but in practice, any key may be used, as
    /// implementations should simply ignore unknown keys.
    ///
    ///   [Section 6 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-6
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Armorer, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Armorer::new(message)
    ///         .add_header("Comment", "No comment.")
    ///         .build()?;
    ///     let mut message = LiteralWriter::new(message).build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!("-----BEGIN PGP MESSAGE-----\n\
    ///             Comment: No comment.\n\
    ///             \n\
    ///             yxJiAAAAAABIZWxsbyB3b3JsZC4=\n\
    ///             =6nHv\n\
    ///             -----END PGP MESSAGE-----\n",
    ///            std::str::from_utf8(&sink)?);
    /// # Ok(()) }
    pub fn add_header<K, V>(mut self, key: K, value: V) -> Self
        where K: AsRef<str>,
              V: AsRef<str>,
    {
        self.headers.push((key.as_ref().to_string(),
                           value.as_ref().to_string()));
        self
    }

    /// Builds the armor writer, returning the writer stack.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Armorer, LiteralWriter};
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Armorer::new(message)
    ///     // Customize the `Armorer` here.
    ///     .build()?;
    /// # Ok(()) }
    pub fn build(self) -> Result<Message<'a>> {
        let level = self.inner.as_ref().cookie_ref().level;
        let mut cookie = Cookie::new(level + 1);
        cookie.private = Private::Armorer {
            set_profile: None,
        };

        writer::Armorer::new(
            self.inner,
            cookie,
            self.kind,
            self.headers,
        )
    }
}

impl<'a> fmt::Debug for Armorer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Armorer")
            .field("inner", &self.inner)
            .field("kind", &self.kind)
            .field("headers", &self.headers)
            .finish()
    }
}


/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// This is mainly useful for testing.  The body will be written using
/// partial length encoding, or, if the body is short, using full
/// length encoding.
pub struct ArbitraryWriter<'a> {
    inner: writer::BoxStack<'a, Cookie>,
}
assert_send_and_sync!(ArbitraryWriter<'_>);

impl<'a> ArbitraryWriter<'a> {
    /// Creates a new writer with the given tag.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::packet::Tag;
    /// use openpgp::serialize::stream::{Message, ArbitraryWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = ArbitraryWriter::new(message, Tag::Literal)?;
    ///     message.write_all(b"t")?;                   // type
    ///     message.write_all(b"\x00")?;                // filename length
    ///     message.write_all(b"\x00\x00\x00\x00")?;    // date
    ///     message.write_all(b"Hello world.")?;        // body
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    pub fn new(mut inner: Message<'a>, tag: Tag)
               -> Result<Message<'a>> {
        let level = inner.as_ref().cookie_ref().level + 1;
        CTB::new(tag).serialize(&mut inner)?;
        Ok(Message::from(Box::new(ArbitraryWriter {
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
    fn inner_ref(&self) -> Option<&(dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut (dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
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

/// Signs a message.
///
/// Signs a message with every [`crypto::Signer`] added to the
/// streaming signer.
///
///   [`crypto::Signer`]: super::super::crypto::Signer
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
    signers: Vec<(Box<dyn crypto::Signer + Send + Sync + 'a>,
                  HashAlgorithm, Vec<u8>)>,

    /// The set of acceptable hashes.
    acceptable_hash_algos: Vec<HashAlgorithm>,

    /// The explicitly selected algo, if any.
    hash_algo: Option<HashAlgorithm>,

    intended_recipients: Vec<Fingerprint>,
    mode: SignatureMode,
    template: signature::SignatureBuilder,
    creation_time: Option<SystemTime>,
    hashes: Vec<HashingMode<crypto::hash::Context>>,
    cookie: Cookie,
    position: u64,
}
assert_send_and_sync!(Signer<'_>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignatureMode {
    Inline,
    Detached,
    Cleartext,
}

impl<'a> Signer<'a> {
    /// Creates a signer.
    ///
    /// Signs the message with the given [`crypto::Signer`].  To
    /// create more than one signature, add more [`crypto::Signer`]s
    /// using [`Signer::add_signer`].  Properties of the signatures
    /// can be tweaked using the methods of this type.  Notably, to
    /// generate a detached signature (see [Section 10.4 of RFC
    /// 9580]), use [`Signer::detached`].  For even more control over
    /// the generated signatures, use [`Signer::with_template`].
    ///
    ///   [`crypto::Signer`]: super::super::crypto::Signer
    ///   [`Signer::add_signer`]: Signer::add_signer()
    ///   [Section 10.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.4
    ///   [`Signer::detached`]: Signer::detached()
    ///   [`Signer::with_template`]: Signer::with_template()
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::{Read, Write};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// let p = &StandardPolicy::new();
    /// let cert: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// let signing_keypair = cert.keys().secret()
    ///     .with_policy(p, None).supported().alive().revoked(false).for_signing()
    ///     .nth(0).unwrap()
    ///     .key().clone().into_keypair()?;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Signer::new(message, signing_keypair)?
    ///         // Customize the `Signer` here.
    ///         .build()?;
    ///     let mut message = LiteralWriter::new(message).build()?;
    ///     message.write_all(b"Make it so, number one!")?;
    ///     message.finalize()?;
    /// }
    ///
    /// // Now check the signature.
    /// struct Helper<'a>(&'a openpgp::Cert);
    /// impl<'a> VerificationHelper for Helper<'a> {
    ///     fn get_certs(&mut self, _: &[openpgp::KeyHandle])
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
    /// let mut verifier = VerifierBuilder::from_bytes(&sink)?
    ///     .with_policy(p, None, Helper(&cert))?;
    ///
    /// let mut message = String::new();
    /// verifier.read_to_string(&mut message)?;
    /// assert_eq!(&message, "Make it so, number one!");
    /// # Ok(()) }
    /// ```
    pub fn new<S>(inner: Message<'a>, signer: S) -> Result<Self>
        where S: crypto::Signer + Send + Sync + 'a
    {
        Self::with_template(inner, signer,
                            signature::SignatureBuilder::new(SignatureType::Binary))
    }

    /// Creates a signer with a given signature template.
    ///
    /// Signs the message with the given [`crypto::Signer`] like
    /// [`Signer::new`], but allows more control over the generated
    /// signatures.  The given [`signature::SignatureBuilder`] is used to
    /// create all the signatures.
    ///
    /// For every signature, the creation time is set to the current
    /// time or the one specified using [`Signer::creation_time`], the
    /// intended recipients are added (see
    /// [`Signer::add_intended_recipient`]), the issuer and issuer
    /// fingerprint subpackets are set according to the signing key,
    /// and the hash algorithm set using [`Signer::hash_algo`] is used
    /// to create the signature.
    ///
    ///   [`crypto::Signer`]: super::super::crypto::Signer
    ///   [`Signer::new`]: Message::new()
    ///   [`signature::SignatureBuilder`]: crate::packet::signature::SignatureBuilder
    ///   [`Signer::creation_time`]: Signer::creation_time()
    ///   [`Signer::hash_algo`]: Signer::hash_algo()
    ///   [`Signer::add_intended_recipient`]: Signer::add_intended_recipient()
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::{Read, Write};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::SignatureType;
    /// use openpgp::packet::signature;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    /// #
    /// # let p = &StandardPolicy::new();
    /// # let cert: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).supported().alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    /// # let mut sink = vec![];
    ///
    /// let message = Message::new(&mut sink);
    /// let message = Signer::with_template(
    ///     message, signing_keypair,
    ///     signature::SignatureBuilder::new(SignatureType::Text)
    ///         .add_notation("issuer@starfleet.command", "Jean-Luc Picard",
    ///                       None, true)?)?
    ///     // Further customize the `Signer` here.
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn with_template<S, T>(inner: Message<'a>, signer: S, template: T)
                               -> Result<Self>
        where S: crypto::Signer + Send + Sync + 'a,
              T: Into<signature::SignatureBuilder>,
    {
        let inner = writer::BoxStack::from(inner);
        let level = inner.cookie_ref().level + 1;
        Signer {
            inner: Some(inner),
            signers: Default::default(),
            acceptable_hash_algos:
            crate::crypto::hash::default_hashes().to_vec(),
            intended_recipients: Vec::new(),
            mode: SignatureMode::Inline,
            template: template.into(),
            creation_time: None,
            hash_algo: Default::default(),
            hashes: vec![],
            cookie: Cookie {
                level,
                private: Private::Signer,
            },
            position: 0,
        }.add_signer(signer)
    }

    /// Creates a signer for a detached signature.
    ///
    /// Changes the `Signer` to create a detached signature (see
    /// [Section 10.4 of RFC 9580]).  Note that the literal data *must
    /// not* be wrapped using the [`LiteralWriter`].
    ///
    /// This overrides any prior call to [`Signer::cleartext`].
    ///
    ///   [Section 10.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.4
    ///   [`Signer::cleartext`]: Signer::cleartext()
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer};
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair
    /// #     = cert.keys().secret()
    /// #           .with_policy(p, None).supported().alive().revoked(false).for_signing()
    /// #           .nth(0).unwrap()
    /// #           .key().clone().into_keypair()?;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut signer = Signer::new(message, signing_keypair)?
    ///         .detached()
    ///         // Customize the `Signer` here.
    ///         .build()?;
    ///
    ///     // Write the data directly to the `Signer`.
    ///     signer.write_all(b"Make it so, number one!")?;
    ///     // In reality, just io::copy() the file to be signed.
    ///     signer.finalize()?;
    /// }
    ///
    /// // Now check the signature.
    /// struct Helper<'a>(&'a openpgp::Cert);
    /// impl<'a> VerificationHelper for Helper<'a> {
    ///     fn get_certs(&mut self, _: &[openpgp::KeyHandle])
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
    /// let mut verifier = DetachedVerifierBuilder::from_bytes(&sink)?
    ///     .with_policy(p, None, Helper(&cert))?;
    ///
    /// verifier.verify_bytes(b"Make it so, number one!")?;
    /// # Ok(()) }
    /// ```
    pub fn detached(mut self) -> Self {
        self.mode = SignatureMode::Detached;
        self
    }

    /// Creates a signer for a cleartext signed message.
    ///
    /// Changes the `Signer` to create a cleartext signed message (see
    /// [Section 7 of RFC 9580]).  Note that the literal data *must
    /// not* be wrapped using the [`LiteralWriter`].  This implies
    /// ASCII armored output, *do not* add an [`Armorer`] to the
    /// stack.
    ///
    /// Note:
    ///
    /// - The cleartext signature framework does not hash trailing
    ///   whitespace (in this case, space and tab, see [Section 7.2 of
    ///   RFC 9580] for more information).  We align what we emit and
    ///   what is being signed by trimming whitespace off of line
    ///   endings.
    ///
    /// - That means that you can not recover a byte-accurate copy of
    ///   the signed message if your message contains either a line
    ///   with trailing whitespace, or no final newline.  This is a
    ///   limitation of the Cleartext Signature Framework, which is
    ///   not designed to be reversible (see [Section 7 of RFC 9580]).
    ///
    /// This overrides any prior call to [`Signer::detached`].
    ///
    ///   [Section 7 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-7
    ///   [Section 7.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-7.2
    ///   [`Signer::detached`]: Signer::detached()
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::{Write, Read};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer};
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair
    /// #     = cert.keys().secret()
    /// #           .with_policy(p, None).supported().alive().revoked(false).for_signing()
    /// #           .nth(0).unwrap()
    /// #           .key().clone().into_keypair()?;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut signer = Signer::new(message, signing_keypair)?
    ///         .cleartext()
    ///         // Customize the `Signer` here.
    ///         .build()?;
    ///
    ///     // Write the data directly to the `Signer`.
    ///     signer.write_all(b"Make it so, number one!")?;
    ///     // In reality, just io::copy() the file to be signed.
    ///     signer.finalize()?;
    /// }
    ///
    /// // Now check the signature.
    /// struct Helper<'a>(&'a openpgp::Cert);
    /// impl<'a> VerificationHelper for Helper<'a> {
    ///     fn get_certs(&mut self, _: &[openpgp::KeyHandle])
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
    /// let mut verifier = VerifierBuilder::from_bytes(&sink)?
    ///     .with_policy(p, None, Helper(&cert))?;
    ///
    /// let mut content = Vec::new();
    /// verifier.read_to_end(&mut content)?;
    /// assert_eq!(content, b"Make it so, number one!");
    /// # Ok(()) }
    /// ```
    //
    // Some notes on the implementation:
    //
    // There are a few pitfalls when implementing the CSF.  We
    // separate concerns as much as possible.
    //
    // - Trailing whitespace must be stripped.  We do this using the
    //   TrailingWSFilter before the data hits this streaming signer.
    //   This filter also adds a final newline, if missing.
    //
    // - We hash what we get from the TrailingWSFilter.
    //
    // - We write into the DashEscapeFilter, which takes care of the
    //   dash-escaping.
    pub fn cleartext(mut self) -> Self {
        self.mode = SignatureMode::Cleartext;
        self
    }

    /// Adds an additional signer.
    ///
    /// Can be used multiple times.
    ///
    /// Note that some signers only support a subset of hash
    /// algorithms, see [`crate::crypto::Signer.acceptable_hashes`].
    /// If the given signer supports at least one hash from the
    /// current set of acceptable hashes, the signer is added and all
    /// algorithms not supported by it are removed from the set of
    /// acceptable hashes.  Otherwise, an error is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).supported().alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    /// # let additional_signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).supported().alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)?
    ///     .add_signer(additional_signing_keypair)?
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn add_signer<S>(mut self, signer: S) -> Result<Self>
        where S: crypto::Signer + Send + Sync + 'a
    {
        // Update the set of acceptable hash algorithms.
        let is_sorted = |data: &[HashAlgorithm]| {
            data.windows(2).all(|w| w[0] <= w[1])
        };

        let mut signer_hashes = signer.acceptable_hashes();
        let mut signer_hashes_;
        if ! is_sorted(signer_hashes) {
            signer_hashes_ = signer_hashes.to_vec();
            signer_hashes_.sort();
            signer_hashes = &signer_hashes_;
        }
        self.acceptable_hash_algos.retain(
            |hash| signer_hashes.binary_search(hash).is_ok());

        if self.acceptable_hash_algos.is_empty() {
            return Err(Error::NoAcceptableHash.into());
        }

        if let Some(a) = self.hash_algo {
            if ! self.acceptable_hash_algos.contains(&a) {
                return Err(Error::NoAcceptableHash.into());
            }
        }

        self.signers.push((Box::new(signer), Default::default(), Vec::new()));
        Ok(self)
    }

    /// Adds an intended recipient.
    ///
    /// Indicates that the given certificate is an intended recipient
    /// of this message.  Can be used multiple times.  This prevents
    /// [*Surreptitious Forwarding*] of encrypted and signed messages,
    /// i.e. forwarding a signed message using a different encryption
    /// context.
    ///
    ///   [*Surreptitious Forwarding*]: http://world.std.com/~dtd/sign_encrypt/sign_encrypt7.html
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).supported().alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    /// let recipient: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy.pgp")[..])?;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)?
    ///     .add_intended_recipient(&recipient)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn add_intended_recipient(mut self, recipient: &Cert) -> Self {
        self.intended_recipients.push(recipient.fingerprint());
        self
    }

    /// Sets the preferred hash algorithm to use for the signatures.
    ///
    /// Note that some signers only support a subset of hash
    /// algorithms, see [`crate::crypto::Signer.acceptable_hashes`].
    /// If the given algorithm is not supported by all signers, an
    /// error is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::HashAlgorithm;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).supported().alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)?
    ///     .hash_algo(HashAlgorithm::SHA384)?
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn hash_algo(mut self, algo: HashAlgorithm) -> Result<Self> {
        if self.acceptable_hash_algos.contains(&algo) {
            self.hash_algo = Some(algo);
            Ok(self)
        } else {
            Err(Error::NoAcceptableHash.into())
        }
    }

    /// Sets the signature's creation time to `time`.
    ///
    /// Note: it is up to the caller to make sure the signing keys are
    /// actually valid as of `time`.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Timestamp;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// let p = &StandardPolicy::new();
    /// let cert: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// let signing_key = cert.keys().secret()
    ///     .with_policy(p, None).supported().alive().revoked(false).for_signing()
    ///     .nth(0).unwrap()
    ///     .key();
    /// let signing_keypair = signing_key.clone().into_keypair()?;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)?
    ///     .creation_time(Timestamp::now()
    ///                    .round_down(None, signing_key.creation_time())?)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn creation_time<T: Into<SystemTime>>(mut self, creation_time: T)
                                              -> Self
    {
        self.creation_time = Some(creation_time.into());
        self
    }

    /// Builds the signer, returning the writer stack.
    ///
    /// The most useful filter to push to the writer stack next is the
    /// [`LiteralWriter`].  Note, if you are creating a signed OpenPGP
    /// message (see [Section 10.3 of RFC 9580]), literal data *must*
    /// be wrapped using the [`LiteralWriter`].  On the other hand, if
    /// you are creating a detached signature (see [Section 10.4 of
    /// RFC 9580]), the literal data *must not* be wrapped using the
    /// [`LiteralWriter`].
    ///
    ///   [Section 10.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3
    ///   [Section 10.4 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.4
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Timestamp;
    /// use openpgp::serialize::stream::{Message, Signer};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let cert: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair
    /// #     = cert.keys().secret()
    /// #           .with_policy(p, None).supported().alive().revoked(false).for_signing()
    /// #           .nth(0).unwrap()
    /// #           .key().clone().into_keypair()?;
    /// #
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)?
    ///     // Customize the `Signer` here.
    ///     .build()?;
    /// # Ok(()) }
    /// ```
    pub fn build(mut self) -> Result<Message<'a>>
    {
        assert!(!self.signers.is_empty(), "The constructor adds a signer.");
        assert!(self.inner.is_some(), "The constructor adds an inner writer.");

        // Possibly configure any armor writer above us.
        if self.signers.iter().all(|(kp, _, _)| kp.public().version() > 4) {
            writer::Armorer::set_profile(&mut self, Profile::RFC9580);
        }

        for (keypair, signer_hash, signer_salt) in self.signers.iter_mut() {
            let algo = if let Some(a) = self.hash_algo {
                a
            } else {
                self.acceptable_hash_algos.get(0)
                    .expect("we make sure the set is never empty")
                    .clone()
            };
            *signer_hash = algo;
            let mut hash = algo.context()?
                .for_signature(keypair.public().version());

            match keypair.public().version() {
                4 => {
                    self.hashes.push(
                        if self.template.typ() == SignatureType::Text
                            || self.mode == SignatureMode::Cleartext
                        {
                            HashingMode::Text(vec![], hash)
                        } else {
                            HashingMode::Binary(vec![], hash)
                        });
                },
                6 => {
                    // Version 6 signatures are salted, and we
                    // need to include it in the OPS packet.
                    // Generate and remember the salt here.
                    let mut salt = vec![0; algo.salt_size()?];
                    crate::crypto::random(&mut salt)?;

                    // Add the salted context.
                    hash.update(&salt);
                    self.hashes.push(
                        if self.template.typ() == SignatureType::Text
                            || self.mode == SignatureMode::Cleartext
                        {
                            HashingMode::Text(salt.clone(), hash)
                        } else {
                            HashingMode::Binary(salt.clone(), hash)
                        });

                    // And remember which signer used which salt.
                    *signer_salt = salt;
                },
                v => return Err(Error::InvalidOperation(
                    format!("Unsupported Key version {}", v)).into()),
            }
        }

        match self.mode {
            SignatureMode::Inline => {
                // For every key we collected, build and emit a one pass
                // signature packet.
                let signers_count = self.signers.len();
                for (i, (keypair, hash_algo, salt)) in
                    self.signers.iter().enumerate()
                {
                    let last = i == signers_count - 1;
                    let key = keypair.public();

                    match key.version() {
                        4 => {
                            let mut ops = OnePassSig3::new(self.template.typ());
                            ops.set_pk_algo(key.pk_algo());
                            ops.set_hash_algo(*hash_algo);
                            ops.set_issuer(key.keyid());
                            ops.set_last(last);
                            Packet::from(ops)
                                .serialize(self.inner.as_mut().unwrap())?;
                        },
                        6 => {
                            // Version 6 signatures are salted, and we
                            // need to include it in the OPS packet.
                            let mut ops = OnePassSig6::new(
                                self.template.typ(), key.fingerprint());
                            ops.set_pk_algo(key.pk_algo());
                            ops.set_hash_algo(*hash_algo);
                            ops.set_salt(salt.clone());
                            ops.set_last(last);
                            Packet::from(ops)
                                .serialize(self.inner.as_mut().unwrap())?;
                        },
                        v => return Err(Error::InvalidOperation(
                            format!("Unsupported Key version {}", v)).into()),
                    }
                }
            },
            SignatureMode::Detached => (), // Do nothing.
            SignatureMode::Cleartext => {
                // Cleartext signatures are always text signatures.
                self.template = self.template.set_type(SignatureType::Text);

                // Write the header.
                let mut sink = self.inner.take().unwrap();
                writeln!(sink, "-----BEGIN PGP SIGNED MESSAGE-----")?;
                let mut hashes = self.signers.iter().filter_map(
                    |(keypair, algo, _)| if keypair.public().version() == 4 {
                        Some(algo)
                    } else {
                        None
                    })
                    .collect::<Vec<_>>();
                hashes.sort();
                hashes.dedup();
                for hash in hashes {
                    writeln!(sink, "Hash: {}", hash.text_name()?)?;
                }
                writeln!(sink)?;

                // We now install two filters.  See the comment on
                // Signer::cleartext.

                // Install the filter dash-escaping the text below us.
                self.inner =
                    Some(writer::BoxStack::from(
                        DashEscapeFilter::new(Message::from(sink),
                                              Default::default())));

                // Install the filter trimming the trailing whitespace
                // above us.
                return Ok(TrailingWSFilter::new(Message::from(Box::new(self)),
                                                Default::default()));
            },
        }

        Ok(Message::from(Box::new(self)))
    }

    fn emit_signatures(&mut self) -> Result<()> {
        if self.mode == SignatureMode::Cleartext {
            // Pop off the DashEscapeFilter.
            let mut inner =
                self.inner.take().expect("It's the DashEscapeFilter")
                .into_inner()?.expect("It's the DashEscapeFilter");

            // Add the separating newline that is not part of the message.
            writeln!(inner)?;

            // And install an armorer.
            self.inner =
                Some(writer::BoxStack::from(
                    writer::Armorer::new(Message::from(inner),
                                         Default::default(),
                                         armor::Kind::Signature,
                                         Option::<(&str, &str)>::None)?));
        }

        if let Some(ref mut sink) = self.inner {
            // Emit the signatures in reverse, so that the
            // one-pass-signature and signature packets "bracket" the
            // message.
            for (signer, algo, signer_salt) in self.signers.iter_mut().rev() {
                let (mut sig, hash) = match signer.public().version() {
                    4 => {
                        // V4 signature.

                        let hash = self.hashes.iter()
                            .find_map(|hash| {
                                if hash.salt().is_empty()
                                    && hash.as_ref().algo() == *algo
                                {
                                    Some(hash.clone())
                                } else {
                                    None
                                }
                            })
                            .expect("we put it in there");

                        // Make and hash a signature packet.
                        let sig = self.template.clone();

                        (sig, hash)
                    },
                    6 => {
                        // V6 signature.
                        let hash = self.hashes.iter()
                            .find_map(|hash| if signer_salt == hash.salt() {
                                Some(hash.clone())
                            } else {
                                None
                            })
                            .expect("we put it in there");

                        // Make and hash a signature packet.
                        let sig = self.template.clone()
                            .set_prefix_salt(signer_salt.clone()).0;

                        (sig, hash)
                    },
                    v => return Err(Error::InvalidOperation(
                        format!("Unsupported Key version {}", v)).into()),
                };

                sig = sig.set_signature_creation_time(
                    self.creation_time
                        .unwrap_or_else(crate::now))?;

                if ! self.intended_recipients.is_empty() {
                    sig = sig.set_intended_recipients(
                        self.intended_recipients.clone())?;
                }

                // Compute the signature.
                let sig = sig.sign_hash(signer.as_mut(),
                                        hash.into_inner())?;

                // And emit the packet.
                Packet::Signature(sig).serialize(sink)?;
            }
        }
        Ok(())
    }
}

impl<'a> fmt::Debug for Signer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Signer")
            .field("inner", &self.inner)
            .field("cookie", &self.cookie)
            .field("mode", &self.mode)
            .finish()
    }
}

impl<'a> Write for Signer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Shortcut empty writes.  This is important for the code
        // below that delays hashing newlines when creating cleartext
        // signed messages.
        if buf.is_empty() {
            return Ok(0);
        }

        use SignatureMode::*;
        let written = match (self.inner.as_mut(), self.mode) {
            // If we are creating a normal signature, pass data
            // through.
            (Some(ref mut w), Inline) => w.write(buf),
            // If we are creating a detached signature, just hash all
            // bytes.
            (Some(_), Detached) => Ok(buf.len()),
            // If we are creating a cleartext signed message, just
            // write through (the DashEscapeFilter takes care of the
            // encoding), and hash all bytes as is.
            (Some(ref mut w), Cleartext) => w.write(buf),
            // When we are popped off the stack, we have no inner
            // writer.  Just hash all bytes.
            (None, _) => Ok(buf.len()),
        };

        if let Ok(amount) = written {
            let data = &buf[..amount];

            self.hashes.iter_mut().for_each(
                |hash| hash.update(data));
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
    fn inner_mut(&mut self) -> Option<&mut (dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_ref(&self) -> Option<&(dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
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
/// Literal data, i.e. the payload or plaintext, must be wrapped in a
/// literal data packet to be transported over OpenPGP (see [Section
/// 5.9 of RFC 9580]).  The body will be written using partial length
/// encoding, or, if the body is short, using full length encoding.
///
///   [Section 5.9 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.9
///
/// # Note on metadata
///
/// A literal data packet can communicate some metadata: a hint as to
/// what kind of data is transported, the original file name, and a
/// timestamp.  Note that this metadata will not be authenticated by
/// signatures (but will be authenticated by a SEIP/MDC container),
/// and are therefore unreliable and should not be trusted.
///
/// Therefore, it is good practice not to set this metadata when
/// creating a literal data packet, and not to interpret it when
/// consuming one.
pub struct LiteralWriter<'a> {
    template: Literal,
    inner: writer::BoxStack<'a, Cookie>,
    signature_writer: Option<writer::BoxStack<'a, Cookie>>,
}
assert_send_and_sync!(LiteralWriter<'_>);

impl<'a> LiteralWriter<'a> {
    /// Creates a new literal writer.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         // Customize the `LiteralWriter` here.
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12b\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn new(inner: Message<'a>) -> Self {
        LiteralWriter {
            template: Literal::new(DataFormat::default()),
            inner: writer::BoxStack::from(inner),
            signature_writer: None,
        }
    }

    /// Sets the data format.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::DataFormat;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         .format(DataFormat::Unicode)
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12u\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn format(mut self, format: DataFormat) -> Self {
        self.template.set_format(format);
        self
    }

    /// Sets the filename.
    ///
    /// The standard does not specify the encoding.  Filenames must
    /// not be longer than 255 bytes.  Returns an error if the given
    /// name is longer than that.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         .filename("foobar")?
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x18b\x06foobar\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn filename<B: AsRef<[u8]>>(mut self, filename: B) -> Result<Self> {
        self.template.set_filename(filename.as_ref())?;
        Ok(self)
    }

    /// Sets the date.
    ///
    /// This date may be the modification date or the creation date.
    /// Returns an error if the given date is not representable by
    /// OpenPGP.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Timestamp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         .date(Timestamp::from(1585925313))?
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12b\x00\x5e\x87\x4c\xc1Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn date<T: Into<SystemTime>>(mut self, timestamp: T) -> Result<Self>
    {
        self.template.set_date(Some(timestamp.into()))?;
        Ok(self)
    }

    /// Builds the literal writer, returning the writer stack.
    ///
    /// The next step is to write the payload to the writer stack.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         // Customize the `LiteralWriter` here.
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12b\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn build(mut self) -> Result<Message<'a>> {
        let level = self.inner.cookie_ref().level + 1;

        // For historical reasons, signatures over literal data
        // packets only include the body without metadata or framing.
        // Therefore, we check whether the writer is a
        // Signer, and if so, we pop it off the stack and
        // store it in 'self.signature_writer'.
        let signer_above =
            matches!(self.inner.cookie_ref(), &Cookie {
                private: Private::Signer{..},
                ..
            });

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
            = PartialBodyFilter::new(Message::from(self.inner),
                                     Cookie::new(level)).into();

        // Nor the headers.
        self.template.serialize_headers(&mut self.inner, false)?;

        Ok(Message::from(Box::new(self)))
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
    fn inner_ref(&self) -> Option<&(dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut (dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
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

/// Compresses a message.
///
/// Writes a compressed data packet containing all packets written to
/// this writer.
pub struct Compressor<'a> {
    algo: CompressionAlgorithm,
    level: CompressionLevel,
    inner: writer::BoxStack<'a, Cookie>,
}
assert_send_and_sync!(Compressor<'_>);

impl<'a> Compressor<'a> {
    /// Creates a new compressor using the default algorithm and
    /// compression level.
    ///
    /// To change the compression algorithm use [`Compressor::algo`].
    /// Use [`Compressor::level`] to change the compression level.
    ///
    ///   [`Compressor::algo`]: Compressor::algo()
    ///   [`Compressor::level`]: Compressor::level()
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    /// use openpgp::types::CompressionAlgorithm;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Compressor::new(message)
    ///     // Customize the `Compressor` here.
    /// #   .algo(CompressionAlgorithm::Uncompressed)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn new(inner: Message<'a>) -> Self {
        Self {
            algo: Default::default(),
            level: Default::default(),
            inner: inner.into(),
        }
    }

    /// Sets the compression algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    /// use openpgp::types::CompressionAlgorithm;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Compressor::new(message)
    ///         .algo(CompressionAlgorithm::Uncompressed)
    ///         .build()?;
    ///     let mut message = LiteralWriter::new(message).build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xc8\x15\x00\xcb\x12b\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn algo(mut self, algo: CompressionAlgorithm) -> Self {
        self.algo = algo;
        self
    }

    /// Sets the compression level.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    /// use openpgp::types::{CompressionAlgorithm, CompressionLevel};
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Compressor::new(message)
    /// #   .algo(CompressionAlgorithm::Uncompressed)
    ///     .level(CompressionLevel::fastest())
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn level(mut self, level: CompressionLevel) -> Self {
        self.level = level;
        self
    }

    /// Builds the compressor, returning the writer stack.
    ///
    /// The most useful filter to push to the writer stack next is the
    /// [`Signer`] or the [`LiteralWriter`].  Finally, literal data
    /// *must* be wrapped using the [`LiteralWriter`].
    ///
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    /// use openpgp::types::CompressionAlgorithm;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Compressor::new(message)
    ///     // Customize the `Compressor` here.
    /// #   .algo(CompressionAlgorithm::Uncompressed)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn build(mut self) -> Result<Message<'a>> {
        let level = self.inner.cookie_ref().level + 1;

        // Packet header.
        CTB::new(Tag::CompressedData).serialize(&mut self.inner)?;
        let inner: Message<'a>
            = PartialBodyFilter::new(Message::from(self.inner),
                                     Cookie::new(level));

        Self::new_naked(inner, self.algo, self.level, level)
    }


    /// Creates a new compressor using the given algorithm.
    pub(crate) // For CompressedData::serialize.
    fn new_naked(mut inner: Message<'a>,
                 algo: CompressionAlgorithm,
                 compression_level: CompressionLevel,
                 level: usize)
                 -> Result<Message<'a>>
    {
        // Compressed data header.
        inner.as_mut().write_u8(algo.into())?;

        // Create an appropriate filter.
        let inner: Message<'a> = match algo {
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

        Ok(Message::from(Box::new(Self {
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
    fn inner_ref(&self) -> Option<&(dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut (dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
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
///
/// OpenPGP messages are encrypted with the subkeys of recipients,
/// identified by the keyid of said subkeys in the [`recipient`] field
/// of [`PKESK`] packets (see [Section 5.1 of RFC 9580]).  The keyid
/// may be a wildcard (as returned by [`KeyID::wildcard()`]) to
/// obscure the identity of the recipient.
///
///   [`recipient`]: crate::packet::PKESK#method.recipient
///   [`PKESK`]: crate::packet::PKESK
///   [Section 5.1 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.1
///   [`KeyID::wildcard()`]: crate::KeyID::wildcard()
///
/// Note that several subkeys in a certificate may be suitable
/// encryption subkeys.  OpenPGP does not specify what should happen
/// in this case.  Some implementations arbitrarily pick one
/// encryption subkey, while others use all of them.  This crate does
/// not dictate a policy, but allows for arbitrary policies.  We do,
/// however, suggest to encrypt to all suitable subkeys.
#[derive(Debug)]
pub struct Recipient<'a> {
    handle: Option<KeyHandle>,
    features: Features,
    key: &'a Key<key::PublicParts, key::UnspecifiedRole>,
}
assert_send_and_sync!(Recipient<'_>);

impl<'a, P> From<ValidSubordinateKeyAmalgamation<'a, P>>
    for Recipient<'a>
where
    P: key::KeyParts,
{
    fn from(ka: ValidSubordinateKeyAmalgamation<'a, P>) -> Self {
        let features = ka.valid_cert().features()
            .unwrap_or_else(Features::empty);
        let handle: KeyHandle = if features.supports_seipdv2() {
            ka.key().fingerprint().into()
        } else {
            ka.key().keyid().into()
        };

        use crate::cert::Preferences;
        use crate::cert::amalgamation::ValidAmalgamation;
        Self::new(features, handle,
                  ka.key().parts_as_public().role_as_unspecified())
    }
}

impl<'a, P> From<ValidErasedKeyAmalgamation<'a, P>>
    for Recipient<'a>
where
    P: key::KeyParts,
{
    fn from(ka: ValidErasedKeyAmalgamation<'a, P>) -> Self {
        let features = ka.valid_cert().features()
            .unwrap_or_else(Features::empty);
        let handle: KeyHandle = if features.supports_seipdv2() {
            ka.key().fingerprint().into()
        } else {
            ka.key().keyid().into()
        };

        use crate::cert::Preferences;
        use crate::cert::amalgamation::ValidAmalgamation;
        Self::new(features, handle,
                  ka.key().parts_as_public().role_as_unspecified())
    }
}

impl<'a> Recipient<'a> {
    /// Creates a new recipient with an explicit recipient keyid.
    ///
    /// Note: If you don't want to change the recipient keyid,
    /// `Recipient`s can be created from [`Key`] and
    /// [`ValidKeyAmalgamation`] using [`From`].
    ///
    ///   [`Key`]: crate::packet::Key
    ///   [`ValidKeyAmalgamation`]: crate::cert::amalgamation::key::ValidKeyAmalgamation
    ///   [`From`]: std::convert::From
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Recipient, Message, Encryptor,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    ///
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      xjMEWlNvABYJKwYBBAHaRw8BAQdA+EC2pvebpEbzPA9YplVgVXzkIG5eK+7wEAez
    /// #    lcBgLJrNMVRlc3R5IE1jVGVzdGZhY2UgKG15IG5ldyBrZXkpIDx0ZXN0eUBleGFt
    /// #    cGxlLm9yZz7CkAQTFggAOBYhBDnRAKtn1b2MBAECBfs3UfFYfa7xBQJaU28AAhsD
    /// #    BQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEPs3UfFYfa7xJHQBAO4/GABMWUcJ
    /// #    5D/DZ9b+6YiFnysSjCT/gILJgxMgl7uoAPwJherI1pAAh49RnPHBR1IkWDtwzX65
    /// #    CJG8sDyO2FhzDs44BFpTbwASCisGAQQBl1UBBQEBB0B+A0GRHuBgdDX50T1nePjb
    /// #    mKQ5PeqXJbWEtVrUtVJaPwMBCAfCeAQYFggAIBYhBDnRAKtn1b2MBAECBfs3UfFY
    /// #    fa7xBQJaU28AAhsMAAoJEPs3UfFYfa7xzjIBANX2/FgDX3WkmvwpEHg/sn40zACM
    /// #    W2hrBY5x0sZ8H7JlAP47mCfCuRVBqyaePuzKbxLJeLe2BpDdc0n2izMVj8t9Cg==
    /// #    =QetZ
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).supported().alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption()
    ///     // Make an anonymous recipient.
    ///     .map(|ka| Recipient::new(ka.valid_cert().features(), None, ka.key()));
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Encryptor::for_recipients(message, recipients).build()?;
    /// # let _ = message;
    /// # Ok(()) }
    /// ```
    pub fn new<F, H, P, R>(features: F, handle: H, key: &'a Key<P, R>)
                           -> Recipient<'a>
    where
        F: Into<Option<Features>>,
        H: Into<Option<KeyHandle>>,
        P: key::KeyParts,
        R: key::KeyRole,
    {
        Recipient {
            features: features.into().unwrap_or_else(Features::sequoia),
            handle: handle.into(),
            key: key.parts_as_public().role_as_unspecified(),
        }
    }

    /// Gets the recipient keyid.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::Recipient;
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    ///
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      xjMEWlNvABYJKwYBBAHaRw8BAQdA+EC2pvebpEbzPA9YplVgVXzkIG5eK+7wEAez
    /// #    lcBgLJrNMVRlc3R5IE1jVGVzdGZhY2UgKG15IG5ldyBrZXkpIDx0ZXN0eUBleGFt
    /// #    cGxlLm9yZz7CkAQTFggAOBYhBDnRAKtn1b2MBAECBfs3UfFYfa7xBQJaU28AAhsD
    /// #    BQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEPs3UfFYfa7xJHQBAO4/GABMWUcJ
    /// #    5D/DZ9b+6YiFnysSjCT/gILJgxMgl7uoAPwJherI1pAAh49RnPHBR1IkWDtwzX65
    /// #    CJG8sDyO2FhzDs44BFpTbwASCisGAQQBl1UBBQEBB0B+A0GRHuBgdDX50T1nePjb
    /// #    mKQ5PeqXJbWEtVrUtVJaPwMBCAfCeAQYFggAIBYhBDnRAKtn1b2MBAECBfs3UfFY
    /// #    fa7xBQJaU28AAhsMAAoJEPs3UfFYfa7xzjIBANX2/FgDX3WkmvwpEHg/sn40zACM
    /// #    W2hrBY5x0sZ8H7JlAP47mCfCuRVBqyaePuzKbxLJeLe2BpDdc0n2izMVj8t9Cg==
    /// #    =QetZ
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).supported().alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption()
    ///     .map(Into::into)
    ///     .collect::<Vec<Recipient>>();
    ///
    /// assert_eq!(recipients[0].key_handle().unwrap(),
    ///            "8BD8 8E94 C0D2 0333".parse()?);
    /// # Ok(()) }
    /// ```
    pub fn key_handle(&self) -> Option<KeyHandle> {
        self.handle.clone()
    }

    /// Sets the recipient key ID or fingerprint.
    ///
    /// When setting the recipient for a v6 key, either `None` or a
    /// fingerprint must be supplied.  Returns
    /// [`Error::InvalidOperation`] if a key ID is given instead.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::{KeyHandle, KeyID};
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Recipient, Message, Encryptor,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    ///
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      xjMEWlNvABYJKwYBBAHaRw8BAQdA+EC2pvebpEbzPA9YplVgVXzkIG5eK+7wEAez
    /// #    lcBgLJrNMVRlc3R5IE1jVGVzdGZhY2UgKG15IG5ldyBrZXkpIDx0ZXN0eUBleGFt
    /// #    cGxlLm9yZz7CkAQTFggAOBYhBDnRAKtn1b2MBAECBfs3UfFYfa7xBQJaU28AAhsD
    /// #    BQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEPs3UfFYfa7xJHQBAO4/GABMWUcJ
    /// #    5D/DZ9b+6YiFnysSjCT/gILJgxMgl7uoAPwJherI1pAAh49RnPHBR1IkWDtwzX65
    /// #    CJG8sDyO2FhzDs44BFpTbwASCisGAQQBl1UBBQEBB0B+A0GRHuBgdDX50T1nePjb
    /// #    mKQ5PeqXJbWEtVrUtVJaPwMBCAfCeAQYFggAIBYhBDnRAKtn1b2MBAECBfs3UfFY
    /// #    fa7xBQJaU28AAhsMAAoJEPs3UfFYfa7xzjIBANX2/FgDX3WkmvwpEHg/sn40zACM
    /// #    W2hrBY5x0sZ8H7JlAP47mCfCuRVBqyaePuzKbxLJeLe2BpDdc0n2izMVj8t9Cg==
    /// #    =QetZ
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).supported().alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption()
    ///     .map(|ka| Recipient::from(ka)
    ///         // Set the recipient keyid to the wildcard id.
    ///         .set_key_handle(None)
    ///             .expect("always safe")
    ///         // Same, but explicit.  Don't do this.
    ///         .set_key_handle(KeyHandle::KeyID(KeyID::wildcard()))
    ///             .expect("safe for v4 recipient")
    ///     );
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Encryptor::for_recipients(message, recipients).build()?;
    /// # let _ = message;
    /// # Ok(()) }
    /// ```
    pub fn set_key_handle<H>(mut self, handle: H) -> Result<Self>
    where
        H: Into<Option<KeyHandle>>,
    {
        let handle = handle.into();
        if self.key.version() == 6
            && matches!(handle, Some(KeyHandle::KeyID(_)))
        {
            return Err(Error::InvalidOperation(
                "need a fingerprint for v6 recipient key".into()).into());
        }

        self.handle = handle;
        Ok(self)
    }
}

/// Encrypts a message.
///
/// The stream will be encrypted using a generated session key, which
/// will be encrypted using the given passwords, and for all given
/// recipients.
///
/// An [`Recipient`] is an encryption-capable (sub)key.  Note that a
/// certificate may have more than one encryption-capable subkey, and
/// even the primary key may be encryption-capable.
///
///
/// To encrypt for more than one certificate, iterate over the
/// certificates and select encryption-capable keys, making sure that
/// at least one key is selected from each certificate.
///
/// # Examples
///
/// This demonstrates encrypting for multiple certificates.
///
/// ```
/// # fn main() -> sequoia_openpgp::Result<()> {
/// # use std::io::Write;
/// # use sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::parse::Parse;
/// use openpgp::serialize::stream::{
///     Message, Encryptor, LiteralWriter,
/// };
/// use openpgp::policy::StandardPolicy;
/// let p = &StandardPolicy::new();
///
/// # let (cert_0, _) =
/// #     CertBuilder::general_purpose(Some("Mr. Pink ☮☮☮"))
/// #     .generate()?;
/// # let (cert_1, _) =
/// #     CertBuilder::general_purpose(Some("Mr. Pink ☮☮☮"))
/// #     .generate()?;
/// let recipient_certs = vec![cert_0, cert_1];
/// let mut recipients = Vec::new();
/// for cert in recipient_certs.iter() {
///     // Make sure we add at least one subkey from every
///     // certificate.
///     let mut found_one = false;
///     for key in cert.keys().with_policy(p, None)
///         .supported().alive().revoked(false).for_transport_encryption()
///     {
///         recipients.push(key);
///         found_one = true;
///     }
///
///     if ! found_one {
///         return Err(anyhow::anyhow!("No suitable encryption subkey for {}",
///                                    cert));
///     }
/// }
/// # assert_eq!(recipients.len(), 2);
///
/// # let mut sink = vec![];
/// let message = Message::new(&mut sink);
/// let message = Encryptor::for_recipients(message, recipients).build()?;
/// let mut w = LiteralWriter::new(message).build()?;
/// w.write_all(b"Hello world.")?;
/// w.finalize()?;
/// # Ok(()) }
/// ```
pub struct Encryptor<'a, 'b>
where 'b: 'a
{
    inner: writer::BoxStack<'a, Cookie>,
    session_key: Option<SessionKey>,
    recipients: Vec<Recipient<'b>>,
    passwords: Vec<Password>,
    sym_algo: SymmetricAlgorithm,
    aead_algo: Option<AEADAlgorithm>,
    /// For the MDC packet.
    hash: crypto::hash::Context,
    cookie: Cookie,
}
assert_send_and_sync!(Encryptor<'_, '_>);

impl<'a, 'b> Encryptor<'a, 'b> {
    /// Creates a new encryptor for the given recipients.
    ///
    /// To add more recipients, use [`Encryptor::add_recipients`].  To
    /// add passwords, use [`Encryptor::add_passwords`].  To change
    /// the symmetric encryption algorithm, use
    /// [`Encryptor::symmetric_algo`].
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      xjMEWlNvABYJKwYBBAHaRw8BAQdA+EC2pvebpEbzPA9YplVgVXzkIG5eK+7wEAez
    /// #    lcBgLJrNMVRlc3R5IE1jVGVzdGZhY2UgKG15IG5ldyBrZXkpIDx0ZXN0eUBleGFt
    /// #    cGxlLm9yZz7CkAQTFggAOBYhBDnRAKtn1b2MBAECBfs3UfFYfa7xBQJaU28AAhsD
    /// #    BQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEPs3UfFYfa7xJHQBAO4/GABMWUcJ
    /// #    5D/DZ9b+6YiFnysSjCT/gILJgxMgl7uoAPwJherI1pAAh49RnPHBR1IkWDtwzX65
    /// #    CJG8sDyO2FhzDs44BFpTbwASCisGAQQBl1UBBQEBB0B+A0GRHuBgdDX50T1nePjb
    /// #    mKQ5PeqXJbWEtVrUtVJaPwMBCAfCeAQYFggAIBYhBDnRAKtn1b2MBAECBfs3UfFY
    /// #    fa7xBQJaU28AAhsMAAoJEPs3UfFYfa7xzjIBANX2/FgDX3WkmvwpEHg/sn40zACM
    /// #    W2hrBY5x0sZ8H7JlAP47mCfCuRVBqyaePuzKbxLJeLe2BpDdc0n2izMVj8t9Cg==
    /// #    =QetZ
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).supported().alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption();
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Encryptor::for_recipients(message, recipients).build()?;
    /// let mut w = LiteralWriter::new(message).build()?;
    /// w.write_all(b"Hello world.")?;
    /// w.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn for_recipients<R>(inner: Message<'a>, recipients: R) -> Self
        where R: IntoIterator,
              R::Item: Into<Recipient<'b>>,
    {
        Self {
            inner: inner.into(),
            session_key: None,
            recipients: recipients.into_iter().map(|r| r.into()).collect(),
            passwords: Vec::new(),
            sym_algo: Default::default(),
            aead_algo: Default::default(),
            hash: HashAlgorithm::SHA1.context().unwrap().for_digest(),
            cookie: Default::default(), // Will be fixed in build.
        }
    }

    /// Creates a new encryptor for the given passwords.
    ///
    /// To add more passwords, use [`Encryptor::add_passwords`].  To
    /// add recipients, use [`Encryptor::add_recipients`].  To change
    /// the symmetric encryption algorithm, use
    /// [`Encryptor::symmetric_algo`].
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Encryptor::with_passwords(
    ///     message, Some("совершенно секретно")).build()?;
    /// let mut w = LiteralWriter::new(message).build()?;
    /// w.write_all(b"Hello world.")?;
    /// w.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn with_passwords<P>(inner: Message<'a>, passwords: P) -> Self
        where P: IntoIterator,
              P::Item: Into<Password>,
    {
        Self {
            inner: inner.into(),
            session_key: None,
            recipients: Vec::new(),
            passwords: passwords.into_iter().map(|p| p.into()).collect(),
            sym_algo: Default::default(),
            aead_algo: Default::default(),
            hash: HashAlgorithm::SHA1.context().unwrap().for_digest(),
            cookie: Default::default(), // Will be fixed in build.
        }
    }

    /// Creates a new encryptor for the given algorithm and session
    /// key.
    ///
    /// Usually, the encryptor creates a session key and decrypts it
    /// for the given recipients and passwords.  Using this function,
    /// the session key can be supplied instead.  There are two main
    /// use cases for this:
    ///
    ///   - Replying to an encrypted message usually requires the
    ///     encryption (sub)keys for every recipient.  If even one key
    ///     is not available, it is not possible to encrypt the new
    ///     session key.  Rather than falling back to replying
    ///     unencrypted, one can reuse the original message's session
    ///     key that was encrypted for every recipient and reuse the
    ///     original [`PKESK`]s.
    ///
    ///   - Using the encryptor if the session key is transmitted or
    ///     derived using a scheme not supported by Sequoia.
    ///
    /// To add more passwords, use [`Encryptor::add_passwords`].  To
    /// add recipients, use [`Encryptor::add_recipients`].
    ///
    /// # Examples
    ///
    /// This example demonstrates how to fall back to the original
    /// message's session key in order to encrypt a reply.
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// # use std::io::{self, Write};
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::{KeyHandle, KeyID, Fingerprint, Result};
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::{KeyPair, SessionKey};
    /// # use openpgp::types::SymmetricAlgorithm;
    /// # use openpgp::parse::{Parse, stream::*};
    /// # use openpgp::serialize::{Serialize, stream::*};
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// # let p = &StandardPolicy::new();
    /// #
    /// // Generate two keys.
    /// let (alice, _) = CertBuilder::general_purpose(
    ///         Some("Alice Lovelace <alice@example.org>")).generate()?;
    /// let (bob, _) = CertBuilder::general_purpose(
    ///         Some("Bob Babbage <bob@example.org>")).generate()?;
    ///
    /// // Encrypt a message for both keys.
    /// let recipients = vec![&alice, &bob].into_iter().flat_map(|cert| {
    ///     cert.keys().with_policy(p, None).supported().alive().revoked(false)
    ///         .for_transport_encryption()
    /// });
    ///
    /// let mut original = vec![];
    /// let message = Message::new(&mut original);
    /// let message = Encryptor::for_recipients(message, recipients).build()?;
    /// let mut w = LiteralWriter::new(message).build()?;
    /// w.write_all(b"Original message")?;
    /// w.finalize()?;
    ///
    /// // Decrypt original message using Alice's key.
    /// let mut decryptor = DecryptorBuilder::from_bytes(&original)?
    ///     .with_policy(p, None, Helper::new(alice))?;
    /// io::copy(&mut decryptor, &mut io::sink())?;
    /// let (algo, sk, pkesks) = decryptor.into_helper().recycling_bin.unwrap();
    ///
    /// // Compose the reply using the same session key.
    /// let mut reply = vec![];
    /// let mut message = Message::new(&mut reply);
    /// for p in pkesks { // Emit the stashed PKESK packets.
    ///     Packet::from(p).serialize(&mut message)?;
    /// }
    /// let message = Encryptor::with_session_key(
    ///     message, algo.unwrap_or_default(), sk)?
    ///     .aead_algo(Default::default())
    ///     .build()?;
    /// let mut w = LiteralWriter::new(message).build()?;
    /// w.write_all(b"Encrypted reply")?;
    /// w.finalize()?;
    ///
    /// // Check that Bob can decrypt it.
    /// let mut decryptor = DecryptorBuilder::from_bytes(&reply)?
    ///     .with_policy(p, None, Helper::new(bob))?;
    /// io::copy(&mut decryptor, &mut io::sink())?;
    ///
    /// /// Decrypts the message preserving algo, session key, and PKESKs.
    /// struct Helper {
    ///     key: Cert,
    ///     recycling_bin: Option<(Option<SymmetricAlgorithm>, SessionKey, Vec<PKESK>)>,
    /// }
    ///
    /// # impl Helper {
    /// #     fn new(key: Cert) -> Self {
    /// #         Helper { key, recycling_bin: None, }
    /// #     }
    /// # }
    /// #
    /// impl DecryptionHelper for Helper {
    ///     fn decrypt(&mut self, pkesks: &[PKESK], _skesks: &[SKESK],
    ///                sym_algo: Option<SymmetricAlgorithm>,
    ///                decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
    ///                -> Result<Option<Cert>>
    ///     {
    ///         let p = &StandardPolicy::new();
    ///         let mut encryption_context = None;
    ///
    ///         for pkesk in pkesks { // Try each PKESK until we succeed.
    ///             for ka in self.key.keys().with_policy(p, None)
    ///                 .supported().unencrypted_secret()
    ///                 .key_handles(pkesk.recipient())
    ///                 .for_storage_encryption().for_transport_encryption()
    ///             {
    ///                 let mut pair = ka.key().clone().into_keypair().unwrap();
    ///                 if pkesk.decrypt(&mut pair, sym_algo)
    ///                     .map(|(algo, session_key)| {
    ///                         let success = decrypt(algo, &session_key);
    ///                         if success {
    ///                             // Copy algor, session key, and PKESKs.
    ///                             encryption_context =
    ///                                 Some((algo, session_key.clone(),
    ///                                       pkesks.iter().cloned().collect()));
    ///                         }
    ///                         success
    ///                     })
    ///                     .unwrap_or(false)
    ///                 {
    ///                     break; // Decryption successful.
    ///                 }
    ///             }
    ///         }
    ///
    ///         self.recycling_bin = encryption_context; // Store for the reply.
    ///         Ok(Some(self.key.clone()))
    ///     }
    /// }
    ///
    /// impl VerificationHelper for Helper {
    ///     // ...
    /// #   fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
    /// #       Ok(Vec::new()) // Lookup certificates here.
    /// #   }
    /// #   fn check(&mut self, structure: MessageStructure) -> Result<()> {
    /// #       Ok(()) // Implement your verification policy here.
    /// #   }
    /// }
    /// # Ok(()) }
    /// ```
    pub fn with_session_key(inner: Message<'a>,
                            sym_algo: SymmetricAlgorithm,
                            session_key: SessionKey)
                            -> Result<Self>
    {
        let sym_key_size = sym_algo.key_size()?;
        if session_key.len() != sym_key_size {
            return Err(Error::InvalidArgument(
                format!("{} requires a {} bit key, but session key has {}",
                        sym_algo, sym_key_size, session_key.len())).into());
        }

        Ok(Self {
            inner: inner.into(),
            session_key: Some(session_key),
            recipients: Vec::new(),
            passwords: Vec::with_capacity(0),
            sym_algo,
            aead_algo: Default::default(),
            hash: HashAlgorithm::SHA1.context().unwrap().for_digest(),
            cookie: Default::default(), // Will be fixed in build.
        })
    }

    /// Adds recipients.
    ///
    /// The resulting message can be encrypted by any recipient and
    /// with any password.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
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
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).supported().alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption();
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::with_passwords(message, Some("совершенно секретно"))
    ///     .add_recipients(recipients)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn add_recipients<R>(mut self, recipients: R) -> Self
        where R: IntoIterator,
              R::Item: Into<Recipient<'b>>,
    {
        for r in recipients {
            self.recipients.push(r.into());
        }
        self
    }

    /// Adds passwords to encrypt with.
    ///
    /// The resulting message can be encrypted with any password and
    /// by any recipient.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
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
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).supported().alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption();
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::for_recipients(message, recipients)
    ///         .add_passwords(Some("совершенно секретно"))
    ///         .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn add_passwords<P>(mut self, passwords: P) -> Self
        where P: IntoIterator,
              P::Item: Into<Password>,
    {
        for p in passwords {
            self.passwords.push(p.into());
        }
        self
    }

    /// Sets the symmetric algorithm to use.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::SymmetricAlgorithm;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::with_passwords(message, Some("совершенно секретно"))
    ///         .symmetric_algo(SymmetricAlgorithm::AES128)
    ///         .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn symmetric_algo(mut self, algo: SymmetricAlgorithm) -> Self {
        self.sym_algo = algo;
        self
    }

    /// Enables AEAD and sets the AEAD algorithm to use.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::AEADAlgorithm;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::with_passwords(message, Some("совершенно секретно"))
    ///         .aead_algo(AEADAlgorithm::default())
    ///         .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn aead_algo(mut self, algo: AEADAlgorithm) -> Self {
        self.aead_algo = Some(algo);
        self
    }

    // The default chunk size.
    //
    // A page, 3 per mille overhead.
    const AEAD_CHUNK_SIZE : usize = 4096;

    /// Builds the encryptor, returning the writer stack.
    ///
    /// The most useful filters to push to the writer stack next are
    /// the [`Padder`] or [`Compressor`], and after that the
    /// [`Signer`].  Finally, literal data *must* be wrapped using the
    /// [`LiteralWriter`].
    ///
    ///   [`Padder`]: padding::Padder
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::with_passwords(message, Some("совершенно секретно"))
    ///         // Customize the `Encryptor` here.
    ///         .build()?;
    ///
    /// // Optionally add a `Padder` or `Compressor` here.
    /// // Optionally add a `Signer` here.
    ///
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn build(mut self) -> Result<Message<'a>> {
        if self.recipients.len() + self.passwords.len() == 0
            && self.session_key.is_none()
        {
            return Err(Error::InvalidOperation(
                "Neither recipients, passwords, nor session key given".into()
            ).into());
        }

        if self.aead_algo.is_none() {
            // See whether all recipients support SEIPDv2.
            if ! self.recipients.is_empty()
                && self.recipients.iter().all(|r| {
                    r.features.supports_seipdv2()
                })
            {
                // This prefers OCB if supported.  OCB is MTI.
                self.aead_algo = Some(AEADAlgorithm::default());
            }
        }

        struct AEADParameters {
            algo: AEADAlgorithm,
            chunk_size: usize,
            salt: [u8; 32],
        }

        let aead = if let Some(algo) = self.aead_algo {
            // Configure any armor writer above us.
            writer::Armorer::set_profile(&mut self, Profile::RFC9580);

            let mut salt = [0u8; 32];
            crypto::random(&mut salt)?;
            Some(AEADParameters {
                algo,
                chunk_size: Self::AEAD_CHUNK_SIZE,
                salt,
            })
        } else {
            None
        };

        let mut inner = self.inner;
        let level = inner.as_ref().cookie_ref().level + 1;

        // Reuse existing session key or generate a new one.
        let sym_key_size = self.sym_algo.key_size()?;
        let sk = self.session_key.take()
            .map(|sk| Ok(sk))
            .unwrap_or_else(|| SessionKey::new(sym_key_size))?;
        if sk.len() != sym_key_size {
            return Err(Error::InvalidOperation(
                format!("{} requires a {} bit key, but session key has {}",
                        self.sym_algo, sym_key_size, sk.len())).into());
        }

        // Write the PKESK packet(s).
        for recipient in self.recipients.iter() {
            if aead.is_some() {
                let mut pkesk =
                    PKESK6::for_recipient(&sk, recipient.key)?;
                pkesk.set_recipient(recipient.key_handle()
                                    .map(TryInto::try_into)
                                    .transpose()?);
                Packet::from(pkesk).serialize(&mut inner)?;
            } else {
                let mut pkesk =
                    PKESK3::for_recipient(self.sym_algo, &sk, recipient.key)?;
                pkesk.set_recipient(recipient.key_handle().map(Into::into));
                Packet::PKESK(pkesk.into()).serialize(&mut inner)?;
            }
        }

        // Write the SKESK packet(s).
        for password in self.passwords.iter() {
            if let Some(aead) = aead.as_ref() {
                let skesk = SKESK6::with_password(self.sym_algo,
                                                  self.sym_algo,
                                                  aead.algo,
                                                  Default::default(),
                                                  &sk, password).unwrap();
                Packet::SKESK(skesk.into()).serialize(&mut inner)?;
            } else {
                let skesk = SKESK4::with_password(self.sym_algo,
                                                  self.sym_algo,
                                                  Default::default(),
                                                  &sk, password).unwrap();
                Packet::SKESK(skesk.into()).serialize(&mut inner)?;
            }
        }

        if let Some(aead) = aead {
            // Write the SEIPDv2 packet.
            CTB::new(Tag::SEIP).serialize(&mut inner)?;
            let mut inner = PartialBodyFilter::new(Message::from(inner),
                                                   Cookie::new(level));
            let seip = SEIP2::new(self.sym_algo, aead.algo,
                                 aead.chunk_size as u64, aead.salt)?;
            seip.serialize_headers(&mut inner)?;

            use crate::crypto::aead::SEIPv2Schedule;
            let schedule = SEIPv2Schedule::new(
                &sk,
                seip.symmetric_algo(), seip.aead(), aead.chunk_size,
                seip.salt())?;

            // Note: we have consumed self, and we are returning a
            // different encryptor here.  self will be dropped, and
            // therefore, Self::emit_mdc will not be invoked.

            writer::AEADEncryptor::new(
                inner,
                Cookie::new(level).set_private(Private::Encryptor {
                    profile: Profile::RFC9580,
                }),
                seip.symmetric_algo(),
                seip.aead(),
                aead.chunk_size,
                schedule,
            )
        } else {
            // Write the SEIPDv1 packet.
            CTB::new(Tag::SEIP).serialize(&mut inner)?;
            let mut inner = PartialBodyFilter::new(Message::from(inner),
                                                   Cookie::new(level));
            inner.write_all(&[1])?; // Version.

            // Install encryptor.
            self.inner = writer::Encryptor::new(
                inner,
                Cookie::new(level),
                self.sym_algo,
                &sk,
            )?.into();
            self.cookie = Cookie::new(level)
                .set_private(Private::Encryptor {
                    profile: Profile::RFC4880,
                });

            // Write the initialization vector, and the quick-check
            // bytes.  The hash for the MDC must include the
            // initialization vector, hence we must write this to
            // self after installing the encryptor at self.inner.
            let mut iv = vec![0; self.sym_algo.block_size()?];
            crypto::random(&mut iv)?;
            self.write_all(&iv)?;
            self.write_all(&iv[iv.len() - 2..])?;

            Ok(Message::from(Box::new(self)))
        }
    }

    /// Emits the MDC packet and recovers the original writer.
    ///
    /// Note: This is only invoked for SEIPDv1 messages, because
    /// Self::build consumes self, and will only return a writer stack
    /// with Self on top for SEIPDv1 messages.  For SEIPDv2 messages,
    /// a different writer is returned.
    fn emit_mdc(mut self) -> Result<writer::BoxStack<'a, Cookie>> {
        let mut w = self.inner;

        // Write the MDC, which must be the last packet inside the
        // encrypted packet stream.  The hash includes the MDC's
        // CTB and length octet.
        let mut header = Vec::new();
        CTB::new(Tag::MDC).serialize(&mut header)?;
        BodyLength::Full(20).serialize(&mut header)?;

        self.hash.update(&header);
        #[allow(deprecated)]
        Packet::MDC(MDC::from(self.hash.clone())).serialize(&mut w)?;

        // Now recover the original writer.  First, strip the
        // Encryptor.
        let w = w.into_inner()?.unwrap();
        // And the partial body filter.
        let w = w.into_inner()?.unwrap();

        Ok(w)
    }
}

impl<'a, 'b> fmt::Debug for Encryptor<'a, 'b>
    where 'b: 'a
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, 'b> Write for Encryptor<'a, 'b>
    where 'b: 'a
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf);
        if let Ok(amount) = written {
            self.hash.update(&buf[..amount]);
        }
        written
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, 'b> writer::Stackable<'a, Cookie> for Encryptor<'a, 'b>
    where 'b: 'a
{
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&(dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
        Some(&self.inner)
    }
    fn inner_mut(&mut self) -> Option<&mut (dyn writer::Stackable<'a, Cookie> + Send + Sync)> {
        Some(&mut self.inner)
    }
    fn into_inner(self: Box<Self>) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
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
        self.inner.position()
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use crate::{Packet, PacketPile, Profile, packet::CompressedData};
    use crate::parse::{Parse, PacketParserResult, PacketParser};
    use super::*;
    use crate::types::DataFormat::Unicode as T;
    use crate::policy::Policy;
    use crate::policy::StandardPolicy as P;

    #[test]
    fn arbitrary() {
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let mut ustr = ArbitraryWriter::new(m, Tag::Literal).unwrap();
            ustr.write_all(b"u").unwrap(); // type
            ustr.write_all(b"\x00").unwrap(); // fn length
            ustr.write_all(b"\x00\x00\x00\x00").unwrap(); // date
            ustr.write_all(b"Hello world.").unwrap(); // body
            ustr.finalize().unwrap();
        }

        let mut pp = PacketParser::from_bytes(&o).unwrap().unwrap();
        if let Packet::Literal(ref l) = pp.packet {
                assert_eq!(l.format(), DataFormat::Unicode);
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
        assert!(ppr.is_eof());
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
            ls.finalize().unwrap();
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
            ls.finalize().unwrap();
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
                key.clone().parts_into_secret().unwrap().into_keypair()
                    .expect("expected unencrypted secret key")
            }).collect::<Vec<KeyPair>>();

            let m = Message::new(&mut o);
            let mut signer = Signer::new(m, signers.pop().unwrap()).unwrap();
            for s in signers.into_iter() {
                signer = signer.add_signer(s).unwrap();
            }
            let signer = signer.build().unwrap();
            let mut ls = LiteralWriter::new(signer).build().unwrap();
            ls.write_all(b"Tis, tis, tis.  Tis is important.").unwrap();
            let _ = ls.finalize().unwrap();
        }

        let mut ppr = PacketParser::from_bytes(&o).unwrap();
        let mut good = 0;
        while let PacketParserResult::Some(mut pp) = ppr {
            if let Packet::Signature(sig) = &mut pp.packet {
                let key = keys.get(sig.issuer_fingerprints().next().unwrap())
                    .unwrap();
                sig.verify_document(key).unwrap();
                good += 1;
            }

            // Get the next packet.
            ppr = pp.recurse().unwrap().1;
        }
        assert_eq!(good, 2);
    }

    #[test]
    fn encryptor() {
        let passwords = vec!["streng geheim".into(),
                             "top secret".into()];
        let message = b"Hello world.";

        // Write a simple encrypted message...
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let encryptor = Encryptor::with_passwords(m, passwords.clone())
                .build().unwrap();
            let mut literal = LiteralWriter::new(encryptor).build()
                .unwrap();
            literal.write_all(message).unwrap();
            literal.finalize().unwrap();
        }

        // ... and recover it...
        #[derive(Debug, PartialEq)]
        enum State {
            Start,
            Decrypted(Vec<(Option<SymmetricAlgorithm>, SessionKey)>),
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
                    #[allow(deprecated)]
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
    fn aead_eax() -> Result<()> {
        test_aead_messages(AEADAlgorithm::EAX)
    }

    #[test]
    fn aead_ocb() -> Result<()> {
        test_aead_messages(AEADAlgorithm::OCB)
    }

    #[test]
    fn aead_gcm() -> Result<()> {
        test_aead_messages(AEADAlgorithm::GCM)
    }

    fn test_aead_messages(algo: AEADAlgorithm) -> Result<()> {
        test_aead_messages_v(algo, Profile::RFC4880)?;
        test_aead_messages_v(algo, Profile::RFC9580)?;
        Ok(())
    }

    fn test_aead_messages_v(algo: AEADAlgorithm, profile: Profile)
                            -> Result<()>
    {
        eprintln!("Testing with {:?}", profile);

        if ! algo.is_supported() {
            eprintln!("Skipping because {} is not supported.", algo);
            return Ok(());
        }

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
                DecryptorBuilder,
                DecryptionHelper,
                VerificationHelper,
                MessageStructure,
            },
        };
        use crate::cert::prelude::*;

        let (tsk, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .set_profile(profile)?
            .add_transport_encryption_subkey()
            .generate().unwrap();

        struct Helper<'a> {
            policy: &'a dyn Policy,
            tsk: &'a Cert,
        }
        impl<'a> VerificationHelper for Helper<'a> {
            fn get_certs(&mut self, _ids: &[crate::KeyHandle])
                               -> Result<Vec<Cert>> {
                Ok(Vec::new())
            }
            fn check(&mut self, _structure: MessageStructure) -> Result<()> {
                Ok(())
            }
            fn inspect(&mut self, pp: &PacketParser<'_>) -> Result<()> {
                assert!(! matches!(&pp.packet, Packet::Unknown(_)));
                eprintln!("Parsed {:?}", pp.packet);
                Ok(())
            }
        }
        impl<'a> DecryptionHelper for Helper<'a> {
            fn decrypt(&mut self, pkesks: &[PKESK], _skesks: &[SKESK],
                       sym_algo: Option<SymmetricAlgorithm>,
                       decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
                       -> Result<Option<Cert>>
            {
                let mut keypair = self.tsk.keys().with_policy(self.policy, None)
                    .for_transport_encryption()
                    .map(|ka| ka.key()).next().unwrap()
                    .clone().parts_into_secret().unwrap()
                    .into_keypair().unwrap();
                pkesks[0].decrypt(&mut keypair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key));
                Ok(None)
            }
        }

        let p = unsafe { &crate::policy::NullPolicy::new() };

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
                    let recipients = tsk
                        .keys().with_policy(p, None)
                        .for_storage_encryption().for_transport_encryption();
                    let encryptor = Encryptor::for_recipients(m, recipients)
                        .aead_algo(algo)
                        .build().unwrap();
                    let mut literal = LiteralWriter::new(encryptor).build()
                        .unwrap();
                    literal.write_all(&content).unwrap();
                    literal.finalize().unwrap();
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
                        let mut v = match DecryptorBuilder::from_bytes(&msg)?
                            .with_policy(p, None, h)
                        {
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
                        // should get all the content.
                        assert_eq!(msg_len, decrypted_content.len());
                        assert_eq!(content, decrypted_content);
                    }
                }
            }
        }
        Ok(())
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
        let ka = cert.keys().with_policy(p, None).for_signing().next().unwrap();

        // A timestamp later than the key's creation.
        let timestamp = ka.key().creation_time()
            + std::time::Duration::from_secs(14 * 24 * 60 * 60);
        assert!(ka.key().creation_time() < timestamp);

        let mut o = vec![];
        {
            let signer_keypair : KeyPair =
                ka.key().clone().parts_into_secret().unwrap().into_keypair()
                    .expect("expected unencrypted secret key");

            let m = Message::new(&mut o);
            let signer = Signer::new(m, signer_keypair).unwrap();
            let signer = signer.creation_time(timestamp);
            let signer = signer.build().unwrap();

            let mut ls = LiteralWriter::new(signer).build().unwrap();
            ls.write_all(b"Tis, tis, tis.  Tis is important.").unwrap();
            let signer = ls.finalize_one().unwrap().unwrap();
            let _ = signer.finalize_one().unwrap().unwrap();
        }

        let mut ppr = PacketParser::from_bytes(&o).unwrap();
        let mut good = 0;
        while let PacketParserResult::Some(mut pp) = ppr {
            if let Packet::Signature(sig) = &mut pp.packet {
                assert_eq!(sig.signature_creation_time(), Some(timestamp));
                sig.verify_document(ka.key()).unwrap();
                good += 1;
            }

            // Get the next packet.
            ppr = pp.recurse().unwrap().1;
        }
        assert_eq!(good, 1);
    }

    /// Checks that newlines are properly normalized when verifying
    /// text signatures.
    #[test]
    fn issue_530_signing() -> Result<()> {
        use std::io::Write;
        use crate::*;
        use crate::packet::signature;
        use crate::serialize::stream::{Message, Signer};

        use crate::policy::StandardPolicy;
        use crate::{Result, Cert};
        use crate::parse::Parse;
        use crate::parse::stream::*;

        let normalized_data = b"one\r\ntwo\r\nthree";

        let p = &StandardPolicy::new();
        let cert: Cert =
            Cert::from_bytes(crate::tests::key("testy-new-private.pgp"))?;

        for data in &[
            &b"one\r\ntwo\r\nthree"[..], // dos
            b"one\ntwo\nthree",          // unix
            b"one\ntwo\r\nthree",        // mixed
            b"one\r\ntwo\nthree",
            b"one\rtwo\rthree",          // classic mac
        ] {
            eprintln!("{:?}", String::from_utf8(data.to_vec())?);
            let signing_keypair = cert.keys().secret()
                .with_policy(p, None).supported()
                .alive().revoked(false).for_signing().next().unwrap()
                .key().clone().into_keypair()?;
            let mut signature = vec![];
            {
                let message = Message::new(&mut signature);
                let mut message = Signer::with_template(
                    message, signing_keypair,
                    signature::SignatureBuilder::new(SignatureType::Text)
                )?.detached().build()?;
                message.write_all(data)?;
                message.finalize()?;
            }

            struct Helper {}
            impl VerificationHelper for Helper {
                fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>>
                {
                    Ok(vec![
                        Cert::from_bytes(crate::tests::key("testy-new.pgp"))?])
                }
                fn check(&mut self, structure: MessageStructure) -> Result<()> {
                    for (i, layer) in structure.iter().enumerate() {
                        assert_eq!(i, 0);
                        if let MessageLayer::SignatureGroup { results } = layer
                        {
                            assert_eq!(results.len(), 1);
                            results[0].as_ref().unwrap();
                            assert!(results[0].is_ok());
                            return Ok(());
                        } else {
                            unreachable!();
                        }
                    }
                    unreachable!()
                }
            }

            let h = Helper {};
            let mut v = DetachedVerifierBuilder::from_bytes(&signature)?
                .with_policy(p, None, h)?;

            v.verify_bytes(data)?;
            v.verify_bytes(normalized_data)?;
        }

        Ok(())
    }

    struct BadSigner;

    impl crypto::Signer for BadSigner {
        fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
            panic!("public not impl")
        }

        /// Returns a list of hashes that this signer accepts.
        fn acceptable_hashes(&self) -> &[HashAlgorithm] {
            &[]
        }

        fn sign(&mut self, _hash_algo: HashAlgorithm, _digest: &[u8])
        -> Result<crypto::mpi::Signature> {
            panic!("sign not impl")
        }
    }

    struct GoodSigner(Vec<HashAlgorithm>, Key<key::PublicParts, key::UnspecifiedRole>);

    impl crypto::Signer for GoodSigner {
        fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
            &self.1
        }

        /// Returns a list of hashes that this signer accepts.
        fn acceptable_hashes(&self) -> &[HashAlgorithm] {
            &self.0
        }

        fn sign(&mut self, _hash_algo: HashAlgorithm, _digest: &[u8])
        -> Result<crypto::mpi::Signature> {
            unimplemented!()
        }
    }

    impl Default for GoodSigner {
        fn default() -> Self {
            let p = &P::new();

            let (cert, _) = CertBuilder::new().generate().unwrap();

            let ka = cert.keys().with_policy(p, None).next().unwrap();

            Self(vec![HashAlgorithm::default()], ka.key().clone())
        }
    }

    #[test]
    fn overlapping_hashes() {
        let mut signature = vec![];
        let message = Message::new(&mut signature);

        Signer::new(message, GoodSigner::default()).unwrap().build().unwrap();
    }

    #[test]
    fn no_overlapping_hashes() {
        let mut signature = vec![];
        let message = Message::new(&mut signature);

        if let Err(e) = Signer::new(message, BadSigner) {
            assert_eq!(e.downcast_ref::<Error>(), Some(&Error::NoAcceptableHash));
        } else {
            unreachable!();
        };
    }

    #[test]
    fn no_overlapping_hashes_for_new_signer() {
        let mut signature = vec![];
        let message = Message::new(&mut signature);

        let signer = Signer::new(message, GoodSigner::default()).unwrap();
        if let Err(e) = signer.add_signer(BadSigner) {
            assert_eq!(e.downcast_ref::<Error>(), Some(&Error::NoAcceptableHash));
        } else {
            unreachable!();
        };
    }

    /// Tests that multiple signatures are in the correct order.
    #[test]
    fn issue_816() -> Result<()> {
        use crate::{
            packet::key::{Key4, PrimaryRole},
            types::Curve,
            KeyHandle,
        };

        let signer_a =
            Key4::<_, PrimaryRole>::generate_ecc(true, Curve::Ed25519)?
            .into_keypair()?;

        let signer_b =
            Key4::<_, PrimaryRole>::generate_ecc(true, Curve::Ed25519)?
            .into_keypair()?;

        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let message = Signer::new(message, signer_a)?
            .add_signer(signer_b)?
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(b"Make it so, number one!")?;
        message.finalize()?;

        let pp = crate::PacketPile::from_bytes(&sink)?;
        assert_eq!(pp.children().count(), 5);

        let first_signer: KeyHandle =
            if let Packet::OnePassSig(ops) = pp.path_ref(&[0]).unwrap() {
                ops.issuer().into()
            } else {
                panic!("expected ops packet")
            };

        let second_signer: KeyHandle =
            if let Packet::OnePassSig(ops) = pp.path_ref(&[1]).unwrap() {
                ops.issuer().into()
            } else {
                panic!("expected ops packet")
            };

        assert!(matches!(pp.path_ref(&[2]).unwrap(), Packet::Literal(_)));

        // OPS and Signature packets "bracket" the literal, i.e. the
        // last occurring ops packet is met by the first occurring
        // signature packet.
        if let Packet::Signature(sig) = pp.path_ref(&[3]).unwrap() {
            assert!(sig.get_issuers()[0].aliases(&second_signer));
        } else {
            panic!("expected sig packet")
        }

        if let Packet::Signature(sig) = pp.path_ref(&[4]).unwrap() {
            assert!(sig.get_issuers()[0].aliases(&first_signer));
        } else {
            panic!("expected sig packet")
        }

        Ok(())
    }

    // Example copied from `Encryptor::aead_algo` and slightly
    // adjusted since the doctest from `Encryptor::aead_algo` does not
    // run.  Additionally this test case utilizes
    // `AEADAlgorithm::default` to detect which algorithm to
    // use.
    #[test]
    fn experimental_aead_encryptor() -> Result<()> {
        use std::io::Write;
        use crate::types::AEADAlgorithm;
        use crate::policy::NullPolicy;
        use crate::serialize::stream::{
            Message, Encryptor, LiteralWriter,
        };
        use crate::parse::stream::{
            DecryptorBuilder, VerificationHelper,
            DecryptionHelper, MessageStructure,
        };

        let mut sink = vec![];
        let message = Message::new(&mut sink);
        let message =
          Encryptor::with_passwords(message, Some("совершенно секретно"))
              .aead_algo(AEADAlgorithm::default())
              .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(b"Hello world.")?;
        message.finalize()?;

        struct Helper;

        impl VerificationHelper for Helper {
            fn get_certs(&mut self, _ids: &[crate::KeyHandle]) -> Result<Vec<Cert>> where {
                Ok(Vec::new())
            }

            fn check(&mut self, _structure: MessageStructure) -> Result<()> {
                Ok(())
            }
        }

        impl DecryptionHelper for Helper {
            fn decrypt(&mut self, _: &[PKESK], skesks: &[SKESK],
                       _sym_algo: Option<SymmetricAlgorithm>,
                       decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
                       -> Result<Option<Cert>>
            {
                skesks[0].decrypt(&"совершенно секретно".into())
                    .map(|(algo, session_key)| decrypt(algo, &session_key))?;
                Ok(None)
            }
        }

        let p = unsafe { &NullPolicy::new() };
        let mut v = DecryptorBuilder::from_bytes(&sink)?.with_policy(p, None, Helper)?;
        let mut content = vec![];
        v.read_to_end(&mut content)?;
        assert_eq!(content, b"Hello world.");
        Ok(())
    }

    /// Signs using our set of public keys.
    #[test]
    fn signer() -> Result<()> {
        use crate::policy::StandardPolicy;
        use crate::parse::stream::{
            VerifierBuilder,
            test::VHelper,
        };

        let p = StandardPolicy::new();
        for alg in &[
            "rsa", "dsa",
            "nistp256", "nistp384", "nistp521",
            "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
            "secp256k1",
        ] {
            eprintln!("Test vector {:?}...", alg);
            let key = Cert::from_bytes(crate::tests::key(
                &format!("signing/{}.pgp", alg)))?;
            if let Some(k) = key.with_policy(&p, None).ok()
                .and_then(|vcert| vcert.keys().for_signing().supported().next())
            {
                use crate::crypto::mpi::PublicKey;
                match k.key().mpis() {
                    PublicKey::ECDSA { curve, .. } |
                    PublicKey::EdDSA { curve, .. }
                    if ! curve.is_supported() => {
                        eprintln!("Skipping {} because we don't support \
                                   the curve {}", alg, curve);
                        continue;
                    },
                    _ => (),
                }
            } else {
                eprintln!("Skipping {} because we don't support the algorithm",
                          alg);
                continue;
            }

            let signing_keypair = key.keys().secret()
                .with_policy(&p, None).supported()
                .alive().revoked(false).for_signing()
                .nth(0).unwrap()
                .key().clone().into_keypair()?;

            let mut sink = vec![];
            let message = Message::new(&mut sink);
            let message = Signer::new(message, signing_keypair)?
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(b"Hello world.")?;
            message.finalize()?;

            let h = VHelper::new(1, 0, 0, 0, vec![key]);
            let mut d = VerifierBuilder::from_bytes(&sink)?
                .with_policy(&p, None, h)?;
            assert!(d.message_processed());

            let mut content = Vec::new();
            d.read_to_end(&mut content).unwrap();
            assert_eq!(&b"Hello world."[..], &content[..]);
        }

        Ok(())
    }

    /// Encrypts using public key cryptography.
    #[test]
    fn pk_encryptor() -> Result<()> {
        use crate::policy::StandardPolicy;
        use crate::parse::stream::{
            DecryptorBuilder,
            test::VHelper,
        };

        let p = StandardPolicy::new();
        for path in [
            "rsa", "elg", "cv25519", "cv25519.unclamped",
            "nistp256", "nistp384", "nistp521",
            "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1",
            "secp256k1",
        ].iter().map(|alg| format!("messages/encrypted/{}.sec.pgp", alg))
            .chain(vec![
                "crypto-refresh/v6-minimal-secret.key".into(),
            ].into_iter())
        {
            eprintln!("Test vector {:?}...", path);
            let key = Cert::from_bytes(crate::tests::file(&path))?;
            if let Some(k) =
                key.with_policy(&p, None)?.keys().subkeys().supported().next()
            {
                use crate::crypto::mpi::PublicKey;
                match k.key().mpis() {
                    PublicKey::ECDH { curve, .. } if ! curve.is_supported() => {
                        eprintln!("Skipping {} because we don't support \
                                   the curve {}", path, curve);
                        continue;
                    },
                    _ => (),
                }
            } else {
                eprintln!("Skipping {} because we don't support the algorithm",
                          path);
                continue;
            }

            let recipients =
                key.with_policy(&p, None)?.keys().for_storage_encryption();

            let mut sink = vec![];
            let message = Message::new(&mut sink);
            let message =
                Encryptor::for_recipients(message, recipients)
                .build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(b"Hello world.")?;
            message.finalize()?;

            let h = VHelper::for_decryption(0, 0, 0, 0, Vec::new(),
                                            vec![key], Vec::new());
            let mut d = DecryptorBuilder::from_bytes(&sink)?
                .with_policy(&p, None, h)?;
            assert!(d.message_processed());

            let mut content = Vec::new();
            d.read_to_end(&mut content).unwrap();
            assert_eq!(&b"Hello world."[..], &content[..]);
        }

        Ok(())
    }

    #[test]
    fn encryptor_lifetime()
    {
        // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/1028
        //
        // Using Encryptor instead of Encryptor, we get the error:
        //
        // pub fn _encrypt_data<'a, B: AsRef<[u8]>, R>(data: B, recipients: R)
        //                      -- lifetime `'a` defined here
        //
        //     let message = Message::new(&mut sink);
        //                   -------------^^^^^^^^^-
        //                   |            |
        //                   |            borrowed value does not live long enough
        //                   argument requires that `sink` is borrowed for `'a`
        //
        // }
        // - `sink` dropped here while still borrowed
        pub fn _encrypt_data<'a, B: AsRef<[u8]>, R>(data: B, recipients: R)
            -> anyhow::Result<Vec<u8>>
        where
            R: IntoIterator,
            R::Item: Into<Recipient<'a>>,
        {
            let mut sink = vec![];
            let message = Message::new(&mut sink);
            let armorer = Armorer::new(message).build()?;
            let encryptor = Encryptor::for_recipients(armorer, recipients).build()?;
            let mut writer = LiteralWriter::new(encryptor).build()?;
            writer.write_all(data.as_ref())?;
            writer.finalize()?;

            Ok(sink)
        }
    }

    /// Encrypts to a v4 and a v6 recipient using SEIPDv1.
    #[test]
    fn mixed_recipients_seipd1() -> Result<()> {
        let alice = CertBuilder::general_purpose(Some("alice"))
            .set_profile(Profile::RFC9580)?
            .generate()?.0;
        let bob = CertBuilder::general_purpose(Some("bob"))
            .set_profile(Profile::RFC4880)?
            .set_features(Features::empty().set_seipdv1())?
            .generate()?.0;
        mixed_recipients_intern(alice, bob, 1)
    }

    /// Encrypts to a v4 and a v6 recipient using SEIPDv2.
    #[test]
    fn mixed_recipients_seipd2() -> Result<()> {
        let alice = CertBuilder::general_purpose(Some("alice"))
            .set_profile(Profile::RFC9580)?
            .generate()?.0;
        let bob = CertBuilder::general_purpose(Some("bob"))
            .set_profile(Profile::RFC4880)?
            .generate()?.0;
        mixed_recipients_intern(alice, bob, 2)
    }

    fn mixed_recipients_intern(alice: Cert, bob: Cert, seipdv: u8)
                               -> Result<()>
    {
        use crate::policy::StandardPolicy;
        use crate::parse::stream::{
            DecryptorBuilder,
            test::VHelper,
        };

        let p = StandardPolicy::new();
        let recipients = [&alice, &bob].into_iter().flat_map(
            |c| c.keys().with_policy(&p, None).for_storage_encryption());

        let mut sink = vec![];
        let message = Message::new(&mut sink);
        let message =
            Encryptor::for_recipients(message, recipients)
            .build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(b"Hello world.")?;
        message.finalize()?;

        for key in [alice, bob] {
            eprintln!("Decrypting with key version {}",
                      key.primary_key().key().version());
            let h = VHelper::for_decryption(0, 0, 0, 0, Vec::new(),
                                            vec![key], Vec::new());
            let mut d = DecryptorBuilder::from_bytes(&sink)?
                .with_policy(&p, None, h)?;
            assert!(d.message_processed());

            let mut content = Vec::new();
            d.read_to_end(&mut content).unwrap();
            assert_eq!(&b"Hello world."[..], &content[..]);

            use Packet::*;
            match seipdv {
                1 => d.helper_ref().packets.iter().for_each(
                    |p| match p {
                        PKESK(p) => assert_eq!(p.version(), 3),
                        SKESK(p) => assert_eq!(p.version(), 4),
                        SEIP(p) => assert_eq!(p.version(), 1),
                        _ => (),
                    }),

                2 => d.helper_ref().packets.iter().for_each(
                    |p| match p {
                        PKESK(p) => assert_eq!(p.version(), 6),
                        SKESK(p) => assert_eq!(p.version(), 6),
                        SEIP(p) => assert_eq!(p.version(), 2),
                        _ => (),
                    }),

                _ => unreachable!(),
            }
        }

        Ok(())
    }
}
