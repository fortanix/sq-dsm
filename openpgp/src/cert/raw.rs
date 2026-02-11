//! Functionality for dealing with mostly unparsed certificates.
//!
//! Parsing a certificate is not cheap.  When reading a keyring, most
//! certificates are discarded or never used as they are not relevant.
//! This module provides the [`RawCertParser`] and [`RawCert`] data
//! structures that can help reduce the amount of unnecessary
//! computation.
//!
//! [`RawCertParser`] splits a keyring into [`RawCert`]s by looking
//! primarily at the packet framing and the packet headers.  This is
//! much faster than parsing the packets' contents, as the
//! [`CertParser`] does.
//!
//! [`CertParser`]: crate::cert::CertParser
//!
//! [`RawCert`] exposes just enough functionality to allow the user to
//! quickly check if a certificate is not relevant.  Note: to check if
//! a certificate is really relevant, the check usually needs to be
//! repeated after canonicalizing it (by using, e.g., [`Cert::from`])
//! and validating it (by using [`Cert::with_policy`]).
//!
//! [`Cert::from`]: From<RawCert>
//!
//! # Examples
//!
//! Search for a specific certificate in a keyring:
//!
//! ```rust
//! # use std::convert::TryFrom;
//! #
//! use sequoia_openpgp as openpgp;
//!
//! # use openpgp::Result;
//! use openpgp::cert::prelude::*;
//! use openpgp::cert::raw::RawCertParser;
//! use openpgp::parse::Parse;
//! # use openpgp::serialize::Serialize;
//! #
//! # fn main() -> Result<()> {
//! # fn doit() -> Result<Cert> {
//! #      let (cert, _) = CertBuilder::new()
//! #          .generate()?;
//! #      let fpr = cert.fingerprint();
//! #
//! #      let mut bytes = Vec::new();
//! #      cert.serialize(&mut bytes);
//! for cert in RawCertParser::from_bytes(&bytes)? {
//!     /// Ignore corrupt and invalid certificates.
//!     let cert = if let Ok(cert) = cert {
//!         cert
//!     } else {
//!         continue;
//!     };
//!
//!     if cert.fingerprint() == fpr {
//!         // Found it!  Try to convert it to a Cert.
//!         return Cert::try_from(cert);
//!     }
//! }
//!
//! // Not found.
//! return Err(anyhow::anyhow!("Not found!").into());
//! # }
//! # doit().expect("Found the certificate");
//! # Ok(())
//! # }
//! ```
use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt;

use buffered_reader::{BufferedReader, Dup, EOF, Memory};

use crate::Fingerprint;
use crate::KeyID;
use crate::Result;
use crate::armor;
use crate::cert::Cert;
use crate::packet::Header;
use crate::packet::Key;
use crate::packet::Packet;
use crate::packet::Tag;
use crate::packet::UserID;
use crate::packet::header::BodyLength;
use crate::packet::header::CTB;
use crate::packet::key;
use crate::parse::Cookie;
use crate::parse::PacketParser;
use crate::parse::Parse;
use crate::parse::RECOVERY_THRESHOLD;

use super::TRACE;

mod iter;
pub use iter::KeyIter;

/// A mostly unparsed `Packet`.
///
/// This is returned by [`RawCert::packets`].
///
/// The data includes the OpenPGP framing (i.e., the CTB, and length
/// information).  [`RawPacket::body`] returns just the bytes
/// corresponding to the packet's body, i.e., without the OpenPGP
/// framing.
///
/// You can convert it to a [`Packet`] using `TryFrom`.
///
/// # Examples
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::cert::raw::RawCert;
/// use openpgp::packet::Packet;
/// use openpgp::packet::Tag;
/// # use openpgp::parse::Parse;
/// # use openpgp::serialize::Serialize;
/// #
/// # fn main() -> Result<()> {
/// #      let (cert, _) = CertBuilder::new()
/// #          .add_signing_subkey()
/// #          .add_certification_subkey()
/// #          .add_transport_encryption_subkey()
/// #          .add_storage_encryption_subkey()
/// #          .add_authentication_subkey()
/// #          .generate()?;
/// #
/// #      let mut bytes = Vec::new();
/// #      cert.as_tsk().serialize(&mut bytes);
/// # let mut count = 0;
/// #
/// # let rawcert = RawCert::from_bytes(&bytes)?;
/// for p in rawcert.packets() {
///     if p.tag() == Tag::SecretSubkey {
///         if let Ok(packet) = Packet::try_from(p) {
///             // Do something with the packet.
/// #           count += 1;
///         }
/// #       else { panic!("Failed to parse packet"); }
///     }
/// }
/// #     assert_eq!(count, 5);
/// #     Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RawPacket<'a> {
    tag: Tag,
    header_len: usize,
    data: &'a [u8],
}
assert_send_and_sync!(RawPacket<'_>);

impl fmt::Debug for RawPacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawPacket")
            .field("tag", &self.tag)
            .field("data (bytes)", &self.data.len())
            .finish()
    }
}

impl<'a> RawPacket<'a> {
    fn new(tag: Tag, header_len: usize, bytes: &'a [u8]) -> Self {
        Self {
            tag,
            header_len,
            data: bytes,
        }
    }

    /// Returns the packet's tag.
    pub fn tag(&self) -> Tag {
        self.tag
    }

    /// Returns the packet's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.data
    }

    /// Return the packet's body without the OpenPGP framing.
    pub fn body(&self) -> &[u8] {
        &self.data[self.header_len..]
    }
}

impl<'a> TryFrom<RawPacket<'a>> for Packet {
    type Error = anyhow::Error;

    fn try_from(p: RawPacket<'a>) -> Result<Self> {
        Packet::from_bytes(p.as_bytes())
    }
}

impl<'a> crate::seal::Sealed for RawPacket<'a> {}
impl<'a> crate::serialize::Marshal for RawPacket<'a> {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        o.write_all(self.as_bytes())?;
        Ok(())
    }
}

/// A mostly unparsed `Cert`.
///
/// This data structure contains the unparsed packets for a
/// certificate or key.  The packet sequence is well-formed in the
/// sense that the sequence of tags conforms to the [Transferable
/// Public Key grammar] or [Transferable Secret Key grammar], and that
/// it can extract the primary key's fingerprint.  Beyond that, the
/// packets are not guaranteed to be valid.
///
/// [Transferable Public Key grammar]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.1
/// [Transferable Secret Key grammar]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.2
///
/// This data structure exists to quickly split a large keyring, and
/// only parse those certificates that appear to be relevant.
#[derive(Clone)]
pub struct RawCert<'a> {
    data: Cow<'a, [u8]>,

    primary_key: Key<key::PublicParts, key::PrimaryRole>,

    // The packet's tag, the length of the header, and the offset of
    // the start of the packet (including the header) into data.
    packets: Vec<(Tag, usize, usize)>,
}
assert_send_and_sync!(RawCert<'_>);

impl<'a> fmt::Debug for RawCert<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawCert")
            .field("fingerprint", &self.fingerprint())
            .field("packets",
                   &self.packets
                   .iter()
                   .map(|p| format!("{} (offset: {})", p.0, p.1))
                   .collect::<Vec<String>>()
                   .join(", "))
            .field("data (bytes)", &self.data.as_ref().len())
            .finish()
    }
}

impl<'a> PartialEq for RawCert<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<'a> Eq for RawCert<'a> {
}

impl<'a> RawCert<'a> {
    /// Returns the certificate's bytes.
    ///
    /// If you want an individual packet's bytes, use
    /// [`RawCert::packet`] or [`RawCert::packets`], and then call
    /// [`RawPacket::as_bytes`].
    pub fn as_bytes(&'a self) -> &'a [u8] {
        self.data.as_ref()
    }

    /// Returns the certificate's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.primary_key.fingerprint()
    }

    /// Returns the certificate's Key ID.
    pub fn keyid(&self) -> KeyID {
        KeyID::from(self.fingerprint())
    }

    /// Returns the ith packet.
    pub fn packet(&self, i: usize) -> Option<RawPacket> {
        let data: &[u8] = self.data.as_ref();

        let &(tag, header_len, start) = self.packets.get(i)?;
        let following = self.packets
            .get(i + 1)
            .map(|&(_, _, offset)| offset)
            .unwrap_or(data.len());

        Some(RawPacket::new(tag, header_len, &data[start..following]))
    }

    /// Returns an iterator over each raw packet.
    pub fn packets(&self) -> impl Iterator<Item=RawPacket> {
        let data: &[u8] = self.data.as_ref();

        let count = self.packets.len();
        (0..count)
            .map(move |i| {
                let (tag, header_len, start) = self.packets[i];
                let following = self.packets
                    .get(i + 1)
                    .map(|&(_, _, offset)| offset)
                    .unwrap_or(data.len());

                RawPacket::new(tag, header_len, &data[start..following])
            })
    }

    /// Returns the number of packets.
    pub fn count(&self) -> usize {
        self.packets.len()
    }

    /// Returns an iterator over the certificate's keys.
    ///
    /// Note: this parses the key packets, but it does not verify any
    /// binding signatures.  As such, this can only be used as part of
    /// a precheck.  If the certificate appears to match, then the
    /// caller must convert the [`RawCert`] to a [`Cert`] or a
    /// [`ValidCert`], depending on the requirements, and perform the
    /// check again.
    ///
    /// [`ValidCert`]: crate::cert::ValidCert
    ///
    /// Use [`subkeys`] to just return the subkeys.  This function
    /// also changes the return type.  Instead of the iterator
    /// returning a [`Key`] whose role is [`key::UnspecifiedRole`],
    /// the role is [`key::SubordinateRole`].
    ///
    /// [`subkeys`]: KeyIter::subkeys
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    //
    /// # use openpgp::Result;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::cert::raw::RawCertParser;
    /// use openpgp::parse::Parse;
    /// # use openpgp::serialize::Serialize;
    /// #
    /// # fn main() -> Result<()> {
    /// #      let (cert, _) = CertBuilder::new()
    /// #          .add_signing_subkey()
    /// #          .add_certification_subkey()
    /// #          .add_transport_encryption_subkey()
    /// #          .add_storage_encryption_subkey()
    /// #          .add_authentication_subkey()
    /// #          .generate()?;
    /// #
    /// #      let mut bytes = Vec::new();
    /// #      cert.serialize(&mut bytes);
    /// # let mut certs = 0;
    /// # let mut keys = 0;
    /// for cert in RawCertParser::from_bytes(&bytes)? {
    ///     /// Ignore corrupt and invalid certificates.
    ///     let cert = if let Ok(cert) = cert {
    ///         cert
    ///     } else {
    ///         continue;
    ///     };
    ///
    ///     // Iterate over the keys.  Note: this parses the Key
    ///     // packets.
    ///     for key in cert.keys() {
    ///         println!("{}", key.fingerprint());
    /// #       keys += 1;
    ///     }
    /// #   certs += 1;
    /// }
    /// # assert_eq!(certs, 1);
    /// # assert_eq!(keys, 6);
    /// #     Ok(())
    /// # }
    /// ```
    pub fn keys(&self) -> KeyIter<key::PublicParts, key::UnspecifiedRole> {
        KeyIter::new(self)
    }

    // Returns an iterator over the certificate's keys.
    //
    // This is used by `KeyIter`, which implements a number of
    // filters.
    fn keys_internal(&self)
        -> impl Iterator<Item=Key<key::PublicParts, key::UnspecifiedRole>> + '_
    {
        std::iter::once(self.primary_key().clone().role_into_unspecified())
            .chain(self.packets()
                   .filter(|p| matches!(p.tag(),
                                        Tag::PublicKey | Tag::PublicSubkey
                                        | Tag::SecretKey | Tag::SecretSubkey))
                   .skip(1) // The primary key.
                   .filter_map(|p| Key::from_bytes(p.body())
                               .ok()
                               .map(|k| k.parts_into_public())))
    }

    /// Returns the certificate's primary key.
    ///
    /// Note: this parses the primary key packet, but it does not
    /// verify any binding signatures.  As such, this can only be used
    /// as part of a precheck.  If the certificate appears to match,
    /// then the caller must convert the [`RawCert`] to a [`Cert`] or
    /// a [`ValidCert`], depending on the requirements, and perform
    /// the check again.
    ///
    /// [`ValidCert`]: crate::cert::ValidCert
    pub fn primary_key(&self) -> Key<key::PublicParts, key::PrimaryRole> {
        self.primary_key.clone()
    }

    /// Returns the certificate's User IDs.
    ///
    /// Note: this parses the User ID packets, but it does not verify
    /// any binding signatures.  That is, there is no guarantee that
    /// the User IDs should actually be associated with the primary
    /// key.  As such, this can only be used as part of a precheck.
    /// If a User ID appears to match, then the caller must convert
    /// the [`RawCert`] to a [`Cert`] or a [`ValidCert`], depending on
    /// the requirements, and perform the check again.
    ///
    /// [`ValidCert`]: crate::cert::ValidCert
    pub fn userids(&self) -> impl Iterator<Item=UserID> + '_
    {
        self.packets()
            .filter_map(|p| {
                if p.tag() == Tag::UserID {
                    UserID::try_from(p.body()).ok()
                } else {
                    None
                }
            })
    }

    /// Changes the `RawCert`'s lifetime to the static lifetime.
    ///
    /// Returns a `RawCert` with a static lifetime by copying any
    /// referenced data.
    ///
    /// [`RawCertParser::next`] returns a `RawCert` with the same
    /// lifetime as its reader.  In certain situations,
    /// `RawCertParser::next` can take advantage of this to avoid
    /// copying data.  Tying the `RawCert`'s lifetime to the reader is
    /// inconvenient when the `RawCert` needs to outlive the reader,
    /// however.  This function copies any referenced data thereby
    /// breaking the dependency.
    ///
    /// ```
    /// # use sequoia_openpgp::Result;
    /// # use sequoia_openpgp::cert::raw::RawCert;
    /// # use sequoia_openpgp::cert::raw::RawCertParser;
    /// # use sequoia_openpgp::parse::Parse;
    ///
    /// # fn main() -> Result<()> {
    /// fn read_certs<'a>() -> Result<Vec<RawCert<'static>>> {
    ///     let input = // ...
    ///     # Vec::new();
    ///
    ///     // The lifetime of the returned certs is tied to input.
    ///     // We use into_owned to break the dependency.
    ///     let parser = RawCertParser::from_bytes(&input)?;
    ///     let certs = parser
    ///         .map(|r| r.map(|c| c.into_owned()))
    ///         .collect::<Result<Vec<_>>>()?;
    ///     Ok(certs)
    /// }
    ///
    /// let cert = read_certs()?;
    /// # assert_eq!(cert.len(), 0);
    /// # Ok(()) }
    /// ```
    pub fn into_owned(self) -> RawCert<'static> {
        match self.data {
            Cow::Owned(data) => {
                RawCert {
                    data: Cow::Owned(data),
                    primary_key: self.primary_key,
                    packets: self.packets,
                }
            }
            Cow::Borrowed(data) => {
                RawCert {
                    data: Cow::Owned(data.to_vec()),
                    primary_key: self.primary_key,
                    packets: self.packets,
                }
            }
        }
    }
}

impl<'a> TryFrom<&RawCert<'a>> for Cert {
    type Error = anyhow::Error;

    fn try_from(c: &RawCert) -> Result<Self> {
        Cert::from_bytes(c.as_bytes())
    }
}

impl<'a> TryFrom<RawCert<'a>> for Cert {
    type Error = anyhow::Error;

    fn try_from(c: RawCert) -> Result<Self> {
        Cert::try_from(&c)
    }
}

impl<'a> Parse<'a, RawCert<'a>> for RawCert<'a> {
    /// Returns the first RawCert encountered in the reader.
    ///
    /// Returns an error if there are multiple certificates.
    fn from_buffered_reader<R>(reader: R) -> Result<RawCert<'a>>
    where
        R: BufferedReader<Cookie> + 'a
    {
        fn parse<'a>(reader: Box<dyn BufferedReader<Cookie> + 'a>) -> Result<RawCert<'a>> {
            let mut parser = RawCertParser::from_buffered_reader(reader)?;
            if let Some(cert_result) = parser.next() {
                if parser.next().is_some() {
                    Err(crate::Error::MalformedCert(
                        "Additional packets found, is this a keyring?".into()
                    ).into())
                } else {
                    cert_result
                }
            } else {
                Err(crate::Error::MalformedCert("No data".into()).into())
            }
        }

        parse(reader.into_boxed())
    }
}

impl<'a> crate::seal::Sealed for RawCert<'a> {}
impl<'a> crate::serialize::Marshal for RawCert<'a> {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        o.write_all(self.as_bytes())?;
        Ok(())
    }
}

/// An iterator over a sequence of unparsed certificates, i.e., an
/// OpenPGP keyring.
///
/// A `RawCertParser` returns each certificate that it encounters.
///
/// It implements the same state machine as [`CertParser`], however, a
/// `CertParser` is stricter.  Specifically, a `CertParser` performs
/// some sanity checks on the content of the packets whereas a
/// `RawCertParser` doesn't do those checks, because it avoids parsing
/// the packets' contents; it primarily looks at the packets' framing,
/// and their headers.
///
/// [`CertParser`]: crate::cert::CertParser
///
/// `RawCertParser` checks that the packet sequence is well-formed in
/// the sense that the sequence of tags conforms to the [Transferable
/// Public Key grammar] or [Transferable Secret Key grammar], and it
/// performs a few basic checks.  See the documentation for
/// [`RawCert`] for details.
///
/// [Transferable Public Key grammar]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.1
/// [Transferable Secret Key grammar]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.2
///
/// Because a `RawCertParser` doesn't parse the contents of the
/// packets, it is significantly faster than a [`CertParser`] when
/// many of the certificates in a keyring are irrelevant.
///
/// # Examples
///
/// Search for a specific certificate in a keyring:
///
/// ```rust
/// # use std::convert::TryFrom;
/// #
/// use sequoia_openpgp as openpgp;
///
/// # use openpgp::Result;
/// use openpgp::cert::prelude::*;
/// use openpgp::cert::raw::RawCertParser;
/// use openpgp::parse::Parse;
/// # use openpgp::serialize::Serialize;
/// #
/// # fn main() -> Result<()> {
/// # fn doit() -> Result<Cert> {
/// #      let (cert, _) = CertBuilder::new()
/// #          .generate()?;
/// #      let fpr = cert.fingerprint();
/// #
/// #      let mut bytes = Vec::new();
/// #      cert.serialize(&mut bytes);
/// for cert in RawCertParser::from_bytes(&bytes)? {
///     /// Ignore corrupt and invalid certificates.
///     let cert = if let Ok(cert) = cert {
///         cert
///     } else {
///         continue;
///     };
///
///     if cert.fingerprint() == fpr {
///         // Found it!  Try to convert it to a Cert.
///         if let cert = Cert::try_from(cert) {
///             return cert;
///         }
///     }
/// }
///
/// // Not found.
/// return Err(anyhow::anyhow!("Not found!").into());
/// # }
/// # doit().expect("Found the certificate");
/// # Ok(())
/// # }
/// ```
pub struct RawCertParser<'a>
{
    // If the data is being read from a slice, then the slice.  This
    // is used to avoid copying the data into the RawCert.
    slice: Option<&'a [u8]>,

    // Where `RawCertParser` reads the data.  When reading from a
    // slice, this is a `buffered_reader::Memory`.  Note: the slice
    // field will not be set, if the input needs to be transferred
    // (i.e., dearmored).
    reader: Box<dyn BufferedReader<Cookie> + 'a>,

    // Whether we are dearmoring the input.
    dearmor: bool,

    // The total number of bytes read.
    bytes_read: usize,

    // Any pending error.
    pending_error: Option<anyhow::Error>,

    // Whether there was an unrecoverable error.
    done: bool,
}
assert_send_and_sync!(RawCertParser<'_>);

impl<'a> RawCertParser<'a> {
    fn new(reader: Box<dyn BufferedReader<Cookie> + 'a>) -> Result<Self>
    {
        // Check that we can read the first header and that it is
        // reasonable.  Note: an empty keyring is not an error; we're
        // just checking for bad data here.  If not, try again after
        // dearmoring the input.
        let mut dearmor = false;
        let mut dup = Dup::with_cookie(reader, Default::default());
        if ! dup.eof() {
            match Header::parse(&mut dup) {
                Ok(header) => {
                    let tag = header.ctb().tag();
                    if matches!(tag, Tag::Unknown(_) | Tag::Private(_)) {
                        return Err(crate::Error::MalformedCert(
                            format!("A certificate must start with a \
                                     public key or a secret key packet, \
                                     got a {}",
                                    tag))
                                   .into());
                    }
                }
                Err(_err) => {
                    // We failed to read a header.  Try to dearmor the
                    // input.
                    dearmor = true;
                }
            }
        }

        // Strip the Dup reader.
        let mut reader = dup.into_boxed().into_inner().expect("inner");

        if dearmor {
            reader = armor::Reader::from_cookie_reader(
                reader, armor::ReaderMode::Tolerant(None),
                Default::default()).into_boxed();

            let mut dup = Dup::with_cookie(reader, Default::default());
            match Header::parse(&mut dup) {
                Ok(header) => {
                    let tag = header.ctb().tag();
                    if matches!(tag, Tag::Unknown(_) | Tag::Private(_)) {
                        return Err(crate::Error::MalformedCert(
                            format!("A certificate must start with a \
                                     public key or a secret key packet, \
                                     got a {}",
                                    tag))
                                   .into());
                    }
                }
                Err(err) => {
                    return Err(err);
                }
            }

            reader = dup.into_boxed().into_inner().expect("inner");
        }

        Ok(RawCertParser {
            slice: None,
            reader,
            dearmor,
            bytes_read: 0,
            pending_error: None,
            done: false,
        })
    }
}

impl<'a> Parse<'a, RawCertParser<'a>> for RawCertParser<'a>
{
    /// Initializes a `RawCertParser` from a `BufferedReader`.
    fn from_buffered_reader<R>(reader: R) -> Result<RawCertParser<'a>>
    where
        R: BufferedReader<Cookie> + 'a
    {
        RawCertParser::new(reader.into_boxed())
    }

    /// Initializes a `RawCertParser` from a byte string.
    fn from_bytes<D: AsRef<[u8]> + ?Sized + Send + Sync>(data: &'a D) -> Result<Self> {
        let data = data.as_ref();
        let mut p = RawCertParser::new(
            Memory::with_cookie(data, Default::default()).into_boxed())?;

        // If we are dearmoring the input, then the slice doesn't
        // reflect the raw packets.
        if ! p.dearmor {
            p.slice = Some(data);
        }
        Ok(p)
    }
}

impl<'a> crate::seal::Sealed for RawCertParser<'a> {}

impl<'a> Iterator for RawCertParser<'a>
{
    type Item = Result<RawCert<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        tracer!(TRACE, "RawCertParser::next", 0);

        // Return the pending error.
        if let Some(err) = self.pending_error.take() {
            t!("Returning the queued error: {}", err);
            return Some(Err(err));
        }

        if self.done {
            return None;
        }

        if self.reader.eof() && self.dearmor {
            // We are dearmoring and hit EOF.  Maybe there is a second
            // armor block next to this one!

            // Get the reader,
            let reader = std::mem::replace(
                &mut self.reader,
                EOF::with_cookie(Default::default()).into_boxed());

            // peel off the armor reader,
            let reader = reader.into_inner().expect("the armor reader");

            // and install a new one!
            self.reader = armor::Reader::from_cookie_reader(
                reader, armor::ReaderMode::Tolerant(None),
                Default::default()).into_boxed();
        }

        if self.reader.eof() {
            return None;
        }

        let mut reader = Dup::with_cookie(
            std::mem::replace(&mut self.reader,
                              Box::new(EOF::with_cookie(Default::default()))),
                Default::default());

        // The absolute start of this certificate in the stream.
        let cert_start_absolute = self.bytes_read;

        // The number of bytes processed relative to the start of the
        // dup'ed buffered reader.  This may be less than the number
        // of bytes read, e.g., when we encounter a new certificate,
        // we read the header, but we don't necessarily want to
        // consider it consumed.
        let mut processed = 0;

        // The certificate's span relative to the start of the dup'ed
        // buffered reader.  The start will be larger than zero when
        // we skip a marker packet.
        let mut cert_start = 0;
        let mut cert_end = 0;

        // (Tag, header length, offset from start of the certificate)
        let mut packets: Vec<(Tag, usize, usize)> = Vec::new();
        let mut primary_key = None;

        let mut pending_error = None;
        'packet_parser: loop {
            if reader.eof() {
                break;
            }

            let packet_start = reader.total_out();
            processed = packet_start;

            let mut skip = 0;
            let mut header_len = 0;
            let header = loop {
                match Header::parse(&mut reader) {
                    Err(err) => {
                        if skip == 0 {
                            t!("Reading the next packet's header: {}", err);
                        }

                        if skip >= RECOVERY_THRESHOLD {
                            pending_error = Some(err.context(
                                format!("Splitting keyring at offset {}",
                                        self.bytes_read + packet_start)));
                            processed = reader.total_out();

                            // We tried to recover and failed.  Once
                            // we return the above error, we're done.
                            self.done = true;

                            break 'packet_parser;
                        } else if reader.eof() {
                            t!("EOF while trying to recover");
                            skip += 1;
                            break Header::new(CTB::new(Tag::Reserved),
                                              BodyLength::Full(skip as u32));
                        } else {
                            skip += 1;
                            reader.rewind();
                            reader.consume(packet_start + skip);
                        }
                    }
                    Ok(header) if skip > 0 => {
                        if PacketParser::plausible_cert(&mut reader, &header)
                            .is_ok()
                        {
                            // We recovered.  First return an error.  The
                            // next time this function is called, we'll
                            // resume here.
                            t!("Found a valid header after {} bytes \
                                of junk: {:?}",
                               skip, header);

                            break Header::new(CTB::new(Tag::Reserved),
                                              BodyLength::Full(skip as u32));
                        } else {
                            skip += 1;
                            reader.rewind();
                            reader.consume(packet_start + skip);
                        }
                    }
                    Ok(header) => {
                        header_len = reader.total_out() - packet_start;
                        break header;
                    }
                }
            };

            if skip > 0 {
                // Fabricate a header.
                t!("Recovered after {} bytes of junk", skip);

                pending_error = Some(crate::Error::MalformedPacket(
                    format!("Encountered {} bytes of junk at offset {}",
                            skip, self.bytes_read)).into());

                // Be careful: if we recovered, then we
                // reader.total_out() includes the good header.
                processed += skip;

                break;
            }

            let tag = header.ctb().tag();
            t!("Found a {:?}, length: {:?}",
               tag, header.length());

            if packet_start > cert_start
                && (tag == Tag::PublicKey || tag == Tag::SecretKey)
            {
                // Start of new cert.  Note: we don't advanced
                // processed!  That would consume the header that
                // we want to read the next time this function is
                // called.
                t!("Stopping: found the start of a new cert ({})", tag);
                break;
            }

            match header.length() {
                BodyLength::Full(l) => {
                    let l = *l as usize;

                    match reader.data_consume_hard(l) {
                        Err(err) => {
                            t!("Stopping: reading {}'s body: {}", tag, err);

                            // If we encountered an EOF while reading
                            // the packet body, then we're done.
                            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                                t!("Got an unexpected EOF, done.");
                                self.done = true;
                            }

                            pending_error = Some(
                                anyhow::Error::from(err).context(format!(
                                    "While reading {}'s body", tag)));

                            break;
                        }
                        Ok(data) => {
                            if tag == Tag::PublicKey
                                || tag == Tag::SecretKey
                            {
                                let data = &data[..l];
                                match Key::from_bytes(data) {
                                    Err(err) => {
                                        t!("Stopping: parsing public key: {}",
                                           err);
                                        primary_key = Some(Err(err));
                                    }
                                    Ok(key) => primary_key = Some(
                                        Ok(key.parts_into_public()
                                           .role_into_primary())),
                                }
                            }
                        }
                    }
                }
                BodyLength::Partial(_) => {
                    t!("Stopping: Partial body length not allowed \
                        for {} packets",
                       tag);
                    pending_error = Some(
                        crate::Error::MalformedPacket(
                            format!("Packet {} uses partial body length \
                                     encoding, which is not allowed in \
                                     certificates",
                                    tag))
                            .into());
                    self.done = true;
                    break;
                }
                BodyLength::Indeterminate => {
                    t!("Stopping: Indeterminate length not allowed \
                        for {} packets",
                       tag);
                    pending_error = Some(
                        crate::Error::MalformedPacket(
                            format!("Packet {} uses intedeterminite length \
                                     encoding, which is not allowed in \
                                     certificates",
                                    tag))
                            .into());
                    self.done = true;
                    break;
                }
            }

            let end = reader.total_out();
            processed = end;

            let r = if packet_start == cert_start {
                if tag == Tag::Marker {
                    // Silently skip marker packets at the start of a
                    // packet sequence.
                    cert_start = end;
                    Ok(())
                } else {
                    packets.push((tag, header_len, packet_start));
                    Cert::valid_start(tag)
                }
            } else {
                packets.push((tag, header_len, packet_start));
                Cert::valid_packet(tag)
            };
            if let Err(err) = r {
                t!("Stopping: {:?} => not a certificate: {}", header, err);
                pending_error = Some(err);

                if self.bytes_read == 0 && packet_start == cert_start
                    && matches!(tag, Tag::Unknown(_) | Tag::Private(_))
                {
                    // The very first packet is not known.  Don't
                    // bother to parse anything else.
                    self.done = true;
                }

                break;
            }

            cert_end = end;
        }

        t!("{} bytes processed; RawCert @ offset {}, {} bytes",
           processed,
           self.bytes_read + cert_start, cert_end - cert_start);

        assert!(cert_start <= cert_end);
        assert!(cert_end <= processed);
        self.bytes_read += processed;

        // Strip the buffered_reader::Dup.
        self.reader = Box::new(reader).into_inner()
            .expect("just put it there");

        // Consume the data.
        let cert_data = &self.reader
            .data_consume_hard(processed)
            .expect("just read it")[cert_start..cert_end];

        if let Some(err) = pending_error.take() {
            if cert_start == cert_end {
                // We didn't read anything.
                t!("Directly returning the error");
                return Some(Err(err));
            } else {
                t!("Queuing the error");
                self.pending_error = Some(err);
            }
        }

        if cert_start == cert_end {
            t!("No data.");
            return None;
        }

        match primary_key.expect("set") {
            Ok(primary_key) => Some(Ok(RawCert {
                data: if let Some(slice) = self.slice.as_ref() {
                    let data = &slice[cert_start_absolute + cert_start
                                      ..cert_start_absolute + cert_end];
                    assert_eq!(data, cert_data);
                    Cow::Borrowed(data)
                } else {
                    Cow::Owned(cert_data.to_vec())
                },
                primary_key,
                packets,
            })),
            Err(err) =>
                Some(Err(Error::UnsupportedCert(err, cert_data.into()).into())),
        }
    }
}

/// Errors used in this module.
#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Unsupported Cert.
    ///
    /// This usually occurs, because the primary key is in an
    /// unsupported format.  In particular, Sequoia does not support
    /// version 3 keys.
    #[error("Unsupported Cert: {0}")]
    UnsupportedCert(anyhow::Error, Vec<u8>),
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::cert::CertParser;
    use crate::cert::CertBuilder;
    use crate::packet::Literal;
    use crate::parse::RECOVERY_THRESHOLD;
    use crate::parse::PacketParserResult;
    use crate::serialize::Serialize;
    use crate::types::DataFormat;
    use crate::packet::Unknown;
    use crate::packet::CompressedData;

    fn cert_cmp(a: Cert, b: Cert)
    {
        if a == b {
            return;
        }

        let a = a.into_tsk().into_packets().collect::<Vec<_>>();
        let b = b.into_tsk().into_packets().collect::<Vec<_>>();

        for (i, (a, b)) in a.iter().zip(b.iter()).enumerate() {
            if a != b {
                panic!("Differ at element #{}:\n  {:?}\n  {:?}",
                       i, a, b);
            }
        }
        if a.len() > b.len() {
            eprintln!("Left has more packets:");
            for p in &a[b.len()..] {
                eprintln!("  - {}", p.tag());
            }
        }
        if b.len() > a.len() {
            eprintln!("Right has more packets:");
            for p in &b[a.len()..] {
                eprintln!("  - {}", p.tag());
            }
        }
        if a.len() != b.len() {
            panic!("Different lengths (common prefix identical): {} vs. {}",
                   a.len(), b.len());
        }
    }

    // Compares the result of a RawCertParser with the results of a
    // CertParser on a particular byte stream.
    fn compare_parse(bytes: &[u8]) -> Vec<RawCert> {
        let mut result = Vec::new();

        // We do the comparison two times: once with a byte stream
        // (this exercises the Cow::Borrowed path), and one
        // with a buffered reader (this exercises the Cow::Owned
        // code path).
        for &from_bytes in [true, false].iter() {
            let cp = CertParser::from_bytes(bytes);
            let rp = if from_bytes {
                eprintln!("=== RawCertParser::from_bytes");
                RawCertParser::from_bytes(bytes)
            } else {
                eprintln!("=== RawCertParser::from_reader");
                RawCertParser::from_reader(std::io::Cursor::new(bytes))
            };

            assert_eq!(cp.is_err(), rp.is_err(),
                       "CertParser: {:?}; RawCertParser: {:?}",
                       cp.map(|_| "Parsed"),
                       rp.map(|_| "Parsed"));
            if cp.is_err() && rp.is_err() {
                return Vec::new();
            }

            let mut cp = cp.expect("valid");
            let mut rp = rp.expect("valid");

            let mut raw_certs = Vec::new();
            loop {
                eprintln!("=== NEXT CERTPARSER");
                let c = cp.next();
                eprintln!("=== END CERTPARSER");
                eprintln!("=== NEXT RAWCERTPARSER");
                let r = rp.next();
                eprintln!("=== END RAWCERTPARSER");

                let (c, r) = match (c, r) {
                    // Both return ok.
                    (Some(Ok(c)), Some(Ok(r))) => (c, r),
                    // Both return an error.
                    (Some(Err(_)), Some(Err(_))) => continue,
                    // Both return EOF.
                    (None, None) => break,
                    (c, r) => {
                        panic!("\n\
                                CertParser returned: {:?}\n\
                                RawCertParser returned: {:?}",
                               c, r);
                    }
                };

                assert_eq!(c.fingerprint(), r.fingerprint());

                eprintln!("CertParser says:");
                for (i, p) in c.clone().into_tsk().into_packets().enumerate() {
                    eprintln!("  - {}. {}", i, p.tag());
                }

                let rp = Cert::from_bytes(r.as_bytes()).unwrap();
                eprintln!("RawCertParser says:");
                for (i, p) in rp.clone().into_tsk().into_packets().enumerate() {
                    eprintln!("  - {}. {}", i, p.tag());
                }

                cert_cmp(c.clone(), rp);

                raw_certs.push(r);
            }

            result = raw_certs;
        }
        result
    }

    #[test]
    fn empty() {
        let bytes = &[];

        let certs = compare_parse(bytes);
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn a_cert() {
        let testy = crate::tests::key("testy.pgp");

        let bytes = testy;

        let certs = compare_parse(bytes);
        assert_eq!(certs.len(), 1);
        let cert = &certs[0];
        assert_eq!(cert.as_bytes(), testy);

        let tags = &[ Tag::PublicKey,
                      Tag::UserID, Tag::Signature,
                      Tag::PublicSubkey, Tag::Signature
        ];
        assert_eq!(
            &cert.packets().map(|p| p.tag()).collect::<Vec<Tag>>()[..],
            tags);

        // Check that we can parse the individual packets and that
        // they have the correct tag.
        for (p, tag) in cert.packets().zip(tags.iter()) {
            let ppr = PacketParser::from_bytes(p.as_bytes()).expect("valid");
            if let PacketParserResult::Some(pp) = ppr {
                let (p, pp) = pp.next().expect("valid");
                assert_eq!(p.tag(), *tag);
                assert!(matches!(pp, PacketParserResult::EOF(_)));
            } else {
                panic!("Unexpected EOF");
            }
        }
    }

    #[test]
    fn two_certs() {
        let testy = crate::tests::key("testy.pgp");

        let mut bytes = testy.to_vec();
        bytes.extend_from_slice(testy);

        let certs = compare_parse(&bytes[..]);
        assert_eq!(certs.len(), 2);
        for cert in certs.into_iter() {
            assert_eq!(cert.as_bytes(), testy);
            assert_eq!(
                &cert.packets().map(|p| p.tag()).collect::<Vec<Tag>>()[..],
                &[ Tag::PublicKey,
                   Tag::UserID, Tag::Signature,
                   Tag::PublicSubkey, Tag::Signature
                ]);
        }
    }

    #[test]
    fn marker_packet_ignored() {
        use crate::serialize::Serialize;

        // Only a marker packet.
        let mut marker = Vec::new();
        Packet::Marker(Default::default())
            .serialize(&mut marker).unwrap();
        compare_parse(&marker[..]);

        // Marker at the start.
        let mut testy_with_marker = Vec::new();
        Packet::Marker(Default::default())
            .serialize(&mut testy_with_marker).unwrap();
        testy_with_marker.extend_from_slice(crate::tests::key("testy.pgp"));
        compare_parse(&testy_with_marker[..]);

        // Marker at the end.
        let mut testy_with_marker = Vec::new();
        testy_with_marker.extend_from_slice(crate::tests::key("testy.pgp"));
        Packet::Marker(Default::default())
            .serialize(&mut testy_with_marker).unwrap();
        compare_parse(&testy_with_marker[..]);
    }

    #[test]
    fn invalid_packets() -> Result<()> {
        tracer!(TRACE, "invalid_packets", 0);

        let (cert, _) =
            CertBuilder::general_purpose(Some("alice@example.org"))
            .generate()?;
        let cert = cert.into_packets().collect::<Vec<_>>();

        // A userid packet.
        let userid : Packet = cert.clone()
            .into_iter()
            .filter(|p| p.tag() == Tag::UserID)
            .next()
            .unwrap();

        // An unknown packet.
        let tag = Tag::Private(61);
        let unknown : Packet
            = Unknown::new(tag, crate::Error::UnsupportedPacketType(tag).into())
            .into();

        // A literal packet.  (This is a valid OpenPGP Message.)
        let mut lit = Literal::new(DataFormat::Unicode);
        lit.set_body(b"test".to_vec());
        let lit = Packet::from(lit);

        // A compressed data packet containing a literal data packet.
        // (This is a valid OpenPGP Message.)
        let cd = {
            use crate::types::CompressionAlgorithm;
            use crate::packet;
            use crate::PacketPile;
            use crate::serialize::Serialize;
            use crate::parse::Parse;

            let mut cd = CompressedData::new(
                CompressionAlgorithm::Uncompressed);
            let mut body = Vec::new();
            lit.serialize(&mut body)?;
            cd.set_body(packet::Body::Processed(body));
            let cd = Packet::from(cd);

            // Make sure we created the message correctly: serialize,
            // parse it, and then check its form.
            let mut bytes = Vec::new();
            cd.serialize(&mut bytes)?;

            let pp = PacketPile::from_bytes(&bytes[..])?;

            assert_eq!(pp.descendants().count(), 2);
            assert_eq!(pp.path_ref(&[ 0 ]).unwrap().tag(),
                       packet::Tag::CompressedData);
            assert_eq!(pp.path_ref(&[ 0, 0 ]), Some(&lit));

            cd
        };

        fn check(input: impl Iterator<Item=Packet>) {
            let mut bytes = Vec::new();
            for p in input {
                p.serialize(&mut bytes).unwrap();
            }

            compare_parse(&bytes[..]);
        }

        fn interleave(cert: &Vec<Packet>, p: &Packet) {
            t!("A certificate, a {}.", p.tag());
            check(
                cert.clone().into_iter()
                    .chain(p.clone()));

            t!("A certificate, two {}.", p.tag());
            check(
                cert.clone().into_iter()
                    .chain(p.clone())
                    .chain(p.clone()));

            t!("A {}, a certificate.", p.tag());
            check(
                p.clone().into_iter()
                    .chain(cert.clone()));

            t!("Two {}, a certificate.", p.tag());
            check(
                p.clone().into_iter()
                    .chain(p.clone())
                    .chain(cert.clone()));

            t!("Two {}, a certificate, two {}.", p.tag(), p.tag());
            check(
                p.clone().into_iter()
                    .chain(p.clone())
                    .chain(cert.clone())
                    .chain(p.clone())
                    .chain(p.clone()));

            t!("Two {}, two certificates, two {}, a certificate.");
            check(
                p.clone().into_iter()
                    .chain(p.clone())
                    .chain(cert.clone())
                    .chain(cert.clone())
                    .chain(p.clone())
                    .chain(p.clone())
                    .chain(cert.clone()));
        }

        interleave(&cert, &lit);

        // The certificate parser shouldn't recurse into containers.
        // So, the compressed data packets should show up as a single
        // error.
        interleave(&cert, &cd);


        // The certificate parser should treat unknown packets as
        // valid certificate components.
        let mut cert_plus = cert.clone();
        cert_plus.push(unknown.clone());

        t!("A certificate, an unknown.");
        check(
            cert.clone().into_iter()
                .chain(unknown.clone()));

        t!("An unknown, a certificate.");
        check(
             unknown.clone().into_iter()
                 .chain(cert.clone()));

        t!("A certificate, two unknowns.");
        check(
            cert.clone().into_iter()
                .chain(unknown.clone())
                .chain(unknown.clone()));

        t!("A certificate, an unknown, a certificate.");
        check(
            cert.clone().into_iter()
                .chain(unknown.clone())
                .chain(cert.clone()));

        t!("A Literal, two User IDs");
        check(
            lit.clone().into_iter()
                .chain(userid.clone())
                .chain(userid.clone()));

        t!("A User ID, a certificate");
        check(
            userid.clone().into_iter()
                .chain(cert.clone()));

        t!("Two User IDs, a certificate");
        check(
            userid.clone().into_iter()
                .chain(userid.clone())
                .chain(cert.clone()));

        Ok(())
    }

    fn parse_test(n: usize, literal: bool, bad: usize) -> Result<()> {
        tracer!(TRACE, "t", 0);

        // Parses keyrings with different numbers of keys and
        // different errors.

        // n: number of keys
        // literal: whether to interleave literal packets.
        // bad: whether to insert invalid data (NUL bytes where
        //      the start of a certificate is expected).
        let nulls = vec![ 0; bad ];

        t!("n: {}, literals: {}, bad data: {}",
           n, literal, bad);

        let mut data = Vec::new();

        let mut certs_orig = vec![];
        for i in 0..n {
            let (cert, _) =
                CertBuilder::general_purpose(
                    Some(format!("{}@example.org", i)))
                .generate()?;

            cert.as_tsk().serialize(&mut data)?;
            certs_orig.push(cert);

            if literal {
                let mut lit = Literal::new(DataFormat::Unicode);
                lit.set_body(b"data".to_vec());

                Packet::from(lit).serialize(&mut data)?;
            }
            // Push some NUL bytes.
            data.extend(&nulls[..bad]);
        }
        if n == 0 {
            // Push some NUL bytes even if we didn't add any packets.
            data.extend(&nulls[..bad]);
        }
        assert_eq!(certs_orig.len(), n);

        t!("Start of data: {} {}",
           if let Some(x) = data.get(0) {
               format!("{:02X}", x)
           } else {
               "XX".into()
           },
           if let Some(x) = data.get(1) {
               format!("{:02X}", x)
           } else {
               "XX".into()
           });

        compare_parse(&data);

        Ok(())
    }

    #[test]
    fn parse_keyring_simple() -> Result<()> {
        for n in [1, 100, 0].iter() {
            parse_test(*n, false, 0)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_literals() -> Result<()> {
        for n in [1, 100, 0].iter() {
            parse_test(*n, true, 0)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_small_junk() -> Result<()> {
        for n in [1, 100, 0].iter() {
            parse_test(*n, false, 1)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_unrecoverable_junk() -> Result<()> {
        // PacketParser is pretty good at recovering from junk in the
        // middle: it will search the next RECOVERY_THRESHOLD bytes
        // for a valid packet.  If it finds it, it will turn the junk
        // into a reserved packet and resume.  Insert a lot of NULs to
        // prevent the recovery mechanism from working.
        for n in [1, 100, 0].iter() {
            parse_test(*n, false, 2 * RECOVERY_THRESHOLD)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_literal_and_small_junk() -> Result<()> {
        for n in [1, 100, 0].iter() {
            parse_test(*n, true, 1)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_literal_and_unrecoverable_junk() -> Result<()> {
        for n in [1, 100, 0].iter() {
            parse_test(*n, true, 2 * RECOVERY_THRESHOLD)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_no_public_key() -> Result<()> {
        tracer!(TRACE, "parse_keyring_no_public_key", 0);

        // The first few packets are not the valid start of a
        // certificate.  Each of those should return in an Error.
        // But, that shouldn't stop us from parsing the rest of the
        // keyring.

        let (cert_1, _) =
            CertBuilder::general_purpose(
                Some("a@example.org"))
            .generate()?;
        let cert_1_packets: Vec<Packet>
            = cert_1.into_packets().collect();

        let (cert_2, _) =
            CertBuilder::general_purpose(
                Some("b@example.org"))
            .generate()?;

        for n in 1..cert_1_packets.len() {
            t!("n: {}", n);

            let mut data = Vec::new();

            for i in n..cert_1_packets.len() {
                cert_1_packets[i].serialize(&mut data)?;
            }

            cert_2.as_tsk().serialize(&mut data)?;

            compare_parse(&data);
        }

        Ok(())
    }

    #[test]
    fn accessors() {
        let testy = crate::tests::key("testy.pgp");

        let certs = RawCertParser::from_bytes(testy)
            .expect("valid")
            .collect::<Result<Vec<RawCert>>>()
            .expect("valid");
        assert_eq!(certs.len(), 1);
        let cert = &certs[0];
        assert_eq!(cert.as_bytes(), testy);

        assert_eq!(cert.primary_key().fingerprint(),
                   "3E8877C877274692975189F5D03F6F865226FE8B"
                       .parse().expect("valid"));
        assert_eq!(cert.keys().map(|k| k.fingerprint()).collect::<Vec<_>>(),
                   vec![
                       "3E8877C877274692975189F5D03F6F865226FE8B"
                           .parse().expect("valid"),
                       "01F187575BD45644046564C149E2118166C92632"
                           .parse().expect("valid")
                   ]);
        assert_eq!(cert.keys().subkeys()
                   .map(|k| k.fingerprint()).collect::<Vec<_>>(),
                   vec![
                       "01F187575BD45644046564C149E2118166C92632"
                           .parse().expect("valid")
                   ]);
        assert_eq!(
            cert.userids()
                .map(|u| {
                    String::from_utf8_lossy(u.value()).into_owned()
                })
                .collect::<Vec<_>>(),
            vec![ "Testy McTestface <testy@example.org>" ]);
    }

    // Test the raw cert parser implementation.
    #[test]
    fn raw_cert_parser_impl() {
        // Read one certificate.
        let testy = crate::tests::key("testy.pgp");

        let raw = RawCert::from_bytes(testy).expect("valid");
        let cert = Cert::from_bytes(testy).expect("valid");

        assert_eq!(
            raw.keys().map(|k| k.fingerprint()).collect::<Vec<_>>(),
            cert.keys().map(|k| k.key().fingerprint()).collect::<Vec<_>>());

        assert_eq!(
            raw.userids().collect::<Vec<_>>(),
            cert.userids().map(|ua| ua.userid().clone()).collect::<Vec<_>>());

        // Parse zero certificates.
        eprintln!("Parsing 0 bytes");
        let raw = RawCert::from_bytes(b"");
        match &raw {
            Ok(_) => eprintln!("raw: Ok"),
            Err(err) => eprintln!("raw: {}", err),
        }
        let cert = Cert::from_bytes(b"");
        match &cert {
            Ok(_) => eprintln!("cert: Ok"),
            Err(err) => eprintln!("cert: {}", err),
        }

        assert!(
            matches!(cert.map_err(|e| e.downcast::<crate::Error>()),
                     Err(Ok(crate::Error::MalformedCert(_)))));
        assert!(
            matches!(raw.map_err(|e| e.downcast::<crate::Error>()),
                     Err(Ok(crate::Error::MalformedCert(_)))));

        // Parse two certificates.
        let mut bytes = Vec::new();
        bytes.extend(testy);
        bytes.extend(testy);

        let parser = CertParser::from_bytes(&bytes).expect("valid");
        assert_eq!(parser.count(), 2);

        eprintln!("Parsing two certificates");
        let raw = RawCert::from_bytes(&bytes);
        match &raw {
            Ok(_) => eprintln!("raw: Ok"),
            Err(err) => eprintln!("raw: {}", err),
        }
        let cert = Cert::from_bytes(&bytes);
        match &cert {
            Ok(_) => eprintln!("cert: Ok"),
            Err(err) => eprintln!("cert: {}", err),
        }

        assert!(
            matches!(cert.map_err(|e| e.downcast::<crate::Error>()),
                     Err(Ok(crate::Error::MalformedCert(_)))));
        assert!(
            matches!(raw.map_err(|e| e.downcast::<crate::Error>()),
                     Err(Ok(crate::Error::MalformedCert(_)))));
    }

    #[test]
    fn concatenated_armored_certs() -> Result<()> {
        let mut keyring = Vec::new();
        keyring.extend_from_slice(b"some\ntext\n");
        keyring.extend_from_slice(crate::tests::key("testy.asc"));
        keyring.extend_from_slice(crate::tests::key("testy.asc"));
        keyring.extend_from_slice(b"some\ntext\n");
        keyring.extend_from_slice(crate::tests::key("testy.asc"));
        keyring.extend_from_slice(b"some\ntext\n");
        let certs = RawCertParser::from_bytes(&keyring)?.collect::<Vec<_>>();
        assert_eq!(certs.len(), 3);
        assert!(certs.iter().all(|c| c.is_ok()));
        Ok(())
    }
}
