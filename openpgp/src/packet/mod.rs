//! Packet-related data types.
//!
//! OpenPGP data structures are [packet based].  This module defines
//! the corresponding data structures.
//!
//! Most users of this library will not need to generate these packets
//! themselves.  Instead, the packets are instantiated as a side
//! effect of [parsing a message], or [creating a message].  The main
//! current exception are `Signature` packets.  Working with
//! `Signature` packets is, however, simplified by using the
//! [`SignatureBuilder`].
//!
//! # Data Types
//!
//! Many OpenPGP packets include a version field.  Versioning is used
//! to make it easier to change the standard.  For instance, using
//! versioning, it is possible to remove a field from a packet without
//! introducing a new packet type, which would also require changing
//! [the grammar].  Versioning also enables a degree of forward
//! compatibility when a new version of a packet can be safely
//! ignored.  For instance, there are currently two versions of the
//! [`Signature`] packet with completely different layouts: [v3] and
//! [v4].  An implementation that does not understand the latest
//! version of the packet can still parse and display a message using
//! them; it will just be unable to verify that signature.
//!
//! In Sequoia, packets that have a version field are represented by
//! `enum`s, and each supported version of the packet has a variant,
//! and a corresponding `struct`.  This is the case even when only one
//! version of the packet is currently defined, as is the case with
//! the [`OnePassSig`] packet.  The `enum`s implement forwarders for
//! common operations.  As such, users of this library can often
//! ignore that there are multiple versions of a given packet.
//!
//! # Unknown Packets
//!
//! Sequoia gracefully handles unsupported packets by storing them as
//! [`Unknown`] packets.  There are several types of unknown packets:
//!
//!   - Packets that are known, but explicitly not supported.
//!
//!     The two major examples are the [`SED`] packet type and v3
//!     `Signature` packets, which have both been considered insecure
//!     for well over a decade.
//!
//!     Note: future versions of Sequoia may add limited support for
//!     these packets to enable parsing archived messages.
//!
//!   - Packets that are known about, but that use unsupported
//!     options, e.g., a [`Compressed Data`] packet using an unknown or
//!     unsupported algorithm.
//!
//!   - Packets that are unknown, e.g., future or [private
//!     extensions].
//!
//! When Sequoia [parses] a message containing these packets, it
//! doesn't fail.  Instead, Sequoia stores them in the [`Unknown`]
//! data structure.  This allows applications to not only continue to
//! process such messages (albeit with degraded performance), but to
//! losslessly reserialize the messages, should that be required.
//!
//! # Containers
//!
//! Packets can be divided into two categories: containers and
//! non-containers.  A container is a packet that contains other
//! OpenPGP packets.  For instance, by definition, a [`Compressed
//! Data`] packet contains an [OpenPGP Message].  It is possible to
//! iterate over a container's descendants using the
//! [`Container::descendants`] method.  (Note: `Container`s have a
//! `.container_ref()` and a `.container_mut()` method that return a
//! reference to [`Container`].)
//!
//! # Packet Headers and Bodies
//!
//! Conceptually, packets have zero or more headers and an optional
//! body.  The headers are small, and have a known upper bound.  The
//! version field is, for instance, 4 bytes, and although
//! [`Signature`][] [`SubpacketArea`][] areas are variable in size,
//! they are limited to 64 KB.  In contrast the body, can be unbounded
//! in size.
//!
//! To limit memory use, and enable streaming processing (i.e.,
//! ensuring that processing a message can be done using a fixed size
//! buffer), Sequoia does not require that a packet's body be present
//! in memory.  For instance, the body of a literal data packet may be
//! streamed.  And, at the end, a [`Literal`] packet is still
//! returned.  This allows the caller to examine the message
//! structure, and the message headers in *in toto* even when
//! streaming.  It is even possible to compare two streamed version of
//! a packet: Sequoia stores a hash of the body.  See the [`Body`]
//! data structure for more details.
//!
//! # Equality
//!
//! There are several reasonable ways to define equality for
//! `Packet`s.  Unfortunately, none of them are appropriate in all
//! situations.  This makes choosing a general-purpose equality
//! function for [`Eq`] difficult.
//!
//! Consider defining `Eq` as the equivalence of two `Packet`s'
//! serialized forms.  If an application naively deduplicates
//! signatures, then an attacker can potentially perform a
//! denial-of-service attack by causing the application to process many
//! cryptographically-valid `Signature`s by varying the content of one
//! cryptographically-valid `Signature`'s unhashed area.  This attack
//! can be prevented by only comparing data that is protected by the
//! signature.  But this means that naively deduplicating `Signature`
//! packets will return in "a random" variant being used.  So, again,
//! an attacker could create variants of a cryptographically-valid
//! `Signature` to get the implementation to incorrectly drop a useful
//! one.
//!
//! These issues are also relevant when comparing [`Key`s]: should the
//! secret key material be compared?  Usually we want to merge the
//! secret key material.  But, again, if done naively, the incorrect
//! secret key material may be retained or dropped completely.
//!
//! Instead of trying to come up with a definition of equality that is
//! reasonable for all situations, we use a conservative definition:
//! two packets are considered equal if the serialized forms of their
//! packet bodies as defined by RFC 9580 are equal.  That is, two
//! packets are considered equal if and only if their serialized forms
//! are equal modulo the OpenPGP framing ([`CTB`] and [length style],
//! potential [partial body encoding]).  This definition will avoid
//! unintentionally dropping information when naively deduplicating
//! packets, but it will result in potential redundancies.
//!
//! For some packets, we provide additional variants of equality.  For
//! instance, [`Key::public_cmp`] compares just the public parts of
//! two keys.
//!
//! [packet based]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5
//! [the grammar]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10
//! [v3]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.2
//! [v4]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3
//! [parsing a message]: crate::parse
//! [creating a message]: crate::serialize::stream
//! [`SignatureBuilder`]: signature::SignatureBuilder
//! [`SED`]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.7
//! [private extensions]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5
//! [`Compressed Data`]: CompressedData
//! [parses]: crate::parse
//! [OpenPGP Message]: https://www.rfc-editor.org/rfc/rfc9580.html#section-10.3
//! [`Container::descendants`]: Container::descendants()
//! [`Deref`]: std::ops::Deref
//! [`SubpacketArea`]: signature::subpacket::SubpacketArea
//! [`Eq`]: std::cmp::Eq
//! [`Key`s]: Key
//! [`CTB`]: header::CTB
//! [length style]: https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2
//! [partial body encoding]: https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2.1.4
//! [`Key::public_cmp`]: Key::public_cmp()
use std::fmt;
use std::hash::Hasher;
use std::ops::{Deref, DerefMut};
use std::slice;
use std::iter::IntoIterator;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Result;

#[macro_use]
mod container;
pub use container::Container;
pub use container::Body;

pub mod prelude;

mod any;
pub use self::any::Any;

mod tag;
pub use self::tag::Tag;
pub mod header;
pub use self::header::Header;

mod unknown;
pub use self::unknown::Unknown;
pub mod signature;
pub mod one_pass_sig;
pub use one_pass_sig::OnePassSig;
pub mod key;
pub use key::Key;
mod marker;
pub use self::marker::Marker;
mod trust;
pub use self::trust::Trust;
mod userid;
pub use self::userid::UserID;
pub mod user_attribute;
pub use self::user_attribute::UserAttribute;
mod literal;
pub use self::literal::Literal;
mod compressed_data;
pub use self::compressed_data::CompressedData;
pub mod seip;
pub mod skesk;
pub use skesk::SKESK;
pub mod pkesk;
pub use pkesk::PKESK;
mod mdc;
pub use self::mdc::MDC;
mod padding;
pub use self::padding::Padding;

/// Enumeration of packet types.
///
/// The different OpenPGP packets are detailed in [Section 5 of RFC 9580].
///
///   [Section 5 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5
///
/// The [`Unknown`] packet allows Sequoia to deal with packets that it
/// doesn't understand.  It is basically a binary blob that includes
/// the packet's [tag].  See the [module-level documentation] for
/// details.
///
/// # A note on equality
///
/// We define equality on `Packet` as the equality of the serialized
/// form of their packet bodies as defined by RFC 9580.  That is, two
/// packets are considered equal if and only if their serialized forms
/// are equal, modulo the OpenPGP framing ([`CTB`] and [length style],
/// potential [partial body encoding]).
///
/// [`Unknown`]: crate::packet::Unknown
/// [tag]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5
/// [module-level documentation]: crate::packet#unknown-packets
/// [`CTB`]: crate::packet::header::CTB
/// [length style]: https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2
/// [partial body encoding]: https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2.1.4
#[non_exhaustive]
#[derive(PartialEq, Eq, Hash, Clone)]
pub enum Packet {
    /// Unknown packet.
    Unknown(Unknown),
    /// Signature packet.
    Signature(Signature),
    /// One pass signature packet.
    OnePassSig(OnePassSig),
    /// Public key packet.
    PublicKey(key::PublicKey),
    /// Public subkey packet.
    PublicSubkey(key::PublicSubkey),
    /// Public/Secret key pair.
    SecretKey(key::SecretKey),
    /// Public/Secret subkey pair.
    SecretSubkey(key::SecretSubkey),
    /// Marker packet.
    Marker(Marker),
    /// Trust packet.
    Trust(Trust),
    /// User ID packet.
    UserID(UserID),
    /// User attribute packet.
    UserAttribute(UserAttribute),
    /// Literal data packet.
    Literal(Literal),
    /// Compressed literal data packet.
    CompressedData(CompressedData),
    /// Public key encrypted data packet.
    PKESK(PKESK),
    /// Symmetric key encrypted data packet.
    SKESK(SKESK),
    /// Symmetric key encrypted, integrity protected data packet.
    SEIP(SEIP),
    /// Modification detection code packet.
    #[deprecated]
    MDC(MDC),
    /// Padding packet.
    Padding(Padding),
}
assert_send_and_sync!(Packet);

macro_rules! impl_into_iterator {
    ($t:ty) => {
        impl_into_iterator!($t where);
    };
    ($t:ty where $( $w:ident: $c:path ),*) => {
        /// Implement `IntoIterator` so that
        /// `cert::insert_packets(sig)` just works.
        impl<$($w),*> IntoIterator for $t
            where $($w: $c ),*
        {
            type Item = $t;
            type IntoIter = std::iter::Once<$t>;

            fn into_iter(self) -> Self::IntoIter {
                std::iter::once(self)
            }
        }
    }
}

impl_into_iterator!(Packet);
impl_into_iterator!(Unknown);
impl_into_iterator!(Signature);
impl_into_iterator!(OnePassSig);
impl_into_iterator!(Marker);
impl_into_iterator!(Trust);
impl_into_iterator!(UserID);
impl_into_iterator!(UserAttribute);
impl_into_iterator!(Literal);
impl_into_iterator!(CompressedData);
impl_into_iterator!(PKESK);
impl_into_iterator!(SKESK);
impl_into_iterator!(SEIP);
impl_into_iterator!(MDC);
impl_into_iterator!(Key<P, R> where P: key::KeyParts, R: key::KeyRole);

// Make it easy to pass an iterator of Packets to something expecting
// an iterator of Into<Result<Packet>> (specifically,
// CertParser::into_iter).
impl From<Packet> for Result<Packet> {
    fn from(p: Packet) -> Self {
        Ok(p)
    }
}

impl Packet {
    /// Returns the `Packet's` corresponding OpenPGP tag.
    ///
    /// Tags are explained in [Section 5 of RFC 9580].
    ///
    ///   [Section 5 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5
    pub fn tag(&self) -> Tag {
        match self {
            Packet::Unknown(ref packet) => packet.tag(),
            Packet::Signature(_) => Tag::Signature,
            Packet::OnePassSig(_) => Tag::OnePassSig,
            Packet::PublicKey(_) => Tag::PublicKey,
            Packet::PublicSubkey(_) => Tag::PublicSubkey,
            Packet::SecretKey(_) => Tag::SecretKey,
            Packet::SecretSubkey(_) => Tag::SecretSubkey,
            Packet::Marker(_) => Tag::Marker,
            Packet::Trust(_) => Tag::Trust,
            Packet::UserID(_) => Tag::UserID,
            Packet::UserAttribute(_) => Tag::UserAttribute,
            Packet::Literal(_) => Tag::Literal,
            Packet::CompressedData(_) => Tag::CompressedData,
            Packet::PKESK(_) => Tag::PKESK,
            Packet::SKESK(_) => Tag::SKESK,
            Packet::SEIP(_) => Tag::SEIP,
            #[allow(deprecated)]
            Packet::MDC(_) => Tag::MDC,
            Packet::Padding(_) => Tag::Padding,
        }
    }

    /// Returns the parsed `Packet's` corresponding OpenPGP tag.
    ///
    /// Returns the packets tag, but only if it was successfully
    /// parsed into the corresponding packet type.  If e.g. a
    /// Signature Packet uses some unsupported methods, it is parsed
    /// into an `Packet::Unknown`.  `tag()` returns `Tag::Signature`,
    /// whereas `kind()` returns `None`.
    pub fn kind(&self) -> Option<Tag> {
        match self {
            Packet::Unknown(_) => None,
            _ => Some(self.tag()),
        }
    }

    /// Returns whether this is a critical packet.
    ///
    /// Upon encountering an unknown critical packet, implementations
    /// MUST reject the whole packet sequence.  On the other hand,
    /// unknown non-critical packets MUST be ignored.  See [Section
    /// 4.3 of RFC 9580].
    ///
    /// [Section 4.3 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-4.3
    pub fn is_critical(&self) -> bool {
        self.tag().is_critical()
    }

    /// Returns the `Packet's` version, if the packet is versioned and
    /// recognized.
    ///
    /// If the packet is not versioned, or we couldn't parse the
    /// packet, this function returns `None`.
    pub fn version(&self) -> Option<u8> {
        match self {
            Packet::Unknown(_) => None,
            Packet::Signature(p) => Some(p.version()),
            Packet::OnePassSig(p) => Some(p.version()),
            Packet::PublicKey(p) => Some(p.version()),
            Packet::PublicSubkey(p) => Some(p.version()),
            Packet::SecretKey(p) => Some(p.version()),
            Packet::SecretSubkey(p) => Some(p.version()),
            Packet::Marker(_) => None,
            Packet::Trust(_) => None,
            Packet::UserID(_) => None,
            Packet::UserAttribute(_) => None,
            Packet::Literal(_) => None,
            Packet::CompressedData(_) => None,
            Packet::PKESK(p) => Some(p.version()),
            Packet::SKESK(p) => Some(p.version()),
            Packet::SEIP(p) => Some(p.version()),
            #[allow(deprecated)]
            Packet::MDC(_) => None,
            Packet::Padding(_) => None,
        }
    }

    /// Hashes most everything into state.
    ///
    /// This is an alternate implementation of [`Hash`], which does
    /// not hash:
    ///
    ///   - The unhashed subpacket area of Signature packets.
    ///   - Secret key material.
    ///
    ///   [`Hash`]: std::hash::Hash
    ///
    /// Unlike [`Signature::normalize`], this method ignores
    /// authenticated packets in the unhashed subpacket area.
    ///
    ///   [`Signature::normalize`]: Signature::normalize()
    pub fn normalized_hash<H>(&self, state: &mut H)
        where H: Hasher
    {
        use std::hash::Hash;

        match self {
            Packet::Signature(sig) => sig.normalized_hash(state),
            Packet::OnePassSig(x) => Hash::hash(&x, state),
            Packet::PublicKey(k) => k.public_hash(state),
            Packet::PublicSubkey(k) => k.public_hash(state),
            Packet::SecretKey(k) => k.public_hash(state),
            Packet::SecretSubkey(k) => k.public_hash(state),
            Packet::Marker(x) => Hash::hash(&x, state),
            Packet::Trust(x) => Hash::hash(&x, state),
            Packet::UserID(x) => Hash::hash(&x, state),
            Packet::UserAttribute(x) => Hash::hash(&x, state),
            Packet::Literal(x) => Hash::hash(&x, state),
            Packet::CompressedData(x) => Hash::hash(&x, state),
            Packet::PKESK(x) => Hash::hash(&x, state),
            Packet::SKESK(x) => Hash::hash(&x, state),
            Packet::SEIP(x) => Hash::hash(&x, state),
            #[allow(deprecated)]
            Packet::MDC(x) => Hash::hash(&x, state),
            Packet::Unknown(x) => Hash::hash(&x, state),
            Packet::Padding(x) => Padding::hash(x, state),
        }
    }
}

// Allow transparent access of common fields.
impl Packet {
    /// Returns a reference to the packet's `Common` struct.
    fn common(&self) -> &Common {
        match self {
            Packet::Unknown(ref packet) => &packet.common,
            Packet::Signature(ref packet) => &packet.common,
            Packet::OnePassSig(OnePassSig::V3(packet)) => &packet.common,
            Packet::OnePassSig(OnePassSig::V6(packet)) => &packet.common.common,
            Packet::PublicKey(Key::V4(packet)) => &packet.common,
            Packet::PublicKey(Key::V6(packet)) => &packet.common.common,
            Packet::PublicSubkey(Key::V4(packet)) => &packet.common,
            Packet::PublicSubkey(Key::V6(packet)) => &packet.common.common,
            Packet::SecretKey(Key::V4(packet)) => &packet.common,
            Packet::SecretKey(Key::V6(packet)) => &packet.common.common,
            Packet::SecretSubkey(Key::V4(packet)) => &packet.common,
            Packet::SecretSubkey(Key::V6(packet)) => &packet.common.common,
            Packet::Marker(ref packet) => &packet.common,
            Packet::Trust(ref packet) => &packet.common,
            Packet::UserID(ref packet) => &packet.common,
            Packet::UserAttribute(ref packet) => &packet.common,
            Packet::Literal(ref packet) => &packet.common,
            Packet::CompressedData(ref packet) => &packet.common,
            Packet::PKESK(PKESK::V3(packet)) => &packet.common,
            Packet::PKESK(PKESK::V6(packet)) => &packet.common,
            Packet::SKESK(SKESK::V4(ref packet)) => &packet.common,
            Packet::SKESK(SKESK::V6(ref packet)) => &packet.skesk4.common,
            Packet::SEIP(SEIP::V1(packet)) => &packet.common,
            Packet::SEIP(SEIP::V2(packet)) => &packet.common,
            #[allow(deprecated)]
            Packet::MDC(ref packet) => &packet.common,
            Packet::Padding(packet) => &packet.common,
        }
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fn debug_fmt(p: &Packet, f: &mut fmt::Formatter) -> fmt::Result {
            match p {
                Packet::Unknown(v) => write!(f, "Unknown({:?})", v),
                Packet::Signature(v) => write!(f, "Signature({:?})", v),
                Packet::OnePassSig(v) => write!(f, "OnePassSig({:?})", v),
                Packet::PublicKey(v) => write!(f, "PublicKey({:?})", v),
                Packet::PublicSubkey(v) => write!(f, "PublicSubkey({:?})", v),
                Packet::SecretKey(v) => write!(f, "SecretKey({:?})", v),
                Packet::SecretSubkey(v) => write!(f, "SecretSubkey({:?})", v),
                Packet::Marker(v) => write!(f, "Marker({:?})", v),
                Packet::Trust(v) => write!(f, "Trust({:?})", v),
                Packet::UserID(v) => write!(f, "UserID({:?})", v),
                Packet::UserAttribute(v) => write!(f, "UserAttribute({:?})", v),
                Packet::Literal(v) => write!(f, "Literal({:?})", v),
                Packet::CompressedData(v) => write!(f, "CompressedData({:?})", v),
                Packet::PKESK(v) => write!(f, "PKESK({:?})", v),
                Packet::SKESK(v) => write!(f, "SKESK({:?})", v),
                Packet::SEIP(v) => write!(f, "SEIP({:?})", v),
                #[allow(deprecated)]
                Packet::MDC(v) => write!(f, "MDC({:?})", v),
                Packet::Padding(v) => write!(f, "Padding({:?})", v),
            }
        }

        fn try_armor_fmt(p: &Packet, f: &mut fmt::Formatter)
                         -> Result<fmt::Result> {
            use crate::armor::{Writer, Kind};
            use crate::serialize::Serialize;
            let mut w = Writer::new(Vec::new(), Kind::File)?;
            p.serialize(&mut w)?;
            let buf = w.finalize()?;
            Ok(f.write_str(std::str::from_utf8(&buf).expect("clean")))
        }

        if ! cfg!(test) {
            debug_fmt(self, f)
        } else {
            try_armor_fmt(self, f).unwrap_or_else(|_| debug_fmt(self, f))
        }
    }
}

#[cfg(test)]
impl Arbitrary for Packet {
    fn arbitrary(g: &mut Gen) -> Self {
        use crate::arbitrary_helper::gen_arbitrary_from_range;

        match gen_arbitrary_from_range(0..16, g) {
            0 => Signature::arbitrary(g).into(),
            1 => OnePassSig::arbitrary(g).into(),
            2 => Key::<key::PublicParts, key::PrimaryRole>::arbitrary(g)
                .into(),
            3 => Key::<key::PublicParts, key::SubordinateRole>::arbitrary(g)
                .into(),
            4 => Key::<key::SecretParts, key::PrimaryRole>::arbitrary(g)
                .into(),
            5 => Key::<key::SecretParts, key::SubordinateRole>::arbitrary(g)
                .into(),
            6 => Marker::arbitrary(g).into(),
            7 => Trust::arbitrary(g).into(),
            8 => UserID::arbitrary(g).into(),
            9 => UserAttribute::arbitrary(g).into(),
            10 => Literal::arbitrary(g).into(),
            11 => CompressedData::arbitrary(g).into(),
            12 => PKESK::arbitrary(g).into(),
            13 => SKESK::arbitrary(g).into(),
            14 => Padding::arbitrary(g).into(),
            15 => loop {
                let mut u = Unknown::new(
                    Tag::arbitrary(g), anyhow::anyhow!("Arbitrary::arbitrary"));
                u.set_body(Arbitrary::arbitrary(g));
                let u = Packet::Unknown(u);

                // Check that we didn't accidentally make a valid
                // packet.
                use crate::parse::Parse;
                use crate::serialize::SerializeInto;
                if let Ok(Packet::Unknown(_)) = Packet::from_bytes(
                    &u.to_vec().unwrap())
                {
                    break u;
                }

                // Try again!
            },
            _ => unreachable!(),
        }
    }
}

/// Fields used by multiple packet types.
#[derive(Default, Debug, Clone)]
pub(crate) struct Common {
    // In the future, this structure will hold the parsed CTB, packet
    // length, and lengths of chunks of partial body encoded packets.
    // This will allow for bit-perfect roundtripping of parsed
    // packets.  Since we consider Packets to be equal if their
    // serialized form is equal modulo CTB, packet length encoding,
    // and chunk lengths, this structure has trivial implementations
    // for PartialEq, Eq, PartialOrd, Ord, and Hash, so that we can
    // derive PartialEq, Eq, PartialOrd, Ord, and Hash for most
    // packets.

    /// XXX: Prevents trivial matching on this structure.  Remove once
    /// this structure actually gains some fields.
    dummy: std::marker::PhantomData<()>,
}
assert_send_and_sync!(Common);

impl Common {
    /// Returns a default version of `Common`.
    ///
    /// This is equivalent to using `Common::from`, but the function
    /// is constant.
    pub(crate) const fn new() -> Self {
        Common {
            dummy: std::marker::PhantomData
        }
    }
}

#[cfg(test)]
impl Arbitrary for Common {
    fn arbitrary(_: &mut Gen) -> Self {
        // XXX: Change if this gets interesting fields.
        Common::default()
    }
}

impl PartialEq for Common {
    fn eq(&self, _: &Common) -> bool {
        // Don't compare anything.
        true
    }
}

impl Eq for Common {}

impl PartialOrd for Common {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Common {
    fn cmp(&self, _: &Self) -> std::cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}

impl std::hash::Hash for Common {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {
        // Don't hash anything.
    }
}


/// An iterator over the *contents* of a packet in depth-first order.
///
/// Given a [`Packet`], an `Iter` iterates over the `Packet` and any
/// `Packet`s that it contains.  For non-container `Packet`s, this
/// just returns a reference to the `Packet` itself.  For [container
/// `Packet`s] like [`CompressedData`], and [`SEIP`], this
/// walks the `Packet` hierarchy in depth-first order, and returns the
/// `Packet`s the first time they are visited.  (Thus, the packet
/// itself is always returned first.)
///
/// This is returned by [`PacketPile::descendants`] and
/// [`Container::descendants`].
///
/// [container `Packet`s]: self#containers
/// [`PacketPile::descendants`]: super::PacketPile::descendants()
/// [`Container::descendants`]: Container::descendants()
pub struct Iter<'a> {
    // An iterator over the current message's children.
    children: slice::Iter<'a, Packet>,
    // The current child (i.e., the last value returned by
    // children.next()).
    child: Option<&'a Packet>,
    // The iterator over the current child's children.
    grandchildren: Option<Box<Iter<'a>>>,

    // The depth of the last returned packet.  This is used by the
    // `paths` iter.
    depth: usize,
}
assert_send_and_sync!(Iter<'_>);

impl<'a> Default for Iter<'a> {
    fn default() -> Self {
        Iter {
            children: [].iter(),
            child: None,
            grandchildren: None,
            depth: 0,
        }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Packet;

    fn next(&mut self) -> Option<Self::Item> {
        // If we don't have a grandchild iterator (self.grandchildren
        // is None), then we are just starting, and we need to get the
        // next child.
        if let Some(ref mut grandchildren) = self.grandchildren {
            let grandchild = grandchildren.next();
            // If the grandchild iterator is exhausted (grandchild is
            // None), then we need the next child.
            if grandchild.is_some() {
                self.depth = grandchildren.depth + 1;
                return grandchild;
            }
        }

        // Get the next child and the iterator for its children.
        self.child = self.children.next();
        if let Some(child) = self.child {
            self.grandchildren = child.descendants().map(Box::new);
        }

        // First return the child itself.  Subsequent calls will
        // return its grandchildren.
        self.depth = 0;
        self.child
    }
}

impl<'a> Iter<'a> {
    /// Extends an `Iter` to also return each packet's `pathspec`.
    ///
    /// This is similar to `enumerate`, but instead of counting, this
    /// returns each packet's `pathspec` in addition to a reference to
    /// the packet.
    ///
    /// See [`PacketPile::path_ref`] for an explanation of
    /// `pathspec`s.
    ///
    /// [`PacketPile::path_ref`]: super::PacketPile::path_ref
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::packet::prelude::*;
    /// use openpgp::PacketPile;
    ///
    /// # fn main() -> Result<()> {
    /// # let message = {
    /// #     use openpgp::types::CompressionAlgorithm;
    /// #     use openpgp::packet;
    /// #     use openpgp::PacketPile;
    /// #     use openpgp::serialize::Serialize;
    /// #     use openpgp::parse::Parse;
    /// #     use openpgp::types::DataFormat;
    /// #
    /// #     let mut lit = Literal::new(DataFormat::Unicode);
    /// #     lit.set_body(b"test".to_vec());
    /// #     let lit = Packet::from(lit);
    /// #
    /// #     let mut cd = CompressedData::new(
    /// #         CompressionAlgorithm::Uncompressed);
    /// #     cd.set_body(packet::Body::Structured(vec![lit.clone()]));
    /// #     let cd = Packet::from(cd);
    /// #
    /// #     // Make sure we created the message correctly: serialize,
    /// #     // parse it, and then check its form.
    /// #     let mut bytes = Vec::new();
    /// #     cd.serialize(&mut bytes)?;
    /// #
    /// #     let pp = PacketPile::from_bytes(&bytes[..])?;
    /// #
    /// #     assert_eq!(pp.descendants().count(), 2);
    /// #     assert_eq!(pp.path_ref(&[0]).unwrap().tag(),
    /// #                packet::Tag::CompressedData);
    /// #     assert_eq!(pp.path_ref(&[0, 0]), Some(&lit));
    /// #
    /// #     cd
    /// # };
    /// #
    /// let pp = PacketPile::from(message);
    /// let tags: Vec<(Vec<usize>, Tag)> = pp.descendants().paths()
    ///     .map(|(path, packet)| (path, packet.into()))
    ///     .collect::<Vec<_>>();
    /// assert_eq!(&tags,
    ///            &[
    ///               // Root.
    ///               ([0].to_vec(), Tag::CompressedData),
    ///               // Root's first child.
    ///               ([0, 0].to_vec(), Tag::Literal),
    ///             ]);
    /// # Ok(()) }
    /// ```
    pub fn paths(self)
                 -> impl Iterator<Item = (Vec<usize>, &'a Packet)> + Send + Sync
    {
        PacketPathIter {
            iter: self,
            path: None,
        }
    }
}


/// Augments the packet returned by `Iter` with its `pathspec`.
///
/// Like [`Iter::enumerate`].
///
/// [`Iter::enumerate`]: std::iter::Iterator::enumerate()
struct PacketPathIter<'a> {
    iter: Iter<'a>,

    // The path to the most recently returned node relative to the
    // start of the iterator.
    path: Option<Vec<usize>>,
}

impl<'a> Iterator for PacketPathIter<'a> {
    type Item = (Vec<usize>, &'a Packet);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(packet) = self.iter.next() {
            if self.path.is_none() {
                // Init.
                let mut path = Vec::with_capacity(4);
                path.push(0);
                self.path = Some(path);
            } else {
                let mut path = self.path.take().unwrap();
                let old_depth = path.len() - 1;

                let depth = self.iter.depth;
                if old_depth > depth {
                    // We popped.
                    path.truncate(depth + 1);
                    path[depth] += 1;
                } else if old_depth == depth {
                    // Sibling.
                    path[old_depth] += 1;
                } else if old_depth + 1 == depth {
                    // Recursion.
                    path.push(0);
                }
                self.path = Some(path);
            }
            Some((self.path.as_ref().unwrap().clone(), packet))
        } else {
            None
        }
    }
}

// Tests the `paths`() iter and `path_ref`().
#[test]
fn packet_path_iter() {
    use crate::parse::Parse;
    use crate::PacketPile;

    fn paths<'a>(iter: impl Iterator<Item=&'a Packet>) -> Vec<Vec<usize>> {
        let mut lpaths : Vec<Vec<usize>> = Vec::new();
        for (i, packet) in iter.enumerate() {
            let mut v = Vec::new();
            v.push(i);
            lpaths.push(v);

            if let Some(container) = packet.container_ref() {
                if let Some(c) = container.children() {
                    for mut path in paths(c).into_iter()
                    {
                        path.insert(0, i);
                        lpaths.push(path);
                    }
                }
            }
        }
        lpaths
    }

    for i in 1..5 {
        let pile = PacketPile::from_bytes(
            crate::tests::message(&format!("recursive-{}.pgp", i)[..])).unwrap();

        let mut paths1 : Vec<Vec<usize>> = Vec::new();
        for path in paths(pile.children()).iter() {
            paths1.push(path.clone());
        }

        let mut paths2 : Vec<Vec<usize>> = Vec::new();
        for (path, packet) in pile.descendants().paths() {
            assert_eq!(Some(packet), pile.path_ref(&path[..]));
            paths2.push(path);
        }

        if paths1 != paths2 {
            eprintln!("PacketPile:");
            pile.pretty_print();

            eprintln!("Expected paths:");
            for p in paths1 {
                eprintln!("  {:?}", p);
            }

            eprintln!("Got paths:");
            for p in paths2 {
                eprintln!("  {:?}", p);
            }

            panic!("Something is broken.  Don't panic.");
        }
    }
}

/// Holds a signature packet.
///
/// Signature packets are used to hold all kinds of signatures
/// including certifications, and signatures over documents.  See
/// [Section 5.2 of RFC 9580] for details.
///
///   [Section 5.2 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2
///
/// When signing a document, a `Signature` packet is typically created
/// indirectly by the [streaming `Signer`].  Similarly, a `Signature`
/// packet is created as a side effect of parsing a signed message
/// using the [`PacketParser`].
///
/// `Signature` packets are also used for [self signatures on Keys],
/// [self signatures on User IDs], [self signatures on User
/// Attributes], [certifications of User IDs], and [certifications of
/// User Attributes].  In these cases, you'll typically want to use
/// the [`SignatureBuilder`] to create the `Signature` packet.  See
/// the linked documentation for details, and examples.
///
/// [streaming `Signer`]: crate::serialize::stream::Signer
/// [`PacketParser`]: crate::parse::PacketParser
/// [self signatures on Keys]: Key::bind()
/// [self signatures on User IDs]: UserID::bind()
/// [self signatures on User Attributes]: user_attribute::UserAttribute::bind()
/// [certifications of User IDs]: UserID::certify()
/// [certifications of User Attributes]: user_attribute::UserAttribute::certify()
/// [`SignatureBuilder`]: signature::SignatureBuilder
///
/// # A note on equality
///
/// Two `Signature` packets are considered equal if their serialized
/// form is equal.  Notably this includes the unhashed subpacket area
/// and the order of subpackets and notations.  This excludes the
/// computed digest and signature level, which are not serialized.
///
/// A consequence of considering packets in the unhashed subpacket
/// area is that an adversary can take a valid signature and create
/// many distinct but valid signatures by changing the unhashed
/// subpacket area.  This has the potential of creating a denial of
/// service vector, if `Signature`s are naively deduplicated.  To
/// protect against this, consider using [`Signature::normalized_eq`].
///
///   [`Signature::normalized_eq`]: Signature::normalized_eq()
///
/// # Examples
///
/// Add a User ID to an existing certificate:
///
/// ```
/// use std::time;
/// use sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::packet::prelude::*;
/// use openpgp::policy::StandardPolicy;
///
/// # fn main() -> openpgp::Result<()> {
/// let p = &StandardPolicy::new();
///
/// let t1 = time::SystemTime::now();
/// let t2 = t1 + time::Duration::from_secs(1);
///
/// let (cert, _) = CertBuilder::new()
///     .set_creation_time(t1)
///     .add_userid("Alice <alice@example.org>")
///     .generate()?;
///
/// // Add a new User ID.
/// let mut signer = cert
///     .primary_key().key().clone().parts_into_secret()?.into_keypair()?;
///
/// // Use the existing User ID's signature as a template.  This ensures that
/// // we use the same
/// let userid = UserID::from("Alice <alice@other.com>");
/// let template: signature::SignatureBuilder
///     = cert.with_policy(p, t1)?.primary_userid().unwrap()
///         .binding_signature().clone().into();
/// let sig = template.clone()
///     .set_signature_creation_time(t2)?;
/// let sig = userid.bind(&mut signer, &cert, sig)?;
///
/// let cert = cert.insert_packets(vec![Packet::from(userid), sig.into()])?.0;
/// # assert_eq!(cert.with_policy(p, t2)?.userids().count(), 2);
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Debug)]
pub enum Signature {
    /// Signature packet version 3.
    V3(self::signature::Signature3),

    /// Signature packet version 4.
    V4(self::signature::Signature4),

    /// Signature packet version 6.
    V6(self::signature::Signature6),
}
assert_send_and_sync!(Signature);

impl Signature {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            Signature::V3(_) => 3,
            Signature::V4(_) => 4,
            Signature::V6(_) => 6,
        }
    }
}

impl From<Signature> for Packet {
    fn from(s: Signature) -> Self {
        Packet::Signature(s)
    }
}

impl Signature {
    /// Gets the salt, if any.
    pub fn salt(&self) -> Option<&[u8]> {
        match self {
            Signature::V3(_) => None,
            Signature::V4(_) => None,
            Signature::V6(s) => Some(s.salt()),
        }
    }

}

// Trivial forwarder for singleton enum.
impl Deref for Signature {
    type Target = signature::Signature4;

    fn deref(&self) -> &Self::Target {
        match self {
            Signature::V3(sig) => &sig.intern,
            Signature::V4(sig) => sig,
            Signature::V6(sig) => &sig.common,
        }
    }
}

// Trivial forwarder for singleton enum.
impl DerefMut for Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Signature::V3(ref mut sig) => &mut sig.intern,
            Signature::V4(ref mut sig) => sig,
            Signature::V6(ref mut sig) => &mut sig.common,
        }
    }
}

/// Holds a SEIP packet.
///
/// A SEIP packet holds encrypted data.  The data contains additional
/// OpenPGP packets.  See [Section 5.13 of RFC 9580] for details.
///
/// A SEIP packet is not normally instantiated directly.  In most
/// cases, you'll create one as a side effect of encrypting a message
/// using the [streaming serializer], or parsing an encrypted message
/// using the [`PacketParser`].
///
/// [Section 5.13 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.13
/// [streaming serializer]: crate::serialize::stream
/// [`PacketParser`]: crate::parse::PacketParser
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
#[non_exhaustive]
pub enum SEIP {
    /// SEIP packet version 1.
    V1(self::seip::SEIP1),

    /// SEIP packet version 2.
    V2(self::seip::SEIP2),
}
assert_send_and_sync!(SEIP);

impl SEIP {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            SEIP::V1(_) => 1,
            SEIP::V2(_) => 2,
        }
    }
}

impl From<SEIP> for Packet {
    fn from(p: SEIP) -> Self {
        Packet::SEIP(p)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::serialize::SerializeInto;
    use crate::parse::Parse;

    quickcheck! {
        fn roundtrip(p: Packet) -> bool {
            let buf = p.to_vec().expect("Failed to serialize packet");
            let q = Packet::from_bytes(&buf).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    quickcheck! {
        /// Given a packet and a position, induces a bit flip in the
        /// serialized form, then checks that PartialEq detects that.
        /// Recall that for packets, PartialEq is defined using the
        /// serialized form.
        fn mutate_eq_discriminates(p: Packet, i: usize) -> bool {
            if p.tag() == Tag::CompressedData {
                // Mutating compressed data streams is not that
                // trivial, because there are bits we can flip without
                // changing the decompressed data.
                return true;
            }

            let mut buf = p.to_vec().unwrap();
            // Avoid first two bytes so that we don't change the
            // type and reduce the chance of changing the length.
            if buf.len() < 3 { return true; }
            let bit = i % ((buf.len() - 2) * 8) + 16;
            buf[bit / 8] ^= 1 << (bit % 8);
            match Packet::from_bytes(&buf) {
                Ok(q) => p != q,
                Err(_) => true, // Packet failed to parse.
            }
        }
    }

    /// Problem on systems with 32-bit time_t.
    #[test]
    fn issue_802() -> Result<()> {
        let pp = crate::PacketPile::from_bytes(b"-----BEGIN PGP ARMORED FILE-----

xiEE/////xIJKyQDAwIIAQENAFYp8M2JngCfc04tIwMBCuU=
-----END PGP ARMORED FILE-----
")?;
        let p = pp.path_ref(&[0]).unwrap();
        let buf = p.to_vec().expect("Failed to serialize packet");
        let q = Packet::from_bytes(&buf).unwrap();
        assert_eq!(p, &q);
        Ok(())
    }
}
