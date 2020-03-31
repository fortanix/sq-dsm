//! Packet-related types.
//!
//! See [Section 4 of RFC 4880] for more details.
//!
//!   [Section 4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::slice;

use crate::Error;
use crate::Result;

#[macro_use]
mod container;
pub use container::Container;
pub use container::Body;

pub mod prelude;

use crate::crypto::KeyPair;

mod tag;
pub use self::tag::Tag;
pub mod header;
pub use self::header::Header;

mod unknown;
pub use self::unknown::Unknown;
pub mod signature;
pub mod one_pass_sig;
pub mod key;
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
pub mod pkesk;
mod mdc;
pub use self::mdc::MDC;
pub mod aed;

// DOC-HACK: To avoid having a top-level re-export of `Cert`, we move
// it in a submodule `def`.
pub use def::Packet;
mod def {
use super::*;
/// The OpenPGP packets that Sequoia understands.
///
/// The different OpenPGP packets are detailed in [Section 5 of RFC 4880].
///
/// The `Unknown` packet allows Sequoia to deal with packets that it
/// doesn't understand.  The `Unknown` packet is basically a binary
/// blob that includes the packet's tag.
///
/// The unknown packet is also used for packets that are understood,
/// but use unsupported options.  For instance, when the packet parser
/// encounters a compressed data packet with an unknown compression
/// algorithm, it returns the packet in an `Unknown` packet rather
/// than a `CompressedData` packet.
///
///   [Section 5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
///
/// # A note on equality
///
/// We define equality on `Packet` like equality of the serialized
/// form of the packet bodies defined by RFC4880, i.e. two packets are
/// considered equal if and only if their serialized form is equal,
/// modulo the OpenPGP framing (`CTB` and length style, potential
/// partial body encoding).
#[derive(Debug)]
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
    MDC(MDC),
    /// AEAD Encrypted Data Packet.
    AED(AED),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}
} // doc-hack, see above

impl Packet {
    /// Returns the `Packet's` corresponding OpenPGP tag.
    ///
    /// Tags are explained in [Section 4.3 of RFC 4880].
    ///
    ///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
    pub fn tag(&self) -> Tag {
        match self {
            &Packet::Unknown(ref packet) => packet.tag(),
            &Packet::Signature(_) => Tag::Signature,
            &Packet::OnePassSig(_) => Tag::OnePassSig,
            &Packet::PublicKey(_) => Tag::PublicKey,
            &Packet::PublicSubkey(_) => Tag::PublicSubkey,
            &Packet::SecretKey(_) => Tag::SecretKey,
            &Packet::SecretSubkey(_) => Tag::SecretSubkey,
            &Packet::Marker(_) => Tag::Marker,
            &Packet::Trust(_) => Tag::Trust,
            &Packet::UserID(_) => Tag::UserID,
            &Packet::UserAttribute(_) => Tag::UserAttribute,
            &Packet::Literal(_) => Tag::Literal,
            &Packet::CompressedData(_) => Tag::CompressedData,
            &Packet::PKESK(_) => Tag::PKESK,
            &Packet::SKESK(_) => Tag::SKESK,
            &Packet::SEIP(_) => Tag::SEIP,
            &Packet::MDC(_) => Tag::MDC,
            &Packet::AED(_) => Tag::AED,
            Packet::__Nonexhaustive => unreachable!(),
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
            &Packet::Unknown(_) => None,
            _ => Some(self.tag()),
        }
    }
}

// Allow transparent access of common fields.
impl<'a> Deref for Packet {
    type Target = Common;

    fn deref(&self) -> &Self::Target {
        match self {
            &Packet::Unknown(ref packet) => &packet.common,
            &Packet::Signature(ref packet) => &packet.common,
            &Packet::OnePassSig(ref packet) => &packet.common,
            &Packet::PublicKey(ref packet) => &packet.common,
            &Packet::PublicSubkey(ref packet) => &packet.common,
            &Packet::SecretKey(ref packet) => &packet.common,
            &Packet::SecretSubkey(ref packet) => &packet.common,
            &Packet::Marker(ref packet) => &packet.common,
            &Packet::Trust(ref packet) => &packet.common,
            &Packet::UserID(ref packet) => &packet.common,
            &Packet::UserAttribute(ref packet) => &packet.common,
            &Packet::Literal(ref packet) => &packet.common,
            &Packet::CompressedData(ref packet) => &packet.common,
            &Packet::PKESK(ref packet) => &packet.common,
            &Packet::SKESK(SKESK::V4(ref packet)) => &packet.common,
            &Packet::SKESK(SKESK::V5(ref packet)) => &packet.skesk4.common,
            Packet::SKESK(SKESK::__Nonexhaustive) => unreachable!(),
            &Packet::SEIP(ref packet) => &packet.common,
            &Packet::MDC(ref packet) => &packet.common,
            &Packet::AED(ref packet) => &packet.common,
            Packet::__Nonexhaustive => unreachable!(),
        }
    }
}

impl<'a> DerefMut for Packet {
    fn deref_mut(&mut self) -> &mut Common {
        match self {
            &mut Packet::Unknown(ref mut packet) => &mut packet.common,
            &mut Packet::Signature(ref mut packet) => &mut packet.common,
            &mut Packet::OnePassSig(ref mut packet) => &mut packet.common,
            &mut Packet::PublicKey(ref mut packet) => &mut packet.common,
            &mut Packet::PublicSubkey(ref mut packet) => &mut packet.common,
            &mut Packet::SecretKey(ref mut packet) => &mut packet.common,
            &mut Packet::SecretSubkey(ref mut packet) => &mut packet.common,
            &mut Packet::Marker(ref mut packet) => &mut packet.common,
            &mut Packet::Trust(ref mut packet) => &mut packet.common,
            &mut Packet::UserID(ref mut packet) => &mut packet.common,
            &mut Packet::UserAttribute(ref mut packet) => &mut packet.common,
            &mut Packet::Literal(ref mut packet) => &mut packet.common,
            &mut Packet::CompressedData(ref mut packet) => &mut packet.common,
            &mut Packet::PKESK(ref mut packet) => &mut packet.common,
            &mut Packet::SKESK(SKESK::V4(ref mut packet)) => &mut packet.common,
            &mut Packet::SKESK(SKESK::V5(ref mut packet)) => &mut packet.skesk4.common,
            Packet::SKESK(SKESK::__Nonexhaustive) => unreachable!(),
            &mut Packet::SEIP(ref mut packet) => &mut packet.common,
            &mut Packet::MDC(ref mut packet) => &mut packet.common,
            &mut Packet::AED(ref mut packet) => &mut packet.common,
            Packet::__Nonexhaustive => unreachable!(),
        }
    }
}

/// Fields used by multiple packet types.
#[derive(Debug, Clone)]
pub struct Common {
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

impl Default for Common {
    fn default() -> Common {
        Common {
            dummy: Default::default(),
        }
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
    fn partial_cmp(&self, _: &Self) -> Option<std::cmp::Ordering> {
        Some(std::cmp::Ordering::Equal)
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


/// A `Iter` iterates over the *contents* of a packet in
/// depth-first order.  It starts by returning the current packet.
pub struct Iter<'a> {
    // An iterator over the current message's children.
    children: slice::Iter<'a, Packet>,
    // The current child (i.e., the last value returned by
    // children.next()).
    child: Option<&'a Packet>,
    // The an iterator over the current child's children.
    grandchildren: Option<Box<Iter<'a>>>,

    // The depth of the last returned packet.  This is used by the
    // `paths` iter.
    depth: usize,
}

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
            self.grandchildren = child.descendants().map(|d| Box::new(d));
        }

        // First return the child itself.  Subsequent calls will
        // return its grandchildren.
        self.depth = 0;
        return self.child;
    }
}

impl<'a> Iter<'a> {
    /// Extends a `Iter` to also return each packet's path.
    ///
    /// This is similar to `enumerate`, but instead of counting, this
    /// returns each packet's path in addition to a reference to the
    /// packet.
    pub fn paths(self) -> impl Iterator<Item = (Vec<usize>, &'a Packet)> {
        PacketPathIter {
            iter: self,
            path: None,
        }
    }
}


/// Like `enumerate`, this augments the packet returned by a
/// `Iter` with its `Path`.
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

    fn paths(iter: slice::Iter<Packet>) -> Vec<Vec<usize>> {
        let mut lpaths : Vec<Vec<usize>> = Vec::new();
        for (i, packet) in iter.enumerate() {
            let mut v = Vec::new();
            v.push(i);
            lpaths.push(v);

            if let Some(ref container) = packet.container_ref() {
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
            crate::tests::message(&format!("recursive-{}.gpg", i)[..])).unwrap();

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
/// Signature packets are used both for certification purposes as well
/// as for document signing purposes.
///
/// See [Section 5.2 of RFC 4880] for details.
///
///   [Section 5.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
///
/// # A note on equality
///
/// Two `Signature` packets are considered equal if their serialized
/// form is equal.  Notably this includes the unhashed subpacket area
/// and the order of subpackets and notations, but excludes the
/// computed digest and signature level.
///
/// A consequence of considering packets in the unhashed subpacket
/// area is that an adversary can take a valid signature and create
/// many distinct but valid signatures by changing the unhashed
/// subpacket area.  This has the potential of creating a denial of
/// service vector.  To protect against this, consider using
/// [`Signature::normalized_eq`].
///
///   [`Signature::normalized_eq`]: #method.normalized_eq
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum Signature {
    /// Signature packet version 4.
    V4(self::signature::Signature4),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Signature {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            &Signature::V4(_) => 4,
            Signature::__Nonexhaustive => unreachable!(),
        }
    }
}

impl From<Signature> for Packet {
    fn from(s: Signature) -> Self {
        Packet::Signature(s)
    }
}

// Trivial forwarder for singleton enum.
impl Deref for Signature {
    type Target = signature::Signature4;

    fn deref(&self) -> &Self::Target {
        match self {
            Signature::V4(sig) => sig,
            Signature::__Nonexhaustive => unreachable!(),
        }
    }
}

// Trivial forwarder for singleton enum.
impl DerefMut for Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Signature::V4(ref mut sig) => sig,
            Signature::__Nonexhaustive => unreachable!(),
        }
    }
}

/// Holds a one-pass signature packet.
///
/// See [Section 5.4 of RFC 4880] for details.
///
///   [Section 5.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.4
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum OnePassSig {
    /// OnePassSig packet version 3.
    V3(self::one_pass_sig::OnePassSig3),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl OnePassSig {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            &OnePassSig::V3(_) => 3,
            OnePassSig::__Nonexhaustive => unreachable!(),
        }
    }
}

impl From<OnePassSig> for Packet {
    fn from(s: OnePassSig) -> Self {
        Packet::OnePassSig(s)
    }
}

// Trivial forwarder for singleton enum.
impl Deref for OnePassSig {
    type Target = one_pass_sig::OnePassSig3;

    fn deref(&self) -> &Self::Target {
        match self {
            OnePassSig::V3(ops) => ops,
            OnePassSig::__Nonexhaustive => unreachable!(),
        }
    }
}

// Trivial forwarder for singleton enum.
impl DerefMut for OnePassSig {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            OnePassSig::V3(ref mut ops) => ops,
            OnePassSig::__Nonexhaustive => unreachable!(),
        }
    }
}

/// Holds an asymmetrically encrypted session key.
///
/// The session key is needed to decrypt the actual ciphertext.  See
/// [Section 5.1 of RFC 4880] for details.
///
///   [Section 5.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.1
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum PKESK {
    /// PKESK packet version 3.
    V3(self::pkesk::PKESK3),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl PKESK {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            PKESK::V3(_) => 3,
            PKESK::__Nonexhaustive => unreachable!(),
        }
    }
}

impl From<PKESK> for Packet {
    fn from(p: PKESK) -> Self {
        Packet::PKESK(p)
    }
}

// Trivial forwarder for singleton enum.
impl Deref for PKESK {
    type Target = self::pkesk::PKESK3;

    fn deref(&self) -> &Self::Target {
        match self {
            PKESK::V3(ref p) => p,
            PKESK::__Nonexhaustive => unreachable!(),
        }
    }
}

// Trivial forwarder for singleton enum.
impl DerefMut for PKESK {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            PKESK::V3(ref mut p) => p,
            PKESK::__Nonexhaustive => unreachable!(),
        }
    }
}

/// Holds an symmetrically encrypted session key.
///
/// Holds an symmetrically encrypted session key.  The session key is
/// needed to decrypt the actual ciphertext.  See [Section 5.3 of RFC
/// 4880] for details.
///
/// [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.3
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SKESK {
    /// SKESK packet version 4.
    V4(self::skesk::SKESK4),
    /// SKESK packet version 5.
    ///
    /// This feature is [experimental](../index.html#experimental-features).
    V5(self::skesk::SKESK5),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl SKESK {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            &SKESK::V4(_) => 4,
            &SKESK::V5(_) => 5,
            SKESK::__Nonexhaustive => unreachable!(),
        }
    }
}

impl From<SKESK> for Packet {
    fn from(p: SKESK) -> Self {
        Packet::SKESK(p)
    }
}

/// Holds a public key, public subkey, private key or private subkey packet.
///
/// See [Section 5.5 of RFC 4880] for details.
///
///   [Section 5.5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.5
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
///
/// # A note on equality
///
/// Two `Key` packets are considered equal if their serialized form is
/// equal.  Notably this includes the secret key material, but
/// excludes the `KeyParts` and `KeyRole` marker traits.
///
/// To compare only the public bits of `Key` packets, use
/// [`Key::public_eq`].
///
///   [`Key::public_eq`]: #method.public_eq
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum Key<P: key::KeyParts, R: key::KeyRole> {
    /// Key packet version 4.
    V4(self::key::Key4<P, R>),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl<P: key::KeyParts, R: key::KeyRole> fmt::Display for Key<P, R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Key::V4(k) => k.fmt(f),
            Key::__Nonexhaustive => unreachable!(),
        }
    }
}

impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            Key::V4(_) => 4,
            Key::__Nonexhaustive => unreachable!(),
        }
    }

    /// Compares the public bits of two keys.
    ///
    /// This returns Ordering::Equal if the public MPIs, version,
    /// creation time and algorithm of the two `Key`s match.  This
    /// does not consider the packet's encoding, packet's tag or the
    /// secret key material.
    pub fn public_cmp<PB, RB>(&self, b: &Key<PB, RB>) -> std::cmp::Ordering
        where PB: key::KeyParts,
              RB: key::KeyRole,
    {
        match (self, b) {
            (Key::V4(a), Key::V4(b)) => a.public_cmp(b),
            (Key::__Nonexhaustive, _) => unreachable!(),
            (_, Key::__Nonexhaustive) => unreachable!(),
        }
    }

    /// This method tests for self and other values to be equal modulo
    /// the secret bits.
    ///
    /// This returns true if the public MPIs, creation time and
    /// algorithm of the two `Key`s match.  This does not consider
    /// the packet's encoding, packet's tag or the secret key
    /// material.
    pub fn public_eq<PB, RB>(&self, b: &Key<PB, RB>) -> bool
        where PB: key::KeyParts,
              RB: key::KeyRole,
    {
        self.public_cmp(b) == std::cmp::Ordering::Equal
    }
}

impl From<Key<key::PublicParts, key::PrimaryRole>> for Packet {
    /// Convert the `Key` struct to a `Packet`.
    fn from(k: Key<key::PublicParts, key::PrimaryRole>) -> Self {
        Packet::PublicKey(k.into())
    }
}

impl From<Key<key::PublicParts, key::SubordinateRole>> for Packet {
    /// Convert the `Key` struct to a `Packet`.
    fn from(k: Key<key::PublicParts, key::SubordinateRole>) -> Self {
        Packet::PublicSubkey(k.into())
    }
}

impl From<Key<key::SecretParts, key::PrimaryRole>> for Packet {
    /// Convert the `Key` struct to a `Packet`.
    fn from(k: Key<key::SecretParts, key::PrimaryRole>) -> Self {
        Packet::SecretKey(k.into())
    }
}

impl From<Key<key::SecretParts, key::SubordinateRole>> for Packet {
    /// Convert the `Key` struct to a `Packet`.
    fn from(k: Key<key::SecretParts, key::SubordinateRole>) -> Self {
        Packet::SecretSubkey(k.into())
    }
}

impl<R: key::KeyRole> Key<key::SecretParts, R> {
    /// Creates a new key pair from a Key packet with an unencrypted
    /// secret key.
    ///
    /// # Errors
    ///
    /// Fails if the secret key is missing, or encrypted.
    pub fn into_keypair(self) -> Result<KeyPair> {
        use crate::packet::key::SecretKeyMaterial;
        let (key, secret) = self.take_secret();
        let secret = match secret {
            SecretKeyMaterial::Unencrypted(secret) => secret,
            SecretKeyMaterial::Encrypted(_) =>
                return Err(Error::InvalidArgument(
                    "secret key is encrypted".into()).into()),
        };

        KeyPair::new(key.mark_role_unspecified(), secret)
    }
}

impl<R: key::KeyRole> key::Key4<key::SecretParts, R> {
    /// Creates a new key pair from a Key packet with an unencrypted
    /// secret key.
    ///
    /// # Errors
    ///
    /// Fails if the secret key is missing, or encrypted.
    pub fn into_keypair(self) -> Result<KeyPair> {
        use crate::packet::key::SecretKeyMaterial;
        let (key, secret) = self.take_secret();
        let secret = match secret {
            SecretKeyMaterial::Unencrypted(secret) => secret,
            SecretKeyMaterial::Encrypted(_) =>
                return Err(Error::InvalidArgument(
                    "secret key is encrypted".into()).into()),
        };

        KeyPair::new(key.mark_role_unspecified().into(), secret)
    }
}

macro_rules! impl_common_secret_functions {
    ($t: path) => {
        /// Secret key handling.
        impl<R: key::KeyRole> Key<$t, R> {
            /// Takes the key packet's `SecretKeyMaterial`, if any.
            pub fn take_secret(self)
                               -> (Key<key::PublicParts, R>,
                                   Option<key::SecretKeyMaterial>)
            {
                match self {
                    Key::V4(k) => {
                        let (k, s) = k.take_secret();
                        (k.into(), s)
                    },
                    Key::__Nonexhaustive => unreachable!(),
                }
            }

            /// Adds `SecretKeyMaterial` to the packet, returning the old if
            /// any.
            pub fn add_secret(self, secret: key::SecretKeyMaterial)
                              -> (Key<key::SecretParts, R>,
                                  Option<key::SecretKeyMaterial>)
            {
                match self {
                    Key::V4(k) => {
                        let (k, s) = k.add_secret(secret);
                        (k.into(), s)
                    },
                    Key::__Nonexhaustive => unreachable!(),
                }
            }
        }
    }
}
impl_common_secret_functions!(key::PublicParts);
impl_common_secret_functions!(key::UnspecifiedParts);

/// Secret key handling.
impl<R: key::KeyRole> Key<key::SecretParts, R> {
    /// Takes the key packet's `SecretKeyMaterial`.
    pub fn take_secret(self)
                       -> (Key<key::PublicParts, R>, key::SecretKeyMaterial)
    {
        match self {
            Key::V4(k) => {
                let (k, s) = k.take_secret();
                (k.into(), s)
            },
            Key::__Nonexhaustive => unreachable!(),
        }
    }

    /// Adds `SecretKeyMaterial` to the packet, returning the old.
    pub fn add_secret(self, secret: key::SecretKeyMaterial)
                      -> (Key<key::SecretParts, R>, key::SecretKeyMaterial)
    {
        match self {
            Key::V4(k) => {
                let (k, s) = k.add_secret(secret);
                (k.into(), s)
            },
            Key::__Nonexhaustive => unreachable!(),
        }
    }
}


// Trivial forwarder for singleton enum.
impl<P: key::KeyParts, R: key::KeyRole> Deref for Key<P, R> {
    type Target = self::key::Key4<P, R>;

    fn deref(&self) -> &Self::Target {
        match self {
            Key::V4(ref p) => p,
            Key::__Nonexhaustive => unreachable!(),
        }
    }
}

// Trivial forwarder for singleton enum.
impl<P: key::KeyParts, R: key::KeyRole> DerefMut for Key<P, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Key::V4(ref mut p) => p,
            Key::__Nonexhaustive => unreachable!(),
        }
    }
}

/// Holds an encrypted data packet.
///
/// An encrypted data packet is a container.  See [Section 5.13 of RFC
/// 4880] for details.
///
/// [Section 5.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.13
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SEIP {
    /// SEIP packet version 1.
    V1(self::seip::SEIP1),
}

impl SEIP {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            SEIP::V1(_) => 1,
        }
    }
}

impl From<SEIP> for Packet {
    fn from(p: SEIP) -> Self {
        Packet::SEIP(p)
    }
}

// Trivial forwarder for singleton enum.
impl Deref for SEIP {
    type Target = self::seip::SEIP1;

    fn deref(&self) -> &Self::Target {
        match self {
            SEIP::V1(ref p) => p,
        }
    }
}

// Trivial forwarder for singleton enum.
impl DerefMut for SEIP {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            SEIP::V1(ref mut p) => p,
        }
    }
}

/// Holds an AEAD encrypted data packet.
///
/// An AEAD encrypted data packet is a container.  See [Section 5.16
/// of RFC 4880bis] for details.
///
/// [Section 5.16 of RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.16
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
///
/// This feature is [experimental](../index.html#experimental-features).
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum AED {
    /// AED packet version 1.
    V1(self::aed::AED1),

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl AED {
    /// Gets the version.
    pub fn version(&self) -> u8 {
        match self {
            AED::V1(_) => 1,
            AED::__Nonexhaustive => unreachable!(),
        }
    }
}

impl From<AED> for Packet {
    fn from(p: AED) -> Self {
        Packet::AED(p)
    }
}

// Trivial forwarder for singleton enum.
impl Deref for AED {
    type Target = self::aed::AED1;

    fn deref(&self) -> &Self::Target {
        match self {
            AED::V1(ref p) => p,
            AED::__Nonexhaustive => unreachable!(),
        }
    }
}

// Trivial forwarder for singleton enum.
impl DerefMut for AED {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            AED::V1(ref mut p) => p,
            AED::__Nonexhaustive => unreachable!(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn packet_is_send_and_sync() {
        fn f<T: Send + Sync>(_: T) {}
        f(Packet::Marker(Default::default()));
    }
}
