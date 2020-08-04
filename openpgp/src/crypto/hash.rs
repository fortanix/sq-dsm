//! Cryptographic hash functions and hashing of OpenPGP data
//! structures.
//!
//! This module provides [`Context`] representing a hash function
//! context independent of the cryptographic backend, as well as trait
//! [`Hash`] that handles hashing of OpenPGP data structures.
//!
//!   [`Context`]: struct.Context.html
//!   [`Hash`]: trait.Hash.html

use std::convert::TryFrom;

use dyn_clone::DynClone;

use crate::HashAlgorithm;
use crate::packet::Key;
use crate::packet::UserID;
use crate::packet::UserAttribute;
use crate::packet::key;
use crate::packet::key::Key4;
use crate::packet::Signature;
use crate::packet::signature::{self, Signature4};
use crate::Result;
use crate::types::Timestamp;

use std::fs::{File, OpenOptions};
use std::io::{self, Write};

// If set to e.g. Some("/tmp/hash"), we will dump everything that is
// hashed to files /tmp/hash-N, where N is a number.
const DUMP_HASHED_VALUES: Option<&str> = None;

/// Hasher capable of calculating a digest for the input byte stream.
pub(crate) trait Digest: DynClone {
    /// Size of the digest in bytes
    fn digest_size(&self) -> usize;

    /// Writes data into the hash function.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash function and writes the digest into the
    /// provided slice.
    ///
    /// Resets the hash function contexts.
    ///
    /// `digest` must be at least `self.digest_size()` bytes large,
    /// otherwise the digest will be truncated.
    fn digest(&mut self, digest: &mut [u8]);
}

dyn_clone::clone_trait_object!(Digest);

/// State of a hash function.
///
/// This provides an abstract interface to the hash functions used in
/// OpenPGP.  `Context`s are created using [`HashAlgorithm::context`].
///
///   [`HashAlgorithm::context`]: ../../types/enum.HashAlgorithm.html#method.context
///
/// # Examples
///
/// ```rust
/// # fn main() -> sequoia_openpgp::Result<()> {
/// use sequoia_openpgp::types::HashAlgorithm;
///
/// // Create a context and feed data to it.
/// let mut ctx = HashAlgorithm::SHA512.context()?;
/// ctx.update(&b"The quick brown fox jumps over the lazy dog."[..]);
///
/// // Extract the digest.
/// let mut digest = vec![0; ctx.digest_size()];
/// ctx.digest(&mut digest);
///
/// use sequoia_openpgp::fmt::hex;
/// assert_eq!(&hex::encode(digest),
///            "91EA1245F20D46AE9A037A989F54F1F7\
///             90F0A47607EEB8A14D12890CEA77A1BB\
///             C6C7ED9CF205E67B7F2B8FD4C7DFD3A7\
///             A8617E45F3C463D481C7E586C39AC1ED");
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct Context {
    algo: HashAlgorithm,
    ctx: Box<dyn Digest>,
}

impl Context {
    /// Returns the algorithm.
    pub fn algo(&self) -> HashAlgorithm {
        self.algo
    }

    /// Size of the digest in bytes
    pub fn digest_size(&self) -> usize {
        self.ctx.digest_size()
    }

    /// Writes data into the hash function.
    pub fn update<D: AsRef<[u8]>>(&mut self, data: D) {
        self.ctx.update(data.as_ref());
    }

    /// Finalizes the hash function and writes the digest into the
    /// provided slice.
    ///
    /// Resets the hash function contexts.
    ///
    /// `digest` must be at least [`self.digest_size()`] bytes large,
    /// otherwise the digest will be truncated.
    ///
    ///   [`self.digest_size()`]: #method.digest_size
    pub fn digest<D: AsMut<[u8]>>(&mut self, mut digest: D) {
        self.ctx.digest(digest.as_mut());
    }
}

impl io::Write for Context {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl HashAlgorithm {
    /// Creates a new hash context for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` if Sequoia does
    /// not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    ///
    ///   [`HashAlgorithm::is_supported`]: #method.is_supported
    pub fn context(self) -> Result<Context> {
        self.new_hasher()
            .map(|hasher| Context {
                algo: self,
                ctx: if let Some(prefix) = DUMP_HASHED_VALUES {
                    Box::new(HashDumper::new(hasher, prefix))
                } else {
                    hasher
                },
            })
    }
}

struct HashDumper {
    hasher: Box<dyn Digest>,
    sink: File,
    filename: String,
    written: usize,
}

impl HashDumper {
    fn new(hasher: Box<dyn Digest>, prefix: &str) -> Self {
        let mut n = 0;
        let mut filename;
        let sink = loop {
            filename = format!("{}-{}", prefix, n);
            match OpenOptions::new().write(true).create_new(true)
                .open(&filename)
            {
                Ok(f) => break f,
                Err(_) => n += 1,
            }
        };
        eprintln!("HashDumper: Writing to {}...", &filename);
        HashDumper {
            hasher,
            sink,
            filename,
            written: 0,
        }
    }
}

impl Clone for HashDumper {
    fn clone(&self) -> HashDumper {
        // We only ever create instances of HashDumper when debugging.
        // Whenever we're cloning an instance, just open another file for
        // inspection.
        let prefix = DUMP_HASHED_VALUES
            .expect("cloning a HashDumper but DUMP_HASHED_VALUES wasn't specified");
        HashDumper::new(self.hasher.clone(), prefix)
    }
}

impl Drop for HashDumper {
    fn drop(&mut self) {
        eprintln!("HashDumper: Wrote {} bytes to {}...", self.written,
                  self.filename);
    }
}

impl Digest for HashDumper {
    fn digest_size(&self) -> usize {
        self.hasher.digest_size()
    }
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.sink.write_all(data).unwrap();
        self.written += data.len();
    }
    fn digest(&mut self, digest: &mut [u8]) {
        self.hasher.digest(digest);
    }
}

/// Hashes OpenPGP packets and related types.
///
/// Some OpenPGP data structures need to be hashed to be covered by
/// OpenPGP signatures.  Hashing is often based on the serialized
/// form, with some aspects fixed to ensure consistent results.  This
/// trait implements hashing as specified by OpenPGP.
///
/// Most of the time it is not necessary to manually compute hashes.
/// Instead, higher level functionality, like the streaming
/// [`Verifier`], [`DetachedVerifier`], or [`Signature`'s verification
/// functions] should be used, which handle the hashing internally.
///
///   [`Verifier`]: ../../parse/stream/struct.Verifier.html
///   [`DetachedVerifier`]: ../../parse/stream/struct.DetachedVerifier.html
///   [`Signature`'s verification functions]: ../../packet/enum.Signature.html#verification-functions
///
/// This is a low-level mechanism.  See [`Signature`'s hashing
/// functions] for how to hash compounds like (Key,UserID)-bindings.
///
///   [`Signature`'s hashing functions]: ../../packet/enum.Signature.html#hashing-functions
pub trait Hash {
    /// Updates the given hash with this object.
    fn hash(&self, hash: &mut Context);
}

impl Hash for UserID {
    fn hash(&self, hash: &mut Context) {
        let len = self.value().len() as u32;

        let mut header = [0; 5];
        header[0] = 0xB4;
        header[1..5].copy_from_slice(&len.to_be_bytes());

        hash.update(header);
        hash.update(self.value());
    }
}

impl Hash for UserAttribute {
    fn hash(&self, hash: &mut Context) {
        let len = self.value().len() as u32;

        let mut header = [0; 5];
        header[0] = 0xD1;
        header[1..5].copy_from_slice(&len.to_be_bytes());

        hash.update(&header);
        hash.update(self.value());
    }
}

impl<P, R> Hash for Key4<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn hash(&self, hash: &mut Context) {
        use crate::serialize::MarshalInto;

        // We hash 9 bytes plus the MPIs.  But, the len doesn't
        // include the tag (1 byte) or the length (2 bytes).
        let len = (9 - 3) + self.mpis().serialized_len() as u16;

        let mut header: Vec<u8> = Vec::with_capacity(9);

        // Tag.  Note: we use this whether
        header.push(0x99);

        // Length (2 bytes, big endian).
        header.extend_from_slice(&len.to_be_bytes());

        // Version.
        header.push(4);

        // Creation time.
        let creation_time: u32 =
            Timestamp::try_from(self.creation_time())
            .unwrap_or_else(|_| Timestamp::from(0))
            .into();
        header.extend_from_slice(&creation_time.to_be_bytes());

        // Algorithm.
        header.push(self.pk_algo().into());

        hash.update(&header[..]);

        // MPIs.
        self.mpis().hash(hash);
    }
}

impl Hash for Signature {
    fn hash(&self, hash: &mut Context) {
        match self {
            Signature::V4(sig) => sig.hash(hash),
            Signature::__Nonexhaustive => unreachable!(),
        }
    }
}

impl Hash for Signature4 {
    fn hash(&self, hash: &mut Context) {
        self.fields.hash(hash);
    }
}

impl Hash for signature::SignatureFields {
    fn hash(&self, hash: &mut Context) {
        use crate::serialize::MarshalInto;

        // XXX: Annoyingly, we have no proper way of handling errors
        // here.
        let hashed_area = self.hashed_area().to_vec()
            .unwrap_or_else(|_| Vec::new());

        // A version 4 signature packet is laid out as follows:
        //
        //   version - 1 byte                    \
        //   type - 1 byte                        \
        //   pk_algo - 1 byte                      \
        //   hash_algo - 1 byte                      Included in the hash
        //   hashed_area_len - 2 bytes (big endian)/
        //   hashed_area                         _/
        //   ...                                 <- Not included in the hash

        let mut header = [0u8; 6];

        // Version.
        header[0] = 4;
        header[1] = self.typ().into();
        header[2] = self.pk_algo().into();
        header[3] = self.hash_algo().into();

        // The length of the hashed area, as a 16-bit big endian number.
        let len = hashed_area.len() as u16;
        header[4..6].copy_from_slice(&len.to_be_bytes());

        hash.update(&header[..]);
        hash.update(&hashed_area);

        // A version 4 signature trailer is:
        //
        //   version - 1 byte
        //   0xFF (constant) - 1 byte
        //   amount - 4 bytes (big endian)
        //
        // The amount field is the amount of hashed from this
        // packet (this excludes the message content, and this
        // trailer).
        //
        // See https://tools.ietf.org/html/rfc4880#section-5.2.4
        let mut trailer = [0u8; 6];

        trailer[0] = 4;
        trailer[1] = 0xff;
        // The signature packet's length, not including the previous
        // two bytes and the length.
        let len = (header.len() + hashed_area.len()) as u32;
        trailer[2..6].copy_from_slice(&len.to_be_bytes());

        hash.update(&trailer[..]);
    }
}

/// Hashing-related functionality.
///
/// <a name="hashing-functions"></a>
impl Signature {
    /// Computes the message digest of standalone signatures.
    pub fn hash_standalone(sig: &signature::SignatureFields)
        -> Result<Vec<u8>>
    {
        let mut h = sig.hash_algo().context()?;

        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }

    /// Computes the message digest of timestamp signatures.
    pub fn hash_timestamp(sig: &signature::SignatureFields)
        -> Result<Vec<u8>>
    {
        Self::hash_standalone(sig)
    }

    /// Returns the message digest of the direct key signature over
    /// the specified primary key.
    pub fn hash_direct_key<P>(sig: &signature::SignatureFields,
                              key: &Key<P, key::PrimaryRole>)
        -> Result<Vec<u8>>
        where P: key::KeyParts,
    {

        let mut h = sig.hash_algo().context()?;

        key.hash(&mut h);
        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }

    /// Returns the message digest of the subkey binding over the
    /// specified primary key and subkey.
    pub fn hash_subkey_binding<P, Q>(sig: &signature::SignatureFields,
                                     key: &Key<P, key::PrimaryRole>,
                                     subkey: &Key<Q, key::SubordinateRole>)
        -> Result<Vec<u8>>
        where P: key::KeyParts,
              Q: key::KeyParts,
    {
        let mut h = sig.hash_algo().context()?;

        key.hash(&mut h);
        subkey.hash(&mut h);
        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }

    /// Returns the message digest of the primary key binding over the
    /// specified primary key and subkey.
    pub fn hash_primary_key_binding<P, Q>(sig: &signature::SignatureFields,
                                          key: &Key<P, key::PrimaryRole>,
                                          subkey: &Key<Q, key::SubordinateRole>)
        -> Result<Vec<u8>>
        where P: key::KeyParts,
              Q: key::KeyParts,
    {
        Self::hash_subkey_binding(sig, key, subkey)
    }

    /// Returns the message digest of the user ID binding over the
    /// specified primary key, user ID, and signature.
    pub fn hash_userid_binding<P>(sig: &signature::SignatureFields,
                                  key: &Key<P, key::PrimaryRole>,
                                  userid: &UserID)
        -> Result<Vec<u8>>
        where P: key::KeyParts,
    {
        let mut h = sig.hash_algo().context()?;

        key.hash(&mut h);
        userid.hash(&mut h);
        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }

    /// Returns the message digest of the user attribute binding over
    /// the specified primary key, user attribute, and signature.
    pub fn hash_user_attribute_binding<P>(
        sig: &signature::SignatureFields,
        key: &Key<P, key::PrimaryRole>,
        ua: &UserAttribute)
        -> Result<Vec<u8>>
        where P: key::KeyParts,
    {
        let mut h = sig.hash_algo().context()?;

        key.hash(&mut h);
        ua.hash(&mut h);
        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Cert;
    use crate::parse::Parse;

    #[test]
    fn hash_verification() {
        fn check(cert: Cert) -> (usize, usize, usize) {
            let mut userid_sigs = 0;
            for (i, binding) in cert.userids().enumerate() {
                for selfsig in binding.self_signatures() {
                    let h = Signature::hash_userid_binding(
                        selfsig,
                        cert.primary_key().key(),
                        binding.userid()).unwrap();
                    if &h[..2] != selfsig.digest_prefix() {
                        eprintln!("{:?}: {:?} / {:?}",
                                  i, binding.userid(), selfsig);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(&h[..2], selfsig.digest_prefix());
                    userid_sigs += 1;
                }
            }
            let mut ua_sigs = 0;
            for (i, a) in cert.user_attributes().enumerate()
            {
                for selfsig in a.self_signatures() {
                    let h = Signature::hash_user_attribute_binding(
                        selfsig,
                        cert.primary_key().key(),
                        a.user_attribute()).unwrap();
                    if &h[..2] != selfsig.digest_prefix() {
                        eprintln!("{:?}: {:?} / {:?}",
                                  i, a.user_attribute(), selfsig);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(&h[..2], selfsig.digest_prefix());
                    ua_sigs += 1;
                }
            }
            let mut subkey_sigs = 0;
            for (i, binding) in cert.subkeys().enumerate() {
                for selfsig in binding.self_signatures() {
                    let h = Signature::hash_subkey_binding(
                        selfsig,
                        cert.primary_key().key(),
                        binding.key()).unwrap();
                    if &h[..2] != selfsig.digest_prefix() {
                        eprintln!("{:?}: {:?}", i, binding);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(h[0], selfsig.digest_prefix()[0]);
                    assert_eq!(h[1], selfsig.digest_prefix()[1]);
                    subkey_sigs += 1;
                }
            }

            (userid_sigs, ua_sigs, subkey_sigs)
        }

        check(Cert::from_bytes(crate::tests::key("hash-algos/MD5.gpg")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/RipeMD160.gpg")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA1.gpg")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA224.gpg")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA256.gpg")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA384.gpg")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA512.gpg")).unwrap());
        check(Cert::from_bytes(crate::tests::key("bannon-all-uids-subkeys.gpg")).unwrap());
        let (_userid_sigs, ua_sigs, _subkey_sigs)
            = check(Cert::from_bytes(crate::tests::key("dkg.gpg")).unwrap());
        assert!(ua_sigs > 0);
    }
}
