//! Cryptographic hash functions and hashing of OpenPGP data
//! structures.
//!
//! This module provides struct [`Context`] representing a hash
//! function context independent of the cryptographic backend, as well
//! as trait [`Hash`] that handles hashing of OpenPGP data structures.
//!
//!
//! # Examples
//!
//! ```rust
//! # fn main() -> sequoia_openpgp::Result<()> {
//! use sequoia_openpgp::types::HashAlgorithm;
//!
//! // Create a context and feed data to it.
//! let mut ctx = HashAlgorithm::SHA512.context()?.for_digest();
//! ctx.update(&b"The quick brown fox jumps over the lazy dog."[..]);
//!
//! // Extract the digest.
//! let mut digest = vec![0; ctx.digest_size()];
//! ctx.digest(&mut digest);
//!
//! use sequoia_openpgp::fmt::hex;
//! assert_eq!(&hex::encode(digest),
//!            "91EA1245F20D46AE9A037A989F54F1F7\
//!             90F0A47607EEB8A14D12890CEA77A1BB\
//!             C6C7ED9CF205E67B7F2B8FD4C7DFD3A7\
//!             A8617E45F3C463D481C7E586C39AC1ED");
//! # Ok(()) }
//! ```

use std::{
    convert::TryFrom,
    sync::OnceLock,
};

use dyn_clone::DynClone;

use crate::HashAlgorithm;
use crate::packet::Key;
use crate::packet::UserID;
use crate::packet::UserAttribute;
use crate::packet::key;
use crate::packet::key::{Key4, Key6};
use crate::packet::Signature;
use crate::packet::signature::{self, Signature3, Signature4, Signature6};
use crate::Error;
use crate::Result;
use crate::types::{SignatureType, Timestamp};

use std::fs::{File, OpenOptions};
use std::io::{self, Write};

// If set to e.g. Some("/tmp/hash"), we will dump everything that is
// hashed to files /tmp/hash-N, where N is a number.
const DUMP_HASHED_VALUES: Option<&str> = None;

// ASN.1 OID values copied from the nettle-rs crate:
// https://gitlab.com/sequoia-pgp/nettle-rs/-/blob/main/src/rsa/pkcs1.rs#L22

/// ASN.1 OID for MD5
const ASN1_OID_MD5: &[u8] = &[
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x02, 0x05, 0x05, 0x00, 0x04, 0x10,
];

/// ASN.1 OID for RipeMD160
const ASN1_OID_RIPEMD160: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x14,
];

/// ASN.1 OID for SHA1
const ASN1_OID_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
    0x00, 0x04, 0x14,
];

/// ASN.1 OID for SHA224
const ASN1_OID_SHA224: &[u8] = &[
    0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C,
];

/// ASN.1 OID for SHA256
const ASN1_OID_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
];

/// ASN.1 OID for SHA384
const ASN1_OID_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
];

/// ASN.1 OID for SHA512
const ASN1_OID_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
];

/// ASN.1 OID for SHA3-256
const ASN1_OID_SHA3_256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20
];

/// ASN.1 OID for SHA3-512.
const ASN1_OID_SHA3_512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40
];

/// List of hashes that the signer may produce.
///
/// This list is ordered by the preference so that the most preferred
/// hash algorithm is first.
pub(crate) fn default_hashes() -> &'static [HashAlgorithm] {
    static DEFAULT_HASHES: OnceLock<Vec<HashAlgorithm>> = OnceLock::new();
    DEFAULT_HASHES.get_or_init(|| vec![
        HashAlgorithm::default(),
        HashAlgorithm::SHA512,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA224,
        HashAlgorithm::SHA1,
        HashAlgorithm::RipeMD,
        HashAlgorithm::MD5,
    ])
}

/// List of hashes that the signer may produce.
///
/// This list is sorted.
pub(crate) fn default_hashes_sorted() -> &'static [HashAlgorithm] {
    static DEFAULT_HASHES: OnceLock<Vec<HashAlgorithm>> = OnceLock::new();
    DEFAULT_HASHES.get_or_init(|| {
        let mut hashes = default_hashes().to_vec();
        hashes.sort();
        hashes
    })
}

/// Hasher capable of calculating a digest for the input byte stream.
///
/// This provides an abstract interface to the hash functions used in
/// OpenPGP.  It is used by the crypto backends to provide a uniform
/// interface to hash functions.
pub(crate) trait Digest: DynClone + Write + Send + Sync {
    /// Writes data into the hash function.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the hash function and writes the digest into the
    /// provided slice.
    ///
    /// Resets the hash function contexts.
    ///
    /// `digest` must be at least `self.digest_size()` bytes large,
    /// otherwise the digest will be truncated.
    fn digest(&mut self, digest: &mut [u8]) -> Result<()>;
}

dyn_clone::clone_trait_object!(Digest);

impl Digest for Box<dyn Digest> {
    fn update(&mut self, data: &[u8]) {
        self.as_mut().update(data)
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()>{
        self.as_mut().digest(digest)
    }
}

/// A hash algorithm context.
///
/// Provides additional metadata for the hashing contexts.  This is
/// implemented here once, so that the backends don't have to provide
/// it.
#[derive(Clone)]
pub struct Context {
    /// The hash algorithm.
    algo: HashAlgorithm,

    /// Whether we are hashing for a signature, and if so, which
    /// version.
    for_signature: Option<u8>,

    /// The underlying bare hash context.
    ctx: Box<dyn Digest>,
}

impl Context {
    /// Returns the algorithm.
    pub fn algo(&self) -> HashAlgorithm {
        self.algo
    }

    /// Size of the digest in bytes.
    pub fn digest_size(&self) -> usize {
        self.algo.digest_size()
            .expect("we only create Contexts for known hash algos")
    }

    /// Writes data into the hash function.
    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data)
    }

    /// Finalizes the hash function and writes the digest into the
    /// provided slice.
    ///
    /// Resets the hash function contexts.
    ///
    /// `digest` must be at least `self.digest_size()` bytes large,
    /// otherwise the digest will be truncated.
    pub fn digest(&mut self, digest: &mut [u8]) -> Result<()>{
        self.ctx.digest(digest)
    }

    /// Finalizes the hash function and computes the digest.
    pub fn into_digest(mut self) -> Result<Vec<u8>>
        where Self: std::marker::Sized
    {
        let mut digest = vec![0u8; self.digest_size()];
        self.digest(&mut digest)?;
        Ok(digest)
    }

    /// Returns whether we are hashing for a signature, and if so,
    /// which version.
    fn for_signature(&self) -> Option<u8> {
        self.for_signature.clone()
    }
}

impl io::Write for Context {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ctx.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.ctx.flush()
    }
}

/// Builds hash contexts.
pub struct Builder(Context);

impl Builder {
    /// Returns a hash context for signing and verification of OpenPGP
    /// signatures.
    pub fn for_signature(self, version: u8) -> Context {
        let mut ctx = self.0;
        ctx.for_signature = Some(version);
        ctx
    }

    /// Returns a hash context for general hashing, i.e. not for the
    /// purpose of signing and verification of OpenPGP signatures
    pub fn for_digest(self) -> Context {
        self.0
    }
}


impl HashAlgorithm {
    /// Creates a new hash context builder for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with [`Error::UnsupportedHashAlgorithm`] if Sequoia does
    /// not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    pub fn context(self) -> Result<Builder> {
        if ! self.is_supported() {
            return Err(Error::UnsupportedHashAlgorithm(self).into());
        }

        let mut hasher: Box<dyn Digest> = match self {
            HashAlgorithm::SHA1 if ! cfg!(feature = "crypto-fuzzing") =>
                Box::new(crate::crypto::backend::sha1cd::build()),
            _ => self.new_hasher()?,
        };

        if let Some(prefix) = DUMP_HASHED_VALUES {
            hasher = Box::new(HashDumper::new(hasher, prefix))
        }

        Ok(Builder(Context {
            algo: self,
            for_signature: None,
            ctx: hasher,
        }))
    }

    /// Returns the prefix of a serialized `DigestInfo` structure
    /// that contains the ASN.1 OID of this hash algorithm.
    ///
    /// The prefix is used for encoding RSA signatures according to
    /// the `EMSA-PKCS1-v1_5` algorithm as specified in [RFC 8017].
    ///
    /// [RFC 8017]: https://www.rfc-editor.org/rfc/rfc8017.html#section-9.2
    ///
    /// ```
    /// # use sequoia_openpgp::types::HashAlgorithm;
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// let algo = HashAlgorithm::SHA512;
    /// let digest = // raw bytes of the digest
    /// # Vec::<u8>::new();
    /// let digest_info = Vec::from(algo.oid()?).extend(digest);
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` for unknown or
    /// private hash algorithms.
    pub fn oid(self) -> Result<&'static [u8]> {
        match self {
            HashAlgorithm::SHA1 => Ok(ASN1_OID_SHA1),
            HashAlgorithm::SHA224 => Ok(ASN1_OID_SHA224),
            HashAlgorithm::SHA256 => Ok(ASN1_OID_SHA256),
            HashAlgorithm::SHA384 => Ok(ASN1_OID_SHA384),
            HashAlgorithm::SHA512 => Ok(ASN1_OID_SHA512),
            HashAlgorithm::SHA3_256 => Ok(ASN1_OID_SHA3_256),
            HashAlgorithm::SHA3_512 => Ok(ASN1_OID_SHA3_512),
            HashAlgorithm::MD5 => Ok(ASN1_OID_MD5),
            HashAlgorithm::RipeMD => Ok(ASN1_OID_RIPEMD160),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(crate::Error::UnsupportedHashAlgorithm(self).into()),
        }
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
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.sink.write_all(data).unwrap();
        self.written += data.len();
    }
    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        self.hasher.digest(digest)
    }
}

impl io::Write for HashDumper {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.hasher.flush()
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
///   [`Verifier`]: crate::parse::stream::Verifier
///   [`DetachedVerifier`]: crate::parse::stream::DetachedVerifier
///   [`Signature`'s verification functions]: crate::packet::Signature#verification-functions
///
/// This is a low-level mechanism.  See [`Signature`'s hashing
/// functions] for how to hash compounds like (Key,UserID)-bindings.
///
///   [`Signature`'s hashing functions]: crate::packet::Signature#hashing-functions
pub trait Hash {
    /// Updates the given hash with this object.
    fn hash(&self, hash: &mut Context) -> Result<()>;
}

impl Hash for UserID {
    fn hash(&self, hash: &mut Context) -> Result<()> {
        let len = self.value().len() as u32;

        let mut header = [0; 5];
        header[0] = 0xB4;
        header[1..5].copy_from_slice(&len.to_be_bytes());

        hash.update(&header);
        hash.update(self.value());
        Ok(())
    }
}

impl Hash for UserAttribute {
    fn hash(&self, hash: &mut Context) -> Result<()> {
        let len = self.value().len() as u32;

        let mut header = [0; 5];
        header[0] = 0xD1;
        header[1..5].copy_from_slice(&len.to_be_bytes());

        hash.update(&header);
        hash.update(self.value());
        Ok(())
    }
}

impl<P, R> Hash for Key<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn hash(&self, hash: &mut Context) -> Result<()> {
        match self {
            Key::V4(k) => k.hash(hash),
            Key::V6(k) => k.hash(hash),
        }
    }
}

/// Writes the appropriate hash prefix for keys.
///
/// In RFC9580, the way key packets are hashed depends not on the
/// version of the key packet, but on the version of the signature
/// that is being verified or generated.
///
/// See [Computing Signatures].
///
/// [Computing Signatures]: https://www.rfc-editor.org/rfc/rfc9580.html#name-computing-signatures
fn write_key_hash_header(header: &mut Vec<u8>,
                         public_len: usize,
                         ctx: &Context)
                         -> Result<()>
{
    match ctx.for_signature() {
        None => Err(crate::Error::InvalidOperation(
            "cannot hash key without knowing the signature version"
                .into()).into()),

        Some(3) | Some(4) => {
            // When a version 4 signature is made over a key, the hash
            // data starts with the octet 0x99, followed by a 2-octet
            // length of the key, followed by the body of the key
            // packet.

            // Note: Reading RFC2440, this is also how keys should be
            // hashed for version 3 signatures.

            // Tag.
            header.push(0x99);

            // Length (2 bytes, big endian).
            header.extend_from_slice(
                &u16::try_from(public_len)?.to_be_bytes());

            Ok(())
        },

        Some(6) => {
            // When a version 6 signature is made over a key, the hash
            // data starts with the [..] octet 0x9B, followed by a
            // 4-octet length of the key, followed by the body of the
            // key packet.

            // Tag.
            header.push(0x9b);

            // Length (4 bytes, big endian).
            header.extend_from_slice(
                &u32::try_from(public_len)?.to_be_bytes());

            Ok(())
        },

        Some(n) => Err(crate::Error::InvalidOperation(format!(
            "don't know how to hash key for v{} signatures", n)
        ).into()),
    }
}

impl<P, R> Hash for Key4<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn hash(&self, hash: &mut Context) -> Result<()> {
        use crate::serialize::MarshalInto;

        // We hash 9 bytes plus the MPIs.  But, the len doesn't
        // include the tag (1 byte) or the length (2 bytes).
        let len = (9 - 3) + self.mpis().serialized_len();

        // Note: When making a v6 signature over the key, we hash a
        // four octet length instead of a two octet length.  Reserve
        // two extra bytes.
        //
        // XXX: Use SmallVec to avoid heap allocations.
        let mut header: Vec<u8> = Vec::with_capacity(9 + 2);

        // Write the appropriate header.  This depends on the version
        // of the signature we hash the data for.
        write_key_hash_header(&mut header, len, hash)?;

        // Version.
        header.push(4);

        // Creation time.
        let creation_time: u32 = self.creation_time_raw().into();
        header.extend_from_slice(&creation_time.to_be_bytes());

        // Algorithm.
        header.push(self.pk_algo().into());

        // Hash the header.
        hash.update(&header[..]);

        // MPIs.
        self.mpis().hash(hash)?;

        Ok(())
    }
}

impl<P, R> Hash for Key6<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn hash(&self, hash: &mut Context) -> Result<()> {
        use crate::serialize::MarshalInto;

        // We hash 15 bytes plus the MPIs.  But, the len doesn't
        // include the tag (1 byte) or the length (4 bytes).
        let len = (15 - 5) + self.mpis().serialized_len();

        // XXX: Use SmallVec to avoid heap allocations.
        let mut header: Vec<u8> = Vec::with_capacity(15);

        // Write the appropriate header.  This depends on the version
        // of the signature we hash the data for.
        write_key_hash_header(&mut header, len, hash)?;

        // Version.
        header.push(6);

        // Creation time.
        let creation_time: u32 = self.creation_time_raw().into();
        header.extend_from_slice(&creation_time.to_be_bytes());

        // Algorithm.
        header.push(self.pk_algo().into());

        // Length of all MPIs.
        header.extend_from_slice(
            &(self.mpis().serialized_len() as u32).to_be_bytes());

        // Hash the header.
        hash.update(&header[..]);

        // MPIs.
        self.mpis().hash(hash)?;

        Ok(())
    }
}

impl Hash for Signature {
    fn hash(&self, hash: &mut Context) -> Result<()> {
        match self {
            Signature::V3(sig) => sig.hash(hash),
            Signature::V4(sig) => sig.hash(hash),
            Signature::V6(sig) => sig.hash(hash),
        }
    }
}

impl Hash for Signature3 {
    fn hash(&self, hash: &mut Context) -> Result<()> {
        Self::hash_fields(hash, self)
    }
}

impl Signature3 {
    /// Hashes this signature.
    ///
    /// Because we need to call this from SignatureFields::hash, we
    /// provide this as associated method.
    fn hash_fields(hash: &mut Context, f: &signature::SignatureFields)
                   -> Result<()>
    {
        let mut buffer = [0u8; 5];

        // Signature type.
        buffer[0] = u8::from(f.typ());

        // Creation time.
        let creation_time: u32 =
            Timestamp::try_from(
                f.signature_creation_time()
                    .unwrap_or(std::time::UNIX_EPOCH))
            .unwrap_or_else(|_| Timestamp::from(0))
            .into();

        buffer[1] = (creation_time >> 24) as u8;
        buffer[2] = (creation_time >> 16) as u8;
        buffer[3] = (creation_time >>  8) as u8;
        buffer[4] = (creation_time      ) as u8;

        hash.update(&buffer[..]);
        Ok(())
    }
}

impl Hash for Signature4 {
    fn hash(&self, hash: &mut Context) -> Result<()> {
        Self::hash_fields(hash, &self.fields)
    }
}

impl Signature4 {
    /// Hashes this signature.
    ///
    /// Because we need to call this from SignatureFields::hash, we
    /// provide this as associated method.
    fn hash_fields(mut hash: &mut Context, f: &signature::SignatureFields)
                   -> Result<()>
    {
        use crate::serialize::{Marshal, MarshalInto};

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
        header[1] = f.typ().into();
        header[2] = f.pk_algo().into();
        header[3] = f.hash_algo().into();

        // The length of the hashed area, as a 16-bit big endian number.
        let hashed_area_len = f.hashed_area().serialized_len();
        header[4..6].copy_from_slice(&(hashed_area_len as u16).to_be_bytes());

        hash.update(&header[..]);
        f.hashed_area().serialize(&mut hash as &mut dyn Write)?;

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
        // See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.4
        let mut trailer = [0u8; 6];

        trailer[0] = 4;
        trailer[1] = 0xff;
        // The signature packet's length, not including the previous
        // two bytes and the length.
        let len = (header.len() + hashed_area_len) as u32;
        trailer[2..6].copy_from_slice(&len.to_be_bytes());

        hash.update(&trailer[..]);

        Ok(())
    }
}

impl Hash for Signature6 {
    fn hash(&self, hash: &mut Context) -> Result<()> {
        Self::hash_fields(hash, &self.fields)
    }
}

impl Signature6 {
    fn hash_fields(mut hash: &mut Context, sig: &signature::SignatureFields)
                   -> Result<()>
    {
        use crate::serialize::{Marshal, MarshalInto};

        // A version 6 signature packet is laid out as follows:
        //
        //   version - 1 byte                    \
        //   type - 1 byte                        \
        //   pk_algo - 1 byte                      \
        //   hash_algo - 1 byte                      Included in the hash
        //   hashed_area_len - 4 bytes (big endian)/
        //   hashed_area                         _/
        //   ...                                 <- Not included in the hash

        let mut header = [0u8; 8];

        // Version.
        header[0] = 6;
        header[1] = sig.typ().into();
        header[2] = sig.pk_algo().into();
        header[3] = sig.hash_algo().into();

        // The length of the hashed area, as a 32-bit big endian number.
        let hashed_area_len = sig.hashed_area().serialized_len();
        header[4..8].copy_from_slice(&(hashed_area_len as u32).to_be_bytes());

        hash.update(&header[..]);

        sig.hashed_area().serialize(&mut hash as &mut dyn Write)?;

        // A version 6 signature trailer is:
        //
        //   version - 1 byte
        //   0xFF (constant) - 1 byte
        //   amount - 4 bytes (big endian)
        //
        // The amount field is the amount of hashed from this
        // packet (this excludes the message content, and this
        // trailer) modulo 2**32.
        //
        // See https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.4
        let mut trailer = [0u8; 6];

        trailer[0] = 6;
        trailer[1] = 0xff;
        // The signature packet's length, not including the previous
        // two bytes and the length modulo 2**32.
        let len = (header.len() + hashed_area_len) as u32;
        trailer[2..6].copy_from_slice(&len.to_be_bytes());

        hash.update(&trailer[..]);

        Ok(())
    }
}

impl Hash for signature::SignatureFields {
    fn hash(&self, hash: &mut Context) -> Result<()> {
        match self.version() {
            3 => Signature3::hash_fields(hash, self),
            4 => Signature4::hash_fields(hash, self),
            6 => Signature6::hash_fields(hash, self),
            n => Err(Error::InvalidOperation(format!(
                "cannot hash a version {} signature packet", n)
            ).into()),
        }
    }
}

impl Hash for signature::SignatureBuilder {
    fn hash(&self, hash: &mut Context) -> Result<()> {
        match self.sb_version {
            signature::SBVersion::V4 {} =>
                Signature4::hash_fields(hash, &self.fields),
            signature::SBVersion::V6 { .. } =>
                Signature6::hash_fields(hash, &self.fields),
        }
    }
}

/// Hashing-related functionality.
///
/// <a id="hashing-functions"></a>
impl signature::SignatureBuilder {
    /// Hashes this standalone signature.
    pub fn hash_standalone(&self, hash: &mut Context)
                           -> Result<()>
    {
        match self.typ() {
            SignatureType::Standalone => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.prefix_salt() {
            hash.update(salt);
        }
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this timestamp signature.
    pub fn hash_timestamp(&self, hash: &mut Context)
                          -> Result<()>
    {
        match self.typ() {
            SignatureType::Timestamp => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }


        if let Some(salt) = self.prefix_salt() {
            hash.update(salt);
        }
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this direct key signature over the specified primary
    /// key, and the primary key.
    pub fn hash_direct_key<P>(&self, hash: &mut Context,
                              key: &Key<P, key::PrimaryRole>)
                              -> Result<()>
        where P: key::KeyParts,
    {
        match self.typ() {
            SignatureType::DirectKey => (),
            SignatureType::KeyRevocation => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.prefix_salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this subkey binding over the specified primary key and
    /// subkey, the primary key, and the subkey.
    pub fn hash_subkey_binding<P, Q>(&self, hash: &mut Context,
                                     key: &Key<P, key::PrimaryRole>,
                                     subkey: &Key<Q, key::SubordinateRole>)
                                     -> Result<()>
        where P: key::KeyParts,
              Q: key::KeyParts,
    {
        match self.typ() {
            SignatureType::SubkeyBinding => (),
            SignatureType::SubkeyRevocation => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.prefix_salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        subkey.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this primary key binding over the specified primary key
    /// and subkey, the primary key, and the subkey.
    pub fn hash_primary_key_binding<P, Q>(&self, hash: &mut Context,
                                          key: &Key<P, key::PrimaryRole>,
                                          subkey: &Key<Q, key::SubordinateRole>)
                                          -> Result<()>
        where P: key::KeyParts,
              Q: key::KeyParts,
    {
        match self.typ() {
            SignatureType::PrimaryKeyBinding => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.prefix_salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        subkey.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this user ID binding over the specified primary key and
    /// user ID, the primary key, and the userid.
    pub fn hash_userid_binding<P>(&self, hash: &mut Context,
                                  key: &Key<P, key::PrimaryRole>,
                                  userid: &UserID)
                                  -> Result<()>
        where P: key::KeyParts,
    {
        match self.typ() {
            SignatureType::GenericCertification => (),
            SignatureType::PersonaCertification => (),
            SignatureType::CasualCertification => (),
            SignatureType::PositiveCertification => (),
            SignatureType::CertificationRevocation => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.prefix_salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        userid.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this user attribute binding over the specified primary
    /// key and user attribute, the primary key, and the user
    /// attribute.
    pub fn hash_user_attribute_binding<P>(
        &self,
        hash: &mut Context,
        key: &Key<P, key::PrimaryRole>,
        ua: &UserAttribute)
        -> Result<()>
        where P: key::KeyParts,
    {
        match self.typ() {
            SignatureType::GenericCertification => (),
            SignatureType::PersonaCertification => (),
            SignatureType::CasualCertification => (),
            SignatureType::PositiveCertification => (),
            SignatureType::CertificationRevocation => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.prefix_salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        ua.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }
}

/// Hashing-related functionality.
///
/// <a id="hashing-functions"></a>
impl Signature {
    /// Hashes this standalone signature.
    pub fn hash_standalone(&self, hash: &mut Context)
                           -> Result<()>
    {
        match self.typ() {
            SignatureType::Standalone => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this timestamp signature.
    pub fn hash_timestamp(&self, hash: &mut Context)
                          -> Result<()>
    {
        match self.typ() {
            SignatureType::Timestamp => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this direct key signature over the specified primary
    /// key, and the primary key.
    pub fn hash_direct_key<P>(&self, hash: &mut Context,
                              key: &Key<P, key::PrimaryRole>)
                              -> Result<()>
        where P: key::KeyParts,
    {
        match self.typ() {
            SignatureType::DirectKey => (),
            SignatureType::KeyRevocation => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this subkey binding over the specified primary key and
    /// subkey, the primary key, and the subkey.
    pub fn hash_subkey_binding<P, Q>(&self, hash: &mut Context,
                                     key: &Key<P, key::PrimaryRole>,
                                     subkey: &Key<Q, key::SubordinateRole>)
                                     -> Result<()>
        where P: key::KeyParts,
              Q: key::KeyParts,
    {
        match self.typ() {
            SignatureType::SubkeyBinding => (),
            SignatureType::SubkeyRevocation => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        subkey.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this primary key binding over the specified primary key
    /// and subkey, the primary key, and the subkey.
    pub fn hash_primary_key_binding<P, Q>(&self, hash: &mut Context,
                                          key: &Key<P, key::PrimaryRole>,
                                          subkey: &Key<Q, key::SubordinateRole>)
                                          -> Result<()>
        where P: key::KeyParts,
              Q: key::KeyParts,
    {
        match self.typ() {
            SignatureType::PrimaryKeyBinding => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        subkey.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this user ID binding over the specified primary key and
    /// user ID, the primary key, and the userid.
    pub fn hash_userid_binding<P>(&self, hash: &mut Context,
                                  key: &Key<P, key::PrimaryRole>,
                                  userid: &UserID)
                                  -> Result<()>
        where P: key::KeyParts,
    {
        match self.typ() {
            SignatureType::GenericCertification => (),
            SignatureType::PersonaCertification => (),
            SignatureType::CasualCertification => (),
            SignatureType::PositiveCertification => (),
            SignatureType::CertificationRevocation => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        userid.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this user attribute binding over the specified primary
    /// key and user attribute, the primary key, and the user
    /// attribute.
    pub fn hash_user_attribute_binding<P>(
        &self,
        hash: &mut Context,
        key: &Key<P, key::PrimaryRole>,
        ua: &UserAttribute)
        -> Result<()>
        where P: key::KeyParts,
    {
        match self.typ() {
            SignatureType::GenericCertification => (),
            SignatureType::PersonaCertification => (),
            SignatureType::CasualCertification => (),
            SignatureType::PositiveCertification => (),
            SignatureType::CertificationRevocation => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        ua.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this user ID approval over the specified primary key
    /// and user ID.
    pub fn hash_userid_approval<P>(&self, hash: &mut Context,
                                  key: &Key<P, key::PrimaryRole>,
                                  userid: &UserID)
                                  -> Result<()>
        where P: key::KeyParts,
    {
        match self.typ() {
            SignatureType::CertificationApproval => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        userid.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this user attribute approval over the specified primary
    /// key and user attribute.
    pub fn hash_user_attribute_approval<P>(
        &self,
        hash: &mut Context,
        key: &Key<P, key::PrimaryRole>,
        ua: &UserAttribute)
        -> Result<()>
        where P: key::KeyParts,
    {
        match self.typ() {
            SignatureType::CertificationApproval => (),
            _ => return Err(Error::UnsupportedSignatureType(self.typ()).into()),
        }

        if let Some(salt) = self.salt() {
            hash.update(salt);
        }
        key.hash(hash)?;
        ua.hash(hash)?;
        self.hash(hash)?;
        Ok(())
    }

    /// Hashes this signature for use in a Third-Party Confirmation
    /// signature.
    pub fn hash_for_confirmation(&self, hash: &mut Context)
                                 -> Result<()>
    {
        match self {
            Signature::V3(s) => s.hash_for_confirmation(hash),
            Signature::V4(s) => s.hash_for_confirmation(hash),
            Signature::V6(s) => s.hash_for_confirmation(hash),
        }
    }
}

/// Hashing-related functionality.
///
/// <a id="hashing-functions"></a>
impl Signature4 {
    /// Hashes this signature for use in a Third-Party Confirmation
    /// signature.
    pub fn hash_for_confirmation(&self, hash: &mut Context)
                                 -> Result<()>
    {
        use crate::serialize::{Marshal, MarshalInto};
        // Section 5.2.4 of RFC4880:
        //
        // > When a signature is made over a Signature packet (type
        // > 0x50), the hash data starts with the octet 0x88, followed
        // > by the four-octet length of the signature, and then the
        // > body of the Signature packet.  (Note that this is an
        // > old-style packet header for a Signature packet with the
        // > length-of-length set to zero.)  The unhashed subpacket
        // > data of the Signature packet being hashed is not included
        // > in the hash, and the unhashed subpacket data length value
        // > is set to zero.

        // This code assumes that the signature has been verified
        // prior to being confirmed, so it is well-formed.
        let mut body = vec![
            self.version(),
            self.typ().into(),
            self.pk_algo().into(),
            self.hash_algo().into(),
        ];

        // The hashed area.
        let l = self.hashed_area().serialized_len()
             // Assumes well-formedness.
            .min(std::u16::MAX as usize);
        body.extend(&(l as u16).to_be_bytes());
         // Assumes well-formedness.
        self.hashed_area().serialize(&mut body)?;

        // The unhashed area.
        body.extend(&[0, 0]); // Size replaced by zero.
        // Unhashed packets omitted.

        body.extend(self.digest_prefix());
        self.mpis().serialize(&mut body)?;

        hash.update(&[0x88]);
        hash.update(&(body.len() as u32).to_be_bytes());
        hash.update(&body);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::Cert;
    use crate::parse::Parse;

    #[test]
    fn hash_verification() {
        fn check(cert: Cert) -> (usize, usize, usize) {
            let mut userid_sigs = 0;
            for (i, binding) in cert.userids().enumerate() {
                for selfsig in binding.self_signatures() {
                    let mut hash =
                        selfsig.hash_algo().context().unwrap()
                        .for_signature(selfsig.version());
                    selfsig.hash_userid_binding(
                        &mut hash,
                        cert.primary_key().key(),
                        binding.userid()).unwrap();
                    let h = hash.into_digest().unwrap();
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
                    let mut hash =
                        selfsig.hash_algo().context().unwrap()
                        .for_signature(selfsig.version());
                    selfsig.hash_user_attribute_binding(
                        &mut hash,
                        cert.primary_key().key(),
                        a.user_attribute()).unwrap();
                    let h = hash.into_digest().unwrap();
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
                    let mut hash =
                        selfsig.hash_algo().context().unwrap()
                        .for_signature(selfsig.version());
                    selfsig.hash_subkey_binding(
                        &mut hash,
                        cert.primary_key().key(),
                        binding.key()).unwrap();
                    let h = hash.into_digest().unwrap();
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

        check(Cert::from_bytes(crate::tests::key("hash-algos/MD5.pgp")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/RipeMD160.pgp")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA1.pgp")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA224.pgp")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA256.pgp")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA384.pgp")).unwrap());
        check(Cert::from_bytes(crate::tests::key("hash-algos/SHA512.pgp")).unwrap());
        check(Cert::from_bytes(crate::tests::key("bannon-all-uids-subkeys.pgp")).unwrap());
        let (_userid_sigs, ua_sigs, _subkey_sigs)
            = check(Cert::from_bytes(crate::tests::key("dkg.pgp")).unwrap());
        assert!(ua_sigs > 0);
    }
}
