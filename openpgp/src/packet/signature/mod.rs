//! Types for signatures.

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::types::Curve;
use crate::Error;
use crate::Result;
use crate::crypto::{
    mpis,
    hash::{self, Hash},
    Signer,
};
use crate::HashAlgorithm;
use crate::PublicKeyAlgorithm;
use crate::SignatureType;
use crate::packet::Signature;
use crate::packet::{
    key,
    Key,
};
use crate::packet::UserID;
use crate::packet::UserAttribute;
use crate::Packet;
use crate::packet;
use crate::packet::signature::subpacket::{
    SubpacketArea,
    SubpacketAreas,
};

use nettle::{dsa, ecc, ecdsa, ed25519, rsa};
use nettle::rsa::verify_digest_pkcs1;

pub mod subpacket;

/// Builds a signature packet.
///
/// This is the mutable version of a `Signature4` packet.  To convert
/// it to one, use [`sign_hash`], [`sign_message`],
/// [`sign_direct_key`], [`sign_subkey_binding`],
/// [`sign_primary_key_binding`], [`sign_userid_binding`],
/// [`sign_user_attribute_binding`], [`sign_standalone`], or
/// [`sign_timestamp`],
///
///   [`sign_hash`]: #method.sign_hash
///   [`sign_message`]: #method.sign_message
///   [`sign_direct_key`]: #method.sign_direct_key
///   [`sign_subkey_binding`]: #method.sign_subkey_binding
///   [`sign_primary_key_binding`]: #method.sign_primary_key_binding
///   [`sign_userid_binding`]: #method.sign_userid_binding
///   [`sign_user_attribute_binding`]: #method.sign_user_attribute_binding
///   [`sign_standalone`]: #method.sign_standalone
///   [`sign_timestamp`]: #method.sign_timestamp
///
/// Signatures must always include a creation time.  We automatically
/// insert a creation time subpacket with the current time into the
/// hashed subpacket area.  To override the creation time, use
/// [`set_signature_creation_time`].
///
///   [`set_signature_creation_time`]: #method.set_signature_creation_time
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Builder {
    /// Version of the signature packet. Must be 4.
    version: u8,
    /// Type of signature.
    typ: SignatureType,
    /// Pub(Crate)lic-key algorithm used for this signature.
    pk_algo: PublicKeyAlgorithm,
    /// Hash algorithm used to compute the signature.
    hash_algo: HashAlgorithm,
    /// Subpackets.
    subpackets: SubpacketAreas,
}

impl Deref for Builder {
    type Target = SubpacketAreas;

    fn deref(&self) -> &Self::Target {
        &self.subpackets
    }
}

impl DerefMut for Builder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.subpackets
    }
}

impl Builder {
    /// Returns a new `Builder` object.
    pub fn new(typ: SignatureType) ->  Self {
        Builder {
            version: 4,
            typ: typ,
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            hash_algo: HashAlgorithm::default(),
            subpackets: SubpacketAreas::empty(),
        }
        .set_signature_creation_time(
            std::time::SystemTime::now())
            .expect("area is empty, insertion cannot fail; \
                     time is representable for the foreseeable future")
    }

    /// Gets the version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Gets the signature type.
    pub fn typ(&self) -> SignatureType {
        self.typ
    }

    /// Sets the signature type.
    pub fn set_type(mut self, t: SignatureType) -> Self {
        self.typ = t;
        self
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Gets the hash algorithm.
    pub fn hash_algo(&self) -> HashAlgorithm {
        self.hash_algo
    }

    /// Sets the hash algorithm.
    pub fn set_hash_algo(mut self, h: HashAlgorithm) -> Self {
        self.hash_algo = h;
        self
    }

    /// Creates a standalone signature.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`.
    pub fn sign_standalone(mut self, signer: &mut dyn Signer)
                           -> Result<Signature>
    {
        self.pk_algo = signer.public().pk_algo();
        let digest = Signature::hash_standalone(&self)?;
        self.sign(signer, digest)
    }

    /// Creates a timestamp signature.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`.
    pub fn sign_timestamp(mut self, signer: &mut dyn Signer)
                          -> Result<Signature>
    {
        self.pk_algo = signer.public().pk_algo();
        let digest = Signature::hash_timestamp(&self)?;
        self.sign(signer, digest)
    }

    /// Signs `signer` using itself.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`.
    pub fn sign_direct_key(mut self, signer: &mut dyn Signer)
        -> Result<Signature>
    {
        self.pk_algo = signer.public().pk_algo();
        let digest =
            Signature::hash_direct_key(&self,
                                       signer.public()
                                       .mark_role_primary_ref())?;

        self.sign(signer, digest)
    }

    /// Signs binding between `userid` and `key` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`.
    pub fn sign_userid_binding(mut self, signer: &mut dyn Signer,
                               key: &key::PublicKey,
                               userid: &UserID)
        -> Result<Signature>
    {
        self.pk_algo = signer.public().pk_algo();
        let digest = Signature::hash_userid_binding(&self, key, userid)?;

        self.sign(signer, digest)
    }

    /// Signs subkey binding from `primary` to `subkey` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`.
    pub fn sign_subkey_binding<P, Q>(mut self, signer: &mut dyn Signer,
                                     primary: &Key<P, key::PrimaryRole>,
                                     subkey: &Key<Q, key::SubordinateRole>)
        -> Result<Signature>
        where P: key:: KeyParts,
              Q: key:: KeyParts,
    {
        self.pk_algo = signer.public().pk_algo();
        let digest = Signature::hash_subkey_binding(&self, primary, subkey)?;

        self.sign(signer, digest)
    }

    /// Signs primary key binding from `primary` to `subkey` using
    /// `subkey_signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `subkey_signer`.
    pub fn sign_primary_key_binding<P, Q>(mut self,
                                          subkey_signer: &mut dyn Signer,
                                          primary: &Key<P, key::PrimaryRole>,
                                          subkey: &Key<Q, key::SubordinateRole>)
        -> Result<Signature>
        where P: key:: KeyParts,
              Q: key:: KeyParts,
    {
        self.pk_algo = subkey_signer.public().pk_algo();
        let digest =
            Signature::hash_primary_key_binding(&self, primary, subkey)?;
        self.sign(subkey_signer, digest)
    }


    /// Signs binding between `ua` and `key` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`.
    pub fn sign_user_attribute_binding(mut self, signer: &mut dyn Signer,
                                       key: &key::PublicKey,
                                       ua: &UserAttribute)
        -> Result<Signature>
    {
        self.pk_algo = signer.public().pk_algo();
        let digest =
            Signature::hash_user_attribute_binding(&self, key, ua)?;

        self.sign(signer, digest)
    }

    /// Signs `hash` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`.
    pub fn sign_hash(mut self, signer: &mut dyn Signer,
                     mut hash: hash::Context)
        -> Result<Signature>
    {
        // Fill out some fields, then hash the packet.
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = hash.algo();
        self.hash(&mut hash);

        // Compute the digest.
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);

        self.sign(signer, digest)
    }

    /// Signs `message` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`.
    pub fn sign_message<M>(mut self, signer: &mut dyn Signer, msg: M)
        -> Result<Signature>
        where M: AsRef<[u8]>
    {
        // Hash the message
        let mut hash = self.hash_algo.context()?;
        hash.update(msg.as_ref());

        // Fill out some fields, then hash the packet.
        self.pk_algo = signer.public().pk_algo();
        self.hash(&mut hash);

        // Compute the digest.
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);

        self.sign(signer, digest)
    }

    fn sign(self, signer: &mut dyn Signer, digest: Vec<u8>)
        -> Result<Signature>
    {
        let algo = self.hash_algo;
        let mpis = signer.sign(algo, &digest)?;

        Ok(Signature4 {
            common: Default::default(),
            fields: self,
            digest_prefix: [digest[0], digest[1]],
            mpis: mpis,
            computed_digest: Some(digest),
            level: 0,
        }.into())
    }
}

impl From<Signature> for Builder {
    fn from(sig: Signature) -> Self {
        match sig {
            Signature::V4(sig) => sig.into(),
        }
    }
}

impl From<Signature4> for Builder {
    fn from(sig: Signature4) -> Self {
        sig.fields
    }
}

impl<'a> From<&'a Signature> for &'a Builder {
    fn from(sig: &'a Signature) -> Self {
        match sig {
            Signature::V4(ref sig) => sig.into(),
        }
    }
}

impl<'a> From<&'a Signature4> for &'a Builder {
    fn from(sig: &'a Signature4) -> Self {
        &sig.fields
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
// Note: we can't derive PartialEq, because it includes the cached data.
#[derive(Eq, Clone)]
pub struct Signature4 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,

    /// Fields as configured using the builder.
    pub(crate) fields: Builder,

    /// Lower 16 bits of the signed hash value.
    digest_prefix: [u8; 2],
    /// Signature MPIs.
    mpis: mpis::Signature,

    /// When used in conjunction with a one-pass signature, this is the
    /// hash computed over the enclosed message.
    computed_digest: Option<Vec<u8>>,

    /// Signature level.
    ///
    /// A level of 0 indicates that the signature is directly over the
    /// data, a level of 1 means that the signature is a notarization
    /// over all level 0 signatures and the data, and so on.
    level: usize,
}

impl fmt::Debug for Signature4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Get the issuer.  Prefer the issuer fingerprint to the
        // issuer keyid, which may be stored in the unhashed area.
        let issuer = if let Some(tmp) = self.issuer_fingerprint() {
            tmp.to_string()
        } else if let Some(tmp) = self.issuer() {
            tmp.to_string()
        } else {
            "Unknown".to_string()
        };

        f.debug_struct("Signature4")
            .field("version", &self.version())
            .field("typ", &self.typ())
            .field("issuer", &issuer)
            .field("pk_algo", &self.pk_algo())
            .field("hash_algo", &self.hash_algo())
            .field("hashed_area", self.hashed_area())
            .field("unhashed_area", self.unhashed_area())
            .field("digest_prefix",
                   &crate::fmt::to_hex(&self.digest_prefix, false))
            .field("computed_digest",
                   &if let Some(ref hash) = self.computed_digest {
                       Some(crate::fmt::to_hex(&hash[..], false))
                   } else {
                       None
                   })
            .field("level", &self.level)
            .field("mpis", &self.mpis)
            .finish()
    }
}

impl PartialEq for Signature4 {
    /// This method tests for self and other values to be equal, and
    /// is used by ==.
    ///
    /// Note: We ignore the unhashed subpacket area when comparing
    /// signatures.  This prevents a malicious party to take valid
    /// signatures, add subpackets to the unhashed area, yielding
    /// valid but distinct signatures.
    ///
    /// The problem we are trying to avoid here is signature spamming.
    /// Ignoring the unhashed subpackets means that we can deduplicate
    /// signatures using this predicate.
    fn eq(&self, other: &Signature4) -> bool {
        self.mpis == other.mpis
            && self.fields.version == other.fields.version
            && self.fields.typ == other.fields.typ
            && self.fields.pk_algo == other.fields.pk_algo
            && self.fields.hash_algo == other.fields.hash_algo
            && self.fields.hashed_area() == other.fields.hashed_area()
    }
}

impl std::hash::Hash for Signature4 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        use std::hash::Hash as StdHash;
        self.fields.version.hash(state);
        self.fields.typ.hash(state);
        self.fields.pk_algo.hash(state);
        self.fields.hash_algo.hash(state);
        self.fields.hashed_area().hash(state);
        StdHash::hash(&self.mpis, state);
    }
}

impl Signature4 {
    /// Creates a new signature packet.
    ///
    /// If you want to sign something, consider using the [`Builder`]
    /// interface.
    ///
    /// [`Builder`]: struct.Builder.html
    pub fn new(typ: SignatureType, pk_algo: PublicKeyAlgorithm,
               hash_algo: HashAlgorithm, hashed_area: SubpacketArea,
               unhashed_area: SubpacketArea,
               digest_prefix: [u8; 2],
               mpis: mpis::Signature) -> Self {
        Signature4 {
            common: Default::default(),
            fields: Builder {
                version: 4,
                typ: typ,
                pk_algo: pk_algo,
                hash_algo: hash_algo,
                subpackets: SubpacketAreas::new(hashed_area, unhashed_area),
            },
            digest_prefix: digest_prefix,
            mpis: mpis,
            computed_digest: None,
            level: 0,
        }
    }

    /// Gets the hash prefix.
    pub fn digest_prefix(&self) -> &[u8; 2] {
        &self.digest_prefix
    }

    /// Sets the hash prefix.
    #[allow(dead_code)]
    pub(crate) fn set_digest_prefix(&mut self, prefix: [u8; 2]) -> [u8; 2] {
        ::std::mem::replace(&mut self.digest_prefix, prefix)
    }

    /// Gets the signature packet's MPIs.
    pub fn mpis(&self) -> &mpis::Signature {
        &self.mpis
    }

    /// Sets the signature packet's MPIs.
    #[allow(dead_code)]
    pub(crate) fn set_mpis(&mut self, mpis: mpis::Signature) -> mpis::Signature
    {
        ::std::mem::replace(&mut self.mpis, mpis)
    }

    /// Gets the computed hash value.
    pub fn computed_digest(&self) -> Option<&[u8]> {
        self.computed_digest.as_ref().map(|d| &d[..])
    }

    /// Sets the computed hash value.
    pub(crate) fn set_computed_digest(&mut self, hash: Option<Vec<u8>>)
        -> Option<Vec<u8>>
    {
        ::std::mem::replace(&mut self.computed_digest, hash)
    }

    /// Gets the signature level.
    ///
    /// A level of 0 indicates that the signature is directly over the
    /// data, a level of 1 means that the signature is a notarization
    /// over all level 0 signatures and the data, and so on.
    pub fn level(&self) -> usize {
        self.level
    }

    /// Sets the signature level.
    ///
    /// A level of 0 indicates that the signature is directly over the
    /// data, a level of 1 means that the signature is a notarization
    /// over all level 0 signatures and the data, and so on.
    pub(crate) fn set_level(&mut self, level: usize) -> usize {
        ::std::mem::replace(&mut self.level, level)
    }

    /// Collects all the issuers.
    ///
    /// A signature can contain multiple hints as to who issued the
    /// signature.
    pub fn get_issuers(&self) -> std::collections::HashSet<crate::KeyHandle> {
        use crate::packet::signature::subpacket:: SubpacketValue;

        self.hashed_area().iter()
            .chain(self.unhashed_area().iter())
            .filter_map(|subpacket| {
                match subpacket.value() {
                    SubpacketValue::Issuer(i) =>
                        Some(crate::KeyHandle::KeyID(i.clone())),
                    SubpacketValue::IssuerFingerprint(i) =>
                        Some(crate::KeyHandle::Fingerprint(i.clone())),
                    _ => None,
                }
            })
            .collect()
    }

    /// Normalizes the signature.
    ///
    /// This function normalizes the *unhashed* signature subpackets.
    /// All but the following subpackets are removed:
    ///
    ///   - `SubpacketValue::Issuer` is left in place, is added, or
    ///     updated from the *hashed* signature subpackets, and
    ///   - the first `SubpacketValue::EmbeddedSignature` is left in
    ///     place.
    pub fn normalize(&self) -> Self {
        use crate::packet::signature::subpacket::{Subpacket, SubpacketTag,
                                           SubpacketValue};
        let mut sig = self.clone();
        {
            let area = sig.unhashed_area_mut();
            area.clear();

            // First, add an Issuer subpacket derived from information
            // from the hashed area.
            if let Some(issuer) = self.issuer_fingerprint() {
                // Prefer the IssuerFingerprint.
                area.add(Subpacket::new(
                    SubpacketValue::Issuer(issuer.into()), false).unwrap())
                    .unwrap();
            } else if let Some(issuer) = self.issuer() {
                // Fall back to the Issuer, which we will also get
                // from the unhashed area if necessary.
                area.add(Subpacket::new(
                    SubpacketValue::Issuer(issuer.clone()), false).unwrap())
                    .unwrap();
            }

            // Second, re-add the EmbeddedSignature, if present.
            if let Some(embedded_sig) =
                self.unhashed_area().iter().find_map(|v| {
                    if v.tag() == SubpacketTag::EmbeddedSignature {
                        Some(v)
                    } else {
                        None
                    }
                })
            {
                area.add(embedded_sig.clone()).unwrap();
            }
        }
        sig
    }

    /// Verifies the signature against `hash`.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature and checks that the key predates the
    /// signature.  Further constraints on the signature, like
    /// creation and expiration time, or signature revocations must be
    /// checked by the caller.
    ///
    /// Likewise, this function does not check whether `key` can made
    /// valid signatures; it is up to the caller to make sure the key
    /// is not revoked, not expired, has a valid self-signature, has a
    /// subkey binding signature (if appropriate), has the signing
    /// capability, etc.
    pub fn verify_digest<P, R, D>(&self, key: &Key<P, R>, digest: D)
        -> Result<bool>
        where P: key::KeyParts,
              R: key::KeyRole,
              D: AsRef<[u8]>,
    {
        use crate::PublicKeyAlgorithm::*;
        use crate::crypto::mpis::PublicKey;
        let digest = digest.as_ref();

        if let Some(creation_time) = self.signature_creation_time() {
            if creation_time < key.creation_time() {
                return Err(Error::BadSignature(
                    format!("Signature (created {:?}) predates key ({:?})",
                            creation_time, key.creation_time())).into());
            }
        } else {
            return Err(Error::BadSignature(
                "Signature has no creation time subpacket".into()).into());
        }

        #[allow(deprecated)]
        match (self.pk_algo(), key.mpis(), self.mpis()) {
            (RSASign,
             &PublicKey::RSA{ ref e, ref n },
             &mpis::Signature::RSA { ref s }) |
            (RSAEncryptSign,
             &PublicKey::RSA{ ref e, ref n },
             &mpis::Signature::RSA { ref s }) => {
                let key = rsa::PublicKey::new(n.value(), e.value())?;

                // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 4880]:
                //   https://tools.ietf.org/html/rfc4880#section-5.2.2
                verify_digest_pkcs1(&key, digest, self.hash_algo().oid()?,
                                    s.value())
            }

            (DSA,
             &PublicKey::DSA{ ref y, ref p, ref q, ref g },
             &mpis::Signature::DSA { ref s, ref r }) => {
                let key = dsa::PublicKey::new(y.value());
                let params = dsa::Params::new(p.value(), q.value(), g.value());
                let signature = dsa::Signature::new(r.value(), s.value());

                Ok(dsa::verify(&params, &key, digest, &signature))
            }

            (EdDSA,
             &PublicKey::EdDSA{ ref curve, ref q },
             &mpis::Signature::EdDSA { ref r, ref s }) => match curve {
                Curve::Ed25519 => {
                    if q.value().get(0).map(|&b| b != 0x40).unwrap_or(true) {
                        return Err(Error::MalformedPacket(
                            "Invalid point encoding".into()).into());
                    }

                    // OpenPGP encodes R and S separately, but our
                    // cryptographic library expects them to be
                    // concatenated.
                    let mut signature =
                        Vec::with_capacity(ed25519::ED25519_SIGNATURE_SIZE);

                    // We need to zero-pad them at the front, because
                    // the MPI encoding drops leading zero bytes.
                    let half = ed25519::ED25519_SIGNATURE_SIZE / 2;
                    if r.value().len() < half {
                        for _ in 0..half - r.value().len() {
                            signature.push(0);
                        }
                    }
                    signature.extend_from_slice(r.value());
                    if s.value().len() < half {
                        for _ in 0..half - s.value().len() {
                            signature.push(0);
                        }
                    }
                    signature.extend_from_slice(s.value());

                    // Let's see if we got it right.
                    if signature.len() != ed25519::ED25519_SIGNATURE_SIZE {
                        return Err(Error::MalformedPacket(
                            format!(
                                "Invalid signature size: {}, r: {:?}, s: {:?}",
                                signature.len(), r.value(), s.value())).into());
                    }

                    ed25519::verify(&q.value()[1..], digest, &signature)
                },
                _ =>
                    Err(Error::UnsupportedEllipticCurve(curve.clone())
                        .into()),
            },

            (ECDSA,
             &PublicKey::ECDSA{ ref curve, ref q },
             &mpis::Signature::ECDSA { ref s, ref r }) => {
                let (x, y) = q.decode_point(curve)?;
                let key = match curve {
                    Curve::NistP256 =>
                        ecc::Point::new::<ecc::Secp256r1>(x, y)?,
                    Curve::NistP384 =>
                        ecc::Point::new::<ecc::Secp384r1>(x, y)?,
                    Curve::NistP521 =>
                        ecc::Point::new::<ecc::Secp521r1>(x, y)?,
                    _ =>
                        return Err(
                            Error::UnsupportedEllipticCurve(curve.clone())
                                .into()),
                };

                let signature = dsa::Signature::new(r.value(), s.value());
                Ok(ecdsa::verify(&key, digest, &signature))
            },

            _ => Err(Error::MalformedPacket(format!(
                "unsupported combination of algorithm {:?}, key {:?} and signature {:?}.",
                self.pk_algo(), key.mpis(), self.mpis)).into())
        }
    }

    /// Verifies the signature over text or binary documents using
    /// `key`.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `key` can make
    /// valid signatures; it is up to the caller to make sure the key
    /// is not revoked, not expired, has a valid self-signature, has a
    /// subkey binding signature (if appropriate), has the signing
    /// capability, etc.
    pub fn verify<R>(&self, key: &Key<key::PublicParts, R>) -> Result<bool>
        where R: key::KeyRole
    {
        if !(self.typ() == SignatureType::Binary
             || self.typ() == SignatureType::Text) {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        if let Some(ref hash) = self.computed_digest {
            self.verify_digest(key, hash)
        } else {
            Err(Error::BadSignature("Hash not computed.".to_string()).into())
        }
    }

    /// Verifies the standalone signature using `key`.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `key` can make
    /// valid signatures; it is up to the caller to make sure the key
    /// is not revoked, not expired, has a valid self-signature, has a
    /// subkey binding signature (if appropriate), has the signing
    /// capability, etc.
    pub fn verify_standalone<R>(&self, key: &Key<key::PublicParts, R>)
                                -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::Standalone {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        // Standalone signatures are like binary-signatures over the
        // zero-sized string.
        let digest = Signature::hash_standalone(self)?;
        self.verify_digest(key, &digest[..])
    }

    /// Verifies the timestamp signature using `key`.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `key` can make
    /// valid signatures; it is up to the caller to make sure the key
    /// is not revoked, not expired, has a valid self-signature, has a
    /// subkey binding signature (if appropriate), has the signing
    /// capability, etc.
    pub fn verify_timestamp<R>(&self, key: &Key<key::PublicParts, R>)
                                -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::Timestamp {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        // Timestamp signatures are like binary-signatures over the
        // zero-sized string.
        let digest = Signature::hash_timestamp(self)?;
        self.verify_digest(key, &digest[..])
    }

    /// Verifies the direct key signature.
    ///
    /// `self` is the direct key signature, `signer` is the
    /// key that allegedly made the signature, and `pk` is the primary
    /// key.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_direct_key<R>(&self,
                                signer: &Key<key::PublicParts, R>,
                                pk: &key::PublicKey)
        -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::DirectKey {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_direct_key(self, pk)?;
        self.verify_digest(signer, &hash[..])
    }

    /// Verifies the primary key revocation certificate.
    ///
    /// `self` is the primary key revocation certificate, `signer` is
    /// the key that allegedly made the signature, and `pk` is the
    /// primary key,
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_primary_key_revocation<R>(&self,
                                            signer: &Key<key::PublicParts, R>,
                                            pk: &key::PublicKey)
        -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::KeyRevocation {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_direct_key(self, pk)?;
        self.verify_digest(signer, &hash[..])
    }

    /// Verifies the subkey binding.
    ///
    /// `self` is the subkey key binding signature, `signer` is the
    /// key that allegedly made the signature, `pk` is the primary
    /// key, and `subkey` is the subkey.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// If the signature indicates that this is a `Signing` capable
    /// subkey, then the back signature is also verified.  If it is
    /// missing or can't be verified, then this function returns
    /// false.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_subkey_binding<R>(&self,
                                    signer: &Key<key::PublicParts, R>,
                                    pk: &key::PublicKey,
                                    subkey: &key::PublicSubkey)
        -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::SubkeyBinding {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_subkey_binding(self, pk, subkey)?;
        if self.verify_digest(signer, &hash[..])? {
            // The signature is good, but we may still need to verify
            // the back sig.
        } else {
            return Ok(false);
        }

        if ! self.key_flags().for_signing() {
            // No backsig required.
            return Ok(true)
        }

        if let Some(Packet::Signature(super::Signature::V4(backsig))) =
            self.embedded_signature()
        {
            backsig.verify_primary_key_binding(pk, subkey)
        } else {
            Err(Error::BadSignature(
                "Primary key binding signature missing".into()).into())
        }
    }

    /// Verifies the primary key binding.
    ///
    /// `self` is the primary key binding signature, `pk` is the
    /// primary key, and `subkey` is the subkey.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `subkey` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_primary_key_binding<P, Q>(
        &self,
        pk: &Key<P, key::PrimaryRole>,
        subkey: &Key<Q, key::SubordinateRole>)
        -> Result<bool>
        where P: key::KeyParts,
              Q: key::KeyParts,
    {
        if self.typ() != SignatureType::PrimaryKeyBinding {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_primary_key_binding(self, pk, subkey)?;
        self.verify_digest(subkey, &hash[..])
    }

    /// Verifies the subkey revocation.
    ///
    /// `self` is the subkey key revocation certificate, `signer` is
    /// the key that allegedly made the signature, `pk` is the primary
    /// key, and `subkey` is the subkey.
    ///
    /// For a self-revocation, `signer` and `pk` will be the same.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_subkey_revocation<R>(&self,
                                       signer: &Key<key::PublicParts, R>,
                                       pk: &key::PublicKey,
                                       subkey: &key::PublicSubkey)
        -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::SubkeyRevocation {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_subkey_binding(self, pk, subkey)?;
        self.verify_digest(signer, &hash[..])
    }

    /// Verifies the user id binding.
    ///
    /// `self` is the user id binding signature, `signer` is the key
    /// that allegedly made the signature, `pk` is the primary key,
    /// and `userid` is the user id.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_userid_binding<R>(&self,
                                    signer: &Key<key::PublicParts, R>,
                                    pk: &key::PublicKey,
                                    userid: &UserID)
        -> Result<bool>
        where R: key::KeyRole
    {
        if !(self.typ() == SignatureType::GenericCertification
             || self.typ() == SignatureType::PersonaCertification
             || self.typ() == SignatureType::CasualCertification
             || self.typ() == SignatureType::PositiveCertification) {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_userid_binding(self, pk, userid)?;
        self.verify_digest(signer, &hash[..])
    }

    /// Verifies the user id revocation certificate.
    ///
    /// `self` is the revocation certificate, `signer` is the key
    /// that allegedly made the signature, `pk` is the primary key,
    /// and `userid` is the user id.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_userid_revocation<R>(&self,
                                       signer: &Key<key::PublicParts, R>,
                                       pk: &key::PublicKey,
                                       userid: &UserID)
        -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::CertificationRevocation {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_userid_binding(self, pk, userid)?;
        self.verify_digest(signer, &hash[..])
    }

    /// Verifies the user attribute binding.
    ///
    /// `self` is the user attribute binding signature, `signer` is
    /// the key that allegedly made the signature, `pk` is the primary
    /// key, and `ua` is the user attribute.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_user_attribute_binding<R>(&self,
                                            signer: &Key<key::PublicParts, R>,
                                            pk: &key::PublicKey,
                                            ua: &UserAttribute)
        -> Result<bool>
        where R: key::KeyRole
    {
        if !(self.typ() == SignatureType::GenericCertification
             || self.typ() == SignatureType::PersonaCertification
             || self.typ() == SignatureType::CasualCertification
             || self.typ() == SignatureType::PositiveCertification) {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_user_attribute_binding(self, pk, ua)?;
        self.verify_digest(signer, &hash[..])
    }

    /// Verifies the user attribute revocation certificate.
    ///
    /// `self` is the user attribute binding signature, `signer` is
    /// the key that allegedly made the signature, `pk` is the primary
    /// key, and `ua` is the user attribute.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_user_attribute_revocation<R>(&self,
                                               signer: &Key<key::PublicParts, R>,
                                               pk: &key::PublicKey,
                                               ua: &UserAttribute)
        -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::CertificationRevocation {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::hash_user_attribute_binding(self, pk, ua)?;
        self.verify_digest(signer, &hash[..])
    }

    /// Verifies a signature of a message.
    ///
    /// `self` is the message signature, `signer` is
    /// the key that allegedly made the signature and `msg` is the message.
    ///
    /// This function is for short messages, if you want to verify larger files
    /// use `Verifier`.
    ///
    /// Note: Due to limited context, this only verifies the
    /// cryptographic signature, checks the signature's type, and
    /// checks that the key predates the signature.  Further
    /// constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_message<R, M>(&self, signer: &Key<key::PublicParts, R>,
                                msg: M)
        -> Result<bool>
        where R: key::KeyRole,
              M: AsRef<[u8]>,
    {
        if self.typ() != SignatureType::Binary &&
            self.typ() != SignatureType::Text {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        // Compute the digest.
        let mut hash = self.hash_algo().context()?;
        let mut digest = vec![0u8; hash.digest_size()];

        hash.update(msg.as_ref());
        self.hash(&mut hash);
        hash.digest(&mut digest);

        self.verify_digest(signer, &digest[..])
    }
}

impl From<Signature4> for Packet {
    fn from(s: Signature4) -> Self {
        Packet::Signature(s.into())
    }
}

impl From<Signature4> for super::Signature {
    fn from(s: Signature4) -> Self {
        super::Signature::V4(s)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::KeyID;
    use crate::crypto;
    use crate::crypto::mpis::MPI;
    use crate::Cert;
    use crate::parse::Parse;
    use crate::packet::Key;
    use crate::packet::key::Key4;

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn signature_verification_test() {
        use super::*;

        use crate::Cert;
        use crate::parse::{PacketParserResult, PacketParser};

        struct Test<'a> {
            key: &'a str,
            data: &'a str,
            good: usize,
        };

        let tests = [
            Test {
                key: &"neal.pgp"[..],
                data: &"signed-1.gpg"[..],
                good: 1,
            },
            Test {
                key: &"neal.pgp"[..],
                data: &"signed-1-sha1-neal.gpg"[..],
                good: 1,
            },
            Test {
                key: &"testy.pgp"[..],
                data: &"signed-1-sha256-testy.gpg"[..],
                good: 1,
            },
            Test {
                key: &"dennis-simon-anton.pgp"[..],
                data: &"signed-1-dsa.pgp"[..],
                good: 1,
            },
            Test {
                key: &"erika-corinna-daniela-simone-antonia-nistp256.pgp"[..],
                data: &"signed-1-ecdsa-nistp256.pgp"[..],
                good: 1,
            },
            Test {
                key: &"erika-corinna-daniela-simone-antonia-nistp384.pgp"[..],
                data: &"signed-1-ecdsa-nistp384.pgp"[..],
                good: 1,
            },
            Test {
                key: &"erika-corinna-daniela-simone-antonia-nistp521.pgp"[..],
                data: &"signed-1-ecdsa-nistp521.pgp"[..],
                good: 1,
            },
            Test {
                key: &"emmelie-dorothea-dina-samantha-awina-ed25519.pgp"[..],
                data: &"signed-1-eddsa-ed25519.pgp"[..],
                good: 1,
            },
            Test {
                key: &"emmelie-dorothea-dina-samantha-awina-ed25519.pgp"[..],
                data: &"signed-twice-by-ed25519.pgp"[..],
                good: 2,
            },
            Test {
                key: "neal.pgp",
                data: "signed-1-notarized-by-ed25519.pgp",
                good: 1,
            },
            Test {
                key: "emmelie-dorothea-dina-samantha-awina-ed25519.pgp",
                data: "signed-1-notarized-by-ed25519.pgp",
                good: 1,
            },
            // Check with the wrong key.
            Test {
                key: &"neal.pgp"[..],
                data: &"signed-1-sha256-testy.gpg"[..],
                good: 0,
            },
            Test {
                key: &"neal.pgp"[..],
                data: &"signed-2-partial-body.gpg"[..],
                good: 1,
            },
        ];

        for test in tests.iter() {
            eprintln!("{}, expect {} good signatures:",
                      test.data, test.good);

            let cert = Cert::from_bytes(crate::tests::key(test.key)).unwrap();

            let mut good = 0;
            let mut ppr = PacketParser::from_bytes(
                crate::tests::message(test.data)).unwrap();
            while let PacketParserResult::Some(pp) = ppr {
                if let Packet::Signature(ref sig) = pp.packet {
                    let result = sig.verify(cert.primary()).unwrap_or(false);
                    eprintln!("  Primary {:?}: {:?}",
                              cert.primary().fingerprint(), result);
                    if result {
                        good += 1;
                    }

                    for sk in cert.subkeys() {
                        let result = sig.verify(sk.key()).unwrap_or(false);
                        eprintln!("   Subkey {:?}: {:?}",
                                  sk.key().fingerprint(), result);
                        if result {
                            good += 1;
                        }
                    }
                }

                // Get the next packet.
                ppr = pp.recurse().unwrap().1;
            }

            assert_eq!(good, test.good, "Signature verification failed.");
        }
    }

    #[test]
    fn signature_level() {
        use crate::PacketPile;
        let p = PacketPile::from_bytes(
            crate::tests::message("signed-1-notarized-by-ed25519.pgp")).unwrap()
            .into_children().collect::<Vec<Packet>>();

        if let Packet::Signature(ref sig) = &p[3] {
            assert_eq!(sig.level(), 0);
        } else {
            panic!("expected signature")
        }

        if let Packet::Signature(ref sig) = &p[4] {
            assert_eq!(sig.level(), 1);
        } else {
            panic!("expected signature")
        }
    }

    #[test]
    fn sign_verify() {
        let hash_algo = HashAlgorithm::SHA512;
        let mut hash = vec![0; hash_algo.context().unwrap().digest_size()];
        crypto::random(&mut hash);

        for key in &[
            "testy-private.pgp",
            "dennis-simon-anton-private.pgp",
            "erika-corinna-daniela-simone-antonia-nistp256-private.pgp",
            "erika-corinna-daniela-simone-antonia-nistp384-private.pgp",
            "erika-corinna-daniela-simone-antonia-nistp521-private.pgp",
            "emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp",
        ] {
            let cert = Cert::from_bytes(crate::tests::key(key)).unwrap();
            let mut pair = cert.primary().clone()
                .mark_parts_secret().unwrap()
                .into_keypair()
                .expect("secret key is encrypted/missing");

            let sig = Builder::new(SignatureType::Binary);
            let hash = hash_algo.context().unwrap();

            // Make signature.
            let sig = sig.sign_hash(&mut pair, hash).unwrap();

            // Good signature.
            let mut hash = hash_algo.context().unwrap();
            sig.hash(&mut hash);
            let mut digest = vec![0u8; hash.digest_size()];
            hash.digest(&mut digest);
            assert!(sig.verify_digest(pair.public(), &digest[..]).unwrap());

            // Bad signature.
            digest[0] ^= 0xff;
            assert!(! sig.verify_digest(pair.public(), &digest[..]).unwrap());
        }
    }

    #[test]
    fn sign_message() {
        use crate::types::Curve;

        let key: Key<key::SecretParts, key::PrimaryRole>
            = Key4::generate_ecc(true, Curve::Ed25519)
            .unwrap().into();
        let msg = b"Hello, World";
        let mut pair = key.into_keypair().unwrap();
        let sig = Builder::new(SignatureType::Binary)
            .set_signature_creation_time(
                std::time::SystemTime::now()).unwrap()
            .set_issuer_fingerprint(pair.public().fingerprint()).unwrap()
            .set_issuer(pair.public().keyid()).unwrap()
            .sign_message(&mut pair, msg).unwrap();

        assert!(sig.verify_message(pair.public(), msg).unwrap());
    }

    #[test]
    fn verify_message() {
        let cert = Cert::from_bytes(crate::tests::key(
                "emmelie-dorothea-dina-samantha-awina-ed25519.pgp")).unwrap();
        let msg = crate::tests::manifesto();
        let p = Packet::from_bytes(
            crate::tests::message("a-cypherpunks-manifesto.txt.ed25519.sig"))
            .unwrap();
        let sig = if let Packet::Signature(s) = p {
            s
        } else {
            panic!("Expected a Signature, got: {:?}", p);
        };

        assert!(sig.verify_message(cert.primary(), &msg[..]).unwrap());
    }

    #[test]
    fn sign_with_short_ed25519_secret_key() {
        use nettle;

        // 20 byte sec key
        let sec = [
            0x0,0x0,
            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
            0x1,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x2,
            0x1,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x2
        ];
        let mut pnt = [0x40u8; nettle::ed25519::ED25519_KEY_SIZE + 1];
        ed25519::public_key(&mut pnt[1..], &sec[..]).unwrap();

        let public_mpis = mpis::PublicKey::EdDSA {
            curve: Curve::Ed25519,
            q: MPI::new(&pnt[..]),
        };
        let private_mpis = mpis::SecretKeyMaterial::EdDSA {
            scalar: MPI::new(&sec[..]).into(),
        };
        let key : key::SecretKey
            = Key4::with_secret(std::time::SystemTime::now(),
                                PublicKeyAlgorithm::EdDSA,
                                public_mpis, private_mpis.into())
            .unwrap()
            .into();
        let mut pair = key.into_keypair().unwrap();
        let msg = b"Hello, World";
        let mut hash = HashAlgorithm::SHA256.context().unwrap();

        hash.update(&msg[..]);

        Builder::new(SignatureType::Text)
            .sign_hash(&mut pair, hash).unwrap();
    }

    #[test]
    fn verify_gpg_3rd_party_cert() {
        use crate::Cert;

        let test1 = Cert::from_bytes(
            crate::tests::key("test1-certification-key.pgp")).unwrap();
        let cert_key1 = test1.keys_all()
            .for_certification()
            .nth(0)
            .map(|x| x.2)
            .unwrap();
        let test2 = Cert::from_bytes(
            crate::tests::key("test2-signed-by-test1.pgp")).unwrap();
        let uid_binding = &test2.primary_key_signature_full(None)
            .unwrap().1.unwrap().0;
        let cert = &uid_binding.certifications()[0];

        assert_eq!(cert.verify_userid_binding(cert_key1,
                                              test2.primary(),
                                              uid_binding.userid()).ok(),
                   Some(true));
    }

    #[test]
    fn normalize() {
        use crate::Fingerprint;
        use crate::packet::signature::subpacket::*;

        let key : key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        let mut pair = key.into_keypair().unwrap();
        let msg = b"Hello, World";
        let mut hash = HashAlgorithm::SHA256.context().unwrap();
        hash.update(&msg[..]);

        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let keyid = KeyID::from(&fp);

        // First, make sure any superfluous subpackets are removed,
        // yet the Issuer and EmbeddedSignature ones are kept.
        let mut builder = Builder::new(SignatureType::Text);
        // This subpacket does not belong there, and should be
        // removed.
        builder.unhashed_area_mut().add(Subpacket::new(
            SubpacketValue::IssuerFingerprint(fp.clone()), false).unwrap())
            .unwrap();
        builder.unhashed_area_mut().add(Subpacket::new(
            SubpacketValue::Issuer(keyid.clone()), false).unwrap())
            .unwrap();

        // Build and add an embedded sig.
        let embedded_sig = Builder::new(SignatureType::PrimaryKeyBinding)
            .sign_hash(&mut pair, hash.clone()).unwrap();
        builder.unhashed_area_mut().add(Subpacket::new(
            SubpacketValue::EmbeddedSignature(embedded_sig.into()), false)
                                        .unwrap()).unwrap();
        let sig = builder.sign_hash(&mut pair,
                                    hash.clone()).unwrap().normalize();
        assert_eq!(sig.unhashed_area().iter().count(), 2);
        assert_eq!(*sig.unhashed_area().iter().nth(0).unwrap(),
                   Subpacket::new(SubpacketValue::Issuer(keyid.clone()),
                                  false).unwrap());
        assert_eq!(sig.unhashed_area().iter().nth(1).unwrap().tag(),
                   SubpacketTag::EmbeddedSignature);

        // Now, make sure that an Issuer subpacket is synthesized from
        // the hashed area for compatibility.
        let sig = Builder::new(SignatureType::Text)
            .set_issuer_fingerprint(fp).unwrap()
            .sign_hash(&mut pair,
                       hash.clone()).unwrap().normalize();
        assert_eq!(sig.unhashed_area().iter().count(), 1);
        assert_eq!(*sig.unhashed_area().iter().nth(0).unwrap(),
                   Subpacket::new(SubpacketValue::Issuer(keyid.clone()),
                                  false).unwrap());
    }

    #[test]
    fn standalone_signature_roundtrip() {
        let key : key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        let mut pair = key.into_keypair().unwrap();

        let sig = Builder::new(SignatureType::Standalone)
            .set_signature_creation_time(
                std::time::SystemTime::now()).unwrap()
            .set_issuer_fingerprint(pair.public().fingerprint()).unwrap()
            .set_issuer(pair.public().keyid()).unwrap()
            .sign_standalone(&mut pair)
            .unwrap();

        assert!(sig.verify_standalone(pair.public()).unwrap());
    }

    #[test]
    fn timestamp_signature() {
        let alpha = Cert::from_bytes(crate::tests::file(
            "contrib/gnupg/keys/alpha.pgp")).unwrap();
        let p = Packet::from_bytes(crate::tests::file(
            "contrib/gnupg/timestamp-signature-by-alice.asc")).unwrap();
        if let Packet::Signature(sig) = p {
            let digest = Signature::hash_standalone(&sig).unwrap();
            eprintln!("{}", crate::fmt::hex::encode(&digest));
            assert!(sig.verify_timestamp(alpha.primary()).unwrap());
        } else {
            panic!("expected a signature packet");
        }
    }

    #[test]
    fn timestamp_signature_roundtrip() {
        let key : key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        let mut pair = key.into_keypair().unwrap();

        let sig = Builder::new(SignatureType::Timestamp)
            .set_signature_creation_time(
                std::time::SystemTime::now()).unwrap()
            .set_issuer_fingerprint(pair.public().fingerprint()).unwrap()
            .set_issuer(pair.public().keyid()).unwrap()
            .sign_timestamp(&mut pair)
            .unwrap();

        assert!(sig.verify_timestamp(pair.public()).unwrap());
    }
}
