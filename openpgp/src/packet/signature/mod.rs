//! Types for signatures.

use std::fmt;
use std::ops::Deref;

use crate::constants::Curve;
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
use crate::KeyID;
use crate::packet::UserID;
use crate::packet::UserAttribute;
use crate::Packet;
use crate::packet;
use crate::packet::signature::subpacket::SubpacketArea;

use nettle::{dsa, ecc, ecdsa, ed25519, rsa};
use nettle::rsa::verify_digest_pkcs1;

pub mod subpacket;

const TRACE : bool = false;

/// Builds a signature packet.
///
/// This is the mutable version of a `Signature4` packet.  To convert
/// it to one, use `sign_hash(..)`.
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
    /// Subpackets that are part of the signature.
    hashed_area: SubpacketArea,
    /// Subpackets _not_ that are part of the signature.
    unhashed_area: SubpacketArea,
}

impl Builder {
    /// Returns a new `Builder` object.
    pub fn new(typ: SignatureType) ->  Self {
        Builder {
            version: 4,
            typ: typ,
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            hash_algo: HashAlgorithm::Unknown(0),
            hashed_area: SubpacketArea::empty(),
            unhashed_area: SubpacketArea::empty(),
        }
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

    /// Gets a reference to the hashed area.
    pub fn hashed_area(&self) -> &SubpacketArea {
        &self.hashed_area
    }

    /// Gets a mutable reference to the hashed area.
    pub fn hashed_area_mut(&mut self) -> &mut SubpacketArea {
        &mut self.hashed_area
    }

    /// Gets a reference to the unhashed area.
    pub fn unhashed_area(&self) -> &SubpacketArea {
        &self.unhashed_area
    }

    /// Gets a mutable reference to the unhashed area.
    pub fn unhashed_area_mut(&mut self) -> &mut SubpacketArea {
        &mut self.unhashed_area
    }

    /// Creates a standalone signature.
    pub fn sign_standalone<R>(mut self, signer: &mut Signer<R>,
                              algo: HashAlgorithm)
                              -> Result<Signature>
        where R: key::KeyRole
    {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest = Signature::standalone_hash(&self)?;
        self.sign(signer, digest)
    }

    /// Creates a timestamp signature.
    pub fn sign_timestamp<R>(mut self, signer: &mut Signer<R>,
                              algo: HashAlgorithm)
                              -> Result<Signature>
        where R: key::KeyRole
    {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest = Signature::timestamp_hash(&self)?;
        self.sign(signer, digest)
    }

    /// Signs `signer` using itself.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_primary_key_binding<R>(mut self, signer: &mut Signer<R>,
                                       algo: HashAlgorithm)
        -> Result<Signature>
        where R: key::KeyRole
    {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest =
            Signature::primary_key_binding_hash(&self,
                                                signer.public()
                                                    .mark_role_primary_ref())?;

        self.sign(signer, digest)
    }

    /// Signs binding between `userid` and `key` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_userid_binding<R>(mut self, signer: &mut Signer<R>,
                                 key: &key::PublicKey,
                                 userid: &UserID,
                                 algo: HashAlgorithm)
        -> Result<Signature>
        where R: key::KeyRole
    {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest = Signature::userid_binding_hash(&self, key, userid)?;

        self.sign(signer, digest)
    }

    /// Signs subkey binding from `primary` to `subkey` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_subkey_binding<R>(mut self, signer: &mut Signer<R>,
                                  primary: &key::PublicKey,
                                  subkey: &key::PublicSubkey,
                                  algo: HashAlgorithm)
        -> Result<Signature>
        where R: key::KeyRole
    {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest = Signature::subkey_binding_hash(&self, primary, subkey)?;

        self.sign(signer, digest)
    }

    /// Signs binding between `ua` and `key` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_user_attribute_binding<R>(mut self, signer: &mut Signer<R>,
                                          key: &key::PublicKey,
                                          ua: &UserAttribute,
                                          algo: HashAlgorithm)
        -> Result<Signature>
        where R: key::KeyRole
    {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest =
            Signature::user_attribute_binding_hash(&self, key, ua)?;

        self.sign(signer, digest)
    }

    /// Signs `hash` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_hash<R>(mut self, signer: &mut Signer<R>,
                        hash_algo: HashAlgorithm, mut hash: hash::Context)
        -> Result<Signature>
        where R: key::KeyRole
    {
        // Fill out some fields, then hash the packet.
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = hash_algo;
        self.hash(&mut hash);

        // Compute the digest.
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);

        self.sign(signer, digest)
    }

    /// Signs `message` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_message<R>(mut self, signer: &mut Signer<R>,
                           hash_algo: HashAlgorithm, msg: &[u8])
        -> Result<Signature>
        where R: key::KeyRole
    {
        // Hash the message
        let mut hash = hash_algo.context()?;
        hash.update(msg);

        // Fill out some fields, then hash the packet.
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = hash_algo;
        self.hash(&mut hash);

        // Compute the digest.
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);

        self.sign(signer, digest)
    }

    fn sign<R>(self, signer: &mut Signer<R>, digest: Vec<u8>)
        -> Result<Signature>
        where R: key::KeyRole
    {
        let algo = self.hash_algo;
        let mpis = signer.sign(algo, &digest)?;

        Ok(Signature4 {
            common: Default::default(),
            fields: self,
            hash_prefix: [digest[0], digest[1]],
            mpis: mpis,
            computed_hash: Some((algo, digest)),
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
    hash_prefix: [u8; 2],
    /// Signature MPIs.
    mpis: mpis::Signature,

    /// When used in conjunction with a one-pass signature, this is the
    /// hash computed over the enclosed message.
    computed_hash: Option<(HashAlgorithm, Vec<u8>)>,

    /// Signature level.
    ///
    /// A level of 0 indicates that the signature is directly over the
    /// data, a level of 1 means that the signature is a notarization
    /// over all level 0 signatures and the data, and so on.
    level: usize,
}

impl Deref for Signature4 {
    type Target = Builder;

    fn deref(&self) -> &Self::Target {
        &self.fields
    }
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
            .field("hash_prefix",
                   &crate::conversions::to_hex(&self.hash_prefix, false))
            .field("computed_hash",
                   &if let Some((algo, ref hash)) = self.computed_hash {
                       Some((algo, crate::conversions::to_hex(&hash[..], false)))
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
        self.fields.version == other.fields.version
            && self.fields.typ == other.fields.typ
            && self.fields.pk_algo == other.fields.pk_algo
            && self.fields.hash_algo == other.fields.hash_algo
            && self.fields.hashed_area == other.fields.hashed_area
            && self.mpis == other.mpis
    }
}

impl std::hash::Hash for Signature4 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        use std::hash::Hash as StdHash;
        self.fields.version.hash(state);
        self.fields.typ.hash(state);
        self.fields.pk_algo.hash(state);
        self.fields.hash_algo.hash(state);
        self.fields.hashed_area.hash(state);
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
               hash_prefix: [u8; 2],
               mpis: mpis::Signature) -> Self {
        Signature4 {
            common: Default::default(),
            fields: Builder {
                version: 4,
                typ: typ,
                pk_algo: pk_algo,
                hash_algo: hash_algo,
                hashed_area: hashed_area,
                unhashed_area: unhashed_area,
            },
            hash_prefix: hash_prefix,
            mpis: mpis,
            computed_hash: None,
            level: 0,
        }
    }

    /// Gets a mutable reference to the unhashed area.
    pub fn unhashed_area_mut(&mut self) -> &mut SubpacketArea {
        &mut self.fields.unhashed_area
    }

    /// Gets the hash prefix.
    pub fn hash_prefix(&self) -> &[u8; 2] {
        &self.hash_prefix
    }

    /// Sets the hash prefix.
    pub fn set_hash_prefix(&mut self, prefix: [u8; 2]) -> [u8; 2] {
        ::std::mem::replace(&mut self.hash_prefix, prefix)
    }

    /// Gets the signature packet's MPIs.
    pub fn mpis(&self) -> &mpis::Signature {
        &self.mpis
    }

    /// Sets the signature packet's MPIs.
    pub fn set_mpis(&mut self, mpis: mpis::Signature) -> mpis::Signature {
        ::std::mem::replace(&mut self.mpis, mpis)
    }

    /// Gets the computed hash value.
    pub fn computed_hash(&self) -> Option<&(HashAlgorithm, Vec<u8>)> {
        self.computed_hash.as_ref()
    }

    /// Sets the computed hash value.
    pub fn set_computed_hash(&mut self, hash: Option<(HashAlgorithm, Vec<u8>)>)
        -> Option<(HashAlgorithm, Vec<u8>)>
    {
        ::std::mem::replace(&mut self.computed_hash, hash)
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
    pub fn set_level(&mut self, level: usize) -> usize {
        ::std::mem::replace(&mut self.level, level)
    }

    /// Gets the issuer.
    pub fn get_issuer(&self) -> Option<KeyID> {
        if let Some(id) = self.issuer() {
            Some(id)
        } else {
            None
        }
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
                    SubpacketValue::Issuer(issuer.to_keyid()), false).unwrap())
                    .unwrap();
            } else if let Some(issuer) = self.issuer() {
                // Fall back to the Issuer, which we will also get
                // from the unhashed area if necessary.
                area.add(Subpacket::new(
                    SubpacketValue::Issuer(issuer), false).unwrap()).unwrap();
            }

            // Second, re-add the EmbeddedSignature, if present.
            if let Some(embedded_sig) =
                self.unhashed_area().iter().find_map(|(_, _, v)| {
                    if v.tag == SubpacketTag::EmbeddedSignature {
                        Some(v)
                    } else {
                        None
                    }
                })
            {
                area.add(embedded_sig).unwrap();
            }
        }
        sig
    }

    /// Verifies the signature against `hash`.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `key` can made
    /// valid signatures; it is up to the caller to make sure the key
    /// is not revoked, not expired, has a valid self-signature, has a
    /// subkey binding signature (if appropriate), has the signing
    /// capability, etc.
    pub fn verify_hash<R>(&self, key: &Key<key::PublicParts, R>,
                          hash_algo: HashAlgorithm,
                          hash: &[u8])
        -> Result<bool>
        where R: key::KeyRole
    {
        use crate::PublicKeyAlgorithm::*;
        use crate::crypto::mpis::PublicKey;

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
                verify_digest_pkcs1(&key, hash, hash_algo.oid()?, s.value())
            }

            (DSA,
             &PublicKey::DSA{ ref y, ref p, ref q, ref g },
             &mpis::Signature::DSA { ref s, ref r }) => {
                let key = dsa::PublicKey::new(y.value());
                let params = dsa::Params::new(p.value(), q.value(), g.value());
                let signature = dsa::Signature::new(r.value(), s.value());

                Ok(dsa::verify(&params, &key, hash, &signature))
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
                    for _ in 0..half - r.value().len() {
                        signature.push(0);
                    }
                    signature.extend_from_slice(r.value());
                    for _ in 0..half - s.value().len() {
                        signature.push(0);
                    }
                    signature.extend_from_slice(s.value());

                    // Let's see if we got it right.
                    if signature.len() != ed25519::ED25519_SIGNATURE_SIZE {
                        return Err(Error::MalformedPacket(
                            format!(
                                "Invalid signature size: {}, r: {:?}, s: {:?}",
                                signature.len(), r.value(), s.value())).into());
                    }

                    ed25519::verify(&q.value()[1..], hash, &signature)
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
                Ok(ecdsa::verify(&key, hash, &signature))
            },

            _ => Err(Error::MalformedPacket(format!(
                "unsupported combination of algorithm {:?}, key {:?} and signature {:?}.",
                self.pk_algo(), key.mpis(), self.mpis)).into())
        }
    }

    /// Verifies the signature over text or binary documents using
    /// `key`.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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

        if let Some((hash_algo, ref hash)) = self.computed_hash {
            self.verify_hash(key, hash_algo, hash)
        } else {
            Err(Error::BadSignature("Hash not computed.".to_string()).into())
        }
    }

    /// Verifies the standalone signature using `key`.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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
        let digest = Signature::standalone_hash(self)?;
        self.verify_hash(key, self.hash_algo(), &digest)
    }

    /// Verifies the timestamp signature using `key`.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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
        let digest = Signature::timestamp_hash(self)?;
        self.verify_hash(key, self.hash_algo(), &digest)
    }

    /// Verifies the primary key binding.
    ///
    /// `self` is the primary key binding signature, `signer` is the
    /// key that allegedly made the signature, and `pk` is the primary
    /// key.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_primary_key_binding<R>(&self,
                                         signer: &Key<key::PublicParts, R>,
                                         pk: &key::PublicKey)
        -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::DirectKey {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::primary_key_binding_hash(self, pk)?;
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the primary key revocation certificate.
    ///
    /// `self` is the primary key revocation certificate, `signer` is
    /// the key that allegedly made the signature, and `pk` is the
    /// primary key,
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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

        let hash = Signature::primary_key_binding_hash(self, pk)?;
        self.verify_hash(signer, self.hash_algo(), &hash[..])
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
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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

        let hash = Signature::subkey_binding_hash(self, pk, subkey)?;
        if self.verify_hash(signer, self.hash_algo(), &hash[..])? {
            // The signature is good, but we may still need to verify
            // the back sig.
        } else {
            return Ok(false);
        }

        if ! self.key_flags().can_sign() {
            // No backsig required.
            return Ok(true)
        }

        let mut backsig_ok = false;
        if let Some(Packet::Signature(super::Signature::V4(backsig))) =
            self.embedded_signature()
        {
            if backsig.typ() != SignatureType::PrimaryKeyBinding {
                return Err(Error::UnsupportedSignatureType(self.typ()).into());
            } else {
                // We can't use backsig.verify_subkey_binding.
                let hash = Signature::subkey_binding_hash(&backsig, pk, subkey)?;
                match backsig.verify_hash(subkey.mark_role_unspecified_ref(),
                                          backsig.hash_algo(), &hash[..])
                {
                    Ok(true) => {
                        if TRACE {
                            eprintln!("{} / {}: Backsig is good!",
                                      pk.keyid(), subkey.keyid());
                        }
                        backsig_ok = true;
                    },
                    Ok(false) => {
                        if TRACE {
                            eprintln!("{} / {}: Backsig is bad!",
                                      pk.keyid(), subkey.keyid());
                        }
                    },
                    Err(err) => {
                        if TRACE {
                            eprintln!("{} / {}: Error validating backsig: {}",
                                      pk.keyid(), subkey.keyid(),
                                      err);
                        }
                    },
                }
            }
        }

        Ok(backsig_ok)
    }

    /// Verifies the subkey revocation.
    ///
    /// `self` is the subkey key revocation certificate, `signer` is
    /// the key that allegedly made the signature, `pk` is the primary
    /// key, and `subkey` is the subkey.
    ///
    /// For a self-revocation, `signer` and `pk` will be the same.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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

        let hash = Signature::subkey_binding_hash(self, pk, subkey)?;
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the user id binding.
    ///
    /// `self` is the user id binding signature, `signer` is the key
    /// that allegedly made the signature, `pk` is the primary key,
    /// and `userid` is the user id.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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
        if !(self.typ() == SignatureType::GenericCertificate
             || self.typ() == SignatureType::PersonaCertificate
             || self.typ() == SignatureType::CasualCertificate
             || self.typ() == SignatureType::PositiveCertificate) {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::userid_binding_hash(self, pk, userid)?;
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the user id revocation certificate.
    ///
    /// `self` is the revocation certificate, `signer` is the key
    /// that allegedly made the signature, `pk` is the primary key,
    /// and `userid` is the user id.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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
        if self.typ() != SignatureType::CertificateRevocation {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::userid_binding_hash(self, pk, userid)?;
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the user attribute binding.
    ///
    /// `self` is the user attribute binding signature, `signer` is
    /// the key that allegedly made the signature, `pk` is the primary
    /// key, and `ua` is the user attribute.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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
        if !(self.typ() == SignatureType::GenericCertificate
             || self.typ() == SignatureType::PersonaCertificate
             || self.typ() == SignatureType::CasualCertificate
             || self.typ() == SignatureType::PositiveCertificate) {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::user_attribute_binding_hash(self, pk, ua)?;
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the user attribute revocation certificate.
    ///
    /// `self` is the user attribute binding signature, `signer` is
    /// the key that allegedly made the signature, `pk` is the primary
    /// key, and `ua` is the user attribute.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
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
        if self.typ() != SignatureType::CertificateRevocation {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        let hash = Signature::user_attribute_binding_hash(self, pk, ua)?;
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies a signature of a message.
    ///
    /// `self` is the message signature, `signer` is
    /// the key that allegedly made the signature and `msg` is the message.
    ///
    /// This function is for short messages, if you want to verify larger files
    /// use `Verifier`.
    ///
    /// Note: This only verifies the cryptographic signature.
    /// Constraints on the signature, like creation and expiration
    /// time, or signature revocations must be checked by the caller.
    ///
    /// Likewise, this function does not check whether `signer` can
    /// made valid signatures; it is up to the caller to make sure the
    /// key is not revoked, not expired, has a valid self-signature,
    /// has a subkey binding signature (if appropriate), has the
    /// signing capability, etc.
    pub fn verify_message<R>(&self, signer: &Key<key::PublicParts, R>, msg: &[u8])
        -> Result<bool>
        where R: key::KeyRole
    {
        if self.typ() != SignatureType::Binary &&
            self.typ() != SignatureType::Text {
            return Err(Error::UnsupportedSignatureType(self.typ()).into());
        }

        // Compute the digest.
        let mut hash = self.hash_algo().context()?;
        let mut digest = vec![0u8; hash.digest_size()];

        hash.update(msg);
        self.hash(&mut hash);
        hash.digest(&mut digest);

        self.verify_hash(signer, self.hash_algo(), &digest[..])
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
    use crate::crypto;
    use crate::crypto::mpis::MPI;
    use crate::TPK;
    use crate::parse::Parse;
    use crate::packet::Key;
    use crate::packet::key::Key4;

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn signature_verification_test() {
        use super::*;

        use crate::TPK;
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

            let tpk = TPK::from_bytes(crate::tests::key(test.key)).unwrap();

            let mut good = 0;
            let mut ppr = PacketParser::from_bytes(
                crate::tests::message(test.data)).unwrap();
            while let PacketParserResult::Some(pp) = ppr {
                if let Packet::Signature(ref sig) = pp.packet {
                    let result = sig.verify(tpk.primary().key()).unwrap_or(false);
                    eprintln!("  Primary {:?}: {:?}",
                              tpk.primary().key().fingerprint(), result);
                    if result {
                        good += 1;
                    }

                    for sk in tpk.subkeys() {
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
            let tpk = TPK::from_bytes(crate::tests::key(key)).unwrap();
            let mut pair = tpk.primary().key().clone()
                .mark_parts_secret()
                .into_keypair()
                .expect("secret key is encrypted/missing");

            let sig = Builder::new(SignatureType::Binary);
            let hash = hash_algo.context().unwrap();

            // Make signature.
            let sig = sig.sign_hash(&mut pair, hash_algo, hash).unwrap();

            // Good signature.
            let mut hash = hash_algo.context().unwrap();
            sig.hash(&mut hash);
            let mut digest = vec![0u8; hash.digest_size()];
            hash.digest(&mut digest);
            assert!(sig.verify_hash(pair.public(), hash_algo, &digest).unwrap());

            // Bad signature.
            digest[0] ^= 0xff;
            assert!(! sig.verify_hash(pair.public(), hash_algo, &digest).unwrap());
        }
    }

    #[test]
    fn sign_message() {
        use time;
        use crate::constants::Curve;

        let key: Key<key::SecretParts, key::PrimaryRole>
            = Key4::generate_ecc(true, Curve::Ed25519)
            .unwrap().into();
        let msg = b"Hello, World";
        let mut pair = key.into_keypair().unwrap();
        let sig = Builder::new(SignatureType::Binary)
            .set_signature_creation_time(time::now()).unwrap()
            .set_issuer_fingerprint(pair.public().fingerprint()).unwrap()
            .set_issuer(pair.public().keyid()).unwrap()
            .sign_message(&mut pair, HashAlgorithm::SHA512, msg).unwrap();

        assert!(sig.verify_message(pair.public(), msg).unwrap());
    }

    #[test]
    fn verify_message() {
        let tpk = TPK::from_bytes(crate::tests::key(
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

        assert!(sig.verify_message(tpk.primary().key(), &msg[..]).unwrap());
    }

    #[test]
    fn sign_with_short_ed25519_secret_key() {
        use crate::conversions::Time;
        use nettle;
        use time;

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
            = Key4::new(time::now().canonicalize(),
                        PublicKeyAlgorithm::EdDSA,
                        public_mpis, Some(private_mpis.into()))
            .unwrap()
            .into();
        let mut pair = key.into_keypair().unwrap();
        let msg = b"Hello, World";
        let mut hash = HashAlgorithm::SHA256.context().unwrap();

        hash.update(&msg[..]);

        Builder::new(SignatureType::Text)
            .sign_hash(&mut pair, HashAlgorithm::SHA256, hash).unwrap();
    }

    #[test]
    fn verify_gpg_3rd_party_cert() {
        use crate::TPK;

        let test1 = TPK::from_bytes(
            crate::tests::key("test1-certification-key.pgp")).unwrap();
        let cert_key1 = test1.keys_all()
            .certification_capable()
            .nth(0)
            .map(|x| x.2)
            .unwrap();
        let test2 = TPK::from_bytes(
            crate::tests::key("test2-signed-by-test1.pgp")).unwrap();
        let uid_binding = &test2.primary_key_signature_full().unwrap().0.unwrap();
        let cert = &uid_binding.certifications()[0];

        assert_eq!(cert.verify_userid_binding(cert_key1,
                                              test2.primary().key(),
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
        let keyid = fp.to_keyid();

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
            .sign_hash(&mut pair, HashAlgorithm::SHA256, hash.clone()).unwrap();
        builder.unhashed_area_mut().add(Subpacket::new(
            SubpacketValue::EmbeddedSignature(embedded_sig.into()), false)
                                        .unwrap()).unwrap();
        let sig = builder.sign_hash(&mut pair, HashAlgorithm::SHA256,
                                    hash.clone()).unwrap().normalize();
        assert_eq!(sig.unhashed_area().iter().count(), 2);
        assert_eq!(sig.unhashed_area().iter().nth(0).unwrap().2,
                   Subpacket::new(SubpacketValue::Issuer(keyid.clone()),
                                  false).unwrap());
        assert_eq!(sig.unhashed_area().iter().nth(1).unwrap().2.tag,
                   SubpacketTag::EmbeddedSignature);

        // Now, make sure that an Issuer subpacket is synthesized from
        // the hashed area for compatibility.
        let sig = Builder::new(SignatureType::Text)
            .set_issuer_fingerprint(fp).unwrap()
            .sign_hash(&mut pair, HashAlgorithm::SHA256,
                       hash.clone()).unwrap().normalize();
        assert_eq!(sig.unhashed_area().iter().count(), 1);
        assert_eq!(sig.unhashed_area().iter().nth(0).unwrap().2,
                   Subpacket::new(SubpacketValue::Issuer(keyid.clone()),
                                  false).unwrap());
    }

    #[test]
    fn standalone_signature_roundtrip() {
        let key : key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        let mut pair = key.into_keypair().unwrap();

        let sig = Builder::new(SignatureType::Standalone)
            .set_signature_creation_time(time::now()).unwrap()
            .set_issuer_fingerprint(pair.public().fingerprint()).unwrap()
            .set_issuer(pair.public().keyid()).unwrap()
            .sign_standalone(&mut pair, HashAlgorithm::SHA256)
            .unwrap();

        assert!(sig.verify_standalone(pair.public()).unwrap());
    }

    #[test]
    fn timestamp_signature_roundtrip() {
        let key : key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        let mut pair = key.into_keypair().unwrap();

        let sig = Builder::new(SignatureType::Timestamp)
            .set_signature_creation_time(time::now()).unwrap()
            .set_issuer_fingerprint(pair.public().fingerprint()).unwrap()
            .set_issuer(pair.public().keyid()).unwrap()
            .sign_timestamp(&mut pair, HashAlgorithm::SHA256)
            .unwrap();

        assert!(sig.verify_timestamp(pair.public()).unwrap());
    }
}
