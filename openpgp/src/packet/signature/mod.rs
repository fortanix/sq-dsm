//! Types for signatures.

use std::fmt;
use std::ops::Deref;

use constants::Curve;
use Error;
use Result;
use crypto::{
    mpis,
    Signer,
};
use HashAlgorithm;
use PublicKeyAlgorithm;
use SignatureType;
use packet::Key;
use KeyID;
use packet::UserID;
use packet::UserAttribute;
use Packet;
use packet;
use packet::signature::subpacket::SubpacketArea;
use serialize::Serialize;

use nettle::{dsa, ecdsa, ed25519, Hash, rsa};
use nettle::rsa::verify_digest_pkcs1;

#[cfg(test)]
use std::path::PathBuf;

pub mod subpacket;

const TRACE : bool = false;

#[cfg(test)]
#[allow(dead_code)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", artifact]
        .iter().collect()
}

/// Builds a signature packet.
///
/// This is the mutable version of a `Signature` packet.  To convert
/// it to one, use `sign_hash(..)`.
#[derive(Clone, Hash, PartialEq, Eq)]
pub struct Builder {
    /// Version of the signature packet. Must be 4.
    version: u8,
    /// Type of signature.
    sigtype: SignatureType,
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
    pub fn new(sigtype: SignatureType) ->  Self {
        Builder {
            version: 4,
            sigtype: sigtype,
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
    pub fn sigtype(&self) -> SignatureType {
        self.sigtype
    }

    /// Sets the signature type.
    pub fn set_sigtype(mut self, t: SignatureType) -> Self {
        self.sigtype = t;
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

    /// Signs `signer` using itself.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_primary_key_binding(mut self, signer: &mut Signer,
                                    algo: HashAlgorithm)
                                    -> Result<Signature> {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest =
            Signature::primary_key_binding_hash(&self, signer.public());

        self.sign(signer, digest)
    }

    /// Signs binding between `userid` and `key` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_userid_binding(mut self, signer: &mut Signer,
                               key: &Key, userid: &UserID, algo: HashAlgorithm)
                               -> Result<Signature> {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest = Signature::userid_binding_hash(&self, key, userid);

        self.sign(signer, digest)
    }

    /// Signs subkey binding from `primary` to `subkey` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_subkey_binding(mut self, signer: &mut Signer,
                               primary: &Key, subkey: &Key, algo: HashAlgorithm)
                               -> Result<Signature> {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest = Signature::subkey_binding_hash(&self, primary, subkey);

        self.sign(signer, digest)
    }

    /// Signs `ua` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_user_attribute_binding(mut self, signer: &mut Signer,
                                       ua: &UserAttribute, algo: HashAlgorithm)
                                       -> Result<Signature> {
        self.pk_algo = signer.public().pk_algo();
        self.hash_algo = algo;
        let digest =
            Signature::user_attribute_binding_hash(&self, signer.public(), ua);

        self.sign(signer, digest)
    }

    /// Signs `hash` using `signer`.
    ///
    /// The Signature's public-key algorithm field is set to the
    /// algorithm used by `signer`, the hash-algorithm field is set to
    /// `hash_algo`.
    pub fn sign_hash(mut self, signer: &mut Signer,
                     hash_algo: HashAlgorithm, mut hash: Box<Hash>)
                     -> Result<Signature> {
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
    pub fn sign_message(mut self, signer: &mut Signer,
                     hash_algo: HashAlgorithm, msg: &[u8])
                     -> Result<Signature> {
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

    fn sign(self, signer: &mut Signer, digest: Vec<u8>) -> Result<Signature> {
        let algo = self.hash_algo;
        let mpis = signer.sign(algo, &digest)?;

        Ok(Signature {
            common: Default::default(),
            fields: self,
            hash_prefix: [digest[0], digest[1]],
            mpis: mpis,
            computed_hash: Some((algo, digest)),
            level: 0,
        })
    }
}

impl From<Signature> for Builder {
    fn from(sig: Signature) -> Self {
        sig.fields
    }
}

impl<'a> From<&'a Signature> for &'a Builder {
    fn from(sig: &'a Signature) -> Self {
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
#[derive(Eq, Hash, Clone)]
pub struct Signature {
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

impl Deref for Signature {
    type Target = Builder;

    fn deref(&self) -> &Self::Target {
        &self.fields
    }
}

impl fmt::Debug for Signature {
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

        f.debug_struct("Signature")
            .field("version", &self.version())
            .field("sigtype", &self.sigtype())
            .field("issuer", &issuer)
            .field("pk_algo", &self.pk_algo())
            .field("hash_algo", &self.hash_algo())
            .field("hashed_area", self.hashed_area())
            .field("unhashed_area", self.unhashed_area())
            .field("hash_prefix",
                   &::conversions::to_hex(&self.hash_prefix, false))
            .field("computed_hash",
                   &if let Some((algo, ref hash)) = self.computed_hash {
                       Some((algo, ::conversions::to_hex(&hash[..], false)))
                   } else {
                       None
                   })
            .field("level", &self.level)
            .field("mpis", &self.mpis)
            .finish()
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Signature) -> bool {
        // Comparing the relevant fields is error prone in case we add
        // a field at some point.  Instead, we compare the serialized
        // versions.  As a small optimization, we compare the MPIs.
        // Note: two `Signatures` could be different even if they have
        // the same MPI if the MPI was not invalidated when changing a
        // field.
        if self.mpis != other.mpis {
            return false;
        }

        // Do a full check by serializing the fields.
        if let (Ok(a), Ok(b)) = (self.to_vec(), other.to_vec()) {
            a == b
        } else {
            false
        }
    }
}

impl Signature {
    pub(crate) fn new(sigtype: SignatureType, pk_algo: PublicKeyAlgorithm,
                      hash_algo: HashAlgorithm, hashed_area: SubpacketArea,
                      unhashed_area: SubpacketArea,
                      hash_prefix: [u8; 2],
                      mpis: mpis::Signature) -> Self {
        Signature {
            common: Default::default(),
            fields: Builder {
                version: 4,
                sigtype: sigtype.into(),
                pk_algo: pk_algo.into(),
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
    pub fn set_hash_prefix(&mut self, prefix: [u8; 2]) {
        self.hash_prefix = prefix;
    }

    /// Gets the signature packet's MPIs.
    pub fn mpis(&self) -> &mpis::Signature {
        &self.mpis
    }

    /// Sets the signature packet's MPIs.
    pub fn set_mpis(&mut self, mpis: mpis::Signature) {
        self.mpis = mpis;
    }

    /// Gets the computed hash value.
    pub fn computed_hash(&self) -> Option<&(HashAlgorithm, Vec<u8>)> {
        self.computed_hash.as_ref()
    }

    /// Sets the computed hash value.
    pub fn set_computed_hash(&mut self, hash: Option<(HashAlgorithm, Vec<u8>)>)
    {
        self.computed_hash = hash;
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
    pub fn set_level(&mut self, level: usize) {
        self.level = level;
    }

    /// Gets the issuer.
    ///
    /// Prefers the issuer fingerprint to the issuer keyid, which may
    /// be stored in the unhashed area.
    pub fn get_issuer(&self) -> Option<KeyID> {
        if let Some(fp) = self.issuer_fingerprint() {
            Some(fp.to_keyid())
        } else if let Some(id) = self.issuer() {
            Some(id)
        } else {
            None
        }
    }

    /// Verifies the signature against `hash`.
    pub fn verify_hash(&self, key: &Key, hash_algo: HashAlgorithm, hash: &[u8])
        -> Result<bool>
    {
        use PublicKeyAlgorithm::*;
        use crypto::mpis::PublicKey;

        #[allow(deprecated)]
        match (self.pk_algo(), key.mpis(), self.mpis()) {
            (RSASign,
             &PublicKey::RSA{ ref e, ref n },
             &mpis::Signature::RSA { ref s }) |
            (RSAEncryptSign,
             &PublicKey::RSA{ ref e, ref n },
             &mpis::Signature::RSA { ref s }) => {
                let key = rsa::PublicKey::new(&n.value, &e.value)?;

                // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 4880]:
                //   https://tools.ietf.org/html/rfc4880#section-5.2.2
                verify_digest_pkcs1(&key, hash, hash_algo.oid()?, &s.value)
            }

            (DSA,
             &PublicKey::DSA{ ref y, ref p, ref q, ref g },
             &mpis::Signature::DSA { ref s, ref r }) => {
                let key = dsa::PublicKey::new(&y.value);
                let params = dsa::Params::new(&p.value, &q.value, &g.value);
                let signature = dsa::Signature::new(&r.value, &s.value);

                Ok(dsa::verify(&params, &key, hash, &signature))
            }

            (EdDSA,
             &PublicKey::EdDSA{ ref curve, ref q },
             &mpis::Signature::EdDSA { ref r, ref s }) => match curve {
                Curve::Ed25519 => {
                    if q.value[0] != 0x40 {
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
                    for _ in 0..half - r.value.len() {
                        signature.push(0);
                    }
                    signature.extend_from_slice(&r.value);
                    for _ in 0..half - s.value.len() {
                        signature.push(0);
                    }
                    signature.extend_from_slice(&s.value);

                    // Let's see if we got it right.
                    if signature.len() != ed25519::ED25519_SIGNATURE_SIZE {
                        return Err(Error::MalformedPacket(
                            format!(
                                "Invalid signature size: {}, r: {:?}, s: {:?}",
                                signature.len(), &r.value, &s.value)).into());
                    }

                    ed25519::verify(&q.value[1..], hash, &signature)
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
                        ecdsa::PublicKey::new::<ecdsa::Secp256r1>(x, y)?,
                    Curve::NistP384 =>
                        ecdsa::PublicKey::new::<ecdsa::Secp384r1>(x, y)?,
                    Curve::NistP521 =>
                        ecdsa::PublicKey::new::<ecdsa::Secp521r1>(x, y)?,
                    _ =>
                        return Err(
                            Error::UnsupportedEllipticCurve(curve.clone())
                                .into()),
                };

                let signature = dsa::Signature::new(&r.value, &s.value);
                Ok(ecdsa::verify(&key, hash, &signature))
            },

            _ => Err(Error::MalformedPacket(format!(
                "unsupported combination of algorithm {:?}, key {:?} and signature {:?}.",
                self.pk_algo(), key.mpis(), self.mpis)).into())
        }
    }

    /// Returns whether `key` made the signature.
    ///
    /// This function does not check whether `key` can made valid
    /// signatures; it is up to the caller to make sure the key is
    /// not revoked, not expired, has a valid self-signature, has a
    /// subkey binding signature (if appropriate), has the signing
    /// capability, etc.
    pub fn verify(&self, key: &Key) -> Result<bool> {
        if !(self.sigtype() == SignatureType::Binary
             || self.sigtype() == SignatureType::Text
             || self.sigtype() == SignatureType::Standalone) {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        if let Some((hash_algo, ref hash)) = self.computed_hash {
            self.verify_hash(key, hash_algo, hash)
        } else {
            Err(Error::BadSignature("Hash not computed.".to_string()).into())
        }
    }

    /// Verifies the primary key binding.
    ///
    /// `self` is the primary key binding signature, `signer` is the
    /// key that allegedly made the signature, and `pk` is the primary
    /// key.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    pub fn verify_primary_key_binding(&self, signer: &Key, pk: &Key)
        -> Result<bool>
    {
        if self.sigtype() != SignatureType::DirectKey {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        let hash = Self::primary_key_binding_hash(self, pk);
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the primary key revocation certificate.
    ///
    /// `self` is the primary key revocation certificate, `signer` is
    /// the key that allegedly made the signature, and `pk` is the
    /// primary key,
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    pub fn verify_primary_key_revocation(&self, signer: &Key, pk: &Key)
        -> Result<bool>
    {
        if self.sigtype() != SignatureType::KeyRevocation {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        let hash = Self::primary_key_binding_hash(self, pk);
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
    pub fn verify_subkey_binding(&self, signer: &Key, pk: &Key, subkey: &Key)
        -> Result<bool>
    {
        if self.sigtype() != SignatureType::SubkeyBinding {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        let hash = Self::subkey_binding_hash(self, pk, subkey);
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
        if let Some(Packet::Signature(backsig)) = self.embedded_signature() {
            if backsig.sigtype() != SignatureType::PrimaryKeyBinding {
                return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
            } else {
                // We can't use backsig.verify_subkey_binding.
                let hash = Self::subkey_binding_hash(&backsig, pk, &subkey);
                match backsig.verify_hash(&subkey, backsig.hash_algo(), &hash[..])
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
    pub fn verify_subkey_revocation(&self, signer: &Key, pk: &Key,
                                    subkey: &Key)
        -> Result<bool>
    {
        if self.sigtype() != SignatureType::SubkeyRevocation {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        let hash = Self::subkey_binding_hash(self, pk, subkey);
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the user id binding.
    ///
    /// `self` is the user id binding signature, `signer` is the key
    /// that allegedly made the signature, `pk` is the primary key,
    /// and `userid` is the user id.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    pub fn verify_userid_binding(&self, signer: &Key,
                                 pk: &Key, userid: &UserID)
        -> Result<bool>
    {
        if !(self.sigtype() == SignatureType::GenericCertificate
             || self.sigtype() == SignatureType::PersonaCertificate
             || self.sigtype() == SignatureType::CasualCertificate
             || self.sigtype() == SignatureType::PositiveCertificate) {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        let hash = Self::userid_binding_hash(self, pk, userid);
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the user id revocation certificate.
    ///
    /// `self` is the revocation certificate, `signer` is the key
    /// that allegedly made the signature, `pk` is the primary key,
    /// and `userid` is the user id.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    pub fn verify_userid_revocation(&self, signer: &Key,
                                    pk: &Key, userid: &UserID)
        -> Result<bool>
    {
        if self.sigtype() != SignatureType::CertificateRevocation {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        let hash = Self::userid_binding_hash(self, pk, userid);
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the user attribute binding.
    ///
    /// `self` is the user attribute binding signature, `signer` is
    /// the key that allegedly made the signature, `pk` is the primary
    /// key, and `ua` is the user attribute.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    pub fn verify_user_attribute_binding(&self, signer: &Key,
                                         pk: &Key, ua: &UserAttribute)
        -> Result<bool>
    {
        if !(self.sigtype() == SignatureType::GenericCertificate
             || self.sigtype() == SignatureType::PersonaCertificate
             || self.sigtype() == SignatureType::CasualCertificate
             || self.sigtype() == SignatureType::PositiveCertificate) {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        let hash = Self::user_attribute_binding_hash(self, pk, ua);
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies the user attribute revocation certificate.
    ///
    /// `self` is the user attribute binding signature, `signer` is
    /// the key that allegedly made the signature, `pk` is the primary
    /// key, and `ua` is the user attribute.
    ///
    /// For a self-signature, `signer` and `pk` will be the same.
    pub fn verify_user_attribute_revocation(&self, signer: &Key,
                                            pk: &Key, ua: &UserAttribute)
        -> Result<bool>
    {
        if self.sigtype() != SignatureType::CertificateRevocation {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
        }

        let hash = Self::user_attribute_binding_hash(self, pk, ua);
        self.verify_hash(signer, self.hash_algo(), &hash[..])
    }

    /// Verifies a signature of a message.
    ///
    /// `self` is the message signature, `signer` is
    /// the key that allegedly made the signature and `msg` is the message.
    ///
    /// This function is for short messages, if you want to verify larger files
    /// use `Verifier`.
    pub fn verify_message(&self, signer: &Key, msg: &[u8])
        -> Result<bool>
    {
        if self.sigtype() != SignatureType::Binary &&
            self.sigtype() != SignatureType::Text {
            return Err(Error::UnsupportedSignatureType(self.sigtype()).into());
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

impl From<Signature> for Packet {
    fn from(s: Signature) -> Self {
        Packet::Signature(s)
    }
}

#[cfg(test)]
mod test {
    use nettle::Yarrow;
    use super::*;
    use crypto::KeyPair;
    use crypto::mpis::MPI;
    use TPK;
    use parse::Parse;

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn signature_verification_test() {
        use super::*;

        use TPK;
        use parse::{PacketParserResult, PacketParser};

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

            let tpk = TPK::from_file(
                path_to(&format!("keys/{}", test.key)[..])).unwrap();

            let mut good = 0;
            let mut ppr = PacketParser::from_file(
                path_to(&format!("messages/{}", test.data)[..])).unwrap();
            while let PacketParserResult::Some(mut pp) = ppr {
                if let Packet::Signature(ref sig) = pp.packet {
                    let result = sig.verify(tpk.primary()).unwrap_or(false);
                    eprintln!("  Primary {:?}: {:?}",
                              tpk.primary().fingerprint(), result);
                    if result {
                        good += 1;
                    }

                    for sk in &tpk.subkeys {
                        let result = sig.verify(sk.subkey()).unwrap_or(false);
                        eprintln!("   Subkey {:?}: {:?}",
                                  sk.subkey().fingerprint(), result);
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
        use PacketPile;
        let p = PacketPile::from_file(
            path_to("messages/signed-1-notarized-by-ed25519.pgp")).unwrap()
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
        use packet::key::SecretKey;

        let hash_algo = HashAlgorithm::SHA512;
        let mut hash = vec![0; hash_algo.context().unwrap().digest_size()];
        Yarrow::default().random(&mut hash);

        for key in &[
            "keys/testy-private.pgp",
            "keys/dennis-simon-anton-private.pgp",
            "keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp",
            "keys/erika-corinna-daniela-simone-antonia-nistp384-private.pgp",
            "keys/erika-corinna-daniela-simone-antonia-nistp521-private.pgp",
            "keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp",
        ] {
            let tpk = TPK::from_file(path_to(key)).unwrap();
            let pair = tpk.primary();

            if let Some(SecretKey::Unencrypted{ mpis: ref sec }) = pair.secret() {
                let mut sig = Builder::new(SignatureType::Binary);
                let mut hash = hash_algo.context().unwrap();

                // Make signature.
                let sig = sig.sign_hash(&mut KeyPair::new(pair.clone(),
                                                          sec.clone()).unwrap(),
                                        hash_algo, hash).unwrap();

                // Good signature.
                let mut hash = hash_algo.context().unwrap();
                sig.hash(&mut hash);
                let mut digest = vec![0u8; hash.digest_size()];
                hash.digest(&mut digest);
                assert!(sig.verify_hash(&pair, hash_algo, &digest).unwrap());

                // Bad signature.
                digest[0] ^= 0xff;
                assert!(! sig.verify_hash(&pair, hash_algo, &digest).unwrap());
            } else {
                panic!("secret key is encrypted/missing");
            }
        }
    }

    #[test]
    fn sign_message() {
        use time;
        use constants::PublicKeyAlgorithm;
        use packet::key::SecretKey;

        let key = Key::generate(PublicKeyAlgorithm::EdDSA)
            .unwrap();
        let msg = b"Hello, World";

        match key.secret() {
            Some(SecretKey::Unencrypted{ ref mpis }) => {
                let sig = Builder::new(SignatureType::Binary)
                    .set_signature_creation_time(time::now()).unwrap()
                    .set_issuer_fingerprint(key.fingerprint()).unwrap()
                    .set_issuer(key.fingerprint().to_keyid()).unwrap()
                    .sign_message(
                        &mut KeyPair::new(key.clone(), mpis.clone()).unwrap(),
                        HashAlgorithm::SHA512, msg).unwrap();

                assert!(sig.verify_message(&key, msg).unwrap());
            }
            _ => unreachable!()
        };
    }

    #[test]
    fn verify_message() {
        use std::fs::File;
        use std::io::Read;

        let tpk = TPK::from_file(path_to(
                "keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"))
            .unwrap();
        let msg = {
            let mut fd = File::open(
                path_to("messages/a-cypherpunks-manifesto.txt")).unwrap();
            let mut buf = Vec::default();

            fd.read_to_end(&mut buf).unwrap();
            buf
        };
        let sig = {
            let mut fd = File::open(path_to(
                "messages/a-cypherpunks-manifesto.txt.ed25519.sig")).unwrap();

            Signature::from_reader(&mut fd).unwrap()
        };

        assert!(sig.verify_message(tpk.primary(), &msg[..]).unwrap());
    }

    #[test]
    fn sign_with_short_ed25519_secret_key() {
        use conversions::Time;
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
        let private_mpis = mpis::SecretKey::EdDSA {
            scalar: MPI::new(&sec[..]),
        };
        let key = Key::new(time::now().canonicalize(),
                           PublicKeyAlgorithm::EdDSA, public_mpis, None)
            .unwrap();
        let msg = b"Hello, World";
        let mut hash = HashAlgorithm::SHA256.context().unwrap();

        hash.update(&msg[..]);

        Builder::new(SignatureType::Text)
            .sign_hash(&mut KeyPair::new(key, private_mpis).unwrap(),
                       HashAlgorithm::SHA256, hash).unwrap();
    }

    #[test]
    fn verify_gpg_3rd_party_cert() {
        use {packet::KeyFlags, TPK};

        let cert_kf = KeyFlags::default().set_certify(true);
        let test1 = TPK::from_file(
            path_to("keys/test1-certification-key.pgp")).unwrap();
        let cert_key1 = test1.select_keys(cert_kf, None)[0];
        let test2 = TPK::from_file(
            path_to("keys/test2-signed-by-test1.pgp")).unwrap();
        let uid_binding = &test2.primary_key_signature_full().unwrap().0.unwrap();
        let cert = uid_binding.certifications().next().unwrap();

        assert_eq!(cert.verify_userid_binding(cert_key1, test2.primary(), uid_binding.userid()).ok(), Some(true));
    }
}
