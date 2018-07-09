use std::fmt;

use constants::Curve;
use Error;
use Result;
use mpis::{MPI, MPIs};
use HashAlgorithm;
use PublicKeyAlgorithm;
use SignatureType;
use Key;
use UserID;
use UserAttribute;
use Packet;
use packet;
use subpacket::SubpacketArea;
use serialize::Serialize;

use nettle::{dsa, ecdsa, ed25519, Hash, rsa, Yarrow};
use nettle::rsa::verify_digest_pkcs1;

#[cfg(test)]
use std::path::PathBuf;

const TRACE : bool = false;

#[cfg(test)]
#[allow(dead_code)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", artifact]
        .iter().collect()
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
#[derive(Clone)]
pub struct Signature {
    /// CTB packet header fields.
    pub common: packet::Common,
    /// Version of the signature packet. Must be 4.
    pub version: u8,
    /// Type of signature.
    pub sigtype: SignatureType,
    /// Public-key algorithm used for this signature.
    pub pk_algo: PublicKeyAlgorithm,
    /// Hash algorithm used to compute the signature.
    pub hash_algo: HashAlgorithm,
    /// Subpackets that are part of the signature.
    pub hashed_area: SubpacketArea,
    /// Subpackets _not_ that are part of the signature.
    pub unhashed_area: SubpacketArea,
    /// Lower 16 bits of the signed hash value.
    pub hash_prefix: [u8; 2],
    /// Signature MPIs. Must be a *Signature variant.
    pub mpis: MPIs,

    /// When used in conjunction with a one-pass signature, this is the
    /// hash computed over the enclosed message.
    pub computed_hash: Option<(HashAlgorithm, Vec<u8>)>,
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
            .field("version", &self.version)
            .field("sigtype", &self.sigtype)
            .field("issuer", &issuer)
            .field("pk_algo", &self.pk_algo)
            .field("hash_algo", &self.hash_algo)
            .field("hashed_area", &self.hashed_area)
            .field("unhashed_area", &self.unhashed_area)
            .field("hash_prefix", &::to_hex(&self.hash_prefix, false))
            .field("computed_hash",
                   &if let Some((algo, ref hash)) = self.computed_hash {
                       Some((algo, ::to_hex(&hash[..], false)))
                   } else {
                       None
                   })
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
        return self.to_vec() == other.to_vec();
    }
}

impl Signature {
    /// Returns a new `Signature` packet.
    pub fn new(sigtype: SignatureType) ->  Self {
        Signature {
            common: Default::default(),
            version: 4,
            sigtype: sigtype,
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            hash_algo: HashAlgorithm::Unknown(0),
            hashed_area: SubpacketArea::empty(),
            unhashed_area: SubpacketArea::empty(),
            hash_prefix: [0, 0],
            mpis: MPIs::empty(),

            computed_hash: Default::default(),
        }
    }

    /// Sets the signature type.
    pub fn sigtype(mut self, t: SignatureType) -> Self {
        self.sigtype = t;
        self
    }

    /// Sets the public key algorithm.
    pub fn pk_algo(mut self, algo: PublicKeyAlgorithm) -> Self {
        // XXX: Do we invalidate the signature data?
        self.pk_algo = algo;
        self
    }

    /// Sets the hash algorithm.
    pub fn hash_algo(mut self, algo: HashAlgorithm) -> Self {
        // XXX: Do we invalidate the signature data?
        self.hash_algo = algo;
        self
    }

    /// Signs `hash` using `signer`.
    pub fn sign_hash(&mut self, signer: &Key, signer_sec: &MPIs,
                     hash_algo: HashAlgorithm, mut hash: Box<Hash>)
                     -> Result<()> {
        use PublicKeyAlgorithm::*;
        use mpis::MPIs::*;

        let mut rng = Yarrow::default();

        // Fill out some fields, then hash the packet.
        self.pk_algo = signer.pk_algo;
        self.hash_algo = hash_algo;
        self.hash(&mut hash);

        // Compute the digest.
        let mut digest = vec![0u8; hash.digest_size()];
        hash.digest(&mut digest);
        self.hash_prefix[0] = digest[0];
        self.hash_prefix[1] = digest[1];

        self.mpis = match (signer.pk_algo, &signer.mpis, signer_sec) {
            (RSASign,
             &RSAPublicKey { ref e, ref n },
             &RSASecretKey { ref p, ref q, ref d, .. }) |
            (RSAEncryptSign,
             &RSAPublicKey { ref e, ref n },
             &RSASecretKey { ref p, ref q, ref d, .. }) => {
                let public = rsa::PublicKey::new(&n.value, &e.value)?;
                let secret = rsa::PrivateKey::new(&d.value, &p.value,
                                                  &q.value, Option::None)?;

                // The signature has the length of the modulus.
                let mut sig = vec![0u8; n.value.len()];

                // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 4880]:
                //   https://tools.ietf.org/html/rfc4880#section-5.2.2
                rsa::sign_digest_pkcs1(&public, &secret, &digest, hash_algo.oid()?,
                                       &mut rng, &mut sig)?;

                MPIs::RSASignature {
                    s: MPI::new(&sig),
                }
            },

            (DSA,
             &DSAPublicKey { ref p, ref q, ref g, .. },
             &DSASecretKey { ref x }) => {
                let params = dsa::Params::new(&p.value, &q.value, &g.value);
                let secret = dsa::PrivateKey::new(&x.value);

                let sig = dsa::sign(&params, &secret, &digest, &mut rng)?;

                MPIs::DSASignature {
                    r: MPI::new(&sig.r()),
                    s: MPI::new(&sig.s()),
                }
            },

            (EdDSA,
             &EdDSAPublicKey { ref curve, ref q },
             &EdDSASecretKey { ref scalar }) => match curve {
                Curve::Ed25519 => {
                    let public = q.decode_point(&Curve::Ed25519)?.0;

                    let mut sig = vec![0; ed25519::ED25519_SIGNATURE_SIZE];
                    ed25519::sign(public, &scalar.value, &digest, &mut sig)?;

                    MPIs::EdDSASignature {
                        r: MPI::new(&sig[..32]),
                        s: MPI::new(&sig[32..]),
                    }
                },
                _ => return Err(
                    Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },

            (ECDSA,
             &ECDSAPublicKey { ref curve, .. },
             &ECDSASecretKey { ref scalar }) => {
                let secret = match curve {
                    Curve::NistP256 =>
                        ecdsa::PrivateKey::new::<ecdsa::Secp256r1>(
                            &scalar.value)?,
                    Curve::NistP384 =>
                        ecdsa::PrivateKey::new::<ecdsa::Secp384r1>(
                            &scalar.value)?,
                    Curve::NistP521 =>
                        ecdsa::PrivateKey::new::<ecdsa::Secp521r1>(
                            &scalar.value)?,
                    _ =>
                        return Err(
                            Error::UnsupportedEllipticCurve(curve.clone())
                                .into()),
                };

                let sig = ecdsa::sign(&secret, &digest, &mut rng);

                MPIs::ECDSASignature {
                    r: MPI::new(&sig.r()),
                    s: MPI::new(&sig.s()),
                }
            },

            _ => return Err(Error::InvalidArgument(format!(
                "unsupported combination of algorithm {:?}, key {:?}, \
                 and secret key {:?}",
                self.pk_algo, signer, signer_sec)).into()),
        };

        Ok(())
    }

    /// Verifies the signature against `hash`.
    pub fn verify_hash(&self, key: &Key, hash_algo: HashAlgorithm, hash: &[u8])
        -> Result<bool>
    {
        use PublicKeyAlgorithm::*;
        use mpis::MPIs::*;

        match (self.pk_algo, &key.mpis, &self.mpis) {
            (RSASign,
             &RSAPublicKey{ ref e, ref n },
             &RSASignature{ ref s }) |
            (RSAEncryptSign,
             &RSAPublicKey{ ref e, ref n },
             &RSASignature{ ref s })=> {
                let key = rsa::PublicKey::new(&n.value, &e.value)?;

                // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
                // to verify the signature, we need to encode the
                // signature data in a PKCS1-v1.5 packet.
                //
                //   [Section 5.2.2 and 5.2.3 of RFC 4880]:
                //   https://tools.ietf.org/html/rfc4880#section-5.2.2
                verify_digest_pkcs1(&key, hash, hash_algo.oid()?, &s.value)
            }

            (DSA, &DSAPublicKey{ ref y, ref p, ref q, ref g }, &DSASignature{ ref s, ref r }) => {
                let key = dsa::PublicKey::new(&y.value);
                let params = dsa::Params::new(&p.value, &q.value, &g.value);
                let signature = dsa::Signature::new(&r.value, &s.value);

                Ok(dsa::verify(&params, &key, hash, &signature))
            }

            (EdDSA, &EdDSAPublicKey{ ref curve, ref q },
             &EdDSASignature{ ref r, ref s }) => match curve {
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

            (ECDSA, &ECDSAPublicKey{ ref curve, ref q },
             &ECDSASignature{ ref s, ref r }) => {
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
                self.pk_algo, key.mpis, self.mpis)).into())
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
        if !(self.sigtype == SignatureType::Binary
             || self.sigtype == SignatureType::Text
             || self.sigtype == SignatureType::Standalone) {
            return Err(Error::UnsupportedSignatureType(self.sigtype).into());
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
        if self.sigtype != SignatureType::DirectKey {
            return Err(Error::UnsupportedSignatureType(self.sigtype).into());
        }

        let hash = self.primary_key_binding_hash(pk);
        self.verify_hash(signer, self.hash_algo, &hash[..])
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
        if self.sigtype != SignatureType::SubkeyBinding {
            return Err(Error::UnsupportedSignatureType(self.sigtype).into());
        }

        let hash = self.subkey_binding_hash(pk, subkey);
        if self.verify_hash(signer, self.hash_algo, &hash[..])? {
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
            if backsig.sigtype != SignatureType::PrimaryKeyBinding {
                return Err(Error::UnsupportedSignatureType(self.sigtype).into());
            } else {
                // We can't use backsig.verify_subkey_binding.
                let hash = backsig.subkey_binding_hash(pk, &subkey);
                match backsig.verify_hash(&subkey, backsig.hash_algo, &hash[..])
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
        if !(self.sigtype == SignatureType::GenericCertificate
             || self.sigtype == SignatureType::PersonaCertificate
             || self.sigtype == SignatureType::CasualCertificate
             || self.sigtype == SignatureType::PositiveCertificate
             || self.sigtype == SignatureType::CertificateRevocation) {
            return Err(Error::UnsupportedSignatureType(self.sigtype).into());
        }

        let hash = self.userid_binding_hash(pk, userid);
        self.verify_hash(signer, self.hash_algo, &hash[..])
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
        if !(self.sigtype == SignatureType::GenericCertificate
             || self.sigtype == SignatureType::PersonaCertificate
             || self.sigtype == SignatureType::CasualCertificate
             || self.sigtype == SignatureType::PositiveCertificate
             || self.sigtype == SignatureType::CertificateRevocation) {
            return Err(Error::UnsupportedSignatureType(self.sigtype).into());
        }

        let hash = self.user_attribute_binding_hash(pk, ua);
        self.verify_hash(signer, self.hash_algo, &hash[..])
    }

    /// Convert the `Signature` struct to a `Packet`.
    pub fn to_packet(self) -> Packet {
        Packet::Signature(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use TPK;

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
                    let result = sig.verify(tpk.primary()).unwrap();
                    eprintln!("  Primary {:?}: {:?}",
                              tpk.primary().fingerprint(), result);
                    if result {
                        good += 1;
                    }

                    for sk in &tpk.subkeys {
                        let result = sig.verify(sk.subkey()).unwrap();
                        eprintln!("   Subkey {:?}: {:?}",
                                  sk.subkey().fingerprint(), result);
                        if result {
                            good += 1;
                        }
                    }
                }

                // Get the next packet.
                let (_packet, _packet_depth, tmp, _pp_depth)
                    = pp.recurse().unwrap();
                ppr = tmp;
            }

            assert_eq!(good, test.good, "Signature verification failed.");
        }
    }

    #[test]
    fn sign_verify() {
        use key::SecretKey;

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

            if let Some(SecretKey::Unencrypted{ mpis: ref sec }) = pair.secret {
                let mut sig = Signature::new(SignatureType::Binary);
                let mut hash = hash_algo.context().unwrap();

                // Make signature.
                sig.sign_hash(&pair, sec, hash_algo, hash).unwrap();

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
}
