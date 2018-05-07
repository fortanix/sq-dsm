use std::fmt;

use Error;
use Result;
use HashAlgo;
use PublicKeyAlgorithm;
use Signature;
use SignatureType;
use Key;
use Packet;
use SubpacketArea;
use serialize::Serialize;

use mpis::MPIs;

use nettle::rsa;
use nettle::rsa::verify_digest_pkcs1;

#[cfg(test)]
use std::path::PathBuf;

#[cfg(test)]
fn path_to(artifact: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "data", artifact]
        .iter().collect()
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
            hash_algo: HashAlgo::Unknown(0),
            hashed_area: SubpacketArea::empty(),
            unhashed_area: SubpacketArea::empty(),
            hash_prefix: [0, 0],
            mpis: MPIs::new(),

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
    pub fn hash_algo(mut self, algo: HashAlgo) -> Self {
        // XXX: Do we invalidate the signature data?
        self.hash_algo = algo;
        self
    }

    // XXX: Add subpacket handling.

    // XXX: Add signature generation.

    pub fn verify_hash(&self, key: &Key, hash_algo: HashAlgo, hash: &[u8])
        -> Result<bool>
    {
        // Extract the public key.
        let key_mpis = key.mpis.values()?;
        let key = match PublicKeyAlgorithm::from(self.pk_algo) {
            PublicKeyAlgorithm::RsaEncryptSign
            | PublicKeyAlgorithm::RsaSign => {
                if key_mpis.len() != 2 {
                    return Err(
                        Error::MalformedPacket(
                            format!("Key: Expected 2 MPIs for an RSA key, got {}",
                                    key_mpis.len())).into());
                }

                rsa::PublicKey::new(key_mpis[0], key_mpis[1])?
            },
            _ => {
                return Err(
                    Error::UnsupportedPublicKeyAlgorithm(self.pk_algo)
                        .into());
            }
        };

        // Extract the signature.
        let sig_mpi = {
            let sig_mpis = self.mpis.values()?;

            if sig_mpis.len() != 1 {
                return Err(
                    Error::MalformedPacket(
                        format!("Signature: Expected 1 MPI, got {}",
                                sig_mpis.len())).into());
            }

            sig_mpis[0]
        };

        // As described in [Section 5.2.2 and 5.2.3 of RFC 4880],
        // to verify the signature, we need to encode the
        // signature data in a PKCS1-v1.5 packet.
        //
        //   [Section 5.2.2 and 5.2.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.2
        verify_digest_pkcs1(&key, hash, hash_algo.oid()?, sig_mpi)
    }

    /// Returns whether `key` generated the signature.
    ///
    /// This function does not check whether `key` can generate valid
    /// signatures.  It is up to the caller to make sure the key is
    /// not revoked, not expired, has a valid self-signature, has a
    /// subkey binding signature (if appropriate), has the signing
    /// capability, etc.
    pub fn verify(&self, key: &Key) -> Result<bool> {
        if let Some((hash_algo, ref hash)) = self.computed_hash {
            self.verify_hash(key, hash_algo, hash)
        } else {
            Err(Error::BadSignature("Hash not computed.".to_string()).into())
        }
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
    use parse::PacketParser;

    #[test]
    fn signature_verification_test() {
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
            let mut ppo = PacketParser::from_file(
                path_to(&format!("messages/{}", test.data)[..])).unwrap();
            while let Some(mut pp) = ppo {
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
                ppo = tmp;
            }

            assert_eq!(good, test.good, "Signature verification failed.");
        }
    }
}
