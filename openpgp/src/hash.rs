//! Functionality to hash packets, and generate hashes.

use HashAlgorithm;
use UserID;
use UserAttribute;
use Key;
use Signature;
use Error;
use Result;

use nettle::Hash;

impl HashAlgorithm {
    pub fn is_supported(self) -> bool {
        match self {
            HashAlgorithm::SHA1 => true,
            HashAlgorithm::SHA224 => true,
            HashAlgorithm::SHA256 => true,
            HashAlgorithm::SHA384 => true,
            HashAlgorithm::SHA512 => true,
            HashAlgorithm::RipeMD => false,
            HashAlgorithm::MD5 => false,
            HashAlgorithm::Private(_) => false,
            HashAlgorithm::Unknown(_) => false,
        }
    }

    pub fn context(self) -> Result<Box<Hash>> {
        use nettle::hash::*;
        use nettle::hash::insecure_do_not_use::Sha1;

        match self {
            HashAlgorithm::SHA1 => Ok(Box::new(Sha1::default())),
            HashAlgorithm::SHA224 => Ok(Box::new(Sha224::default())),
            HashAlgorithm::SHA256 => Ok(Box::new(Sha256::default())),
            HashAlgorithm::SHA384 => Ok(Box::new(Sha384::default())),
            HashAlgorithm::SHA512 => Ok(Box::new(Sha512::default())),
            HashAlgorithm::MD5 | HashAlgorithm::RipeMD =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(Error::UnknownHashAlgorithm(self).into()),
        }
    }

    pub fn oid(self) -> Result<&'static [u8]> {
        use nettle::rsa;

        match self {
            HashAlgorithm::SHA1 => Ok(rsa::ASN1_OID_SHA1),
            HashAlgorithm::SHA224 => Ok(rsa::ASN1_OID_SHA224),
            HashAlgorithm::SHA256 => Ok(rsa::ASN1_OID_SHA256),
            HashAlgorithm::SHA384 => Ok(rsa::ASN1_OID_SHA384),
            HashAlgorithm::SHA512 => Ok(rsa::ASN1_OID_SHA512),
            HashAlgorithm::MD5 | HashAlgorithm::RipeMD =>
                Err(Error::UnsupportedHashAlgorithm(self.into()).into()),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(Error::UnknownHashAlgorithm(self).into()),
        }
    }
}

impl UserID {
    // Update the Hash with a hash of the key.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        let mut header = [0; 5];

        header[0] = 0xB4;
        let len = self.value.len() as u32;
        header[1] = (len >> 24) as u8;
        header[2] = (len >> 16) as u8;
        header[3] = (len >> 8) as u8;
        header[4] = (len) as u8;

        hash.update(&header[..]);
        hash.update(&self.value[..]);
    }
}

impl UserAttribute {
    // Update the Hash with a hash of the key.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        let mut header = [0; 5];

        header[0] = 0xD1;
        let len = self.value.len() as u32;
        header[1] = (len >> 24) as u8;
        header[2] = (len >> 16) as u8;
        header[3] = (len >> 8) as u8;
        header[4] = (len) as u8;

        hash.update(&header[..]);
        hash.update(&self.value[..]);
    }
}

impl Key {
    // Update the Hash with a hash of the key.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        // We hash 8 bytes plus the MPIs.  But, the len doesn't
        // include the tag (1 byte) or the length (2 bytes).
        let len = (9 - 3) + self.mpis.raw.len();

        let mut header : Vec<u8> = Vec::with_capacity(9);

        // Tag.  Note: we use this whether
        header.push(0x99);

        // Length (big endian).
        header.push(((len >> 8) & 0xFF) as u8);
        header.push((len & 0xFF) as u8);

        // Version.
        header.push(4);

        // Creation time.
        header.push(((self.creation_time >> 24) & 0xFF) as u8);
        header.push(((self.creation_time >> 16) & 0xFF) as u8);
        header.push(((self.creation_time >> 8) & 0xFF) as u8);
        header.push((self.creation_time & 0xFF) as u8);

        // Algorithm.
        header.push(self.pk_algo.into());

        hash.update(&header[..]);

        // MPIs.
        hash.update(&self.mpis.raw[..]);
    }
}

impl Signature {
    // Adds the `Signature` to the provided hash context.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        // A version 4 signature packet is laid out as follows:
        //
        //   version - 1 byte                    \
        //   sigtype - 1 byte                     \
        //   pk_algo - 1 byte                      \
        //   hash_algo - 1 byte                      Included in the hash
        //   hashed_area_len - 2 bytes (big endian)/
        //   hashed_area                         _/
        //   ...                                 <- Not included in the hash

        let mut header = [0u8; 6];

        // Version.
        header[0] = 4;
        header[1] = self.sigtype.into();
        header[2] = self.pk_algo.into();
        header[3] = self.hash_algo.into();

        // The length of the hashed area, as a 16-bit endian number.
        let len = self.hashed_area.data.len();
        header[4] = (len >> 8) as u8;
        header[5] = len as u8;

        hash.update(&header[..]);

        hash.update(&self.hashed_area.data[..]);

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

        trailer[0] = 0x4;
        trailer[1] = 0xff;
        // The signature packet's length, not excluding the previous
        // two bytes and the length.
        let len = header.len() + self.hashed_area.data.len();
        trailer[2] = (len >> 24) as u8;
        trailer[3] = (len >> 16) as u8;
        trailer[4] = (len >> 8) as u8;
        trailer[5] = len as u8;

        hash.update(&trailer[..]);
    }
}

/// Hashing-related functionality.
impl Signature {
    // Return the message digest of the primary key binding over the
    // specified primary key, subkey, and signature.
    pub fn primary_key_binding_hash(&self, key: &Key) -> Vec<u8> {
        let h: HashAlgorithm = self.hash_algo.into();
        let mut h: Box<Hash> = h.context().unwrap();

        key.hash(&mut h);
        self.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        return digest;
    }

    // Return the message digest of the subkey binding over the
    // specified primary key, subkey, and signature.
    pub fn subkey_binding_hash(&self, key: &Key, subkey: &Key)
            -> Vec<u8> {
        let h: HashAlgorithm = self.hash_algo.into();
        let mut h: Box<Hash> = h.context().unwrap();

        key.hash(&mut h);
        subkey.hash(&mut h);
        self.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        return digest;
    }

    // Return the message digest of the user ID binding over the
    // specified primary key, user ID, and signature.
    pub fn userid_binding_hash(&self, key: &Key, userid: &UserID)
            -> Vec<u8> {
        let h: HashAlgorithm = self.hash_algo.into();
        let mut h: Box<Hash> = h.context().unwrap();

        key.hash(&mut h);
        userid.hash(&mut h);
        self.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        return digest;
    }

    // Return the message digest of the user attribute binding over
    // the specified primary key, user attribute, and signature.
    pub fn user_attribute_binding_hash(&self, key: &Key, ua: &UserAttribute)
            -> Vec<u8> {
        let h: HashAlgorithm = self.hash_algo.into();
        let mut h: Box<Hash> = h.context().unwrap();

        key.hash(&mut h);
        ua.hash(&mut h);
        self.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        return digest;
    }
}

#[cfg(test)]
mod test {
    use TPK;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../tests/data/keys/", $x)) };
    }

    #[test]
    fn hash_verification() {
        fn check(tpk: TPK) -> (usize, usize, usize) {
            let mut userid_sigs = 0;
            for (i, binding) in tpk.userids().enumerate() {
                for selfsig in binding.selfsigs() {
                    let h = selfsig.userid_binding_hash(
                        tpk.primary(),
                        binding.userid());
                    if h[..2] != selfsig.hash_prefix[..] {
                        eprintln!("{:?}: {:?} / {:?}",
                                  i, binding.userid(), selfsig);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(h[..2], selfsig.hash_prefix[..2]);
                    userid_sigs += 1;
                }
            }
            let mut ua_sigs = 0;
            for (i, binding) in tpk.user_attributes().enumerate() {
                for selfsig in binding.selfsigs() {
                    let h = selfsig.user_attribute_binding_hash(
                        tpk.primary(),
                        binding.user_attribute());
                    if h[..2] != selfsig.hash_prefix[..] {
                        eprintln!("{:?}: {:?} / {:?}",
                                  i, binding.user_attribute(), selfsig);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(h[..2], selfsig.hash_prefix[..2]);
                    ua_sigs += 1;
                }
            }
            let mut subkey_sigs = 0;
            for (i, binding) in tpk.subkeys().enumerate() {
                for selfsig in binding.selfsigs() {
                    let h = selfsig.subkey_binding_hash(
                        tpk.primary(),
                        binding.subkey());
                    if h[..2] != selfsig.hash_prefix[..] {
                        eprintln!("{:?}: {:?}", i, binding);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(h[0], selfsig.hash_prefix[0]);
                    assert_eq!(h[1], selfsig.hash_prefix[1]);
                    subkey_sigs += 1;
                }
            }

            (userid_sigs, ua_sigs, subkey_sigs)
        }

        check(TPK::from_bytes(bytes!("hash-algos/SHA224.gpg")).unwrap());
        check(TPK::from_bytes(bytes!("hash-algos/SHA256.gpg")).unwrap());
        check(TPK::from_bytes(bytes!("hash-algos/SHA384.gpg")).unwrap());
        check(TPK::from_bytes(bytes!("hash-algos/SHA512.gpg")).unwrap());
        check(TPK::from_bytes(bytes!("bannon-all-uids-subkeys.gpg")).unwrap());
        let (_userid_sigs, ua_sigs, _subkey_sigs)
            = check(TPK::from_bytes(bytes!("dkg.gpg")).unwrap());
        assert!(ua_sigs > 0);
    }
}
