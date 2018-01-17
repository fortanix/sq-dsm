//! Functionality to hash packets, and generate hashes.

use HashAlgo;

use UserID;
use UserAttribute;
use Key;
use Signature;

use nettle::Hash;
use nettle::hash::insecure_do_not_use::Sha1;
use nettle::hash::{Sha224, Sha256, Sha384, Sha512};

// Returns a fresh hash context.
pub fn hash_context(hash_algo: HashAlgo) -> Box<Hash> {
    match hash_algo {
        HashAlgo::SHA1 => Box::new(Sha1::default()),
        HashAlgo::SHA224 => Box::new(Sha224::default()),
        HashAlgo::SHA256 => Box::new(Sha256::default()),
        HashAlgo::SHA384 => Box::new(Sha384::default()),
        HashAlgo::SHA512 => Box::new(Sha512::default()),
        algo => {
            eprintln!("algo {:?} not implemented", algo);
            unimplemented!();
        },
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
        let len = (9 - 3) + self.mpis.len();

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
        header.push(self.pk_algo);

        hash.update(&header[..]);

        // MPIs.
        hash.update(&self.mpis[..]);
    }
}

impl Signature {
    // Adds the `Signature` to the provided hash context.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        let mut header = [0u8; 6];

        // Version.
        header[0] = 4;
        header[1] = self.sigtype;
        header[2] = self.pk_algo;
        header[3] = self.hash_algo;

        // The length of the hashed area, as a 16-bit endian number.
        let len = self.hashed_area.data.len();
        header[4] = (len >> 8) as u8;
        header[5] = len as u8;

        hash.update(&header[..]);

        hash.update(&self.hashed_area.data[..]);

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
        let mut h
            = hash_context(HashAlgo::from_numeric(self.hash_algo).unwrap());

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
        let mut h
            = hash_context(HashAlgo::from_numeric(self.hash_algo).unwrap());

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
        let mut h
            = hash_context(HashAlgo::from_numeric(self.hash_algo).unwrap());

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
        let mut h
            = hash_context(HashAlgo::from_numeric(self.hash_algo).unwrap());

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
    use tpk::TPK;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../tests/data/keys/", $x)) };
    }

    macro_rules! assert_match {
        ( $error: pat = $expr:expr ) => {
            let x = $expr;
            if let $error = x {
                /* Pass.  */
            } else {
                panic!("Expected {}, got {:?}.", stringify!($error), x);
            }
        };
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
