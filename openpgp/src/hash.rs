//! Functionality to hash packets, and generate hashes.

use UserID;
use UserAttribute;
use Key;
use Signature;
use Error;
use Result;

use std::str::FromStr;
use std::result;
use std::fmt;

use nettle::Hash;
use quickcheck::{Arbitrary, Gen};

/// The OpenPGP hash algorithms as defined in [Section 9.4 of RFC 4880].
///
///   [Section 9.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.4
///
/// The values correspond to the serialized format.
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum HashAlgo {
    MD5,
    SHA1,
    RipeMD,
    SHA256,
    SHA384,
    SHA512,
    SHA224,
    Private(u8),
    Unknown(u8),
}

impl From<u8> for HashAlgo {
    fn from(u: u8) -> Self {
        match u {
            1 => HashAlgo::MD5,
            2 => HashAlgo::SHA1,
            3 => HashAlgo::RipeMD,
            8 => HashAlgo::SHA256,
            9 => HashAlgo::SHA384,
            10 => HashAlgo::SHA512,
            11 => HashAlgo::SHA224,
            100...110 => HashAlgo::Private(u),
            u => HashAlgo::Unknown(u),
        }
    }
}

impl Into<u8> for HashAlgo {
    fn into(self) -> u8 {
        match self {
            HashAlgo::MD5 => 1,
            HashAlgo::SHA1 => 2,
            HashAlgo::RipeMD => 3,
            HashAlgo::SHA256 => 8,
            HashAlgo::SHA384 => 9,
            HashAlgo::SHA512 => 10,
            HashAlgo::SHA224 => 11,
            HashAlgo::Private(u) => u,
            HashAlgo::Unknown(u) => u,
        }
    }
}

impl FromStr for HashAlgo {
    type Err = ();

    fn from_str(s: &str) -> result::Result<Self, ()> {
        if s == "MD5" {
            Ok(HashAlgo::MD5)
        } else if s == "SHA1" {
            Ok(HashAlgo::SHA1)
        } else if s == "RipeMD160" {
            Ok(HashAlgo::RipeMD)
        } else if s == "SHA256" {
            Ok(HashAlgo::SHA256)
        } else if s == "SHA384" {
            Ok(HashAlgo::SHA384)
        } else if s == "SHA512" {
            Ok(HashAlgo::SHA512)
        } else if s == "SHA224" {
            Ok(HashAlgo::SHA224)
        } else {
            Err(())
        }
    }
}

impl fmt::Display for HashAlgo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashAlgo::MD5 => f.write_str("MD5"),
            HashAlgo::SHA1 => f.write_str("SHA1"),
            HashAlgo::RipeMD => f.write_str("RipeMD160"),
            HashAlgo::SHA256 => f.write_str("SHA256"),
            HashAlgo::SHA384 => f.write_str("SHA384"),
            HashAlgo::SHA512 => f.write_str("SHA512"),
            HashAlgo::SHA224 => f.write_str("SHA224"),
            HashAlgo::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental hash algorithm {}",u)),
            HashAlgo::Unknown(u) =>
                f.write_fmt(format_args!("Unknown hash algorithm {}",u)),
        }
    }
}

impl HashAlgo {
    pub fn is_supported(self) -> bool {
        match self {
            HashAlgo::SHA1 => true,
            HashAlgo::SHA224 => true,
            HashAlgo::SHA256 => true,
            HashAlgo::SHA384 => true,
            HashAlgo::SHA512 => true,
            HashAlgo::RipeMD => false,
            HashAlgo::MD5 => false,
            HashAlgo::Private(_) => false,
            HashAlgo::Unknown(_) => false,
        }
    }

    pub fn context(self) -> Result<Box<Hash>> {
        use nettle::hash::*;
        use nettle::hash::insecure_do_not_use::Sha1;

        match self {
            HashAlgo::SHA1 => Ok(Box::new(Sha1::default())),
            HashAlgo::SHA224 => Ok(Box::new(Sha224::default())),
            HashAlgo::SHA256 => Ok(Box::new(Sha256::default())),
            HashAlgo::SHA384 => Ok(Box::new(Sha384::default())),
            HashAlgo::SHA512 => Ok(Box::new(Sha512::default())),
            HashAlgo::MD5 | HashAlgo::RipeMD =>
                Err(Error::UnknownHashAlgorithm(self.into()).into()),
            HashAlgo::Private(x) | HashAlgo::Unknown(x) =>
                Err(Error::UnknownHashAlgorithm(x).into()),
        }
    }
}

impl Arbitrary for HashAlgo {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        u8::arbitrary(g).into()
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
        header[3] = self.hash_algo.into();

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
        let h: HashAlgo = self.hash_algo.into();
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
        let h: HashAlgo = self.hash_algo.into();
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
        let h: HashAlgo = self.hash_algo.into();
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
        let h: HashAlgo = self.hash_algo.into();
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
    use super::*;
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

    quickcheck! {
        fn hash_roundtrip(hash: HashAlgo) -> bool {
            let val: u8 = hash.clone().into();
            hash == HashAlgo::from(val)
        }
    }

    quickcheck! {
        fn hash_roundtrip_str(hash: HashAlgo) -> bool {
            match hash {
                HashAlgo::Private(_) | HashAlgo::Unknown(_) => true,
                hash => {
                    let s = format!("{}",hash);
                    hash == HashAlgo::from_str(&s).unwrap()
                }
            }
        }
    }

    quickcheck! {
        fn hash_display(hash: HashAlgo) -> bool {
            let s = format!("{}",hash);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn hash_parse(hash: HashAlgo) -> bool {
            match hash {
                HashAlgo::Unknown(u) => u == 0 || (u > 11 && u < 100) ||
                    u > 110 || (u >= 4 && u <= 7) || u == 0,
                HashAlgo::Private(u) => u >= 100 && u <= 110,
                _ => true
            }
        }
    }
}
