use std::{
    fmt,
};
use serde::{Deserialize, Serialize};
use crate::{Error, Result};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

/// The OpenPGP hash algorithms as defined in [Section 9.5 of RFC 9580].
///
/// # Examples
///
/// Use `HashAlgorithm` to set the preferred hash algorithms on a signature:
///
/// ```rust
/// use sequoia_openpgp as openpgp;
/// use openpgp::packet::signature::SignatureBuilder;
/// use openpgp::types::{HashAlgorithm, SignatureType};
///
/// # fn main() -> openpgp::Result<()> {
/// let mut builder = SignatureBuilder::new(SignatureType::DirectKey)
///     .set_hash_algo(HashAlgorithm::SHA512);
/// # Ok(()) }
/// ```
///
/// [Section 9.5 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5
#[non_exhaustive]
#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// Rivest et.al. message digest 5.
    MD5,
    /// NIST Secure Hash Algorithm (deprecated)
    SHA1,
    /// RIPEMD-160
    RipeMD,
    /// 256-bit version of SHA2
    SHA256,
    /// 384-bit version of SHA2
    SHA384,
    /// 512-bit version of SHA2
    SHA512,
    /// 224-bit version of SHA2
    SHA224,
    /// 256-bit version of SHA3
    SHA3_256,
    /// 512-bit version of SHA3
    SHA3_512,
    /// Private hash algorithm identifier.
    Private(u8),
    /// Unknown hash algorithm identifier.
    Unknown(u8),
}
assert_send_and_sync!(HashAlgorithm);

const HASH_ALGORITHM_VARIANTS: [HashAlgorithm; 9] = [
    HashAlgorithm::MD5,
    HashAlgorithm::SHA1,
    HashAlgorithm::RipeMD,
    HashAlgorithm::SHA256,
    HashAlgorithm::SHA384,
    HashAlgorithm::SHA512,
    HashAlgorithm::SHA224,
    HashAlgorithm::SHA3_256,
    HashAlgorithm::SHA3_512,
];

impl Default for HashAlgorithm {
    fn default() -> Self {
        // SHA512 is almost twice as fast as SHA256 on 64-bit
        // architectures because it operates on 64-bit words.
        HashAlgorithm::SHA512
    }
}

impl From<u8> for HashAlgorithm {
    fn from(u: u8) -> Self {
        match u {
            1 => HashAlgorithm::MD5,
            2 => HashAlgorithm::SHA1,
            3 => HashAlgorithm::RipeMD,
            8 => HashAlgorithm::SHA256,
            9 => HashAlgorithm::SHA384,
            10 => HashAlgorithm::SHA512,
            11 => HashAlgorithm::SHA224,
            12 => HashAlgorithm::SHA3_256,
            14 => HashAlgorithm::SHA3_512,
            100..=110 => HashAlgorithm::Private(u),
            u => HashAlgorithm::Unknown(u),
        }
    }
}

impl From<HashAlgorithm> for u8 {
    fn from(h: HashAlgorithm) -> u8 {
        match h {
            HashAlgorithm::MD5 => 1,
            HashAlgorithm::SHA1 => 2,
            HashAlgorithm::RipeMD => 3,
            HashAlgorithm::SHA256 => 8,
            HashAlgorithm::SHA384 => 9,
            HashAlgorithm::SHA512 => 10,
            HashAlgorithm::SHA224 => 11,
            HashAlgorithm::SHA3_256 => 12,
            HashAlgorithm::SHA3_512 => 14,
            HashAlgorithm::Private(u) => u,
            HashAlgorithm::Unknown(u) => u,
        }
    }
}

impl std::str::FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Error> {
        if s.eq_ignore_ascii_case("MD5") {
            Ok(HashAlgorithm::MD5)
        } else if s.eq_ignore_ascii_case("SHA1") {
            Ok(HashAlgorithm::SHA1)
        } else if s.eq_ignore_ascii_case("RipeMD160") {
            Ok(HashAlgorithm::RipeMD)
        } else if s.eq_ignore_ascii_case("SHA256") {
            Ok(HashAlgorithm::SHA256)
        } else if s.eq_ignore_ascii_case("SHA384") {
            Ok(HashAlgorithm::SHA384)
        } else if s.eq_ignore_ascii_case("SHA512") {
            Ok(HashAlgorithm::SHA512)
        } else if s.eq_ignore_ascii_case("SHA224") {
            Ok(HashAlgorithm::SHA224)
        } else if s.eq_ignore_ascii_case("SHA3-256") {
            Ok(HashAlgorithm::SHA3_256)
        } else if s.eq_ignore_ascii_case("SHA3-512") {
            Ok(HashAlgorithm::SHA3_512)
        } else {
            Err(Error::InvalidArgument(format!(
                "Unknown hash algorithm {:?}", s)))
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HashAlgorithm::MD5 => f.write_str("MD5"),
            HashAlgorithm::SHA1 => f.write_str("SHA1"),
            HashAlgorithm::RipeMD => f.write_str("RipeMD160"),
            HashAlgorithm::SHA256 => f.write_str("SHA256"),
            HashAlgorithm::SHA384 => f.write_str("SHA384"),
            HashAlgorithm::SHA512 => f.write_str("SHA512"),
            HashAlgorithm::SHA224 => f.write_str("SHA224"),
            HashAlgorithm::SHA3_256 => f.write_str("SHA3-256"),
            HashAlgorithm::SHA3_512 => f.write_str("SHA3-512"),
            HashAlgorithm::Private(u) =>
                f.write_fmt(format_args!("Private/Experimental hash algorithm {}", u)),
            HashAlgorithm::Unknown(u) =>
                f.write_fmt(format_args!("Unknown hash algorithm {}", u)),
        }
    }
}

impl HashAlgorithm {
    /// Returns the text name of this algorithm.
    ///
    /// [Section 9.5 of RFC 9580] defines a textual representation of
    /// hash algorithms.  This is used in cleartext signed messages
    /// (see [Section 7 of RFC 9580]).
    ///
    ///   [Section 9.5 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-9.5
    ///   [Section 7 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-7
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::types::HashAlgorithm;
    /// # fn main() -> openpgp::Result<()> {
    /// assert_eq!(HashAlgorithm::RipeMD.text_name()?, "RIPEMD160");
    /// # Ok(()) }
    /// ```
    pub fn text_name(&self) -> Result<&str> {
        match self {
            HashAlgorithm::MD5 =>    Ok("MD5"),
            HashAlgorithm::SHA1 =>   Ok("SHA1"),
            HashAlgorithm::RipeMD => Ok("RIPEMD160"),
            HashAlgorithm::SHA256 => Ok("SHA256"),
            HashAlgorithm::SHA384 => Ok("SHA384"),
            HashAlgorithm::SHA512 => Ok("SHA512"),
            HashAlgorithm::SHA224 => Ok("SHA224"),
            HashAlgorithm::SHA3_256 => Ok("SHA3-256"),
            HashAlgorithm::SHA3_512 => Ok("SHA3-512"),
            HashAlgorithm::Private(_) =>
                Err(Error::UnsupportedHashAlgorithm(*self).into()),
            HashAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedHashAlgorithm(*self).into()),
        }
    }

    /// Returns the digest size for this algorithm.
    pub fn digest_size(&self) -> Result<usize> {
        match self {
            HashAlgorithm::MD5 =>    Ok(16),
            HashAlgorithm::SHA1 =>   Ok(20),
            HashAlgorithm::RipeMD => Ok(20),
            HashAlgorithm::SHA256 => Ok(32),
            HashAlgorithm::SHA384 => Ok(48),
            HashAlgorithm::SHA512 => Ok(64),
            HashAlgorithm::SHA224 => Ok(28),
            HashAlgorithm::SHA3_256 => Ok(32),
            HashAlgorithm::SHA3_512 => Ok(64),
            HashAlgorithm::Private(_) =>
                Err(Error::UnsupportedHashAlgorithm(*self).into()),
            HashAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedHashAlgorithm(*self).into()),
        }
    }

    /// Returns the salt size for this algorithm.
    ///
    /// Version 6 signatures salt the hash, and the size of the hash
    /// is dependent on the hash algorithm.
    pub fn salt_size(&self) -> Result<usize> {
        match self {
            HashAlgorithm::SHA256 => Ok(16),
            HashAlgorithm::SHA384 => Ok(24),
            HashAlgorithm::SHA512 => Ok(32),
            HashAlgorithm::SHA224 => Ok(16),
            HashAlgorithm::SHA3_256 => Ok(16),
            HashAlgorithm::SHA3_512 => Ok(32),
            _ => Err(Error::UnsupportedHashAlgorithm(*self).into()),
        }
    }

    /// Returns an iterator over all valid variants.
    ///
    /// Returns an iterator over all known variants.  This does not
    /// include the [`HashAlgorithm::Private`], or
    /// [`HashAlgorithm::Unknown`] variants.
    pub fn variants() -> impl Iterator<Item=Self> {
        HASH_ALGORITHM_VARIANTS.iter().cloned()
    }
}

#[cfg(test)]
impl Arbitrary for HashAlgorithm {
    fn arbitrary(g: &mut Gen) -> Self {
        u8::arbitrary(g).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    quickcheck! {
        fn hash_roundtrip(hash: HashAlgorithm) -> bool {
            let val: u8 = hash.into();
            hash == HashAlgorithm::from(val)
        }
    }

    quickcheck! {
        fn hash_roundtrip_str(hash: HashAlgorithm) -> bool {
            use std::str::FromStr;

            match hash {
                HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) => true,
                hash => {
                    let s = format!("{}", hash);
                    hash == HashAlgorithm::from_str(&s).unwrap()
                }
            }
        }
    }

    quickcheck! {
        fn hash_roundtrip_text_name(hash: HashAlgorithm) -> bool {
            use std::str::FromStr;

            match hash {
                HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) => true,
                hash => {
                    let s = hash.text_name().unwrap();
                    hash == HashAlgorithm::from_str(s).unwrap()
                }
            }
        }
    }

    quickcheck! {
        fn hash_display(hash: HashAlgorithm) -> bool {
            let s = format!("{}", hash);
            !s.is_empty()
        }
    }

    quickcheck! {
        fn hash_parse(hash: HashAlgorithm) -> bool {
            match hash {
                HashAlgorithm::Unknown(u) => u == 0 || (u > 11 && u < 100) ||
                    u > 110 || (4..=7).contains(&u) || u == 0,
                HashAlgorithm::Private(u) => (100..=110).contains(&u),
                _ => true
            }
        }
    }

    #[test]
    fn hash_algorithms_variants() {
        use std::collections::HashSet;
        use std::iter::FromIterator;

        // HASH_ALGORITHM_VARIANTS is a list.  Derive it in a
        // different way to double-check that nothing is missing.
        let derived_variants = (0..=u8::MAX)
            .map(HashAlgorithm::from)
            .filter(|t| {
                match t {
                    HashAlgorithm::Private(_) => false,
                    HashAlgorithm::Unknown(_) => false,
                    _ => true,
                }
            })
            .collect::<HashSet<_>>();

        let known_variants
            = HashSet::from_iter(HASH_ALGORITHM_VARIANTS
                                 .iter().cloned());

        let missing = known_variants
            .symmetric_difference(&derived_variants)
            .collect::<Vec<_>>();

        assert!(missing.is_empty(), "{:?}", missing);
    }
}
