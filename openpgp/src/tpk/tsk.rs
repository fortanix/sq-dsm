use std::io;

use Result;
use TPK;
use packet::{Key, Tag};
use serialize::{Serialize, SerializeKey};

/// A reference to a TPK that allows serialization of secret keys.
///
/// To avoid accidental leakage `TPK::serialize()` skips secret keys.
/// To serialize `TPK`s with secret keys, use [`TPK::as_tsk()`] to
/// create a `TSK`, which is a shim on top of the `TPK`, and serialize
/// this.
///
/// [`TPK::as_tsk()`]: ../struct.TPK.html#method.as_tsk
///
/// # Example
/// ```
/// # use sequoia_openpgp::{*, tpk::*, parse::Parse, serialize::Serialize};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let (tpk, _) = TPKBuilder::default().generate()?;
/// assert!(tpk.is_tsk());
///
/// let mut buf = Vec::new();
/// tpk.as_tsk().serialize(&mut buf)?;
///
/// let tpk_ = TPK::from_bytes(&buf)?;
/// assert!(tpk_.is_tsk());
/// assert_eq!(tpk, tpk_);
/// # Ok(()) }
pub struct TSK<'a> {
    tpk: &'a TPK,
    filter: Option<Box<'a + Fn(&'a Key) -> bool>>,
}

impl<'a> TSK<'a> {
    /// Creates a new view for the given `TPK`.
    pub(crate) fn new(tpk: &'a TPK) -> Self {
        Self {
            tpk: tpk,
            filter: None,
        }
    }

    /// Filters which secret keys to export using the given predicate.
    ///
    /// Note that the given filter replaces any existing filter.
    ///
    /// # Example
    /// ```
    /// # use sequoia_openpgp::{*, tpk::*, parse::Parse, serialize::Serialize};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// let (tpk, _) = TPKBuilder::default().add_signing_subkey().generate()?;
    /// assert_eq!(tpk.keys_valid().secret(true).count(), 2);
    ///
    /// // Only write out the primary key's secret.
    /// let mut buf = Vec::new();
    /// tpk.as_tsk().set_filter(|k| k == tpk.primary()).serialize(&mut buf)?;
    ///
    /// let tpk_ = TPK::from_bytes(&buf)?;
    /// assert_eq!(tpk_.keys_valid().secret(true).count(), 1);
    /// assert!(tpk_.primary().secret().is_some());
    /// # Ok(()) }
    pub fn set_filter<P>(mut self, predicate: P) -> Self
        where P: 'a + Fn(&'a Key) -> bool
    {
        self.filter = Some(Box::new(predicate));
        self
    }
}

impl<'a> Serialize for TSK<'a> {
    fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        // Serializes public or secret key depending on the filter.
        let serialize_key = |o: &mut W, key: &'a Key, tag_public, tag_secret| {
            key.serialize(o,
                          if self.filter.as_ref().map(
                              |f| f(key)).unwrap_or(true)
                          {
                              tag_secret
                          } else {
                              tag_public
                          })
        };
        serialize_key(o, &self.tpk.primary, Tag::PublicKey, Tag::SecretKey)?;

        for s in self.tpk.primary_selfsigs.iter() {
            s.serialize(o)?;
        }
        for s in self.tpk.primary_self_revocations.iter() {
            s.serialize(o)?;
        }
        for s in self.tpk.primary_certifications.iter() {
            s.serialize(o)?;
        }
        for s in self.tpk.primary_other_revocations.iter() {
            s.serialize(o)?;
        }

        for u in self.tpk.userids() {
            u.userid().serialize(o)?;
            for s in u.self_revocations() {
                s.serialize(o)?;
            }
            for s in u.selfsigs() {
                s.serialize(o)?;
            }
            for s in u.other_revocations() {
                s.serialize(o)?;
            }
            for s in u.certifications() {
                s.serialize(o)?;
            }
        }

        for u in self.tpk.user_attributes() {
            u.user_attribute().serialize(o)?;
            for s in u.self_revocations() {
                s.serialize(o)?;
            }
            for s in u.selfsigs() {
                s.serialize(o)?;
            }
            for s in u.other_revocations() {
                s.serialize(o)?;
            }
            for s in u.certifications() {
                s.serialize(o)?;
            }
        }

        for k in self.tpk.subkeys() {
            serialize_key(o, k.subkey(), Tag::PublicSubkey, Tag::SecretSubkey)?;
            for s in k.self_revocations() {
                s.serialize(o)?;
            }
            for s in k.selfsigs() {
                s.serialize(o)?;
            }
            for s in k.other_revocations() {
                s.serialize(o)?;
            }
            for s in k.certifications() {
                s.serialize(o)?;
            }
        }

        for u in self.tpk.unknowns.iter() {
            u.unknown.serialize(o)?;

            for s in u.sigs.iter() {
                s.serialize(o)?;
            }
        }

        for s in self.tpk.bad.iter() {
            s.serialize(o)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use parse::Parse;
    use serialize::Serialize;

    fn test_tpk(name: &str) -> Result<TPK> {
        let path = format!("tests/data/keys/{}.pgp", name);
        TPK::from_file(path)
    }

    fn test_tsk(name: &str) -> Result<TPK> {
        let path = format!("tests/data/keys/{}-private.pgp", name);
        TPK::from_file(path)
    }

    const PUBLIC_TESTS: &[&str] = &[
        "dennis-simon-anton",
        "dsa2048-elgamal3072",
        "emmelie-dorothea-dina-samantha-awina-ed25519",
        "erika-corinna-daniela-simone-antonia-nistp256",
        "erika-corinna-daniela-simone-antonia-nistp384",
        "erika-corinna-daniela-simone-antonia-nistp521",
        "testy-new",
        "testy",
        "neal",
        "dkg-sigs-out-of-order",
    ];
    const SECRET_TESTS: &[&str] = &[
        "dennis-simon-anton",
        "dsa2048-elgamal3072",
        "emmelie-dorothea-dina-samantha-awina-ed25519",
        "erika-corinna-daniela-simone-antonia-nistp256",
        "erika-corinna-daniela-simone-antonia-nistp384",
        "erika-corinna-daniela-simone-antonia-nistp521",
        "testy-new",
        "testy-nistp256",
        "testy-nistp384",
        "testy-nistp521",
        "testy",
    ];

    /// Demonstrates that public keys and all components are
    /// serialized.
    #[test]
    fn roundtrip_tpk() {
        for test in PUBLIC_TESTS {
            let tpk = match test_tpk(dbg!(test)) {
                Ok(t) => t,
                Err(_) => continue,
            };
            assert!(! tpk.is_tsk());

            let mut buf = Vec::new();
            tpk.as_tsk().serialize(&mut buf).unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}.pgp failed", test);
        }
    }

    /// Demonstrates that secret keys and all components are
    /// serialized.
    #[test]
    fn roundtrip_tsk() {
        for test in SECRET_TESTS {
            let tpk = test_tsk(test).unwrap();
            assert!(tpk.is_tsk());

            let mut buf = Vec::new();
            tpk.as_tsk().serialize(&mut buf).unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}-private.pgp failed", test);

            // This time, use a trivial filter.
            let mut buf = Vec::new();
            tpk.as_tsk().set_filter(|_| true).serialize(&mut buf).unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}-private.pgp failed", test);
        }
    }

    /// Demonstrates that TSK::serialize() with the right filter
    /// reduces to TPK::serialize().
    #[test]
    fn reduce_to_tpk_serialize() {
        for test in SECRET_TESTS {
            let tpk = test_tsk(test).unwrap();
            assert!(tpk.is_tsk());

            // First, use TPK::serialize().
            let mut buf_tpk = Vec::new();
            tpk.serialize(&mut buf_tpk).unwrap();

            // When serializing using TSK::serialize, filter out all
            // secret keys.
            let mut buf_tsk = Vec::new();
            tpk.as_tsk().set_filter(|_| false).serialize(&mut buf_tsk).unwrap();

            // Check for equality.
            let tpk_ = TPK::from_bytes(&buf_tpk).unwrap();
            let tsk_ = TPK::from_bytes(&buf_tsk).unwrap();
            assert_eq!(tpk_, tsk_,
                       "reducing failed on {}-private.pgp: not TPK::eq",
                       test);

            // Check for identinty.
            assert_eq!(buf_tpk, buf_tsk,
                       "reducing failed on {}-private.pgp: serialized identity",
                       test);
        }
    }
}
