use std::fmt;

use crate::cert::raw::RawCert;
use crate::packet::Key;
use crate::packet::key;

/// A key iterator for `RawCert`s.
///
/// This is returned by [`RawCert::keys`].  It is analogous to
/// [`KeyAmalgamationIter`], but for `RawCert`s.
///
/// [`KeyAmalgamationIter`]: crate::cert::amalgamation::key::KeyAmalgamationIter
pub struct KeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    key_iter: Box<dyn Iterator<Item=Key<key::PublicParts,
                                        key::UnspecifiedRole>>
                  + Send + Sync + 'a>,

    // Whether the primary key has been returned.
    returned_primary: bool,
    // Whether the primary key should be returned.
    want_primary: bool,

    _p: std::marker::PhantomData<P>,
    _r: std::marker::PhantomData<R>,
}
assert_send_and_sync!(KeyIter<'_, P, R>
     where P: key::KeyParts,
           R: key::KeyRole,
);

impl<'a, P, R> fmt::Debug for KeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyIter")
            .field("want_primary", &self.want_primary)
            .finish()
    }
}

macro_rules! impl_iterator {
    ($parts:path, $role:path, $item:ty) => {
        impl<'a> Iterator for KeyIter<'a, $parts, $role>
        {
            type Item = $item;

            fn next(&mut self) -> Option<Self::Item> {
                // We unwrap the result of the conversion.  But, this
                // is safe by construction: next_common only returns
                // keys that can be correctly converted.
                self.next_common()
            }
        }
    }
}

impl_iterator!(key::PublicParts, key::UnspecifiedRole,
               Key<key::PublicParts, key::UnspecifiedRole>);
impl_iterator!(key::PublicParts, key::SubordinateRole,
               Key<key::PublicParts, key::SubordinateRole>);

impl<'a, P, R> KeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn next_common(&mut self) -> Option<Key<P, R>>
    {
        tracer!(false, "KeyIter::next", 0);
        t!("{:?}", self);

        loop {
            if ! self.returned_primary {
                if ! self.want_primary {
                    // Discard the primary key.
                    let _ = self.key_iter.next();
                }
                self.returned_primary = true;
            }

            let key = self.key_iter.next()?
                .parts_into_unspecified()
                .role_into_unspecified();
            let key = if let Ok(key) = P::convert_key(key) {
                key
            } else {
                // The caller wants secret keys, but this is no secret
                // key, skip it.
                continue;
            };
            let key = R::convert_key(key);

            // Apply any filters.

            return Some(key);
        }
    }
}

impl<'a, P, R> KeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    /// Returns a new `KeyIter` instance.
    pub(crate) fn new(cert: &'a RawCert) -> Self where Self: 'a {
        KeyIter {
            key_iter: Box::new(cert.keys_internal()),

            want_primary: true,
            returned_primary: false,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Changes the iterator to only return subkeys.
    ///
    /// This function also changes the return type.  Instead of the
    /// iterator returning a [`Key`] whose role is
    /// [`key::UnspecifiedRole`], the role is [`key::SubordinateRole`]
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::cert::raw::RawCertParser;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::serialize::Serialize;
    /// #
    /// # fn main() -> Result<()> {
    /// #      let (cert, _) = CertBuilder::new()
    /// #          .add_signing_subkey()
    /// #          .add_certification_subkey()
    /// #          .add_transport_encryption_subkey()
    /// #          .add_storage_encryption_subkey()
    /// #          .add_authentication_subkey()
    /// #          .generate()?;
    /// #
    /// #      let mut bytes = Vec::new();
    /// #      cert.serialize(&mut bytes);
    /// #      let mut parser = RawCertParser::from_bytes(&bytes)?;
    /// #
    /// #      let rawcert = parser.next().expect("have one").expect("valid");
    /// #      assert!(parser.next().is_none());
    /// # let mut i = 0;
    /// for subkey in rawcert.keys().subkeys() {
    ///     // Use it.
    ///     println!("{}", subkey.fingerprint());
    /// #   i += 1;
    /// }
    /// # assert_eq!(i, 5);
    /// #     Ok(())
    /// # }
    /// ```
    ///
    pub fn subkeys(self) -> KeyIter<'a, P, key::SubordinateRole> {
        KeyIter {
            key_iter: self.key_iter,

            want_primary: false,
            returned_primary: self.returned_primary,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }
}
