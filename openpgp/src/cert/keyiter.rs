use std::fmt;

use crate::{
    RevocationStatus,
    packet::key,
    packet::Key,
    packet::key::SecretKeyMaterial,
    types::KeyFlags,
    packet::Signature,
    Cert,
    cert::KeyBindingIter,
};

/// An iterator over all `Key`s (both the primary key and any subkeys)
/// in a Cert.
///
/// Returned by `Cert::keys_all()` and `Cert::keys_valid()`.
///
/// `KeyIter` follows the builder pattern.  There is no need to
/// explicitly finalize it, however: it already implements the
/// `Iterator` interface.
///
/// By default, `KeyIter` will only return live, non-revoked keys.  It
/// is possible to control how `KeyIter` filters using, for instance,
/// `KeyIter::flags` to only return keys with particular flags set.
pub struct KeyIter<'a, P: key::KeyParts, R: key::KeyRole> {
    // This is an option to make it easier to create an empty KeyIter.
    cert: Option<&'a Cert>,
    primary: bool,
    subkey_iter: KeyBindingIter<'a,
                                key::PublicParts,
                                key::SubordinateRole>,

    // If not None, only returns keys with the specified flags.
    flags: Option<KeyFlags>,

    // If not None, only returns keys that are live at the specified
    // time.
    alive_at: Option<std::time::SystemTime>,

    // If not None, filters by revocation status.
    revoked: Option<bool>,

    // If not None, filters by whether a key has a secret.
    secret: Option<bool>,

    // If not None, filters by whether a key has an unencrypted
    // secret.
    unencrypted_secret: Option<bool>,

    _p: std::marker::PhantomData<P>,
    _r: std::marker::PhantomData<R>,
}

impl<'a, P: key::KeyParts, R: key::KeyRole> fmt::Debug
    for KeyIter<'a, P, R>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyIter")
            .field("flags", &self.flags)
            .field("alive_at", &self.alive_at)
            .field("revoked", &self.revoked)
            .field("secret", &self.secret)
            .field("unencrypted_secret", &self.unencrypted_secret)
            .finish()
    }
}

// Very carefully implement Iterator for
// Key<{PublicParts,UnspecifiedParts}, _>.  We cannot just abstract
// over the parts, because then we cannot specialize the
// implementation for Key<SecretParts, _> below.
macro_rules! impl_iterator {
    ($parts:path) => {
        impl<'a, R: 'a + key::KeyRole> Iterator for KeyIter<'a, $parts, R>
            where &'a Key<$parts, R>: From<&'a Key<key::PublicParts,
                                                   key::UnspecifiedRole>>
        {
            type Item = (Option<&'a Signature>, RevocationStatus<'a>,
                         &'a Key<$parts, R>);

            fn next(&mut self) -> Option<Self::Item> {
                self.next_common().map(|(s, r, k)| (s, r, k.into()))
            }
        }
    }
}
impl_iterator!(key::PublicParts);
impl_iterator!(key::UnspecifiedParts);

impl<'a, R: 'a + key::KeyRole> Iterator for KeyIter<'a, key::SecretParts, R>
    where &'a Key<key::SecretParts, R>: From<&'a Key<key::SecretParts,
                                                     key::UnspecifiedRole>>
{
    type Item = (Option<&'a Signature>, RevocationStatus<'a>,
                 &'a Key<key::SecretParts, R>);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_common()
            .map(|(s, r, k)|
                 (s, r,
                  k.mark_parts_secret_ref().expect("has secret parts").into()))
    }
}

impl <'a, P: 'a + key::KeyParts, R: 'a + key::KeyRole> KeyIter<'a, P, R> {
    fn next_common(&mut self)
                   -> Option<(Option<&'a Signature>,
                              RevocationStatus<'a>,
                              &'a Key<key::PublicParts, key::UnspecifiedRole>)>
    {
        tracer!(false, "KeyIter::next", 0);
        t!("KeyIter: {:?}", self);

        if self.cert.is_none() {
            return None;
        }
        let cert = self.cert.unwrap();

        if let Some(flags) = self.flags.as_ref() {
            if flags.is_empty() {
                // Nothing to do.
                t!("short circuiting: flags is empty");
                return None;
            }
        }

        loop {
            let (sigo, revoked, key) : (_, _, &key::UnspecifiedPublic)
                = if ! self.primary {
                    self.primary = true;

                    (cert.primary_key_signature(None),
                     cert.revoked(None),
                     cert.primary().into())
                } else {
                    self.subkey_iter.next()
                        .map(|sk_binding| (sk_binding.binding_signature(None),
                                           sk_binding.revoked(None),
                                           sk_binding.key().into(),))?
                };

            t!("Considering key: {:?}", key);

            if let Some(flags) = self.flags.as_ref() {
                if let Some(sig) = sigo {
                    if (&sig.key_flags() & &flags).is_empty() {
                        t!("Have flags: {:?}, want flags: {:?}... skipping.",
                           sig.key_flags(), flags);
                        continue;
                    }
                } else {
                    // No self-signature, skip it.
                    t!("No self-signature... skipping.");
                    continue;
                }
            }

            if let Some(alive_at) = self.alive_at {
                if let Some(sig) = sigo {
                    if ! sig.key_alive(key, alive_at) {
                        t!("Key not alive... skipping.");
                        continue;
                    }
                } else {
                    // No self-signature, skip it.
                    t!("No self-signature... skipping.");
                    continue;
                }
            }

            if let Some(want_revoked) = self.revoked {
                if let RevocationStatus::Revoked(_) = revoked {
                    // The key is definitely revoked.
                    if ! want_revoked {
                        t!("Key revoked... skipping.");
                        continue;
                    }
                } else {
                    // The key is probably not revoked.
                    if want_revoked {
                        t!("Key not revoked... skipping.");
                        continue;
                    }
                }
            }

            if let Some(want_secret) = self.secret {
                if key.secret().is_some() {
                    // We have a secret.
                    if ! want_secret {
                        t!("Have a secret... skipping.");
                        continue;
                    }
                } else {
                    if want_secret {
                        t!("No secret... skipping.");
                        continue;
                    }
                }
            }

            if let Some(want_unencrypted_secret) = self.unencrypted_secret {
                if let Some(secret) = key.secret() {
                    if let SecretKeyMaterial::Unencrypted { .. } = secret {
                        if ! want_unencrypted_secret {
                            t!("Unencrypted secret... skipping.");
                            continue;
                        }
                    } else {
                        if want_unencrypted_secret {
                            t!("Encrypted secret... skipping.");
                            continue;
                        }
                    }
                } else {
                    // No secret.
                    t!("No secret... skipping.");
                    continue;
                }
            }

            return Some((sigo, revoked, key));
        }
    }
}

impl<'a, P: 'a + key::KeyParts, R: 'a + key::KeyRole> KeyIter<'a, P, R>
{
    /// Returns a new `KeyIter` instance with no filters enabled.
    pub(crate) fn new(cert: &'a Cert) -> Self where Self: 'a {
        KeyIter {
            cert: Some(cert),
            primary: false,
            subkey_iter: cert.subkeys(),

            // The filters.
            flags: None,
            alive_at: None,
            revoked: None,
            secret: None,
            unencrypted_secret: None,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Clears all filters.
    ///
    /// This causes the `KeyIter` to return all keys in the Cert.
    pub fn unfiltered(self) -> Self {
        KeyIter::new(self.cert.unwrap())
    }

    /// Returns an empty KeyIter.
    pub fn empty() -> Self {
        KeyIter {
            cert: None,
            primary: false,
            subkey_iter: KeyBindingIter { iter: None },

            // The filters.
            flags: None,
            alive_at: None,
            revoked: None,
            secret: None,
            unencrypted_secret: None,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Returns keys that have the at least one of the flags specified
    /// in `flags`.
    ///
    /// If you call this function (or one of `certification_capable`
    /// or `signing_capable` functions) multiple times, the *union* of
    /// the values is used.  Thus,
    /// `cert.flags().certification_capable().signing_capable()` will
    /// return keys that are certification capable or signing capable.
    ///
    /// If you need more complex filtering, e.g., you want a key that
    /// is both certification and signing capable, then just use a
    /// normal [`Iterator::filter`].
    ///
    ///   [`Iterator::filter`]: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.filter
    pub fn key_flags(mut self, flags: KeyFlags) -> Self {
        if let Some(flags_old) = self.flags {
            self.flags = Some(&flags | &flags_old);
        } else {
            self.flags = Some(flags);
        }
        self
    }

    /// Returns keys that are certification capable.
    ///
    /// See `key_flags` for caveats.
    pub fn certification_capable(self) -> Self {
        self.key_flags(KeyFlags::default().set_certify(true))
    }

    /// Returns keys that are signing capable.
    ///
    /// See `key_flags` for caveats.
    pub fn signing_capable(self) -> Self {
        self.key_flags(KeyFlags::default().set_sign(true))
    }

    /// Returns keys that are authentication capable.
    ///
    /// See `key_flags` for caveats.
    pub fn authentication_capable(self) -> Self {
        self.key_flags(KeyFlags::default().set_authenticate(true))
    }

    /// Returns keys that are capable of encrypting data at rest.
    ///
    /// See `key_flags` for caveats.
    pub fn encrypting_capable_at_rest(self) -> Self {
        self.key_flags(KeyFlags::default().set_encrypt_at_rest(true))
    }

    /// Returns keys that are capable of encrypting data for transport.
    ///
    /// See `key_flags` for caveats.
    pub fn encrypting_capable_for_transport(self) -> Self {
        self.key_flags(KeyFlags::default().set_encrypt_for_transport(true))
    }

    /// Only returns keys that are live as of `now`.
    ///
    /// If `now` is none, then all keys are returned whether they are
    /// live or not.
    ///
    /// A value of None disables this filter, which is set by default
    /// to only return live keys at the current time.
    ///
    /// If you call this function (or `alive`) multiple times, only
    /// the last value is used.
    pub fn alive_at<T>(mut self, alive_at: T) -> Self
        where T: Into<Option<std::time::SystemTime>>
    {
        self.alive_at = alive_at.into();
        self
    }

    /// Only returns keys that are live right now.
    ///
    /// If you call this function (or `alive_at`) multiple times, only
    /// the last value is used.
    pub fn alive(mut self) -> Self
    {
        self.alive_at = Some(std::time::SystemTime::now());
        self
    }

    /// If not None, filters by whether a key is definitely revoked.
    ///
    /// That is, whether it's revocation status is
    /// `RevocationStatus::Revoked`.
    ///
    /// A value of None disables this filter, which is set by default
    /// to not return revoked keys.
    ///
    /// If you call this function multiple times, only the last value
    /// is used.
    pub fn revoked<T>(mut self, revoked: T) -> Self
        where T: Into<Option<bool>>
    {
        self.revoked = revoked.into();
        self
    }

    /// Changes the filter to only return keys with secret key material.
    pub fn secret(self) -> KeyIter<'a, key::SecretParts, R> {
        KeyIter {
            cert: self.cert,
            primary: self.primary,
            subkey_iter: self.subkey_iter,

            // The filters.
            flags: self.flags,
            alive_at: self.alive_at,
            revoked: self.revoked,
            secret: Some(true),
            unencrypted_secret: self.unencrypted_secret,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Changes the filter to only return keys with unencrypted secret
    /// key material.
    pub fn unencrypted_secret(self)  -> KeyIter<'a, key::SecretParts, R> {
        KeyIter {
            cert: self.cert,
            primary: self.primary,
            subkey_iter: self.subkey_iter,

            // The filters.
            flags: self.flags,
            alive_at: self.alive_at,
            revoked: self.revoked,
            secret: self.secret,
            unencrypted_secret: Some(true),

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        parse::Parse,
        cert::builder::CertBuilder,
    };

    #[test]
    fn key_iter_test() {
        let key = Cert::from_bytes(crate::tests::key("neal.pgp")).unwrap();
        assert_eq!(1 + key.subkeys().count(),
                   key.keys_all().count());
    }

    #[test]
    fn select_no_keys() {
        let (cert, _) = CertBuilder::new()
            .generate().unwrap();
        let flags = KeyFlags::default().set_encrypt_for_transport(true);

        assert_eq!(cert.keys_all().key_flags(flags).count(), 0);
    }

    #[test]
    fn select_valid_and_right_flags() {
        let (cert, _) = CertBuilder::new()
            .add_encryption_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_encrypt_for_transport(true);

        assert_eq!(cert.keys_all().key_flags(flags).count(), 1);
    }

    #[test]
    fn select_valid_and_wrong_flags() {
        let (cert, _) = CertBuilder::new()
            .add_encryption_subkey()
            .add_signing_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_encrypt_for_transport(true);

        assert_eq!(cert.keys_all().key_flags(flags).count(), 1);
    }

    #[test]
    fn select_invalid_and_right_flags() {
        let (cert, _) = CertBuilder::new()
            .add_encryption_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_encrypt_for_transport(true);

        let now = std::time::SystemTime::now()
            - std::time::Duration::new(52 * 7 * 24 * 60 * 60, 0);
        assert_eq!(cert.keys_all().key_flags(flags).alive_at(now).count(), 0);
    }

    #[test]
    fn select_primary() {
        let (cert, _) = CertBuilder::new()
            .add_certification_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_certify(true);

        assert_eq!(cert.keys_all().key_flags(flags).count(), 2);
    }

    #[test]
    fn selectors() {
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_certification_subkey()
            .add_encryption_subkey()
            .add_authentication_subkey()
            .generate().unwrap();
        assert_eq!(cert.keys_valid().certification_capable().count(), 2);
        assert_eq!(cert.keys_valid().encrypting_capable_for_transport().count(),
                   1);
        assert_eq!(cert.keys_valid().encrypting_capable_at_rest().count(), 1);
        assert_eq!(cert.keys_valid().signing_capable().count(), 1);
        assert_eq!(cert.keys_valid().key_flags(
            KeyFlags::default().set_authenticate(true)).count(), 1);
    }
}
