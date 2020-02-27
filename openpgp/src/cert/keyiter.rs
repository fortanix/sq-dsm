use std::fmt;
use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;
use std::borrow::Borrow;

use crate::{
    KeyHandle,
    types::RevocationStatus,
    packet::key,
    packet::key::SecretKeyMaterial,
    types::KeyFlags,
    cert::prelude::*,
    policy::Policy,
};

/// An iterator over all `Key`s (both the primary key and the subkeys)
/// in a certificate.
///
/// Returned by `Cert::keys()`.
///
/// `KeyIter` follows the builder pattern.  There is no need to
/// explicitly finalize it, however: it already implements the
/// `Iterator` trait.
///
/// By default, `KeyIter` returns all keys.  `KeyIter` provides some
/// filters to control what it returns.  For instance,
/// `KeyIter::secret` causes the iterator to only returns keys that
/// include secret key material.  Of course, since `KeyIter`
/// implements `Iterator`, it is possible to use `Iterator::filter` to
/// implement custom filters.
pub struct KeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    // This is an option to make it easier to create an empty KeyIter.
    cert: Option<&'a Cert>,
    primary: bool,
    subkey_iter: UnfilteredKeyBundleIter<'a,
                                key::PublicParts,
                                key::SubordinateRole>,

    // If not None, filters by whether a key has a secret.
    secret: Option<bool>,

    // If not None, filters by whether a key has an unencrypted
    // secret.
    unencrypted_secret: Option<bool>,

    // Only return keys in this set.
    key_handles: Vec<KeyHandle>,

    _p: std::marker::PhantomData<P>,
    _r: std::marker::PhantomData<R>,
}

impl<'a, P, R> fmt::Debug for KeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyIter")
            .field("secret", &self.secret)
            .field("unencrypted_secret", &self.unencrypted_secret)
            .field("key_handles", &self.key_handles)
            .finish()
    }
}

// Very carefully implement Iterator for
// Key<{PublicParts,UnspecifiedParts}, _>.  We cannot just abstract
// over the parts, because then we cannot specialize the
// implementation for Key<SecretParts, _> below.
macro_rules! impl_iterator {
    ($parts:path) => {
        impl<'a> Iterator for KeyIter<'a, $parts, key::UnspecifiedRole>
        {
            type Item = ErasedKeyAmalgamation<'a, $parts>;

            fn next(&mut self) -> Option<Self::Item> {
                self.next_common().map(|k| k.into())
            }
        }
    }
}
impl_iterator!(key::PublicParts);
impl_iterator!(key::UnspecifiedParts);

impl<'a> Iterator for KeyIter<'a, key::SecretParts, key::UnspecifiedRole> {
    type Item = ErasedKeyAmalgamation<'a, key::SecretParts>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_common().map(|k| k.try_into().expect("has secret parts"))
    }
}

impl<'a, P, R> KeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn next_common(&mut self) -> Option<ErasedKeyAmalgamation<'a, key::PublicParts>>
    {
        tracer!(false, "KeyIter::next", 0);
        t!("KeyIter: {:?}", self);

        if self.cert.is_none() {
            return None;
        }
        let cert = self.cert.unwrap();

        loop {
            let ka : ErasedKeyAmalgamation<key::PublicParts>
                = if ! self.primary {
                    self.primary = true;
                    PrimaryKeyAmalgamation::new(cert).into()
                } else {
                    SubordinateKeyAmalgamation::new(
                        cert, self.subkey_iter.next()?).into()
                };

            t!("Considering key: {:?}", ka.key());

            if self.key_handles.len() > 0 {
                if !self.key_handles
                    .iter()
                    .any(|h| h.aliases(ka.key().key_handle()))
                {
                    t!("{} is not one of the keys that we are looking for ({:?})",
                       ka.key().fingerprint(), self.key_handles);
                    continue;
                }
            }

            if let Some(want_secret) = self.secret {
                if ka.key().has_secret() {
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
                if let Some(secret) = ka.key().optional_secret() {
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

            return Some(ka);
        }
    }
}

impl<'a, P, R> KeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    /// Returns a new `KeyIter` instance.
    pub(crate) fn new(cert: &'a Cert) -> Self where Self: 'a {
        KeyIter {
            cert: Some(cert),
            primary: false,
            subkey_iter: cert.subkeys(),

            // The filters.
            secret: None,
            unencrypted_secret: None,
            key_handles: Vec::with_capacity(0),

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Changes the filter to only return keys with secret key material.
    pub fn secret(self) -> KeyIter<'a, key::SecretParts, R> {
        KeyIter {
            cert: self.cert,
            primary: self.primary,
            subkey_iter: self.subkey_iter,

            // The filters.
            secret: Some(true),
            unencrypted_secret: self.unencrypted_secret,
            key_handles: self.key_handles,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Changes the filter to only return keys with unencrypted secret
    /// key material.
    pub fn unencrypted_secret(self) -> KeyIter<'a, key::SecretParts, R> {
        KeyIter {
            cert: self.cert,
            primary: self.primary,
            subkey_iter: self.subkey_iter,

            // The filters.
            secret: self.secret,
            unencrypted_secret: Some(true),
            key_handles: self.key_handles,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Only returns a key if it matches the specified handle.
    ///
    /// Note: this function is cumulative.  If you call this function
    /// (or `key_handles`) multiple times, then the iterator returns a
    /// key if it matches *any* of the specified handles.
    pub fn key_handle<H>(mut self, h: H) -> Self
        where H: Into<KeyHandle>
    {
        self.key_handles.push(h.into());
        self
    }

    /// Only returns a key if it matches any of the specified handles.
    ///
    /// Note: this function is cumulative.  If you call this function
    /// (or `key_handle`) multiple times, then the iterator returns a
    /// key if it matches *any* of the specified handles.
    pub fn key_handles<'b>(mut self, h: impl Iterator<Item=&'b KeyHandle>)
        -> Self
        where 'a: 'b
    {
        self.key_handles.extend(h.map(|h| h.clone()));
        self
    }

    /// Changes the iterator to skip the primary key.
    pub fn skip_primary(mut self) -> Self {
        self.primary = true;
        self
    }

    /// Changes the iterator to only return keys that are valid at
    /// time `time`.
    ///
    /// If `time` is None, then the current time is used.
    ///
    /// See `ValidKeyIter` for the definition of a valid key.
    ///
    /// This also makes a number of filters like `alive` and `revoked`
    /// available and causes the iterator to return a
    /// `KeyAmalgamation` instead of a bare `Key`.
    ///
    /// As a general rule of thumb, when encrypting or signing a
    /// message, you only want to use keys that are alive, not
    /// revoked, and have the appropriate capabilities keys right now.
    /// For example:
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::types::RevocationStatus;
    /// use sequoia_openpgp::policy::StandardPolicy;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// let p = &StandardPolicy::new();
    ///
    /// if let RevocationStatus::Revoked(_) = cert.revoked(p, None) {
    ///     // The certificate is revoked, don't use any keys from it.
    /// } else if let Err(_) = cert.alive(p, None) {
    ///     // The certificate is not alive, don't use any keys from it.
    /// } else {
    ///     for key in cert.keys().with_policy(p, None).alive().revoked(false).for_signing() {
    ///         // We can sign the message with this key.
    ///     }
    /// }
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// When verifying a message, you only want to use keys that were
    /// alive, not revoked, and signing capable when the message was
    /// signed.  These are the only keys that the signer could have
    /// used; anything else suggests an attack, e.g., a forged time
    /// stamp.
    ///
    /// For version 4 Signature packets, the `Signature Creation Time`
    /// subpacket indicates when the signature was allegedly created.
    /// For the purpose of finding the key to verify the signature,
    /// this time stamp should be trusted.
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::types::RevocationStatus;
    /// use sequoia_openpgp::policy::StandardPolicy;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// # let timestamp = None;
    /// if let RevocationStatus::Revoked(_) = cert.revoked(p, None) {
    ///     // The certificate is revoked, don't use any keys from it.
    /// } else if let Err(_) = cert.alive(p, None) {
    ///     // The certificate is not alive, don't use any keys from it.
    /// } else {
    ///     for key in cert.keys().with_policy(p, timestamp).alive().revoked(false).for_signing() {
    ///         // Verify the message with this keys.
    ///     }
    /// }
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// Similarly, when decrypting a message, you should only consider
    /// keys that were alive, not revoked, and encryption-capable when
    /// the message was encrypted.  Unfortunately, we don't know when
    /// a message was encrypted.  This, of course, precludes checking
    /// the key's liveness, its revocation status, and its key
    /// capabilities at the time of encryption.
    ///
    /// Decrypting a message encrypt to an expired or revoked key is
    /// not a security problem.  In fact, due to the slow propagation
    /// of revocation certificates, it is better to not ignore revoked
    /// keys in this case.  However, checking whether a key is
    /// encryption capable is important.  [This discussion] explains
    /// why using a signing key to decrypt a message can be dangerous.
    ///
    /// A possible workaround is to check whether the key is
    /// encryption capable now.  Since a key's key flags don't
    /// typically change, this will correctly filter out keys that are
    /// not encryption capable.  But, it will also skip keys whose
    /// self signature is now expired.  Happily, no one appears to use
    /// [signature expirations] on self signatures.  Since using the
    /// current time will almost never result in skipping the correct
    /// decryption key, but does protect the user from a dangerous
    /// attack, we recommend this approach when looking up a
    /// decryption key.
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::cert::prelude::*;
    /// use sequoia_openpgp::policy::StandardPolicy;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// let decryption_keys = cert.keys().with_policy(p, None)
    ///     .for_storage_encryption().for_transport_encryption()
    ///     .collect::<Vec<_>>();
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// [signature expirations]: https://tools.ietf.org/html/rfc4880#section-5.2.3.10
    /// [This discussion]: https://crypto.stackexchange.com/a/12138
    pub fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> ValidKeyIter<'a, P, R>
        where T: Into<Option<SystemTime>>
    {
        ValidKeyIter {
            cert: self.cert,
            primary: self.primary,
            subkey_iter: self.subkey_iter,

            policy: policy,
            time: time.into().unwrap_or_else(SystemTime::now),

            // The filters.
            secret: self.secret,
            unencrypted_secret: self.unencrypted_secret,
            key_handles: self.key_handles,
            flags: None,
            alive: None,
            revoked: None,

            _p: self._p,
            _r: self._r,
        }
    }

    /// Changes the iterator to return key bundles.
    ///
    /// A key bundle is similar to a key amalgamation, but is not
    /// bound to a specific time.  It contains the key and all
    /// relevant signatures.
    ///
    /// If the primary key satisfies the current filter on this
    /// iterator, it is returned first.
    pub fn bundles(self) -> KeyBundleIter<'a, P, key::UnspecifiedRole> {
        KeyBundleIter {
            cert: self.cert,
            primary: self.primary,
            subkey_iter: self.subkey_iter,

            // The filters.
            secret: self.secret,
            unencrypted_secret: self.unencrypted_secret,
            key_handles: self.key_handles,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Changes the iterator to return subkey bundles.
    ///
    /// A key bundle is similar to a key amalgamation, but is not
    /// bound to a specific time.  It contains the key and all
    /// relevant signatures.
    ///
    /// The primary key is never returned from this iterator.
    pub fn subkeys(self) -> KeyBundleIter<'a, P, key::SubordinateRole> {
        KeyBundleIter {
            cert: self.cert,
            primary: true,
            subkey_iter: self.subkey_iter,

            // The filters.
            secret: self.secret,
            unencrypted_secret: self.unencrypted_secret,
            key_handles: self.key_handles,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }
}

/// An iterator over all valid `Key`s in a certificate.
///
/// A key is valid at time `t` if it was not created after `t` and it
/// has a live *self-signature* at time `t`.  Note: this does not mean
/// that the key or the certificate is also live at time `t`; the key
/// or certificate may be expired, but the self-signature is still
/// valid.
///
/// `ValidKeyIter` follows the builder pattern.  There is no need to
/// explicitly finalize it, however: it already implements the
/// `Iterator` trait.
pub struct ValidKeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    // This is an option to make it easier to create an empty ValidKeyIter.
    cert: Option<&'a Cert>,
    primary: bool,
    subkey_iter: UnfilteredKeyBundleIter<'a,
                                key::PublicParts,
                                key::SubordinateRole>,

    // The policy.
    policy: &'a dyn Policy,

    // The time.
    time: SystemTime,

    // If not None, filters by whether a key has a secret.
    secret: Option<bool>,

    // If not None, filters by whether a key has an unencrypted
    // secret.
    unencrypted_secret: Option<bool>,

    // Only return keys in this set.
    key_handles: Vec<KeyHandle>,

    // If not None, only returns keys with the specified flags.
    flags: Option<KeyFlags>,

    // If not None, filters by whether a key is alive at time `t`.
    alive: Option<()>,

    // If not None, filters by whether the key is revoked or not at
    // time `t`.
    revoked: Option<bool>,

    _p: std::marker::PhantomData<P>,
    _r: std::marker::PhantomData<R>,
}

impl<'a, P, R> fmt::Debug for ValidKeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ValidKeyIter")
            .field("policy", &self.policy)
            .field("time", &self.time)
            .field("secret", &self.secret)
            .field("unencrypted_secret", &self.unencrypted_secret)
            .field("key_handles", &self.key_handles)
            .field("flags", &self.flags)
            .field("alive", &self.alive)
            .field("revoked", &self.revoked)
            .finish()
    }
}

// Very carefully implement Iterator for
// Key<{PublicParts,UnspecifiedParts}, _>.  We cannot just abstract
// over the parts, because then we cannot specialize the
// implementation for Key<SecretParts, _> below.
macro_rules! impl_valid_key_iterator {
    ($parts:path) => {
        impl<'a> Iterator for ValidKeyIter<'a, $parts, key::UnspecifiedRole>
        {
            type Item = ValidErasedKeyAmalgamation<'a, $parts>;

            fn next(&mut self) -> Option<Self::Item> {
                self.next_common().map(|ka| ka.into())
            }
        }
    }
}
impl_valid_key_iterator!(key::PublicParts);
impl_valid_key_iterator!(key::UnspecifiedParts);

impl<'a> Iterator for ValidKeyIter<'a, key::SecretParts, key::UnspecifiedRole>
{
    type Item = ValidErasedKeyAmalgamation<'a, key::SecretParts>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_common().map(|ka| ka.try_into().expect("has secret parts"))
    }
}

impl<'a, P, R> ValidKeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn next_common(&mut self)
        -> Option<ValidErasedKeyAmalgamation<'a, key::PublicParts>>
    {
        tracer!(false, "ValidKeyIter::next", 0);
        t!("ValidKeyIter: {:?}", self);

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
            let ka = if ! self.primary {
                self.primary = true;
                let ka : ErasedKeyAmalgamation<'a, key::PublicParts>
                    = PrimaryKeyAmalgamation::new(cert).into();
                match ka.with_policy(self.policy, self.time) {
                    Ok(ka) => ka,
                    Err(err) => {
                        // The primary key is bad.  Abort.
                        t!("Getting primary key: {:?}", err);
                        return None;
                    }
                }
            } else {
                let ka : ErasedKeyAmalgamation<'a, key::PublicParts>
                    = SubordinateKeyAmalgamation::new(
                        cert.into(), self.subkey_iter.next()?).into();
                match ka.with_policy(self.policy, self.time) {
                    Ok(ka) => ka,
                    Err(err) => {
                        // The subkey is bad, abort.
                        t!("Getting subkey: {:?}", err);
                        continue;
                    }
                }
            };

            let key = ka.key();
            t!("Considering key: {:?}", key);

            if self.key_handles.len() > 0 {
                if !self.key_handles
                    .iter()
                    .any(|h| h.aliases(key.key_handle()))
                {
                    t!("{} is not one of the keys that we are looking for ({:?})",
                       key.key_handle(), self.key_handles);
                    continue;
                }
            }

            if let Some(flags) = self.flags.as_ref() {
                if !ka.has_any_key_flag(flags) {
                    t!("Have flags: {:?}, want flags: {:?}... skipping.",
                      flags, flags);
                    continue;
                }
            }

            if let Some(()) = self.alive {
                if let Err(err) = ka.alive() {
                    t!("Key not alive: {:?}", err);
                    continue;
                }
            }

            if let Some(want_revoked) = self.revoked {
                if let RevocationStatus::Revoked(_) = ka.revoked() {
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
                if key.has_secret() {
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
                if let Some(secret) = key.optional_secret() {
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

            return Some(ka.into());
        }
    }
}

impl<'a, P, R> ValidKeyIter<'a, P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    /// Returns keys that have the at least one of the flags specified
    /// in `flags`.
    ///
    /// If you call this function (or one of `for_certification` or
    /// `for_signing` functions) multiple times, the *union* of the
    /// values is used.  Thus,
    /// `cert.flags().for_certification().for_signing()` will return
    /// keys that are certification capable *or* signing capable.
    ///
    /// If you need more complex filtering, e.g., you want a key that
    /// is both certification and signing capable, then use
    /// [`Iterator::filter`].
    ///
    ///   [`Iterator::filter`]: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.filter
    pub fn key_flags<F>(mut self, flags: F) -> Self
        where F: Borrow<KeyFlags>
    {
        let flags = flags.borrow();
        if let Some(flags_old) = self.flags {
            self.flags = Some(flags | &flags_old);
        } else {
            self.flags = Some(flags.clone());
        }
        self
    }

    /// Returns keys that are certification capable.
    ///
    /// See `key_flags` for caveats.
    pub fn for_certification(self) -> Self {
        self.key_flags(KeyFlags::default().set_certification(true))
    }

    /// Returns keys that are signing capable.
    ///
    /// See `key_flags` for caveats.
    pub fn for_signing(self) -> Self {
        self.key_flags(KeyFlags::default().set_signing(true))
    }

    /// Returns keys that are authentication capable.
    ///
    /// See `key_flags` for caveats.
    pub fn for_authentication(self) -> Self {
        self.key_flags(KeyFlags::default().set_authentication(true))
    }

    /// Returns keys that are capable of encrypting data at rest.
    ///
    /// See `key_flags` for caveats.
    pub fn for_storage_encryption(self) -> Self {
        self.key_flags(KeyFlags::default().set_storage_encryption(true))
    }

    /// Returns keys that are capable of encrypting data for transport.
    ///
    /// See `key_flags` for caveats.
    pub fn for_transport_encryption(self) -> Self {
        self.key_flags(KeyFlags::default().set_transport_encryption(true))
    }

    /// Only returns keys that are alive.
    ///
    /// Note: this only checks if the key is alive; it does not check
    /// whether the certificate is alive.
    pub fn alive(mut self) -> Self
    {
        self.alive = Some(());
        self
    }

    /// Filters by whether a key is definitely revoked.
    ///
    /// A value of None disables this filter.
    ///
    /// Note: If you call this function multiple times on the same
    /// iterator, only the last value is used.
    ///
    /// Note: This only checks if the key is not revoked; it does not
    /// check whether the certificate not revoked.
    ///
    /// This filter checks whether a key's revocation status is
    /// `RevocationStatus::Revoked` or not.  The latter (i.e.,
    /// `revoked(false)`) is equivalent to:
    ///
    /// ```rust
    /// extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::types::RevocationStatus;
    /// use openpgp::cert::prelude::*;
    /// use sequoia_openpgp::policy::StandardPolicy;
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// let p = &StandardPolicy::new();
    ///
    /// # let timestamp = None;
    /// let non_revoked_keys = cert
    ///     .keys()
    ///     .with_policy(p, timestamp)
    ///     .filter(|ka| {
    ///         match ka.revoked() {
    ///             RevocationStatus::Revoked(_) =>
    ///                 // It's definitely revoked, skip it.
    ///                 false,
    ///             RevocationStatus::CouldBe(_) =>
    ///                 // There is a designated revoker that we
    ///                 // should check, but don't (or can't).  To
    ///                 // avoid a denial of service arising from fake
    ///                 // revocations, we assume that the key has not
    ///                 // been revoked and return it.
    ///                 true,
    ///             RevocationStatus::NotAsFarAsWeKnow =>
    ///                 // We have no evidence to suggest that the key
    ///                 // is revoked.
    ///                 true,
    ///         }
    ///     })
    ///     .map(|ka| ka.key())
    ///     .collect::<Vec<_>>();
    /// #     Ok(())
    /// # }
    /// ```
    ///
    /// As the example shows, this filter is significantly less
    /// flexible than using `KeyAmalgamation::revoked`.  However, this
    /// filter implements a typical policy, and does not preclude
    /// using `filter` to realize alternative policies.
    pub fn revoked<T>(mut self, revoked: T) -> Self
        where T: Into<Option<bool>>
    {
        self.revoked = revoked.into();
        self
    }

    /// Changes the filter to only return keys with secret key material.
    pub fn secret(self) -> ValidKeyIter<'a, key::SecretParts, R> {
        ValidKeyIter {
            cert: self.cert,
            primary: self.primary,
            subkey_iter: self.subkey_iter,

            time: self.time,
            policy: self.policy,

            // The filters.
            secret: Some(true),
            unencrypted_secret: self.unencrypted_secret,
            key_handles: self.key_handles,
            flags: self.flags,
            alive: self.alive,
            revoked: self.revoked,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Changes the filter to only return keys with unencrypted secret
    /// key material.
    pub fn unencrypted_secret(self) -> ValidKeyIter<'a, key::SecretParts, R> {
        ValidKeyIter {
            cert: self.cert,
            primary: self.primary,
            subkey_iter: self.subkey_iter,

            time: self.time,
            policy: self.policy,

            // The filters.
            secret: self.secret,
            unencrypted_secret: Some(true),
            key_handles: self.key_handles,
            flags: self.flags,
            alive: self.alive,
            revoked: self.revoked,

            _p: std::marker::PhantomData,
            _r: std::marker::PhantomData,
        }
    }

    /// Only returns a key if it matches the specified handle.
    ///
    /// Note: this function is cumulative.  If you call this function
    /// (or `key_handles`) multiple times, then the iterator returns a
    /// key if it matches *any* of the specified handles.
    pub fn key_handle<H>(mut self, h: H) -> Self
        where H: Into<KeyHandle>
    {
        self.key_handles.push(h.into());
        self
    }

    /// Only returns a key if it matches any of the specified handles.
    ///
    /// Note: this function is cumulative.  If you call this function
    /// (or `key_handle`) multiple times, then the iterator returns a
    /// key if it matches *any* of the specified handles.
    pub fn key_handles<'b>(mut self, h: impl Iterator<Item=&'b KeyHandle>)
        -> Self
        where 'a: 'b
    {
        self.key_handles.extend(h.map(|h| h.clone()));
        self
    }
}

pub struct KeyBundleIter<'a, P: key::KeyParts, R: key::KeyRole> {
    // This is an option to make it easier to create an empty KeyIter.
    cert: Option<&'a Cert>,
    primary: bool,
    subkey_iter: UnfilteredKeyBundleIter<'a,
                                key::PublicParts,
                                key::SubordinateRole>,
    // If not None, filters by whether a key has a secret.
    secret: Option<bool>,

    // If not None, filters by whether a key has an unencrypted
    // secret.
    unencrypted_secret: Option<bool>,

    // Only return keys in this set.
    key_handles: Vec<KeyHandle>,

    _p: std::marker::PhantomData<P>,
    _r: std::marker::PhantomData<R>,
}

impl<'a, P: key::KeyParts, R: key::KeyRole> fmt::Debug
    for KeyBundleIter<'a, P, R>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("KeyBundleIter")
            .field("primary", &self.primary)
            .field("secret", &self.secret)
            .field("unencrypted_secret", &self.unencrypted_secret)
            .field("key_handles", &self.key_handles)
            .finish()
    }
}

// Very carefully implement Iterator for
// Key<{PublicParts,UnspecifiedParts}, _>.  We cannot just abstract
// over the parts, because then we cannot specialize the
// implementation for Key<SecretParts, _> below.
macro_rules! impl_key_component_iterator {
    ($parts:path) => {
        impl<'a, R: 'a + key::KeyRole> Iterator for KeyBundleIter<'a, $parts, R>
            where &'a KeyBundle<$parts, R>:
                      From<&'a KeyBundle<key::PublicParts, key::UnspecifiedRole>>
        {
            type Item = &'a KeyBundle<$parts, R>;

            fn next(&mut self) -> Option<Self::Item> {
                self.next_common().map(|b| b.into())
            }
        }
    }
}
impl_key_component_iterator!(key::PublicParts);
impl_key_component_iterator!(key::UnspecifiedParts);

impl<'a, R: 'a + key::KeyRole, E> Iterator for KeyBundleIter<'a, key::SecretParts, R>
    where &'a KeyBundle<key::SecretParts, R>:
              TryFrom<&'a KeyBundle<key::PublicParts, key::UnspecifiedRole>,
                      Error = E>,
          E: std::fmt::Debug,
{
    type Item = &'a KeyBundle<key::SecretParts, R>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_common().map(|ka| ka.try_into().expect("has secret parts"))
    }
}

impl<'a, P: 'a + key::KeyParts, R: 'a + key::KeyRole> KeyBundleIter<'a, P, R>
{
    fn next_common(&mut self) -> Option<&'a KeyBundle<key::PublicParts, key::UnspecifiedRole>>
    {
        tracer!(false, "KeyBundleIter::next", 0);
        t!("KeyBundleIter: {:?}", self);

        if self.cert.is_none() {
            return None;
        }
        let cert = self.cert.unwrap();

        loop {
            let binding =
                if ! self.primary {
                    self.primary = true;
                    cert.primary.mark_role_unspecified_ref()
                } else {
                    self.subkey_iter.next()?.mark_role_unspecified_ref()
                };

            let key = binding.key();
            t!("Considering key: {:?}", key);

            if self.key_handles.len() > 0 {
                if !self.key_handles
                    .iter()
                    .any(|h| h.aliases(key.key_handle()))
                {
                    t!("{} is not one of the keys that we are looking for ({:?})",
                       key.key_handle(), self.key_handles);
                    continue;
                }
            }


            if let Some(want_secret) = self.secret {
                if key.has_secret() {
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
                if let Some(secret) = key.optional_secret() {
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

            return Some(binding);
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
    use crate::policy::StandardPolicy as P;

    #[test]
    fn key_iter_test() {
        let key = Cert::from_bytes(crate::tests::key("neal.pgp")).unwrap();
        assert_eq!(1 + key.subkeys().count(),
                   key.keys().count());
    }

    #[test]
    fn select_no_keys() {
        let p = &P::new();
        let (cert, _) = CertBuilder::new()
            .generate().unwrap();
        let flags = KeyFlags::default().set_transport_encryption(true);

        assert_eq!(cert.keys().with_policy(p, None).key_flags(flags).count(), 0);
    }

    #[test]
    fn select_valid_and_right_flags() {
        let p = &P::new();
        let (cert, _) = CertBuilder::new()
            .add_transport_encryption_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_transport_encryption(true);

        assert_eq!(cert.keys().with_policy(p, None).key_flags(flags).count(), 1);
    }

    #[test]
    fn select_valid_and_wrong_flags() {
        let p = &P::new();
        let (cert, _) = CertBuilder::new()
            .add_transport_encryption_subkey()
            .add_signing_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_transport_encryption(true);

        assert_eq!(cert.keys().with_policy(p, None).key_flags(flags).count(), 1);
    }

    #[test]
    fn select_invalid_and_right_flags() {
        let p = &P::new();
        let (cert, _) = CertBuilder::new()
            .add_transport_encryption_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_transport_encryption(true);

        let now = SystemTime::now()
            - std::time::Duration::new(52 * 7 * 24 * 60 * 60, 0);
        assert_eq!(cert.keys().with_policy(p, now).key_flags(flags).alive().count(),
                   0);
    }

    #[test]
    fn select_primary() {
        let p = &P::new();
        let (cert, _) = CertBuilder::new()
            .add_certification_subkey()
            .generate().unwrap();
        let flags = KeyFlags::default().set_certification(true);

        assert_eq!(cert.keys().with_policy(p, None).key_flags(flags).count(),
                   2);
    }

    #[test]
    fn selectors() {
        let p = &P::new();
        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_certification_subkey()
            .add_transport_encryption_subkey()
            .add_storage_encryption_subkey()
            .add_authentication_subkey()
            .generate().unwrap();
        assert_eq!(cert.keys().with_policy(p, None).alive().revoked(false)
                       .for_certification().count(),
                   2);
        assert_eq!(cert.keys().with_policy(p, None).alive().revoked(false)
                       .for_transport_encryption().count(),
                   1);
        assert_eq!(cert.keys().with_policy(p, None).alive().revoked(false)
                       .for_storage_encryption().count(),
                   1);

        assert_eq!(cert.keys().with_policy(p, None).alive().revoked(false)
                       .for_signing().count(),
                   1);
        assert_eq!(cert.keys().with_policy(p, None).alive().revoked(false)
                       .key_flags(KeyFlags::default().set_authentication(true))
                       .count(),
                   1);
    }

    #[test]
    fn select_key_handle() {
        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .add_certification_subkey()
            .add_transport_encryption_subkey()
            .add_storage_encryption_subkey()
            .add_authentication_subkey()
            .generate().unwrap();

        let keys = cert.keys().count();
        assert_eq!(keys, 6);

        let keyids = cert.keys().map(|ka| ka.key().keyid()).collect::<Vec<_>>();

        fn check(got: &[KeyHandle], expected: &[KeyHandle]) {
            if expected.len() != got.len() {
                panic!("Got {}, expected {} handles",
                       got.len(), expected.len());
            }

            for (g, e) in got.iter().zip(expected.iter()) {
                if !e.aliases(g) {
                    panic!("     Got: {:?}\nExpected: {:?}",
                           got, expected);
                }
            }
        }

        for i in 1..keys {
            for keyids in keyids[..].windows(i) {
                let keyids : Vec<KeyHandle>
                    = keyids.iter().map(Into::into).collect();
                assert_eq!(keyids.len(), i);

                check(
                    &cert.keys().key_handles(keyids.iter())
                        .map(|ka| ka.key().key_handle())
                        .collect::<Vec<KeyHandle>>(),
                    &keyids);
                check(
                    &cert.keys().with_policy(p, None).key_handles(keyids.iter())
                        .map(|ka| ka.key().key_handle())
                        .collect::<Vec<KeyHandle>>(),
                    &keyids);
                check(
                    &cert.keys().key_handles(keyids.iter()).with_policy(p, None)
                        .map(|ka| ka.key().key_handle())
                        .collect::<Vec<KeyHandle>>(),
                    &keyids);
            }
        }
    }
}
