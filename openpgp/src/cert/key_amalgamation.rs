use std::time;
use std::convert::TryInto;
use std::convert::TryFrom;
use std::borrow::Borrow;

use crate::{
    Cert,
    cert::KeyBinding,
    packet::key,
    packet::key::SecretKeyMaterial,
    packet::Key,
    packet::Signature,
    Result,
    RevocationStatus,
    types::KeyFlags,
};

/// A variant of `KeyAmalgamation` for primary keys.
#[derive(Debug)]
struct PrimaryKeyAmalgamation<'a, P: key::KeyParts> {
    cert: &'a Cert,
    binding: &'a KeyBinding<P, key::PrimaryRole>,
}

/// A variant of `KeyAmalgamation` for subkeys.
#[derive(Debug)]
struct SubordinateKeyAmalgamation<'a, P: key::KeyParts> {
    cert: &'a Cert,
    binding: &'a KeyBinding<P, key::SubordinateRole>,
}

/// The underlying `KeyAmalgamation` type.
///
/// We don't make this type public, because an enum's variant types
/// must also all be public, and we don't want that here.  Wrapping
/// this in a struct means that we can hide that.
#[derive(Debug)]
enum KeyAmalgamation0<'a, P: key::KeyParts> {
    Primary(PrimaryKeyAmalgamation<'a, P>),
    Subordinate(SubordinateKeyAmalgamation<'a, P>),
}

/// A `Key` and its associated data.
#[derive(Debug)]
pub struct KeyAmalgamation<'a, P: key::KeyParts>(KeyAmalgamation0<'a, P>);

impl<'a, P> From<(&'a Cert, &'a KeyBinding<P, key::PrimaryRole>)>
    for KeyAmalgamation<'a, P>
    where P: key::KeyParts
{
    fn from(x: (&'a Cert, &'a KeyBinding<P, key::PrimaryRole>)) -> Self {
        KeyAmalgamation(KeyAmalgamation0::Primary(PrimaryKeyAmalgamation {
            cert: x.0,
            binding: x.1,
        }))
    }
}

impl<'a, P> From<(&'a Cert, &'a KeyBinding<P, key::SubordinateRole>)>
    for KeyAmalgamation<'a, P>
    where P: key::KeyParts
{
    fn from(x: (&'a Cert, &'a KeyBinding<P, key::SubordinateRole>)) -> Self {
        KeyAmalgamation(KeyAmalgamation0::Subordinate(SubordinateKeyAmalgamation {
            cert: x.0,
            binding: x.1,
        }))
    }
}

// We can't make the key parts generic, because then the impl would
// conflict with 'impl<T> std::convert::From<T> for T'.
impl<'a> From<KeyAmalgamation<'a, key::PublicParts>>
    for KeyAmalgamation<'a, key::UnspecifiedParts>
{
    fn from(ka: KeyAmalgamation<'a, key::PublicParts>) -> Self {
        match ka {
            KeyAmalgamation(KeyAmalgamation0::Primary(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Primary(
                    PrimaryKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.into(),
                    })
                )
            }
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Subordinate(
                    SubordinateKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.into(),
                    })
                )
            }
        }
    }
}

impl<'a> From<KeyAmalgamation<'a, key::SecretParts>>
    for KeyAmalgamation<'a, key::PublicParts>
{
    fn from(ka: KeyAmalgamation<'a, key::SecretParts>) -> Self {
        match ka {
            KeyAmalgamation(KeyAmalgamation0::Primary(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Primary(
                    PrimaryKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.into(),
                    })
                )
            }
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Subordinate(
                    SubordinateKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.into(),
                    })
                )
            }
        }
    }
}

impl<'a> TryFrom<KeyAmalgamation<'a, key::PublicParts>>
    for KeyAmalgamation<'a, key::SecretParts>
{
    type Error = failure::Error;

    fn try_from(ka: KeyAmalgamation<'a, key::PublicParts>) -> Result<Self> {
        Ok(match ka {
            KeyAmalgamation(KeyAmalgamation0::Primary(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Primary(
                    PrimaryKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.try_into()?,
                    })
                )
            }
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Subordinate(
                    SubordinateKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.try_into()?,
                    })
                )
            }
        })
    }
}

impl<'a, P: 'a + key::KeyParts> KeyAmalgamation<'a, P> {
    /// Returns the key.
    pub fn key(&self) -> &'a Key<P, key::UnspecifiedRole>
        where &'a Key<P, key::UnspecifiedRole>: From<&'a key::PublicKey>
    {
        match self {
            KeyAmalgamation(KeyAmalgamation0::Primary(ref h)) =>
                h.cert.primary.key().into(),
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ref h)) =>
                h.binding.key().into(),
        }
    }

    /// Returns the key's binding signature at time `t`, if any.
    pub fn binding_signature<T>(&self, t: T) -> Option<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        match self {
            KeyAmalgamation(KeyAmalgamation0::Primary(ref h)) =>
                h.cert.primary_key_signature(t),
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ref h)) =>
                h.binding.binding_signature(t),
        }
    }

    /// Returns the key's revocation status at time `t`.
    pub fn revoked<T>(&self, t: T) -> RevocationStatus<'a>
        where T: Into<Option<time::SystemTime>>
    {
        match self {
            KeyAmalgamation(KeyAmalgamation0::Primary(ref h)) =>
                h.cert.revoked(t),
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ref h)) =>
                h.binding.revoked(t),
        }
    }

    /// Returns the key's key flags at time `time`.
    pub fn key_flags<T>(&self, time: T) -> Option<KeyFlags>
        where T: Into<Option<time::SystemTime>>
    {
        self.binding_signature(time).map(|sig| sig.key_flags())
    }

    /// Returns whether the key has at least one of the specified key
    /// flags at time `time`.
    pub fn has_any_key_flag<T, F>(&self, time: T, flags: F) -> bool
        where T: Into<Option<time::SystemTime>>,
              F: Borrow<KeyFlags>
    {
        if let Some(our_flags) = self.key_flags(time) {
            !(&our_flags & flags.borrow()).is_empty()
        } else {
            // We have no key flags.
            false
        }
    }

    /// Returns whether key is certification capable at time `time`.
    pub fn for_certification<T>(&self, time: T) -> bool
        where T: Into<Option<time::SystemTime>>
    {
        self.has_any_key_flag(time, KeyFlags::empty().set_certification(true))
    }

    /// Returns whether key is signing capable at time `time`.
    pub fn for_signing<T>(&self, time: T) -> bool
        where T: Into<Option<time::SystemTime>>
    {
        self.has_any_key_flag(time, KeyFlags::empty().set_signing(true))
    }

    /// Returns whether key is authentication capable at time `time`.
    pub fn for_authentication<T>(&self, time: T) -> bool
        where T: Into<Option<time::SystemTime>>
    {
        self.has_any_key_flag(time, KeyFlags::empty().set_authentication(true))
    }

    /// Returns whether key is intended for storage encryption at time
    /// `time`.
    pub fn for_storage_encryption<T>(&self, time: T) -> bool
        where T: Into<Option<std::time::SystemTime>>
    {
        self.has_any_key_flag(time, KeyFlags::empty().set_storage_encryption(true))
    }

    /// Returns whether key is intended for transport encryption at
    /// time `time`.
    pub fn for_transport_encryption<T>(&self, time: T) -> bool
        where T: Into<Option<std::time::SystemTime>>
    {
        self.has_any_key_flag(time, KeyFlags::empty().set_transport_encryption(true))
    }

    /// Returns whether the key is alive at time `time`.
    pub fn alive<T>(&self, time: T) -> bool
        where T: Into<Option<std::time::SystemTime>>,
              &'a Key<P, key::UnspecifiedRole>: From<&'a key::PublicKey>
    {
        if let Some(sig) = self.binding_signature(None) {
            sig.key_alive(self.key(), time).is_ok()
        } else {
            false
        }
    }

    /// Returns whether the key contains secret key material.
    pub fn has_secret(&self) -> bool
        where &'a Key<P, key::UnspecifiedRole>: From<&'a key::PublicKey>
    {
        self.key().secret().is_some()
    }

    /// Returns whether the key contains unencrypted secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool
        where &'a Key<P, key::UnspecifiedRole>: From<&'a key::PublicKey>
    {
        if let Some(secret) = self.key().secret() {
            if let SecretKeyMaterial::Unencrypted { .. } = secret {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}
