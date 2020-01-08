use std::time;
use std::time::SystemTime;
use std::convert::TryInto;
use std::convert::TryFrom;
use std::borrow::Borrow;

use crate::{
    Cert,
    cert::KeyBinding,
    Error,
    packet::key,
    packet::key::SecretKeyMaterial,
    packet::Key,
    packet::Signature,
    Result,
    RevocationStatus,
    types::KeyFlags,
};

/// A variant of `KeyAmalgamation` for primary keys.
#[derive(Debug, Clone)]
struct PrimaryKeyAmalgamation<'a, P: key::KeyParts> {
    cert: &'a Cert,
    binding: &'a KeyBinding<P, key::PrimaryRole>,
    time: SystemTime,
}

/// A variant of `KeyAmalgamation` for subkeys.
#[derive(Debug, Clone)]
struct SubordinateKeyAmalgamation<'a, P: key::KeyParts> {
    cert: &'a Cert,
    binding: &'a KeyBinding<P, key::SubordinateRole>,
    time: SystemTime,
}

/// The underlying `KeyAmalgamation` type.
///
/// We don't make this type public, because an enum's variant types
/// must also all be public, and we don't want that here.  Wrapping
/// this in a struct means that we can hide that.
#[derive(Debug, Clone)]
enum KeyAmalgamation0<'a, P: key::KeyParts> {
    Primary(PrimaryKeyAmalgamation<'a, P>),
    Subordinate(SubordinateKeyAmalgamation<'a, P>),
}

/// A `Key` and its associated data.
#[derive(Debug, Clone)]
pub struct KeyAmalgamation<'a, P: key::KeyParts>(KeyAmalgamation0<'a, P>);

impl<'a, P> From<(&'a Cert, &'a KeyBinding<P, key::PrimaryRole>, SystemTime)>
    for KeyAmalgamation<'a, P>
    where P: key::KeyParts
{
    fn from(x: (&'a Cert, &'a KeyBinding<P, key::PrimaryRole>, SystemTime)) -> Self {
        KeyAmalgamation(KeyAmalgamation0::Primary(PrimaryKeyAmalgamation {
            cert: x.0,
            binding: x.1,
            time: x.2,
        }))
    }
}

impl<'a, P> From<(&'a Cert, &'a KeyBinding<P, key::SubordinateRole>, SystemTime)>
    for KeyAmalgamation<'a, P>
    where P: key::KeyParts
{
    fn from(x: (&'a Cert, &'a KeyBinding<P, key::SubordinateRole>, SystemTime)) -> Self {
        KeyAmalgamation(KeyAmalgamation0::Subordinate(SubordinateKeyAmalgamation {
            cert: x.0,
            binding: x.1,
            time: x.2,
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
                        time: ka.time,
                    })
                )
            }
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Subordinate(
                    SubordinateKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.into(),
                        time: ka.time,
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
                        time: ka.time,
                    })
                )
            }
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Subordinate(
                    SubordinateKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.into(),
                        time: ka.time,
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
                        time: ka.time,
                    })
                )
            }
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ka)) => {
                KeyAmalgamation(KeyAmalgamation0::Subordinate(
                    SubordinateKeyAmalgamation {
                        cert: ka.cert,
                        binding: ka.binding.try_into()?,
                        time: ka.time,
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

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a key is
    /// created at `t_c` and expires at `t_e`, then
    /// `KeyAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    pub fn time(&self) -> SystemTime {
        match self {
            KeyAmalgamation(KeyAmalgamation0::Primary(ref h)) =>
                h.time,
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ref h)) =>
                h.time,
        }
    }

    /// Changes the amalgamation's reference time.
    ///
    /// If `time` is `None`, the current time is used.
    pub fn set_time<T>(mut self, time: T) -> Self
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        match self {
            KeyAmalgamation(KeyAmalgamation0::Primary(ref mut h)) =>
                h.time = time,
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ref mut h)) =>
                h.time = time,
        }

        self
    }

    /// Returns the key's binding signature as of the reference time,
    /// if any.
    pub fn binding_signature(&self) -> Option<&'a Signature>
    {
        match self {
            KeyAmalgamation(KeyAmalgamation0::Primary(ref h)) =>
                h.cert.primary_key_signature(self.time()),
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ref h)) =>
                h.binding.binding_signature(self.time()),
        }
    }

    /// Returns the key's revocation status as of the amalgamtion's
    /// reference time.
    pub fn revoked(&self) -> RevocationStatus<'a>
    {
        match self {
            KeyAmalgamation(KeyAmalgamation0::Primary(ref h)) =>
                h.cert.revoked(self.time()),
            KeyAmalgamation(KeyAmalgamation0::Subordinate(ref h)) =>
                h.binding.revoked(self.time()),
        }
    }

    /// Returns the key's key flags as of the amalgamtion's
    /// reference time.
    pub fn key_flags(&self) -> Option<KeyFlags>
    {
        self.binding_signature().map(|sig| sig.key_flags())
    }

    /// Returns whether the key has at least one of the specified key
    /// flags as of the amalgamtion's reference time.
    pub fn has_any_key_flag<F>(&self, flags: F) -> bool
        where F: Borrow<KeyFlags>
    {
        if let Some(our_flags) = self.key_flags() {
            !(&our_flags & flags.borrow()).is_empty()
        } else {
            // We have no key flags.
            false
        }
    }

    /// Returns whether key is certification capable as of the
    /// amalgamtion's reference time.
    pub fn for_certification(&self) -> bool {
        self.has_any_key_flag(KeyFlags::empty().set_certification(true))
    }

    /// Returns whether key is signing capable as of the amalgamtion's
    /// reference time.
    pub fn for_signing(&self) -> bool {
        self.has_any_key_flag(KeyFlags::empty().set_signing(true))
    }

    /// Returns whether key is authentication capable as of the
    /// amalgamtion's reference time.
    pub fn for_authentication(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_authentication(true))
    }

    /// Returns whether key is intended for storage encryption as of
    /// the amalgamtion's reference time.
    pub fn for_storage_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_storage_encryption(true))
    }

    /// Returns whether key is intended for transport encryption as of the
    /// amalgamtion's reference time.
    pub fn for_transport_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_transport_encryption(true))
    }

    /// Returns whether the key is alive as of the amalgamtion's
    /// reference time.
    pub fn alive(&self) -> Result<()>
        where &'a Key<P, key::UnspecifiedRole>: From<&'a key::PublicKey>
    {
        if let Some(sig) = self.binding_signature() {
            sig.key_alive(self.key(), self.time())
        } else {
            Err(Error::NoBindingSignature(self.time()).into())
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
