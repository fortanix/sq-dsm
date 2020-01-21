use std::time;
use std::time::SystemTime;
use std::convert::TryInto;
use std::convert::TryFrom;
use std::borrow::Borrow;

use crate::{
    Cert,
    cert::components::KeyBinding,
    Error,
    packet::key,
    packet::key::SecretKeyMaterial,
    packet::Key,
    packet::Signature,
    Result,
    RevocationStatus,
    types::KeyFlags,
};

/// The underlying `KeyAmalgamation` type.
///
/// We don't make this type public, because an enum's variant types
/// must also all be public, and we don't want that here.  Wrapping
/// this in a struct means that we can hide that.
#[derive(Debug, Clone)]
enum KeyAmalgamationBinding<'a, P: key::KeyParts> {
    Primary(),
    Subordinate(&'a KeyBinding<P, key::SubordinateRole>),
}

/// A `Key` and its associated data.
#[derive(Debug, Clone)]
pub struct KeyAmalgamation<'a, P: key::KeyParts> {
    cert: &'a Cert,
    binding: KeyAmalgamationBinding<'a, P>,

    // The reference time.
    time: SystemTime,
    // The binding siganture at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}

impl<'a, P> TryFrom<(&'a Cert, SystemTime)>
    for KeyAmalgamation<'a, P>
    where P: key::KeyParts
{
    type Error = failure::Error;

    fn try_from(x: (&'a Cert, SystemTime)) -> Result<Self> {
        Ok(KeyAmalgamation {
            cert: x.0,
            binding: KeyAmalgamationBinding::Primary(),
            time: x.1,
            binding_signature:
                x.0.primary_key_signature(x.1)
                    .ok_or_else(|| Error::NoBindingSignature(x.1))?,
        })
    }
}

impl<'a, P> TryFrom<(&'a Cert, &'a KeyBinding<P, key::SubordinateRole>, SystemTime)>
    for KeyAmalgamation<'a, P>
    where P: key::KeyParts
{
    type Error = failure::Error;

    fn try_from(x: (&'a Cert, &'a KeyBinding<P, key::SubordinateRole>, SystemTime))
        -> Result<Self>
    {
        Ok(KeyAmalgamation {
            cert: x.0,
            binding: KeyAmalgamationBinding::Subordinate(x.1),
            time: x.2,
            binding_signature:
                x.1.binding_signature(x.2)
                    .ok_or_else(|| Error::NoBindingSignature(x.2))?,
        })
    }
}

// We can't make the key parts generic, because then the impl would
// conflict with 'impl<T> std::convert::From<T> for T'.
impl<'a> From<KeyAmalgamation<'a, key::PublicParts>>
    for KeyAmalgamation<'a, key::UnspecifiedParts>
{
    fn from(ka: KeyAmalgamation<'a, key::PublicParts>) -> Self {
        match ka {
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Primary(),
                time,
                binding_signature,
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Primary(),
                    time,
                    binding_signature,
                },
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Subordinate(binding),
                time,
                binding_signature,
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Subordinate(binding.into()),
                    time,
                    binding_signature,
                },
        }
    }
}

impl<'a> From<KeyAmalgamation<'a, key::SecretParts>>
    for KeyAmalgamation<'a, key::PublicParts>
{
    fn from(ka: KeyAmalgamation<'a, key::SecretParts>) -> Self {
        match ka {
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Primary(),
                time,
                binding_signature,
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Primary(),
                    time,
                    binding_signature,
                },
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Subordinate(binding),
                time,
                binding_signature,
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Subordinate(binding.into()),
                    time,
                    binding_signature,
                },
        }
    }
}

impl<'a> TryFrom<KeyAmalgamation<'a, key::PublicParts>>
    for KeyAmalgamation<'a, key::SecretParts>
{
    type Error = failure::Error;

    fn try_from(ka: KeyAmalgamation<'a, key::PublicParts>) -> Result<Self> {
        Ok(match ka {
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Primary(),
                time,
                binding_signature,
            } => {
                // Error out if the primary key does not have secret
                // key material.
                let _ : &KeyBinding<key::SecretParts, key::PrimaryRole>
                    = (&cert.primary).try_into()?;
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Primary(),
                    time,
                    binding_signature,
                }
            }
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Subordinate(binding),
                time,
                binding_signature,
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Subordinate(binding.try_into()?),
                    time,
                    binding_signature,
                },
        })
    }
}

impl<'a, P: 'a + key::KeyParts> KeyAmalgamation<'a, P> {
    /// Returns the key.
    pub fn key(&self) -> &'a Key<P, key::UnspecifiedRole>
        where &'a Key<P, key::UnspecifiedRole>: From<&'a key::PublicKey>
    {
        match self {
            KeyAmalgamation { binding: KeyAmalgamationBinding::Primary(), .. } =>
                self.cert.primary.key().into(),
            KeyAmalgamation { binding: KeyAmalgamationBinding::Subordinate(ref binding), .. } =>
                binding.key().into(),
        }
    }

    /// Returns the key, but without conversion to P.
    fn generic_key(&self)
                   -> &'a Key<key::UnspecifiedParts, key::UnspecifiedRole> {
        match self {
            KeyAmalgamation { binding: KeyAmalgamationBinding::Primary(), .. } =>
                self.cert.primary.key().into(),
            KeyAmalgamation { binding: KeyAmalgamationBinding::Subordinate(ref binding), .. } =>
                binding.key().mark_parts_unspecified_ref().into(),
        }
    }

    /// Returns the certificate that the key came from.
    pub fn cert(&self) -> &'a Cert
    {
        self.cert
    }

    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a key is
    /// created at `t_c` and expires at `t_e`, then
    /// `KeyAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    pub fn time(&self) -> SystemTime {
        self.time
    }

    /// Changes the amalgamation's reference time.
    ///
    /// If `time` is `None`, the current time is used.
    pub fn set_time<T>(mut self, time: T) -> Result<Self>
        where T: Into<Option<time::SystemTime>>
    {
        self.time = time.into().unwrap_or_else(SystemTime::now);
        self.binding_signature = match self {
            KeyAmalgamation {
                binding: KeyAmalgamationBinding::Primary(),
                ..
            } =>
                self.cert.primary_key_signature(self.time)
                    .ok_or_else(|| Error::NoBindingSignature(self.time))?,
            KeyAmalgamation {
                binding: KeyAmalgamationBinding::Subordinate(binding),
                ..
            } =>
                binding.binding_signature(self.time)
                    .ok_or_else(|| Error::NoBindingSignature(self.time))?,
        };
        Ok(self)
    }

    /// Returns the key's binding signature as of the reference time,
    /// if any.
    pub fn binding_signature(&self) -> &'a Signature
    {
        self.binding_signature
    }

    /// Returns the key's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    pub fn revoked(&self) -> RevocationStatus<'a>
    {
        match self {
            KeyAmalgamation { binding: KeyAmalgamationBinding::Primary(), .. } =>
                self.cert.revoked(self.time()),
            KeyAmalgamation { binding: KeyAmalgamationBinding::Subordinate(ref binding), .. } =>
                binding.revoked(self.time()),
        }
    }

    /// Returns the certificate's revocation status as of the
    /// amalgamtion's reference time.
    pub fn cert_revoked(&self) -> RevocationStatus<'a>
    {
        self.cert().revoked(self.time())
    }

    /// Returns the key's key flags as of the amalgamtion's
    /// reference time.
    pub fn key_flags(&self) -> KeyFlags
    {
        self.binding_signature.key_flags()
    }

    /// Returns whether the key has at least one of the specified key
    /// flags as of the amalgamtion's reference time.
    pub fn has_any_key_flag<F>(&self, flags: F) -> bool
        where F: Borrow<KeyFlags>
    {
        let our_flags = self.key_flags();
        !(&our_flags & flags.borrow()).is_empty()
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

    /// Returns whether the certificateis alive as of the
    /// amalgamtion's reference time.
    pub fn cert_alive(&self) -> Result<()>
    {
        self.cert().alive(self.time())
    }

    /// Returns whether the key is alive as of the amalgamtion's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    pub fn alive(&self) -> Result<()>
    {
        self.binding_signature.key_alive(self.generic_key(), self.time())
    }

    /// Returns whether the key contains secret key material.
    pub fn has_secret(&self) -> bool
    {
        self.generic_key().secret().is_some()
    }

    /// Returns whether the key contains unencrypted secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool
    {
        if let Some(secret) = self.generic_key().secret() {
            if let SecretKeyMaterial::Unencrypted { .. } = secret {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Returns this key's binding.
    pub fn binding(&self) -> &'a KeyBinding<P, key::UnspecifiedRole>
        where &'a KeyBinding<P, key::UnspecifiedRole>:
            From<&'a KeyBinding<key::PublicParts, key::PrimaryRole>>
    {
        match self {
            KeyAmalgamation { binding: KeyAmalgamationBinding::Primary(), .. } =>
                (&self.cert.primary).into(),
            KeyAmalgamation { binding: KeyAmalgamationBinding::Subordinate(binding), .. } =>
                (*binding).into(),
        }
    }
}
