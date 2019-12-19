use std::time;
use std::convert::TryInto;
use std::convert::TryFrom;

use crate::{
    Cert,
    cert::KeyBinding,
    packet::key,
    packet::Key,
    packet::Signature,
    Result,
    RevocationStatus,
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
}
