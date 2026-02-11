//! A context-free certificate component and its associated signatures.

use std::sync::Arc;

use crate::{
    cert::ComponentBundle,
    packet::{
        Key,
        Packet,
        Signature,
        Unknown,
        UserAttribute,
        UserID,
        key,
    },
    policy::HashAlgoSecurity,
};

/// A context-free certificate component and its associated signatures.
#[derive(Debug)]
pub struct PreBundle<C> {
    component: C,
    hash_algo_security: HashAlgoSecurity,
    signatures: Vec<Signature>,
}
assert_send_and_sync!(PreBundle<C> where C);

/// A key (primary or subkey, public or private) and any associated
/// signatures.
///
/// [See the module level documentation.](self)
pub type KeyBundle<KeyPart, KeyRole> = PreBundle<Key<KeyPart, KeyRole>>;

/// A primary key and any associated signatures.
///
/// [See the module level documentation.](self)
pub type PrimaryKeyBundle<KeyPart> =
    KeyBundle<KeyPart, key::PrimaryRole>;

/// A subkey and any associated signatures.
///
/// [See the module level documentation.](self)
pub type SubkeyBundle<KeyPart>
    = KeyBundle<KeyPart, key::SubordinateRole>;

/// A User ID and any associated signatures.
///
/// [See the module level documentation.](self)
pub type UserIDBundle = PreBundle<UserID>;

/// A User Attribute and any associated signatures.
///
/// [See the module level documentation.](self)
pub type UserAttributeBundle = PreBundle<UserAttribute>;

/// An unknown component and any associated signatures.
///
/// Note: all signatures are stored as certifications.
///
/// [See the module level documentation.](self)
pub type UnknownBundle = PreBundle<Unknown>;


impl<C> PreBundle<C> {
    /// Creates a new component.
    pub fn new(component: C,
               hash_algo_security: HashAlgoSecurity,
               signatures: Vec<Signature>)
               -> PreBundle<C>
    {
        PreBundle {
            component,
            hash_algo_security,
            signatures,
        }
    }

    pub fn with_context(self,
                        primary_key: Arc<Key<key::PublicParts, key::PrimaryRole>>)
                        -> ComponentBundle<C>
    {
        ComponentBundle::new(self.component,
                             self.hash_algo_security,
                             self.signatures,
                             primary_key)
    }

    pub fn into_packets(self) -> impl Iterator<Item=Packet> + Send + Sync
    where
        Packet: From<C>,
    {
        let p: Packet = self.component.into();
        std::iter::once(p)
            .chain(self.signatures.into_iter().map(Into::into))
    }
}

impl<P> SubkeyBundle<P>
where
    P: key::KeyParts,
{
    pub fn with_subkey_context(self,
                               primary_key: Arc<Key<key::PublicParts, key::PrimaryRole>>)
                               -> ComponentBundle<Key<P, key::SubordinateRole>>
    {
        ComponentBundle::new_subkey(self.component,
                                    self.hash_algo_security,
                                    self.signatures,
                                    primary_key)
    }

}
