//! Brings most relevant types and traits into scope for working with
//! certificates.
//!
//! Less often used types and types that are more likely to lead to a
//! naming conflict are not brought into scope.
//!
//! Traits are brought into scope anonymously.
//!
//! ```
//! # #![allow(unused_imports)]
//! # extern crate sequoia_openpgp as openpgp;
//! use openpgp::cert::prelude::*;
//! ```

#![allow(unused_imports)]
pub use crate::cert::{
    Cert,
    CertAmalgamation,
    CertBuilder,
    CertParser,
    CertRevocationBuilder,
    CertValidator,
    CertValidity,
    CipherSuite,
    KeyringValidator,
    KeyringValidity,
    Preferences as _,
    SubkeyRevocationBuilder,
    UserAttributeRevocationBuilder,
    UserIDRevocationBuilder,
    amalgamation::ComponentAmalgamation,
    amalgamation::ValidAmalgamation as _,
    amalgamation::ValidComponentAmalgamation,
    amalgamation::ValidateAmalgamation as _,
    components::ComponentBundle,
    components::ComponentBundleIter,
    components::ComponentIter,
    components::KeyBundle,
    components::KeyIter,
    components::PrimaryKeyBundle,
    components::SubkeyBundle,
    components::UnfilteredKeyBundleIter,
    components::UnknownBundle,
    components::UnknownBundleIter,
    components::UserAttributeBundle,
    components::UserAttributeBundleIter,
    components::UserIDBundle,
    components::UserIDBundleIter,
    components::ValidComponentIter,
    components::ValidKeyIter,
    key_amalgamation::ErasedKeyAmalgamation,
    key_amalgamation::KeyAmalgamation,
    key_amalgamation::Primary as _,
    key_amalgamation::PrimaryKeyAmalgamation,
    key_amalgamation::SubordinateKeyAmalgamation,
    key_amalgamation::ValidErasedKeyAmalgamation,
    key_amalgamation::ValidKeyAmalgamation,
    key_amalgamation::ValidPrimaryKeyAmalgamation,
    key_amalgamation::ValidSubordinateKeyAmalgamation,
};
