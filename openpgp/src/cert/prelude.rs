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
    ValidCert,
    amalgamation::ComponentAmalgamation,
    amalgamation::ValidAmalgamation as _,
    amalgamation::ValidComponentAmalgamation,
    amalgamation::ValidateAmalgamation as _,
    bundle::ComponentBundle,
    bundle::ComponentIter,
    bundle::KeyBundle,
    bundle::KeyIter,
    bundle::PrimaryKeyBundle,
    bundle::SubkeyBundle,
    bundle::UnknownBundle,
    bundle::UserAttributeBundle,
    bundle::UserIDBundle,
    bundle::ValidComponentIter,
    bundle::ValidKeyIter,
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
