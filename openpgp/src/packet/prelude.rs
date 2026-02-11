//! Brings the most relevant types and traits into scope for working
//! with packets.
//!
//! Less often used types and traits that are more likely to lead to a
//! naming conflict are not brought into scope.  For instance, the
//! markers [`PublicParts`], etc. are not imported to avoid potential
//! naming conflicts.  Instead, they should be accessed as
//! [`key::PublicParts`].  And, [`user_attribute::Subpacket`] is not
//! imported, because it is rarely used.  If required, it should be
//! imported explicitly.
//!
//! [`PublicParts`]: key::PublicParts
//! [`user_attribute::Subpacket`]: user_attribute::Subpacket
//!
//! # Examples
//!
//! ```
//! # #![allow(unused_imports)]
//! # use sequoia_openpgp as openpgp;
//! use openpgp::packet::prelude::*;
//! ```

pub use crate::packet::{
    Any,
    Body,
    CompressedData,
    Container,
    Header,
    Key,
    Literal,
    MDC,
    Marker,
    OnePassSig,
    PKESK,
    Packet,
    Padding,
    SEIP,
    SKESK,
    Signature,
    Tag,
    Trust,
    Unknown,
    UserAttribute,
    UserID,
    key,
    key::Key4,
    key::Key6,
    key::SecretKeyMaterial,
    one_pass_sig::OnePassSig3,
    one_pass_sig::OnePassSig6,
    pkesk::{
        PKESK3,
        PKESK6,
    },
    seip::{
        SEIP1,
        SEIP2,
    },
    signature,
    signature::Signature4,
    signature::Signature6,
    signature::SignatureBuilder,
    skesk::SKESK4,
    skesk::SKESK6,
    user_attribute,
};
