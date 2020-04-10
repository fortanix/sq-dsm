//! Concrete implementation of the crypto primitives used by the rest of the
//! crypto API.

#[cfg(feature = "crypto-nettle")]
mod nettle;
#[cfg(feature = "crypto-nettle")]
pub use self::nettle::*;

#[cfg(feature = "crypto-cng")]
mod cng;
#[cfg(feature = "crypto-cng")]
pub use self::cng::*;
