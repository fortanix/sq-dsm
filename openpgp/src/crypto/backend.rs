//! Concrete implementation of the crypto primitives used by the rest of the
//! crypto API.

pub(crate) mod interface;
pub(crate) mod sha1cd;

// Nettle is the default backend, but on Windows targets we instead
// enable CNG for running the tests in non-leaf crates that depend on
// sequoia-openpgp.  This creates a conflict, and makes `cargo test`
// fail.  To mitigate this, only enable the Nettle backend if we are
// not compiling the tests and have a different backend selected.
//
// Note: If you add a new crypto backend, add it to the expression,
// and also synchronize the expression to `build.rs`.
#[cfg(all(feature = "crypto-nettle",
          not(all(feature = "__implicit-crypto-backend-for-tests",
                  any(feature = "crypto-openssl",
                      feature = "crypto-botan",
                      feature = "crypto-botan2",
                      feature = "crypto-fuzzing",
                      feature = "crypto-rust")))))]
mod nettle;
#[cfg(all(feature = "crypto-nettle",
          not(all(feature = "__implicit-crypto-backend-for-tests",
                  any(feature = "crypto-openssl",
                      feature = "crypto-botan",
                      feature = "crypto-botan2",
                      feature = "crypto-fuzzing",
                      feature = "crypto-rust")))))]
pub use self::nettle::*;
#[cfg(all(feature = "crypto-nettle",
          not(all(feature = "__implicit-crypto-backend-for-tests",
                  any(feature = "crypto-openssl",
                      feature = "crypto-botan",
                      feature = "crypto-botan2",
                      feature = "crypto-rust")))))]
pub use self::nettle::Backend;

// Nettle is the default backend, but on Windows targets we instead
// enable CNG for running the tests in non-leaf crates that depend on
// sequoia-openpgp.  This creates a conflict, and makes `cargo test`
// fail.  To mitigate this, only enable the CNG backend if we are
// not compiling the tests and have a different backend selected.
//
// Note: If you add a new crypto backend, add it to the expression,
// and also synchronize the expression to `build.rs`.
#[cfg(all(feature = "crypto-cng",
          not(all(feature = "__implicit-crypto-backend-for-tests",
                  any(feature = "crypto-nettle",
                      feature = "crypto-openssl",
                      feature = "crypto-botan",
                      feature = "crypto-botan2",
                      feature = "crypto-fuzzing",
                      feature = "crypto-rust")))))]
mod cng;
#[cfg(all(feature = "crypto-cng",
          not(all(feature = "__implicit-crypto-backend-for-tests",
                  any(feature = "crypto-nettle",
                      feature = "crypto-openssl",
                      feature = "crypto-botan",
                      feature = "crypto-botan2",
                      feature = "crypto-fuzzing",
                      feature = "crypto-rust")))))]
pub use self::cng::*;
#[cfg(all(feature = "crypto-cng",
          not(all(feature = "__implicit-crypto-backend-for-tests",
                  any(feature = "crypto-nettle",
                      feature = "crypto-openssl",
                      feature = "crypto-botan",
                      feature = "crypto-botan2",
                      feature = "crypto-fuzzing",
                      feature = "crypto-rust")))))]
pub use self::cng::Backend;

#[cfg(feature = "crypto-rust")]
mod rust;
#[cfg(feature = "crypto-rust")]
pub use self::rust::*;
#[cfg(feature = "crypto-rust")]
pub use self::rust::Backend;

#[cfg(feature = "crypto-openssl")]
mod openssl;
#[cfg(feature = "crypto-openssl")]
pub use self::openssl::*;
#[cfg(feature = "crypto-openssl")]
pub use self::openssl::Backend;

#[cfg(any(feature = "crypto-botan", feature = "crypto-botan2"))]
mod botan;
#[cfg(any(feature = "crypto-botan", feature = "crypto-botan2"))]
pub use self::botan::*;
#[cfg(feature = "crypto-botan")]
pub use self::botan::Backend;

#[cfg(feature = "crypto-fuzzing")]
mod fuzzing;
#[cfg(feature = "crypto-fuzzing")]
pub use self::fuzzing::*;
#[cfg(feature = "crypto-fuzzing")]
pub use self::fuzzing::Backend;
