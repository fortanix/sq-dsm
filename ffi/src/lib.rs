//! Provides a Foreign Function Interface.
//!
//! We provide a set of functions that use C types and the C calling
//! convention.  This interfaces allows you to use Sequoia safely from
//! any other language.
//!
//! # Guarantees
//!
//! Provided that the caller obeys her side of the contract, this
//! library...
//!
//!  - will not make an invalid memory access,
//!  - will not `abort(2)`,
//!  - XXX
//!
//! # Types
//!
//! Sequoia objects are opaque objects.  They are created in
//! constructors, and must be freed when no longer needed.
//!
//! Pointers handed to Sequoia must not be `NULL`, unless explicitly
//! stated.  See [references].
//!
//! [references]: #references
//!
//! Enumeration-like values must be in the valid range.
//!
//! Strings must be UTF-8 encoded and zero-terminated.  Malformed
//! characters will be substituted, and the result is likely not what
//! you expect.
//!
//! # Ownership
//!
//! When ownership of a `T` is transferred across the FFI boundary, a
//! `*mut T` is used.
//!
//! To transfer ownership from Rust to C, we box the Rust object, and
//! use [`Box::into_raw(..)`].  From this moment on, ownership must be
//! managed by the C application.
//!
//! [`Box::into_raw(..)`]: std::boxed::Box::into_raw()
//!
//! To transfer ownership from C to Rust, we re-create the box using
//! [`Box::from_raw(..)`].
//!
//! [`Box::from_raw(..)`]: std::boxed::Box::from_raw()
//!
//! In this crate we use a series of macros to transfer ownership from
//! Rust to C.  `fry_box` matches on `Result<T>`, handling errors by
//! terminating the current function, returning the error using the
//! context.  `maybe_box_raw` matches on `Option<T>`, turning `None`
//! into `NULL`.  Finally, `box_raw` is merely a shortcut for
//! `Box::into_raw(Box::new(..))`.
//!
//! # References
//!
//! When references are transferred across the FFI boundary, we use
//! `*const T`, or `*mut T`.  If the parameter is optional, a
//! `Option<&T>` or `Option<&mut T>` is used.
//!
//! Application code must adhere to Rust's reference rules:
//!
//!  - Either one mutable reference or any number of immutable ones.
//!  - All references are non-`NULL`.
//!  - All references are valid.
//!
//! In this crate we enforce the second rule by asserting that all
//! pointers handed in are non-`NULL`.  If a parameter of an FFI
//! function uses `Option<&T>` or `Option<&mut T>`, it may be called
//! with `NULL`.  A notable example are the destructors (`sq_*_free`).
//!
//! # Lifetimes
//!
//! If you derive a complex object from another complex object, you
//! must assume that the original object is borrowed by the resulting
//! object unless explicitly stated otherwise.  For example, objects
//! created using a context must not outlive that context.  Similarly,
//! iterators must not outlive the object they are created from.
//!
//! Failing to adhere to lifetime restrictions results in undefined
//! behavior.
//!
//! # Error handling
//!
//! Sequoia will panic if you provide bad arguments, e.g. hand a
//! `NULL` pointer to a function that does not explicitly allow this.
//!
//! Failing functions return `NULL`.  Functions that require a
//! `Context` return complex errors.  Complex errors are stored in the
//! `Context`, and can be retrieved using `sq_last_strerror`.
//!
//! # Examples
//!
//! ```c
//! #include <sequoia.h>
//! #include <error.h>
//!
//! pgp_error_t err;
//! pgp_cert_t cert;
//!
//! cert = pgp_cert_from_file (&err, "../openpgp/tests/data/keys/testy.pgp");
//! if (cert == NULL)
//!   error (1, 0, "pgp_cert_from_bytes: %s", pgp_error_to_string (err));
//!
//! pgp_cert_free (cert);
//! ```

#![doc(html_favicon_url = "https://docs.sequoia-pgp.org/favicon.png")]
#![doc(html_logo_url = "https://docs.sequoia-pgp.org/logo.svg")]
#![warn(missing_docs)]

use sequoia_ffi_macros::{
    ffi_wrapper_type,
};

#[macro_use]
pub mod openpgp {
    //! Bindings for the low-level openpgp crate.
    include!("../../openpgp-ffi/src/common.rs");
}

pub(crate) use crate::openpgp::{
    io,
    build_hasher,
    strndup,
    MoveFromRaw,
    RefRaw,
    RefMutRaw,
    MoveIntoRaw,
    MoveResultIntoRaw,
    Maybe,
    maybe_time,
    to_time_t,
};

/* Error handling with implicit context.  */

/// Emits local macros for error handling that use the given context
/// to store complex errors.
macro_rules! ffi_make_fry_from_ctx {
    ($ctx:ident) => {
        ffi_make_fry_from_errp!(Some($ctx.errp()))
    }
}

pub mod core;
pub mod error;
pub mod net;
pub mod store;

