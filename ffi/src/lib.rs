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
//! [`Box::into_raw(..)`]: https://doc.rust-lang.org/std/boxed/struct.Box.html#method.into_raw
//!
//! To transfer ownership from C to Rust, we re-create the box using
//! [`Box::from_raw(..)`].
//!
//! [`Box::from_raw(..)`]: https://doc.rust-lang.org/std/boxed/struct.Box.html#method.from_raw
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
//! # Example
//!
//! ```c
//! #include <sequoia.h>
//! #include <error.h>
//!
//! pgp_error_t err;
//! pgp_tpk_t tpk;
//!
//! tpk = pgp_tpk_from_file (&err, "../openpgp/tests/data/keys/testy.pgp");
//! if (tpk == NULL)
//!   error (1, 0, "pgp_tpk_from_bytes: %s", pgp_error_string (err));
//!
//! pgp_tpk_free (tpk);
//! ```

#![warn(missing_docs)]

extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate native_tls;

extern crate sequoia_ffi_macros;
use sequoia_ffi_macros::{
    ffi_catch_abort,
    ffi_wrapper_type,
};
extern crate sequoia_core;
extern crate sequoia_net;
extern crate sequoia_store;

#[macro_use]
pub mod openpgp {
    //! Bindings for the low-level openpgp crate.
    include!("../../openpgp-ffi/src/common.rs");
}

pub(crate) use openpgp::{
    build_hasher,
    strndup,
    MoveFromRaw,
    RefRaw,
    RefMutRaw,
    MoveIntoRaw,
    MoveResultIntoRaw,
    Maybe,
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

