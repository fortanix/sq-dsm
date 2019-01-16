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
//! sq_error_t err;
//! sq_context_t ctx;
//! sq_tpk_t tpk;
//!
//! ctx = sq_context_new ("org.sequoia-pgp.example", &err);
//! if (ctx == NULL)
//!   error (1, 0, "Initializing sequoia failed: %s", sq_error_string (err));
//!
//! tpk = sq_tpk_from_file (ctx, "../openpgp/tests/data/keys/testy.pgp");
//! if (tpk == NULL)
//!    {
//!      err = sq_context_last_error (ctx);
//!      error (1, 0, "sq_tpk_from_bytes: %s", sq_error_string (err));
//!    }
//!
//! sq_tpk_free (tpk);
//! sq_context_free (ctx);
//! ```

#![warn(missing_docs)]

extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate native_tls;

extern crate sequoia_ffi_macros;
use sequoia_ffi_macros::ffi_catch_abort;
extern crate sequoia_core;
extern crate sequoia_net;
extern crate sequoia_store;

use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::BuildHasher;

/* Canonical free().  */

/// Transfers ownership from C to Rust, then frees the object.
///
/// NOP if called with NULL.
macro_rules! ffi_free {
    ($name:ident) => {{
        if let Some(ptr) = $name {
            unsafe {
                drop(Box::from_raw(ptr))
            }
        }
    }};
}

/* Parameter handling.  */

/// Transfers ownership from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_move {
    ($name:expr) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            Box::from_raw($name)
        }
    }};
}

/// Transfers a reference from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_ref {
    ($name:ident) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            &*$name
        }
    }};
}

/// Transfers a mutable reference from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_ref_mut {
    ($name:ident) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            &mut *$name
        }
    }};
}

/// Transfers a reference to a string from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_cstr {
    ($name:expr) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            ::std::ffi::CStr::from_ptr($name)
        }
    }};
}

/* Return value handling.  */

/// Duplicates a string similar to strndup(3).
fn strndup(src: &[u8]) -> Option<*mut libc::c_char> {
    if src.contains(&0) {
        return None;
    }

    let l = src.len() + 1;
    let s = unsafe {
        ::std::slice::from_raw_parts_mut(libc::malloc(l) as *mut u8, l)
    };
    &mut s[..l - 1].copy_from_slice(src);
    s[l - 1] = 0;

    Some(s.as_mut_ptr() as *mut libc::c_char)
}

/// Transfers a string from Rust to C, allocating it using malloc.
///
/// # Panics
///
/// Panics if the given string contains a 0.
macro_rules! ffi_return_string {
    ($name:expr) => {{
        let string = $name;
        let bytes: &[u8] = string.as_ref();
        ::strndup(bytes).expect(
            &format!("Returned string {} contains a 0 byte.", stringify!($name))
        )
    }};
}

/// Transfers a string from Rust to C, allocating it using malloc.
///
/// # Panics
///
/// Does *NOT* panic if the given string contains a 0, but returns
/// `NULL`.
macro_rules! ffi_return_maybe_string {
    ($name:expr) => {{
        let string = $name;
        let bytes: &[u8] = string.as_ref();
        ::strndup(bytes).unwrap_or(::std::ptr::null_mut())
    }};
}

/* Error handling with implicit context.  */

/// Emits local macros for error handling that use the given context
/// to store complex errors.
macro_rules! ffi_make_fry_from_ctx {
    ($ctx:ident) => {
        /// Like try! for ffi glue.
        ///
        /// Evaluates the given expression.  On success, evaluate to
        /// `Status.Success`.  On failure, stashes the error in the
        /// context and evaluates to the appropriate Status code.
        #[allow(unused_macros)]
        macro_rules! ffi_try_status {
            ($expr:expr) => {
                match $expr {
                    Ok(_) => Status::Success,
                    Err(e) => {
                        let status = Status::from(&e);
                        $ctx.e = Some(e);
                        status
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Unwraps the given expression.  On failure, stashes the
        /// error in the context and returns $or.
        #[allow(unused_macros)]
        macro_rules! ffi_try_or {
            ($expr:expr, $or:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        $ctx.e = Some(e);
                        return $or;
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Unwraps the given expression.  On failure, stashes the
        /// error in the context and returns NULL.
        #[allow(unused_macros)]
        macro_rules! ffi_try {
            ($expr:expr) => {
                ffi_try_or!($expr, ::std::ptr::null_mut())
            };
        }

        /// Like try! for ffi glue, then box into raw pointer.
        ///
        /// This is used to transfer ownership from Rust to C.
        ///
        /// Unwraps the given expression.  On success, it boxes the
        /// value and turns it into a raw pointer.  On failure,
        /// stashes the error in the context and returns NULL.
        #[allow(unused_macros)]
        macro_rules! ffi_try_box {
            ($expr:expr) => {
                Box::into_raw(Box::new(ffi_try!($expr)))
            }
        }
    }
}

/// Box, then turn into raw pointer.
///
/// This is used to transfer ownership from Rust to C.
macro_rules! box_raw {
    ($expr:expr) => {
        Box::into_raw(Box::new($expr))
    }
}

/// Box an Option<T>, then turn into raw pointer.
///
/// This is used to transfer ownership from Rust to C.
macro_rules! maybe_box_raw {
    ($expr:expr) => {
        $expr.map(|x| box_raw!(x)).unwrap_or(ptr::null_mut())
    }
}

/// Builds hashers for computing hashes.
///
/// This is used to derive Hasher instances for computing hashes of
/// objects so that they can be used in hash tables by foreign code.
pub(crate) fn build_hasher() -> DefaultHasher {
    lazy_static! {
        static ref RANDOM_STATE: RandomState = RandomState::new();
    }
    RANDOM_STATE.build_hasher()
}

pub mod error;
pub mod core;
pub mod openpgp;
pub mod net;
pub mod store;
