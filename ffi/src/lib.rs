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
//! Pointers handed to Sequoia must not be `NULL`, destructors are
//! exempt from this rule.  Freeing `NULL` is a nop.
//!
//! Enumeration-like values must be in the valid range.
//!
//! Strings must be UTF-8 encoded and zero-terminated.  Malformed
//! characters will be substituted, and the result is likely not what
//! you expect.
//!
//! # Lifetimes
//!
//! Objects created using a context must not outlive that context.
//! Similarly, iterators must not outlive the object they are created
//! from.
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
//! ```text
//! #include <sequoia.h>
//!
//! struct sq_context *ctx;
//! struct sq_tpk *tpk;
//!
//! ctx = sq_context_new("org.sequoia-pgp.example");
//! if (ctx == NULL)
//!   error (1, 0, "Initializing sequoia failed.");
//!
//! tpk = sq_tpk_from_bytes (ctx, buf, len);
//! if (tpk == NULL)
//!   error (1, 0, "sq_tpk_from_bytes: %s", sq_last_strerror (ctx));
//!
//! sq_tpk_dump (tpk);
//! sq_tpk_free (tpk);
//! sq_context_free (ctx);
//! ```

extern crate failure;
extern crate libc;
extern crate native_tls;
extern crate sequoia_core;
extern crate sequoia_net;
extern crate sequoia_store;

/// Like try! for ffi glue.
///
/// Unwraps the given expression.  On failure, stashes the error in
/// the context and returns $or.
macro_rules! fry_or {
    ($ctx:expr, $expr:expr, $or:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                $ctx.e = Some(Box::new(e));
                return $or;
            },
        }
    };
}

/// Like try! for ffi glue.
///
/// Unwraps the given expression.  On failure, stashes the error in
/// the context and returns NULL.
macro_rules! fry {
    ($ctx:expr, $expr:expr) => {
        fry_or!($ctx, $expr, ptr::null_mut())
    };
}

/// Like try! for ffi glue, then box into raw pointer.
///
/// Unwraps the given expression.  On success, it boxes the value
/// and turns it into a raw pointer.  On failure, stashes the
/// error in the context and returns NULL.
macro_rules! fry_box {
    ($ctx:expr, $expr:expr) => {
        Box::into_raw(Box::new(fry!($ctx, $expr)))
    }
}

/// Box, then turn into raw pointer.
macro_rules! box_raw {
    ($expr:expr) => {
        Box::into_raw(Box::new($expr))
    }
}

pub mod core;
pub mod openpgp;
pub mod net;
pub mod store;
