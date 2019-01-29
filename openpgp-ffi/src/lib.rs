//! OpenPGP data types and associated machinery for C.
//!
//! This crate aims to provide a complete implementation of OpenPGP as
//! defined by [RFC 4880] as well as several extensions (e.g., [RFC
//! 6637], which describes ECC cryptography for OpenPGP, and [RFC
//! 4880bis], the draft of the next OpenPGP standard).  This includes
//! support for unbuffered message processing.
//!
//! A few features that the OpenPGP community considers to be
//! deprecated (e.g., version 3 compatibility) have been left out as
//! well as support for functionality that we consider to be not only
//! completely useless, but also dangerous (e.g., support for
//! [unhashed signature subpackets]).  We have also updated some
//! OpenPGP defaults to avoid foot guns (e.g., this crate does not
//! fallback to IDEA, but instead assumes all OpenPGP implementations
//! understand AES).  If some functionality is missing, please file a
//! bug report.
//!
//! A non-goal of this crate is support for any sort of high-level,
//! bolted-on functionality.  For instance, [RFC 4880] does not define
//! trust models, such as the web of trust, direct trust, or TOFU.
//! Neither does this crate.  [RFC 4880] does provide some mechanisms
//! for creating trust models (specifically, UserID certifications),
//! and this crate does expose those mechanisms.
//!
//! We also try hard to avoid dictating how OpenPGP should be used.
//! This doesn't mean that we don't have opinions about how OpenPGP
//! should be used in a number of common scenarios (for instance,
//! message validation).  But, in this crate, we refrain from
//! expressing those opinions; we expose an opinionated, high-level
//! interface in the [sequoia-core] and related crates.  In our
//! opinion, you should generally use those crates instead of this
//! one.
//!
//! [RFC 4880]: https://tools.ietf.org/html/rfc4880
//! [RFC 6637]: https://tools.ietf.org/html/rfc6637
//! [RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05
//! [unhashed signature subpackets]: https://tools.ietf.org/html/rfc4880#section-5.2.3.2
//! [sequoia-core]: ../sequoia_core
//!
//!
//! # Dear User,
//!
//! This library is written in Rust.  Its expressive type system helps
//! prevent many classes of bugs, but it is also very demanding.
//! For example, the infamous borrow checker, feared by those who dare
//! to approach Rust, allows us to safely use shared resources.  If
//! you want to use this library, we need you to follow a set of
//! rules, and you don't have the borrow checker to double check.
//!
//! We provide a set of functions that use C types and the C calling
//! convention.  These interfaces allow you to use Sequoia safely from
//! any other language provided that you follow [The Rules].
//!
//! If you don't follow [The Rules], we will terminate the process.
//! That is not meant as a threat, of course.  But, as in C, passing a
//! bad pointer to a function is undefined behavior in Rust.
//! Therefore, passing a bad pointer to a function in this crate is
//! undefined behavior as well.  We try to mitigate this problem by
//! trying to detect undefined behavior resulting from not following
//! [The Rules] by printing assertion failures on stderr, and
//! terminating the process.
//!
//! In return for following [The Rules], you can enjoy the reliability
//! that Rust's type system brings this library.  For example, the
//! robust tracking of ownership ensures that we will not leak memory.
//!
//! The C API is documented here.  We invite you to visit the
//! documentation for the [corresponding Rust crate], the structure
//! closely resembles this crate.
//!
//! [The Rules]: #the-rules
//! [corresponding Rust crate]: ../sequoia_openpgp/index.html
//!
//!
//! # Examples
//!
//! This documentation contains examples in the style of Rust
//! examples.  For short examples, we will omit the main function.
//! For example:
//!
//! ```c
//! #include <sequoia/openpgp.h>
//! #include <error.h>
//!
//! pgp_error_t err;
//! pgp_tpk_t tpk = pgp_tpk_from_file (&err, "../openpgp/tests/data/keys/testy.pgp");
//! if (tpk == NULL)
//!   error (1, 0, "pgp_tpk_from_file: %s", pgp_error_to_string (err));
//!
//!  /* XXX: Do something interesting.  */
//!
//! pgp_tpk_free (tpk);
//! ```
//!
//! The examples are compiled and executed as part of the test suite,
//! and they will free all objects that are created.
//!
//!
//! # The Rules
//!
//! These rules must be followed.  Failure to follow these rules
//! results in problems like memory leaks, undefined behavior, or
//! process termination.  This is also a guide on how to read the
//! documentation for this library.
//!
//! ## Undefined Behavior
//!
//! Undefined behavior means that the state of the library is
//! inconsistent, and the resulting behavior is unpredictable.  It
//! often leads to security problems, like information exfiltration,
//! or code execution.
//!
//! Undefined behavior may be the result of a bug in this library, or
//! due to failure to comply to [The Rules].  Furthermore, memory
//! exhaustion may lead to undefined behavior.
//!
//! This library tries to detect cases of undefined behavior, and
//! *abort(3)* the process.  This fail-fast policy helps to protect
//! against exfiltration and code execution attacks, and should
//! clearly highlight either a bug in this library (please get in
//! contact!), or a bug in your code.
//!
//! ## Error Handling
//!
//! Errors happen and must be handled by the caller.  There are
//! functions that cannot fail, functions that may fail, and functions
//! that may fail and communicate a complex error value to the caller.
//!
//! Functions that cannot fail are a nice consequence of the
//! 'fail-fast on undefined behavior'-rule.  An example of such
//! function is [`pgp_fingerprint_to_string`].  This function cannot
//! fail, unless either the given fingerprint reference is invalid,
//! or the allocation for the string failed, which is considered
//! undefined behavior.
//!
//! [`pgp_fingerprint_to_string`]: struct.Fingerprint.html#method.pgp_fingerprint_to_string
//!
//! Failing functions signal failure either in-band (e.g. `NULL`, or
//! -1), using `pgp_status_t`, and may store complex error information
//! in a caller-provided location.  For example, constructors often
//! return `NULL` to signal errors.  An example of a constructor that
//! may fail and return `NULL`, but does not communicate complex error
//! is [`pgp_fingerprint_from_hex`]. [`pgp_packet_parser_from_bytes`],
//! on the other hand, will return `NULL` and store a complex error at
//! the location given using the `errp` parameter.
//!
//! [`pgp_fingerprint_from_hex`]: struct.Fingerprint.html#method.pgp_fingerprint_from_hex
//! [`pgp_packet_parser_from_bytes`]: parse/fn.pgp_packet_parser_from_bytes.html
//!
//! Errors may be inspected using [`pgp_error_status`], and formatted
//! as an error message using [`pgp_error_to_string`].  Errors must be freed
//! using [`pgp_error_free`].
//!
//! [`pgp_error_status`]: error/fn.pgp_error_status.html
//! [`pgp_error_to_string`]: error/fn.pgp_error_to_string.html
//! [`pgp_error_free`]: error/fn.pgp_error_free.html
//!
//! ## Types
//!
//! When we interact across the FFI boundary between C and Rust, we
//! need to talk about the types used to interchange data.  The types
//! follow different rules.
//!
//! ### Objects
//!
//! Sequoia objects are opaque objects.  They are created in
//! constructors, and must be freed when no longer needed.  Failure to
//! free an object results in a memory leak.
//!
//! A typical example of creating an object, using it, and
//! deallocating it is the following in which we [parse a fingerprint]
//! from a hexadecimal number, and then [pretty-print] it for user
//! consumption:
//!
//! [parse a fingerprint]: fingerprint/fn.pgp_fingerprint_from_hex.html
//! [pretty-print]: fingerprint/fn.pgp_fingerprint_to_string.html
//!
//! ```c
//! #include <assert.h>
//! #include <stdlib.h>
//! #include <string.h>
//! #include <sequoia/openpgp.h>
//!
//! pgp_fingerprint_t fp =
//!     pgp_fingerprint_from_hex ("D2F2C5D45BE9FDE6A4EE0AAF31855247603831FD");
//!
//! char *pretty = pgp_fingerprint_to_string (fp);
//! assert (strcmp (pretty,
//!                 "D2F2 C5D4 5BE9 FDE6 A4EE  0AAF 3185 5247 6038 31FD") == 0);
//!
//! free (pretty);
//! pgp_fingerprint_free (fp);
//! ```
//!
//! After use, the fingerprint object must be deallocated.  Although
//! not the case here, an object may reference an existing objects.
//! As such, it is good practice to deallocate the objects in the
//! reverse order to which they were created to avoid having the
//! destructor trigger a use-after-free bug.
//!
//! #### Ownership
//!
//! In Rust, every value has an owner.  A value may reside on the
//! stack, on the heap, or be embedded in a struct or enum.  If you
//! take ownership of an object, e.g., by using some constructor, it
//! is your responsibility to manage its lifetime.  The most common
//! way to transfer ownership back to Rust is to deallocate the
//! object.  Failure to deallocate an object leads to a memory leak.
//!
//! Looking at the Rust functions in this library, when ownership of
//! an object of type `T` is transferred across the FFI boundary, the
//! function signature uses the type `*mut T`.
//!
//! In this crate, we use a series of macros to transfer ownership from
//! Rust to C.  `ffi_try_box` matches on `Result<T>`, handling errors
//! by terminating the current function and returning the error.
//! `maybe_box_raw` matches on `Option<T>`, turning `None` into
//! `NULL`.  Finally, `box_raw` is merely a shortcut for
//! `Box::into_raw(Box::new(..))`.
//!
//! ### References
//!
//! All references transferred across the FFI boundary must be valid,
//! and point to live objects constructed using constructors of this
//! library.  Using references constructed in any other way results in
//! undefined behavior.
//!
//! In some places, references handed to, or returned from this
//! library may be `NULL`.  This is the exception rather than the
//! rule.  If you look at a function's Rust signature, an `Option<&T>`
//! or `Option<&mut T>` is used for arguments or results that may be
//! NULL.  On the other hand, function arguments that are not optional
//! use `*const T`, or `*mut T`.
//!
//! Application code must adhere to Rust's reference rules:
//!
//!  - Either one mutable reference or any number of immutable ones.
//!  - All references are non-`NULL`.
//!  - All references are valid.
//!
//! In this crate we enforce the second rule by asserting that all
//! pointers handed in are non-`NULL`.  An exception is if a parameter
//! of an FFI function uses `Option<&T>` or `Option<&mut T>`.  In that
//! case it may be called with `NULL`.  Notable exceptions are the
//! destructors (`pgp_*_free`).
//!
//! ### Lifetimes
//!
//! If you derive a complex object from another complex object, you
//! must assume that the original object is borrowed (i.e.,
//! referenced) by the resulting object unless explicitly stated
//! otherwise.  For example, objects created using a context must not
//! outlive that context.  Similarly, iterators must not outlive the
//! object they are created from.  It is a good practice to
//! deallocate the objects in the reverse order they were created in.
//!
//! Failing to adhere to lifetime restrictions results in undefined
//! behavior.
//!
//! ### Strings
//!
//! Strings given to this library must be UTF-8 encoded and
//! zero-terminated.  Malformed characters will be substituted.
//!
//! Strings produced by this library will be UTF-8 encoded and
//! zero-terminated.  Malformed characters will be substituted.  They
//! will be allocated using *malloc(3)* und must be *free(3)* d.  A
//! few functions in this library may return a `const char *`, which
//! must not be freed.
//!
//! ### Enumerations
//!
//! Values must be constructed using functionality provided by
//! this library.  Using values constructed in any other way is
//! undefined behavior.
//!
//! In the following example, we will decode an armored blob in
//! memory.  Note how we use `PGP_ARMOR_KIND_ANY` in the [constructor]
//! of the armor reader to indicate that we will consume any kind of
//! data, and later use `PGP_ARMOR_KIND_FILE` to check what we got in
//! the end.
//!
//! [constructor]: armor/fn.pgp_armor_reader_from_bytes.html
//!
//! ```c
//! #include <assert.h>
//! #include <error.h>
//! #include <stdlib.h>
//! #include <stdio.h>
//! #include <string.h>
//! #include <sequoia/openpgp.h>
//!
//! const char *armored =
//!   "-----BEGIN PGP ARMORED FILE-----\n"
//!   "\n"
//!   "SGVsbG8gd29ybGQh\n"
//!   "=s4Gu\n"
//!   "-----END PGP ARMORED FILE-----\n";
//!
//! pgp_reader_t armor =
//!     pgp_armor_reader_from_bytes (armored, strlen (armored), PGP_ARMOR_KIND_ANY);
//!
//! pgp_error_t err;
//! char message[12];
//! if (pgp_reader_read (&err, armor, (uint8_t *) message, 12) != 12)
//!     error (1, 0, "Reading failed: %s", pgp_error_to_string (err));
//!
//! assert (pgp_armor_reader_kind (armor) == PGP_ARMOR_KIND_FILE);
//! assert (memcmp (message, "Hello world!", 12) == 0);
//!
//! pgp_reader_free (armor);
//! ```

#![warn(missing_docs)]

extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate memsec;

extern crate sequoia_ffi_macros;
use sequoia_ffi_macros::{
    ffi_catch_abort,
    ffi_wrapper_type,
};

include!("common.rs");
