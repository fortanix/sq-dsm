// Common code for sequoia-openpgp-ffi and sequoia-ffi.

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
#[allow(dead_code)]
pub(crate) fn strndup(src: &[u8]) -> Option<*mut libc::c_char> {
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
        crate::strndup(bytes).expect(
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
        crate::strndup(bytes).unwrap_or(::std::ptr::null_mut())
    }};
}

/* Error handling with implicit error return argument.  */

/// Emits local macros for error handling that use the given context
/// to store complex errors.
macro_rules! ffi_make_fry_from_errp {
    ($errp:expr) => {
        /// Like try! for ffi glue.
        ///
        /// Evaluates the given expression.  On success, evaluate to
        /// `Status.Success`.  On failure, stashes the error in the
        /// context and evaluates to the appropriate Status code.
        #[allow(unused_macros)]
        macro_rules! ffi_try_status {
            ($expr:expr) => {
                match $expr {
                    Ok(_) => crate::error::Status::Success,
                    Err(e) => {
                        use crate::MoveIntoRaw;
                        use anyhow::Error;
                        let status = crate::error::Status::from(&e);
                        if let Some(errp) = $errp {
                            let e : Error = e.into();
                            *errp = e.move_into_raw();
                        }
                        status
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Evaluates the given expression.  `Ok(v)` evaluates to `v`.
        /// On failure, stashes the error in the context and returns
        /// the appropriate Status code.
        #[allow(unused_macros)]
        macro_rules! ffi_try_or_status {
            ($expr:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        use crate::MoveIntoRaw;
                        use anyhow::Error;
                        let status = crate::error::Status::from(&e);
                        if let Some(errp) = $errp {
                            let e : Error = e.into();
                            *errp = e.move_into_raw();
                        }
                        return status;
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
                        use crate::MoveIntoRaw;
                        use anyhow::Error;
                        if let Some(errp) = $errp {
                            let e : Error = e.into();
                            *errp = e.move_into_raw();
                        }
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
        $expr.map(|x| box_raw!(x)).unwrap_or(::std::ptr::null_mut())
    }
}


/* Support for sequoia_ffi_macros::ffi_wrapper_type-based object
 * handling.  */

/// Moves an object from C to Rust, taking ownership.
pub(crate) trait MoveFromRaw<T> {
    /// Moves this object from C to Rust, taking ownership.
    fn move_from_raw(self) -> T;
}

/// Moves a reference to an object from C to Rust.
pub(crate) trait RefRaw<T> {
    /// Moves this reference to an object from C to Rust.
    fn ref_raw(self) -> T;
}

/// Moves a mutable reference to an object from C to Rust.
pub(crate) trait RefMutRaw<T> {
    /// Moves this mutable reference to an object from C to Rust.
    fn ref_mut_raw(self) -> T;
}

/// Moves an object from Rust to C, releasing ownership.
pub(crate) trait MoveIntoRaw<T> {
    /// Moves this object from Rust to C, releasing ownership.
    fn move_into_raw(self) -> T;
}

/// Moves an object from Rust to C, releasing ownership.
pub(crate) trait MoveResultIntoRaw<T> {
    /// Moves this object from Rust to C, releasing ownership.
    fn move_into_raw(self, errp: Option<&mut *mut self::error::Error>) -> T;
}

/// Indicates that a pointer may be NULL.
pub type Maybe<T> = Option<::std::ptr::NonNull<T>>;

/* Hashing support.  */

/// Builds hashers for computing hashes.
///
/// This is used to derive Hasher instances for computing hashes of
/// objects so that they can be used in hash tables by foreign code.
pub(crate) fn build_hasher() -> DefaultHasher {
    lazy_static::lazy_static! {
        static ref RANDOM_STATE: RandomState = RandomState::new();
    }
    RANDOM_STATE.build_hasher()
}

/* time_t support.  */

/// Converts a time_t for use in Sequoia.
pub(crate) fn maybe_time(t: libc::time_t) -> Option<std::time::SystemTime> {
    if t == 0 {
        None
    } else {
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(t as u64, 0))
    }
}

/// Converts a time_t for use in C.
#[allow(dead_code)]
pub(crate) fn to_time_t<T>(t: T) -> libc::time_t
    where T: Into<Option<std::time::SystemTime>>
{
    if let Some(t) = t.into() {
        match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as libc::time_t,
            Err(_) => 0, // Unrepresentable.
        }
    } else {
        0
    }
}

pub mod armor;
pub mod crypto;
pub mod error;
pub mod fingerprint;
pub mod io;
pub mod keyid;
pub mod packet;
pub mod packet_pile;
pub mod parse;
pub mod serialize;
pub mod cert;
pub mod tsk;
pub mod revocation_status;
pub mod policy;
pub mod key_amalgamation;
pub mod amalgamation;
