//! ASCII Armor.
//!
//! Wraps [`sequoia-openpgp::armor`].
//!
//! [`sequoia-openpgp::armor`]: ../../../sequoia_openpgp/armor/index.html

use std::mem::size_of;
use std::ptr;
use std::slice;
use std::io::{Read, Write};
use libc::{self, uint8_t, c_char, c_int, size_t};

extern crate sequoia_openpgp;
use self::sequoia_openpgp::armor;

/// Represents a (key, value) pair in an armor header.
#[repr(C)]
pub struct ArmorHeader {
    key: *const c_char,
    value: *const c_char,
}

fn int_to_kind(kind: c_int) -> Option<armor::Kind> {
    match kind {
        0 => None,
        1 => Some(armor::Kind::Message),
        2 => Some(armor::Kind::PublicKey),
        3 => Some(armor::Kind::SecretKey),
        4 => Some(armor::Kind::Signature),
        5 => Some(armor::Kind::File),
        _ => panic!("Bad kind: {}", kind),
    }
}

fn kind_to_int(kind: Option<armor::Kind>) -> c_int {
    match kind {
        None => 0,
        Some(armor::Kind::Message) => 1,
        Some(armor::Kind::PublicKey) => 2,
        Some(armor::Kind::SecretKey) => 3,
        Some(armor::Kind::Signature) => 4,
        Some(armor::Kind::File) => 5,
    }
}

/// Constructs a new filter for the given type of data.
///
/// A filter that strips ASCII Armor from a stream of data.
///
/// # Example
///
/// ```c
/// #define _GNU_SOURCE
/// #include <assert.h>
/// #include <error.h>
/// #include <stdio.h>
/// #include <stdlib.h>
/// #include <string.h>
///
/// #include <sequoia/openpgp.h>
///
/// const char *armored =
///   "-----BEGIN PGP ARMORED FILE-----\n"
///   "Key0: Value0\n"
///   "Key1: Value1\n"
///   "\n"
///   "SGVsbG8gd29ybGQh\n"
///   "=s4Gu\n"
///   "-----END PGP ARMORED FILE-----\n";
///
/// int
/// main (int argc, char **argv)
/// {
///   pgp_error_t err;
///   pgp_reader_t bytes;
///   pgp_reader_t armor;
///   pgp_armor_kind_t kind;
///   char message[12];
///   pgp_armor_header_t *header;
///   size_t header_len;
///
///   bytes = pgp_reader_from_bytes ((uint8_t *) armored, strlen (armored));
///   armor = pgp_armor_reader_new (bytes, PGP_ARMOR_KIND_ANY);
///
///   header = pgp_armor_reader_headers (&err, armor, &header_len);
///   if (header == NULL)
///     error (1, 0, "Getting headers failed: %s", pgp_error_string (err));
///
///   assert (header_len == 2);
///   assert (strcmp (header[0].key, "Key0") == 0
///           && strcmp (header[0].value, "Value0") == 0);
///   assert (strcmp (header[1].key, "Key1") == 0
///           && strcmp (header[1].value, "Value1") == 0);
///   for (size_t i = 0; i < header_len; i++)
///     {
///       free (header[i].key);
///       free (header[i].value);
///     }
///   free (header);
///
///   kind = pgp_armor_reader_kind (armor);
///   assert (kind == PGP_ARMOR_KIND_FILE);
///
///   if (pgp_reader_read (&err, armor, (uint8_t *) message, 12) < 0)
///     error (1, 0, "Reading failed: %s", pgp_error_string (err));
///
///   assert (memcmp (message, "Hello world!", 12) == 0);
///
///   pgp_reader_free (armor);
///   pgp_reader_free (bytes);
///   return 0;
/// }
/// ```
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_armor_reader_new(inner: *mut Box<Read>,
                                           kind: c_int)
                                           -> *mut Box<Read> {
    let inner = ffi_param_ref_mut!(inner);
    let kind = int_to_kind(kind);

    box_raw!(Box::new(armor::Reader::new(inner, kind)))
}

/// Creates a `Reader` from a file.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_armor_reader_from_file(errp: Option<&mut *mut failure::Error>,
                                                 filename: *const c_char,
                                                 kind: c_int)
                                                 -> *mut Box<Read> {
    ffi_make_fry_from_errp!(errp);
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    let kind = int_to_kind(kind);

    ffi_try_box!(armor::Reader::from_file(&filename, kind)
             .map(|r| Box::new(r))
             .map_err(|e| e.into()))
}

/// Creates a `Reader` from a buffer.
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_armor_reader_from_bytes(b: *const uint8_t, len: size_t,
                                                  kind: c_int)
                                                  -> *mut Box<Read> {
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };
    let kind = int_to_kind(kind);

    box_raw!(Box::new(armor::Reader::from_bytes(buf, kind)))
}

/// Returns the kind of data this reader is for.
///
/// Useful if the kind of data is not known in advance.  If the header
/// has not been encountered yet (try reading some data first!), this
/// function returns PGP_ARMOR_KIND_ANY.
///
/// # Example
///
/// See [this] example.
///
///   [this]: fn.pgp_armor_reader_new.html
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_armor_reader_kind(reader: *mut Box<Read>)
                                            -> c_int {
    // We need to downcast `reader`.  To do that, we need to do a
    // little dance.  We will momentarily take ownership of `reader`,
    // wrapping it in a Box again.  Then, at the end of the function,
    // we will leak it again.
    let reader = ffi_param_move!(reader as *mut Box<armor::Reader>);
    let kind = kind_to_int(reader.kind());
    Box::into_raw(reader);
    kind
}

/// Returns the armored headers.
///
/// The tuples contain a key and a value.
///
/// Note: if a key occurs multiple times, then there are multiple
/// entries in the vector with the same key; values with the same
/// key are *not* combined.
///
/// The returned array and the strings in the headers have been
/// allocated with `malloc`, and the caller is responsible for freeing
/// both the array and the strings.
///
/// # Example
///
/// See [this] example.
///
///   [this]: fn.pgp_armor_reader_new.html
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_armor_reader_headers(errp: Option<&mut *mut failure::Error>,
                                               reader: *mut Box<Read>,
                                               len: *mut size_t)
                                               -> *mut ArmorHeader {
    ffi_make_fry_from_errp!(errp);
    let len = ffi_param_ref_mut!(len);

    // We need to downcast `reader`.  To do that, we need to do a
    // little dance.  We will momentarily take ownership of `reader`,
    // wrapping it in a Box again.  Then, at the end of the function,
    // we will leak it again.
    let mut reader = ffi_param_move!(reader as *mut Box<armor::Reader>);

    // We need to be extra careful here in order not to keep ownership
    // of `reader` in case of errors.
    let result = match reader.headers().map_err(|e| e.into()) {
        Ok(headers) => {
            // Allocate space for the result.
            let buf = unsafe {
                libc::calloc(headers.len(), size_of::<ArmorHeader>())
                    as *mut ArmorHeader
            };
            let sl = unsafe {
                slice::from_raw_parts_mut(buf, headers.len())
            };
            for (i, (key, value)) in headers.iter().enumerate() {
                sl[i].key = strdup(key);
                sl[i].value = strdup(value);
            }

            *len = headers.len();
            buf
        },
        Err(e) => {
            if let Some(errp) = errp {
                *errp = box_raw!(e);
            }
            ptr::null_mut()
        },
    };

    // Release temporary ownership.
    Box::into_raw(reader);
    result
}

/// Creates a zero-terminated C string from a &str allocated using
/// malloc.
fn strdup(s: &str) -> *mut c_char {
    let b = s.as_bytes();
    let len = b.len() + 1;
    let dup = unsafe {
        libc::malloc(len) as *mut c_char
    };
    let sl = unsafe {
        slice::from_raw_parts_mut(dup as *mut uint8_t, len)
    };
    sl[..len-1].copy_from_slice(b);
    sl[len-1] = 0;
    dup
}

/// Constructs a new filter for the given type of data.
///
/// A filter that applies ASCII Armor to the data written to it.
///
/// # Example
///
/// ```c
/// #define _GNU_SOURCE
/// #include <assert.h>
/// #include <error.h>
/// #include <stdio.h>
/// #include <stdlib.h>
/// #include <string.h>
///
/// #include <sequoia/openpgp.h>
///
/// int
/// main (int argc, char **argv)
/// {
///   void *buf = NULL;
///   size_t len = 0;
///   pgp_writer_t alloc;
///   pgp_writer_t armor;
///   pgp_error_t err;
///
///   char *message = "Hello world!";
///   pgp_armor_header_t header[2] = {
///     { "Key0", "Value0" },
///     { "Key1", "Value1" },
///   };
///
///   alloc = pgp_writer_alloc (&buf, &len);
///   armor = pgp_armor_writer_new (&err, alloc, PGP_ARMOR_KIND_FILE, header, 2);
///   if (armor == NULL)
///     error (1, 0, "Creating armor writer failed: %s", pgp_error_string (err));
///
///   if (pgp_writer_write (&err, armor, (uint8_t *) message, strlen (message)) < 0)
///     error (1, 0, "Writing failed: %s", pgp_error_string (err));
//
///   pgp_writer_free (armor);
///   pgp_writer_free (alloc);
///
///   assert (len == 114);
///   assert (memcmp (buf,
///                   "-----BEGIN PGP ARMORED FILE-----\n"
///                   "Key0: Value0\n"
///                   "Key1: Value1\n"
///                   "\n"
///                   "SGVsbG8gd29ybGQh\n"
///                   "=s4Gu\n"
///                   "-----END PGP ARMORED FILE-----\n",
///                   len) == 0);
///
///   free (buf);
///   return 0;
/// }
/// ```
#[::ffi_catch_abort] #[no_mangle]
pub extern "system" fn pgp_armor_writer_new
    (errp: Option<&mut *mut failure::Error>,
     inner: *mut Box<Write>,
     kind: c_int,
     header: *const ArmorHeader,
     header_len: size_t)
     -> *mut Box<Write>
{
    ffi_make_fry_from_errp!(errp);
    let inner = ffi_param_ref_mut!(inner);
    let kind = int_to_kind(kind).expect("KIND must not be PGP_ARMOR_KIND_ANY");

    let mut header_ = Vec::new();
    if header_len > 0 {
        let headers = ffi_param_ref!(header);
        let headers = unsafe {
            slice::from_raw_parts(headers, header_len)
        };
        for header in headers {
            header_.push(
                (ffi_param_cstr!(header.key).to_string_lossy(),
                 ffi_param_cstr!(header.value).to_string_lossy())
            );
        }
    }

    let header: Vec<(&str, &str)> =
        header_.iter().map(|h| (h.0.as_ref(), h.1.as_ref())).collect();

    ffi_try_box!(armor::Writer::new(inner, kind, &header)
             .map(|r| Box::new(r))
             .map_err(|e| e.into()))
}
