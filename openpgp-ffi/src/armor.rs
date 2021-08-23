//! ASCII Armor.
//!
//! Wraps [`sequoia-openpgp::armor`].
//!
//! [`sequoia-openpgp::armor`]: super::super::super::sequoia_openpgp::armor

use std::mem::size_of;
use std::ptr;
use std::slice;
use libc::{self, c_char, c_int, size_t};

use sequoia_openpgp::armor;

use super::io::{Reader, ReaderKind, WriterKind};
use crate::Maybe;
use crate::MoveFromRaw;
use crate::MoveIntoRaw;
use crate::MoveResultIntoRaw;
use crate::RefRaw;
use crate::RefMutRaw;

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

fn int_to_reader_mode(mode: c_int) -> armor::ReaderMode {
    match mode {
        -1 => armor::ReaderMode::VeryTolerant,
        _ => armor::ReaderMode::Tolerant(int_to_kind(mode)),
    }
}

// fn reader_mode_to_int(mode: armor::ReaderMode) -> c_int {
//     match mode {
//         armor::ReaderMode::VeryTolerant => -1,
//         armor::ReaderMode::Tolerant(kind) => kind_to_int(kind),
//     }
// }

/// Constructs a new filter for the given type of data.
///
/// A filter that strips ASCII Armor from a stream of data.
///
/// # Examples
///
/// ```c
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
/// pgp_reader_t bytes = pgp_reader_from_bytes ((uint8_t *) armored, strlen (armored));
/// pgp_reader_t armor = pgp_armor_reader_new (bytes, PGP_ARMOR_KIND_ANY);
///
/// pgp_error_t err;
/// pgp_armor_header_t header;
/// size_t header_len;
/// header = pgp_armor_reader_headers (&err, armor, &header_len);
/// if (header == NULL)
///   error (1, 0, "Getting headers failed: %s", pgp_error_to_string (err));
///
/// assert (header_len == 2);
/// assert (strcmp (header[0].key, "Key0") == 0
///         && strcmp (header[0].value, "Value0") == 0);
/// assert (strcmp (header[1].key, "Key1") == 0
///         && strcmp (header[1].value, "Value1") == 0);
/// for (size_t i = 0; i < header_len; i++)
///   {
///     free (header[i].key);
///     free (header[i].value);
///   }
/// free (header);
///
/// char message[12];
/// if (pgp_reader_read (&err, armor, (uint8_t *) message, 12) < 0)
///   error (1, 0, "Reading failed: %s", pgp_error_to_string (err));
///
/// assert (pgp_armor_reader_kind (armor) == PGP_ARMOR_KIND_FILE);
/// assert (memcmp (message, "Hello world!", 12) == 0);
///
/// pgp_reader_free (armor);
/// pgp_reader_free (bytes);
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_armor_reader_new(inner: *mut Reader,
                                       mode: c_int)
    -> *mut Reader
{
    let inner = inner.ref_mut_raw();
    let mode = int_to_reader_mode(mode);

    ReaderKind::Armored(armor::Reader::new(inner, mode)).move_into_raw()
}

/// Creates a `Reader` from a file.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_armor_reader_from_file(errp: Option<&mut *mut crate::error::Error>,
                                             filename: *const c_char,
                                             mode: c_int)
    -> Maybe<Reader>
{
    let filename = ffi_param_cstr!(filename).to_string_lossy().into_owned();
    let mode = int_to_reader_mode(mode);

    armor::Reader::from_file(&filename, mode)
        .map(ReaderKind::Armored)
        .map_err(::anyhow::Error::from)
        .move_into_raw(errp)
}

/// Creates a `Reader` from a buffer.
///
/// # Examples
///
/// ```c
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
/// pgp_reader_t armor =
///     pgp_armor_reader_from_bytes ((uint8_t *) armored, strlen (armored),
///     PGP_ARMOR_KIND_ANY);
///
/// pgp_error_t err;
/// pgp_armor_header_t header;
/// size_t header_len;
/// header = pgp_armor_reader_headers (&err, armor, &header_len);
/// if (header == NULL)
///   error (1, 0, "Getting headers failed: %s", pgp_error_to_string (err));
///
/// assert (header_len == 2);
/// assert (strcmp (header[0].key, "Key0") == 0
///         && strcmp (header[0].value, "Value0") == 0);
/// assert (strcmp (header[1].key, "Key1") == 0
///         && strcmp (header[1].value, "Value1") == 0);
/// for (size_t i = 0; i < header_len; i++)
///   {
///     free (header[i].key);
///     free (header[i].value);
///   }
/// free (header);
///
/// char message[12];
/// if (pgp_reader_read (&err, armor, (uint8_t *) message, 12) < 0)
///   error (1, 0, "Reading failed: %s", pgp_error_to_string (err));
///
/// assert (pgp_armor_reader_kind (armor) == PGP_ARMOR_KIND_FILE);
/// assert (memcmp (message, "Hello world!", 12) == 0);
///
/// pgp_reader_free (armor);
/// ```
#[::sequoia_ffi_macros::extern_fn] #[no_mangle] pub extern "C"
fn pgp_armor_reader_from_bytes(b: *const u8, len: size_t,
                               mode: c_int)
                               -> *mut Reader {
    assert!(!b.is_null());
    let buf = unsafe {
        slice::from_raw_parts(b, len as usize)
    };
    let mode = int_to_reader_mode(mode);

    ReaderKind::Armored(armor::Reader::from_bytes(buf, mode)).move_into_raw()
}

/// Returns the kind of data this reader is for.
///
/// Useful if the kind of data is not known in advance.  If the header
/// has not been encountered yet (try reading some data first!), this
/// function returns PGP_ARMOR_KIND_ANY.
///
/// # Examples
///
/// See [this] example.
///
///   [this]: pgp_armor_reader_new()
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_armor_reader_kind(reader: *const Reader)
                                             -> c_int {
    if let ReaderKind::Armored(ref armor_reader) = reader.ref_raw()
    {
        kind_to_int(armor_reader.kind())
    } else {
        panic!(
            "FFI contract violation: Wrong parameter type: \
             expected an armor reader")
    }
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
/// # Examples
///
/// See [this] example.
///
///   [this]: pgp_armor_reader_new()
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_armor_reader_headers(errp: Option<&mut *mut crate::error::Error>,
                                               reader: *mut Reader,
                                               len: *mut size_t)
                                               -> *mut ArmorHeader {
    ffi_make_fry_from_errp!(errp);
    let len = ffi_param_ref_mut!(len);

    let reader = if let ReaderKind::Armored(ref mut reader) = reader.ref_mut_raw() {
        reader
    } else {
        panic!("FFI contract violation: Wrong parameter type: \
                expected armor reader");
    };

    match reader.headers().map_err(::anyhow::Error::from) {
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
                sl[i].key =
                    super::strndup(key.as_bytes()).unwrap_or(ptr::null_mut());
                sl[i].value =
                    super::strndup(value.as_bytes()).unwrap_or(ptr::null_mut());
            }

            *len = headers.len();
            buf
        },
        Err(e) => {
            if let Some(errp) = errp {
                *errp = e.move_into_raw();
            }
            ptr::null_mut()
        },
    }
}

/// Constructs a new filter for the given type of data.
///
/// A filter that applies ASCII Armor to the data written to it.
///
/// Note: You must call `pgp_armor_writer_finalize` to deallocate this
/// writer.
///
/// # Examples
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
///   pgp_error_t err = NULL;
///
///   char *message = "Hello world!";
///   struct pgp_armor_header header[] = {
///     { "Key0", "Value0" },
///     { "Key1", "Value1" },
///   };
///
///   alloc = pgp_writer_alloc (&buf, &len);
///   armor = pgp_armor_writer_new (&err, alloc, PGP_ARMOR_KIND_FILE, header, 2);
///   if (armor == NULL)
///     error (1, 0, "Creating armor writer failed: %s", pgp_error_to_string (err));
///
///   if (pgp_writer_write (&err, armor, (uint8_t *) message, strlen (message)) < 0)
///     error (1, 0, "Writing failed: %s", pgp_error_to_string (err));
///
///   pgp_armor_writer_finalize (&err, armor);
///   assert (err == NULL);
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
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_armor_writer_new
    (errp: Option<&mut *mut crate::error::Error>,
     inner: *mut super::io::Writer,
     kind: c_int,
     header: *const ArmorHeader,
     header_len: size_t)
     -> Maybe<super::io::Writer>
{
    let inner = inner.ref_mut_raw();
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

    armor::Writer::with_headers(inner, kind, header)
        .map(WriterKind::Armored)
        .map_err(::anyhow::Error::from)
        .move_into_raw(errp)
}

/// Finalizes the armor writer.
///
/// Consumes the writer.  No further deallocation of the writer is
/// required.
#[::sequoia_ffi_macros::extern_fn] #[no_mangle]
pub extern "C" fn pgp_armor_writer_finalize
    (errp: Option<&mut *mut crate::error::Error>,
     writer: *mut super::io::Writer)
     -> crate::error::Status
{
    ffi_make_fry_from_errp!(errp);
    let writer = if let WriterKind::Armored(writer) = writer.move_from_raw() {
        writer
    } else {
        panic!("FFI contract violation: Wrong parameter type: \
                expected armor writer");
    };

    ffi_try_status!(writer.finalize().map_err(|e| e.into()))
}
