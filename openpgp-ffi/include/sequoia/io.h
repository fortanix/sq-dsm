#ifndef SEQUOIA_IO_H
#define SEQUOIA_IO_H

#include <sequoia/openpgp/error.h>

/*/
/// A generic reader.
/*/
typedef struct pgp_reader *pgp_reader_t;

/*/
/// A generic writer.
/*/
typedef struct pgp_writer *pgp_writer_t;

/*/
/// Opens a file returning a reader.
/*/
pgp_reader_t pgp_reader_from_file (pgp_error_t *errp, const char *filename);

/*/
/// Opens a file descriptor returning a reader.
/*/
pgp_reader_t pgp_reader_from_fd (int fd);

/*/
/// Creates a reader from a buffer.
/*/
pgp_reader_t pgp_reader_from_bytes (const uint8_t *buf, size_t len);

/*/
/// The callback type for the generic callback-based reader interface.
/*/
typedef ssize_t (*pgp_reader_cb_t) (void *cookie, const void *buf, size_t len);

/*/
/// Creates an reader from a callback and cookie.
///
/// This reader calls the given callback to read data.
///
/// # Sending objects across thread boundaries
///
/// If you send a Sequoia object (like a pgp_verifier_t) that reads
/// from an callback across thread boundaries, you must make sure that
/// the callback and cookie support that as well.
/*/
pgp_reader_t pgp_reader_from_callback (pgp_reader_cb_t, void *);

/*/
/// Frees a reader.
/*/
void pgp_reader_free (pgp_reader_t reader);

/*/
/// Reads up to `len` bytes into `buf`.
/*/
ssize_t pgp_reader_read (pgp_error_t *errp, pgp_reader_t reader,
                         uint8_t *buf, size_t len);

/*/
/// Copies up to `len` bytes of `source` into `dest`.
///
/// Note: if you are doing a bulk copy (from a reader to a writer), it
/// is more efficient to use large chunk sizes.
/*/
ssize_t pgp_reader_copy (pgp_error_t *errp, pgp_reader_t source,
                         pgp_writer_t dest, size_t len);

/*/
/// Reads from `source` and discards all of the data.
/*/
ssize_t pgp_reader_discard (pgp_error_t *errp, pgp_reader_t source);

/*/
/// Opens a file returning a writer.
///
/// The file will be created if it does not exist, or be truncated
/// otherwise.  If you need more control, use `pgp_writer_from_fd`.
/*/
pgp_writer_t pgp_writer_from_file (pgp_error_t *errp, const char *filename);

/*/
/// Opens a file descriptor returning a writer.
/*/
pgp_writer_t pgp_writer_from_fd (int fd);

/*/
/// Creates a writer from a buffer.
/*/
pgp_writer_t pgp_writer_from_bytes (uint8_t *buf, size_t len);

/*/
/// Creates an allocating writer.
///
/// This writer allocates memory using `malloc`, and stores the
/// pointer to the memory and the number of bytes written to the given
/// locations `buf`, and `len`.  Both must either be set to zero, or
/// reference a chunk of memory allocated using libc's heap allocator.
/// The caller is responsible to `free` it once the writer has been
/// destroyed.
///
/// # Sending objects across thread boundaries
///
/// If you send a Sequoia object (like a pgp_writer_stack_t) that
/// serializes to an allocating writer across thread boundaries, you
/// must make sure that the system's allocator (i.e. `realloc (3)`)
/// supports reallocating memory allocated by another thread.
/*/
pgp_writer_t pgp_writer_alloc (void **buf, size_t *len);

/*/
/// The callback type for the generic callback-based writer interface.
/*/
typedef ssize_t (*pgp_writer_cb_t) (void *cookie, const void *buf, size_t len);

/*/
/// Creates an writer from a callback and cookie.
///
/// This writer calls the given callback to write data.
///
/// # Sending objects across thread boundaries
///
/// If you send a Sequoia object (like a pgp_writer_stack_t) that
/// serializes to a callback-based writer across thread boundaries,
/// you must make sure that the callback and cookie also support this.
/*/
pgp_writer_t pgp_writer_from_callback (pgp_writer_cb_t, void *);

/*/
/// Frees a writer.
/*/
void pgp_writer_free (pgp_writer_t writer);

/*/
/// Writes up to `len` bytes of `buf` into `writer`.
/*/
ssize_t pgp_writer_write (pgp_error_t *errp, pgp_writer_t writer,
                         const uint8_t *buf, size_t len);

#endif
