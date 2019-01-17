#ifndef SEQUOIA_IO_H
#define SEQUOIA_IO_H

#include <sequoia/openpgp/error.h>

/*/
/// A generic reader.
/*/
typedef struct sq_reader *sq_reader_t;

/*/
/// Opens a file returning a reader.
/*/
sq_reader_t sq_reader_from_file (sq_error_t *errp, const char *filename);

/*/
/// Opens a file descriptor returning a reader.
/*/
sq_reader_t sq_reader_from_fd (int fd);

/*/
/// Creates a reader from a buffer.
/*/
sq_reader_t sq_reader_from_bytes (const uint8_t *buf, size_t len);

/*/
/// Frees a reader.
/*/
void sq_reader_free (sq_reader_t reader);

/*/
/// Reads up to `len` bytes into `buf`.
/*/
ssize_t sq_reader_read (sq_error_t *errp, sq_reader_t reader,
                        uint8_t *buf, size_t len);

/*/
/// A generic writer.
/*/
typedef struct sq_writer *sq_writer_t;

/*/
/// Opens a file returning a writer.
///
/// The file will be created if it does not exist, or be truncated
/// otherwise.  If you need more control, use `sq_writer_from_fd`.
/*/
sq_writer_t sq_writer_from_file (sq_error_t *errp, const char *filename);

/*/
/// Opens a file descriptor returning a writer.
/*/
sq_writer_t sq_writer_from_fd (int fd);

/*/
/// Creates a writer from a buffer.
/*/
sq_writer_t sq_writer_from_bytes (uint8_t *buf, size_t len);

/*/
/// Creates an allocating writer.
///
/// This writer allocates memory using `malloc`, and stores the
/// pointer to the memory and the number of bytes written to the given
/// locations `buf`, and `len`.  Both must either be set to zero, or
/// reference a chunk of memory allocated using libc's heap allocator.
/// The caller is responsible to `free` it once the writer has been
/// destroyed.
/*/
sq_writer_t sq_writer_alloc (void **buf, size_t *len);

/*/
/// Frees a writer.
/*/
void sq_writer_free (sq_writer_t writer);

/*/
/// Writes up to `len` bytes of `buf` into `writer`.
/*/
ssize_t sq_writer_write (sq_error_t *errp, sq_writer_t writer,
                         const uint8_t *buf, size_t len);

#endif
