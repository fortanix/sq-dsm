/* This example demonstrates how to use the low-level interface to
   encrypt a file.  */

#define _GNU_SOURCE
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#include <sequoia/openpgp.h>

int
main (int argc, char **argv)
{
  struct stat st;
  int fd;
  uint8_t *b;
  pgp_status_t rc;
  pgp_error_t err;
  int use_armor = 1;
  pgp_tpk_t tpk;
  pgp_writer_t sink;
  pgp_writer_stack_t writer = NULL;
  void *cipher = NULL;
  size_t cipher_bytes = 0;

  if (argc != 2)
    error (1, 0, "Usage: %s <keyfile> <plain >cipher", argv[0]);

  if (stat (argv[1], &st))
    error (1, errno, "%s", argv[1]);

  fd = open (argv[1], O_RDONLY);
  if (fd == -1)
    error (1, errno, "%s", argv[1]);

  b = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  close (fd);
  if (b == MAP_FAILED)
    error (1, errno, "mmap");

  tpk = pgp_tpk_from_bytes (&err, b, st.st_size);
  if (tpk == NULL)
    error (1, 0, "pgp_packet_parser_from_bytes: %s", pgp_error_to_string (err));

  sink = pgp_writer_alloc (&cipher, &cipher_bytes);

  if (use_armor)
    sink = pgp_armor_writer_new (&err, sink, PGP_ARMOR_KIND_MESSAGE,
                                NULL, 0);

  writer = pgp_writer_stack_message (sink);
  writer = pgp_encryptor_new (&err,
			     writer,
			     NULL, 0, /* no passwords */
			     &tpk, 1,
			     PGP_ENCRYPTION_MODE_FOR_TRANSPORT);
  if (writer == NULL)
    error (1, 0, "pgp_encryptor_new: %s", pgp_error_to_string (err));

  writer = pgp_literal_writer_new (&err, writer);
  if (writer == NULL)
    error (1, 0, "pgp_literal_writer_new: %s", pgp_error_to_string (err));

  size_t nread;
  uint8_t buf[4096];
  while ((nread = fread (buf, 1, sizeof buf, stdin)))
    {
      uint8_t *b = buf;
      while (nread)
	{
	  ssize_t written;
	  written = pgp_writer_stack_write (&err, writer, b, nread);
	  if (written < 0)
            error (1, 0, "pgp_writer_stack_write: %s", pgp_error_to_string (err));

	  b += written;
	  nread -= written;
	}
    }

  rc = pgp_writer_stack_finalize (&err, writer);
  writer = NULL;
  if (rc)
    error (1, 0, "pgp_writer_stack_write: %s", pgp_error_to_string (err));

  fwrite (cipher, 1, cipher_bytes, stdout);

  munmap (b, st.st_size);
  return 0;
}
