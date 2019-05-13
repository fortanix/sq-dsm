/* This example demonstrates how to use the low-level interface to
   encrypt a file.  */

#define _GNU_SOURCE
/* Roughly glibc compatible error reporting.  */
#define error(S, E, F, ...) do {                        \
  fprintf (stderr, (F), __VA_ARGS__);                   \
  int s = (S), e = (E);                                 \
  if (e) { fprintf (stderr, ": %s", strerror (e)); }    \
  fprintf (stderr, "\n");                               \
  fflush (stderr);                                      \
  if (s) { exit (s); }                                  \
  } while (0)
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sequoia/openpgp.h>

int
main (int argc, char **argv)
{
  pgp_status_t rc;
  pgp_error_t err;
  int use_armor = 1;
  pgp_tpk_t tpk;
  pgp_writer_t sink;
  pgp_writer_stack_t writer = NULL;

  if (argc != 2)
    error (1, 0, "Usage: %s <keyfile> <plain >cipher", argv[0]);

  tpk = pgp_tpk_from_file (&err, argv[1]);
  if (tpk == NULL)
    error (1, 0, "pgp_tpk_from_file: %s", pgp_error_to_string (err));

  sink = pgp_writer_from_fd (STDOUT_FILENO);

  if (use_armor)
    sink = pgp_armor_writer_new (&err, sink, PGP_ARMOR_KIND_MESSAGE,
                                NULL, 0);

  writer = pgp_writer_stack_message (sink);
  writer = pgp_encryptor_new (&err,
                              writer,
                              NULL, 0, /* no passwords */
                              &tpk, 1,
                              PGP_ENCRYPTION_MODE_FOR_TRANSPORT,
                              9 /* AES256 */);
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

  pgp_tpk_free (tpk);
  return 0;
}
