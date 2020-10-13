/* This example demonstrates how to use the low-level interface to
   create a signed message.  */

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
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sequoia/openpgp.h>

int
main (int argc, char **argv)
{
  pgp_error_t err;
  pgp_cert_t cert;
  pgp_writer_t sink;
  pgp_writer_t armor_writer;
  pgp_writer_stack_t writer = NULL;
  pgp_policy_t policy = pgp_standard_policy ();

  if (argc != 2)
    error (1, 0, "Usage: %s <keyfile> <plain >cipher", argv[0]);

  cert = pgp_cert_from_file (&err, argv[1]);
  if (cert == NULL)
    error (1, 0, "pgp_cert_from_file: %s", pgp_error_to_string (err));

  /* Iterate over the cert and get the signing key. */
  pgp_signer_t signer;
  {
    pgp_cert_valid_key_iter_t iter;
    pgp_valid_key_amalgamation_t ka;
    pgp_key_t key;
    pgp_key_pair_t signing_keypair;

    iter = pgp_cert_valid_key_iter (cert, policy, 0);
    pgp_cert_valid_key_iter_alive (iter);
    pgp_cert_valid_key_iter_revoked (iter, false);
    pgp_cert_valid_key_iter_for_signing (iter);
    pgp_cert_valid_key_iter_unencrypted_secret (iter);
    ka = pgp_cert_valid_key_iter_next(iter, NULL, NULL);
    if (ka == NULL)
      error (1, 0, "%s has no signing-capable (sub)key", argv[1]);
    key = pgp_valid_key_amalgamation_key (ka);
    assert (pgp_key_has_unencrypted_secret (key));
    signing_keypair =
      pgp_key_into_key_pair (NULL, pgp_key_clone (key));
    assert (signing_keypair);
    signer = pgp_key_pair_as_signer (/* consumes */ signing_keypair);
    pgp_key_free (key);
    pgp_valid_key_amalgamation_free (ka);
    pgp_cert_valid_key_iter_free (iter);
  }

  sink = pgp_writer_from_fd (STDOUT_FILENO);
  armor_writer = pgp_armor_writer_new (&err, sink, PGP_ARMOR_KIND_MESSAGE,
                                       NULL, 0);

  writer = pgp_writer_stack_message (armor_writer);
  writer = pgp_signer_new (&err, writer, /* consumes */ &signer, 1, 0);
  if (writer == NULL)
    error (1, 0, "pgp_signer_new: %s", pgp_error_to_string (err));

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

  if (pgp_writer_stack_finalize (&err, writer))
    error (1, 0, "pgp_writer_stack_write: %s", pgp_error_to_string (err));

  if (pgp_armor_writer_finalize (&err, armor_writer))
    error (1, 0, "pgp_armor_writer_finalize: %s", pgp_error_to_string (err));
  pgp_writer_free (sink);
  pgp_cert_free (cert);
  pgp_policy_free (policy);
  return 0;
}
