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

#include <sequoia.h>

int
main (int argc, char **argv)
{
  pgp_error_t err;
  sq_context_t ctx;
  pgp_keyid_t id;
  sq_keyserver_t ks;
  pgp_cert_t cert;

  ctx = sq_context_new (&err);
  if (ctx == NULL)
    error (1, 0, "Initializing sequoia failed: %s",
           pgp_error_to_string (err));

  ks = sq_keyserver_keys_openpgp_org (ctx, SQ_NETWORK_POLICY_ENCRYPTED);
  if (ks == NULL)
    {
      pgp_error_t err = sq_context_last_error (ctx);
      error (1, 0, "Initializing Keyserver failed: %s", pgp_error_to_string (err));
    }

  id = pgp_keyid_from_bytes ((uint8_t *) "\x24\x7F\x6D\xAB\xC8\x49\x14\xFE");
  cert = sq_keyserver_get (ctx, ks, id);
  if (cert == NULL)
    {
      pgp_error_t err = sq_context_last_error (ctx);
      error (1, 0, "Failed to retrieve key: %s", pgp_error_to_string (err));
    }

  char *debug = pgp_cert_debug (cert);
  printf ("%s", debug);
  free (debug);

  pgp_cert_free (cert);
  pgp_keyid_free (id);
  sq_keyserver_free (ks);
  sq_context_free (ctx);
  return 0;
}
