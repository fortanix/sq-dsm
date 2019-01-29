#define _GNU_SOURCE
#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sequoia.h>

int
main (int argc, char **argv)
{
  pgp_error_t err;
  sq_context_t ctx;
  pgp_keyid_t id;
  sq_keyserver_t ks;
  pgp_tpk_t tpk;

  ctx = sq_context_new ("org.sequoia-pgp.example", &err);
  if (ctx == NULL)
    error (1, 0, "Initializing sequoia failed: %s",
           pgp_error_to_string (err));

  ks = sq_keyserver_sks_pool (ctx);
  if (ks == NULL)
    {
      pgp_error_t err = sq_context_last_error (ctx);
      error (1, 0, "Initializing Keyserver failed: %s", pgp_error_to_string (err));
    }

  id = pgp_keyid_from_bytes ((uint8_t *) "\x24\x7F\x6D\xAB\xC8\x49\x14\xFE");
  tpk = sq_keyserver_get (ctx, ks, id);
  if (tpk == NULL)
    {
      pgp_error_t err = sq_context_last_error (ctx);
      error (1, 0, "Failed to retrieve key: %s", pgp_error_to_string (err));
    }

  char *debug = pgp_tpk_debug (tpk);
  printf ("%s", debug);
  free (debug);

  pgp_tpk_free (tpk);
  pgp_keyid_free (id);
  sq_keyserver_free (ks);
  sq_context_free (ctx);
  return 0;
}
