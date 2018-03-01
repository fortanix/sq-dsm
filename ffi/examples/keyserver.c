#define _GNU_SOURCE
#include <error.h>
#include <errno.h>
#include <stdio.h>

#include <sequoia.h>

int
main (int argc, char **argv)
{
  sq_context_t ctx;
  sq_keyid_t id;
  sq_keyserver_t ks;
  sq_tpk_t tpk;

  ctx = sq_context_new ("org.sequoia-pgp.example");
  if (ctx == NULL)
    error (1, 0, "Initializing sequoia failed.");

  ks = sq_keyserver_sks_pool (ctx);
  if (ks == NULL)
    {
      sq_error_t err = sq_context_last_error (ctx);
      error (1, 0, "Initializing Keyserver failed: %s", sq_error_string (err));
    }

  id = sq_keyid_from_bytes ((uint8_t *) "\x24\x7F\x6D\xAB\xC8\x49\x14\xFE");
  tpk = sq_keyserver_get (ctx, ks, id);
  if (tpk == NULL)
    {
      sq_error_t err = sq_context_last_error (ctx);
      error (1, 0, "Failed to retrieve key: %s", sq_error_string (err));
    }

  sq_tpk_dump (tpk);
  sq_tpk_free (tpk);
  sq_keyid_free (id);
  sq_keyserver_free (ks);
  sq_context_free (ctx);
  return 0;
}
