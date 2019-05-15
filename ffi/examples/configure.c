#define _GNU_SOURCE
#include <assert.h>
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
  sq_config_t cfg;
  sq_context_t ctx;
  sq_keyserver_t ks;

  cfg = sq_context_configure ();
  sq_config_network_policy (cfg, SQ_NETWORK_POLICY_OFFLINE);
  ctx = sq_config_build (cfg, &err);
  if (ctx == NULL)
    error (1, 0, "Initializing sequoia failed: %s",
           pgp_error_to_string (err));

  ks = sq_keyserver_sks_pool (ctx);
  if (ks == NULL)
    {
      pgp_error_t err = sq_context_last_error (ctx);
      assert (pgp_error_status (err) == PGP_STATUS_NETWORK_POLICY_VIOLATION);
      char *msg = pgp_error_to_string (err);
      error (0, 0, "Initializing KeyServer failed as expected: %s",
             msg);
      free (msg);
      pgp_error_free (err);
    }
  else
    assert (! "reachable");

  sq_keyserver_free (ks);
  sq_context_free (ctx);
  return 0;
}
