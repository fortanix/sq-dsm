#define _GNU_SOURCE
#include <assert.h>
#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sequoia.h>

int
main (int argc, char **argv)
{
  sq_error_t err;
  sq_config_t cfg;
  sq_context_t ctx;
  sq_keyserver_t ks;

  cfg = sq_context_configure ("org.sequoia-pgp.example");
  sq_config_network_policy (cfg, SQ_NETWORK_POLICY_OFFLINE);
  ctx = sq_config_build (cfg, &err);
  if (ctx == NULL)
    error (1, 0, "Initializing sequoia failed: %s",
           sq_error_string (err));

  ks = sq_keyserver_sks_pool (ctx);
  if (ks == NULL)
    {
      sq_error_t err = sq_context_last_error (ctx);
      assert (sq_error_status (err) == SQ_STATUS_NETWORK_POLICY_VIOLATION);
      char *msg = sq_error_string (err);
      error (0, 0, "Initializing KeyServer failed as expected: %s",
             msg);
      free (msg);
      sq_error_free (err);
    }
  else
    error (1, 0, "This should not be allowed");

  sq_keyserver_free (ks);
  sq_context_free (ctx);
  return 0;
}
