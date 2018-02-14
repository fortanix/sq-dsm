#define _GNU_SOURCE
#include <error.h>
#include <errno.h>
#include <stdio.h>

#include <sequoia.h>

int
main (int argc, char **argv)
{
  sq_config_t cfg;
  sq_context_t ctx;
  sq_keyserver_t ks;

  cfg = sq_context_configure ("org.sequoia-pgp.example");
  sq_config_network_policy (cfg, SQ_NETWORK_POLICY_OFFLINE);
  ctx = sq_config_build (cfg);
  if (ctx == NULL)
    error (1, 0, "Initializing sequoia failed.");

  ks = sq_keyserver_sks_pool (ctx);
  if (ks == NULL)
    error (0, 0, "Initializing Keyserver failed as expected: %s",
	   sq_last_strerror (ctx));
  else
    error (1, 0, "This should not be allowed");

  sq_keyserver_free (ks);
  sq_context_free (ctx);
  return 0;
}
