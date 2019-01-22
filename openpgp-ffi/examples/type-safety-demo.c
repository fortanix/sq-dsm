#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sequoia/openpgp.h>

int
main (int argc, char **argv)
{
  pgp_keyid_t keyid = pgp_keyid_from_hex ("BBBBBBBBBBBBBBBB");

  // Let's violate The Rules and forge a reference!
  pgp_fingerprint_t fingerprint = (pgp_fingerprint_t) keyid;

  // And use it!
  printf ("%s", pgp_fingerprint_to_string (fingerprint));

  // Always clean up though.
  pgp_keyid_free (keyid);
  return 0;
}
