#define _GNU_SOURCE
#include <errno.h>
/* Roughly glibc compatible error reporting.  */
#define error(S, E, F, ...) do {                        \
  fprintf (stderr, (F), __VA_ARGS__);                   \
  int s = (S), e = (E);                                 \
  if (e) { fprintf (stderr, ": %s", strerror (e)); }    \
  fprintf (stderr, "\n");                               \
  fflush (stderr);                                      \
  if (s) { exit (s); }                                  \
  } while (0)
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
  // Let's make a KeyID!
  pgp_keyid_t keyid = pgp_keyid_from_hex ("BBBBBBBBBBBBBBBB");
  printf ("%s", pgp_keyid_to_string (keyid));

  // Always clean up after you played.
  pgp_keyid_free (keyid);

  // Let's violate The Rules and use the stale reference!
  printf ("%s", pgp_keyid_to_string (keyid));

  return 0;
}
