/* This example demonstrates how to use the packet parser from C.  It
 * also serves as a simple benchmark.  */

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
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include <sequoia/openpgp.h>

int
main (int argc, char **argv)
{
  pgp_status_t rc;
  pgp_error_t err;
  pgp_packet_parser_result_t ppr;
  pgp_packet_parser_t pp;

  if (argc != 2)
    error (1, 0, "Usage: %s <file>", argv[0]);

  size_t n = 0;
  time_t start = time (NULL);
  time_t elapsed;
  size_t tens_of_s = 0;

  ppr = pgp_packet_parser_from_file (&err, argv[1]);
  while (ppr && (pp = pgp_packet_parser_result_packet_parser (ppr)))
    {
      // Get a reference to the packet that is currently being parsed.
      pgp_packet_t p = pgp_packet_parser_packet (pp);

      if (pgp_packet_tag(p) == PGP_TAG_LITERAL)
        {
          // Stream the packet here.
        }

      // Finish parsing the current packet (returned in p), and read
      // the header of the next packet (returned in ppr).
      rc = pgp_packet_parser_next (&err, pp, &p, &ppr);
      if (rc)
        error (1, 0, "pgp_packet_parser_from_bytes: %s",
               pgp_error_to_string (err));

      // We now own p.  If we want, we can save it in some structure.
      // This would be useful when collecting PKESK packets.  Either
      // way, we need to free it when we are done.

      n += 1;

      pgp_packet_free (p);

      elapsed = time (NULL) - start;
      if (elapsed % 10 == 0 && tens_of_s != elapsed / 10)
        {
          fprintf (stderr,
                   "Parsed %ld packets in %ld seconds, %.2f packets/s.\n",
                   n, elapsed, (double) n / (double) elapsed);
          fflush (stderr);
          tens_of_s = elapsed / 10;
        }
    }
  if (ppr == NULL)
    error (1, 0, "pgp_packet_parser_from_bytes: %s", pgp_error_to_string (err));

  fprintf (stderr, "Parsed %ld packets in %ld seconds, %.2f packets/s.\n",
           n, elapsed, (double) n / (double) elapsed);

  pgp_packet_parser_result_free (ppr);
  return 0;
}
