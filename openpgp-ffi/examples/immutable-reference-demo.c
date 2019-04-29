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
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <sequoia/openpgp.h>

const char *SIGNATURE =
  "-----BEGIN PGP SIGNATURE-----\n"
  "\n"
  "woQEHxYKADYCHgMCmwEFglzG4sgFiQWfpgAWIQRQOSL5kHbC6ABk1wR4FqN0BApT\n"
  "FwkQeBajdAQKUxcCFQoAAApUAP9IqLtwGgfxwzwGYqBSQszNwsg9OHAdputlUvVZ\n"
  "WZ+vqgEA5lRTlWwcS3ofH758FQWJFyHwHBQ6weler8510ZEahg4=\n"
  "=Ebj8\n"
  "-----END PGP SIGNATURE-----\n";

int
main (int argc, char **argv)
{
  /* Let's parse a signature.  */
  pgp_packet_parser_result_t ppr;
  pgp_packet_parser_t pp;
  ppr = pgp_packet_parser_from_bytes (NULL,
                                      (uint8_t *) SIGNATURE,
                                      strlen (SIGNATURE));
  while ((pp = pgp_packet_parser_result_packet_parser (ppr)))
    {
      /* Let's borrow a immutable reference from the parser.  */
      pgp_packet_t p = pgp_packet_parser_packet (pp);

      /* We happen to know that it is a signature.  */
      pgp_signature_t sig = pgp_packet_ref_signature (p);
      assert(sig);

      /* Let's violate The Rules and forge a mutable reference from
       * the immutable one!  */
      pgp_signature_t sig_mut = (pgp_signature_t) sig;

      /* And try to convert the Signature to a Packet, moving the ownership!  */
      pgp_signature_into_packet (sig_mut);

      /* Always clean up though.  */
      pgp_signature_free (sig);
      pgp_packet_free (p);
    }

  pgp_packet_parser_result_free (ppr);
  return 0;
}
