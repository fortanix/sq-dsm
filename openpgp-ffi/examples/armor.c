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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sequoia/openpgp.h>

const char *armored =
  "-----BEGIN PGP ARMORED FILE-----\n"
  "Key0: Value0\n"
  "Key1: Value1\n"
  "\n"
  "SGVsbG8gd29ybGQh\n"
  "=s4Gu\n"
  "-----END PGP ARMORED FILE-----\n";

int
main (int argc, char **argv)
{
  pgp_error_t err;
  pgp_reader_t bytes;
  pgp_reader_t armor;
  pgp_armor_kind_t kind;
  char message[12];
  pgp_armor_header_t header;
  size_t header_len;

  bytes = pgp_reader_from_bytes ((uint8_t *) armored, strlen (armored));
  armor = pgp_armor_reader_new (bytes, PGP_ARMOR_KIND_ANY);

  header = pgp_armor_reader_headers (&err, armor, &header_len);
  if (header == NULL)
    error (1, 0, "Getting headers failed: %s", pgp_error_to_string (err));

  assert (header_len == 2);
  assert (strcmp (header[0].key, "Key0") == 0
          && strcmp (header[0].value, "Value0") == 0);
  assert (strcmp (header[1].key, "Key1") == 0
          && strcmp (header[1].value, "Value1") == 0);
  for (size_t i = 0; i < header_len; i++)
    {
      free (header[i].key);
      free (header[i].value);
    }
  free (header);

  kind = pgp_armor_reader_kind (armor);
  assert (kind == PGP_ARMOR_KIND_FILE);

  if (pgp_reader_read (&err, armor, (uint8_t *) message, 12) < 0)
      error (1, 0, "Reading failed: %s", pgp_error_to_string (err));

  assert (memcmp (message, "Hello world!", 12) == 0);

  pgp_reader_free (armor);
  pgp_reader_free (bytes);
  return 0;
}
