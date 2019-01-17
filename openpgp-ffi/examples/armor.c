#define _GNU_SOURCE
#include <assert.h>
#include <error.h>
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
  sq_error_t err;
  sq_reader_t bytes;
  sq_reader_t armor;
  sq_armor_kind_t kind;
  char message[12];
  sq_armor_header_t *header;
  size_t header_len;

  bytes = sq_reader_from_bytes ((uint8_t *) armored, strlen (armored));
  armor = sq_armor_reader_new (bytes, SQ_ARMOR_KIND_ANY);

  header = sq_armor_reader_headers (&err, armor, &header_len);
  if (header == NULL)
    error (1, 0, "Getting headers failed: %s", sq_error_string (err));

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

  kind = sq_armor_reader_kind (armor);
  assert (kind == SQ_ARMOR_KIND_FILE);

  if (sq_reader_read (&err, armor, (uint8_t *) message, 12) < 0)
      error (1, 0, "Reading failed: %s", sq_error_string (err));

  assert (memcmp (message, "Hello world!", 12) == 0);

  sq_reader_free (armor);
  sq_reader_free (bytes);
  return 0;
}
