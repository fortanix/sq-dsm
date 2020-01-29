#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <sequoia/openpgp.h>

int
main (int argv, char **argc)
{
  /* As an example, use read(2) as the callback.  */
  pgp_reader_t r = pgp_reader_from_callback ((pgp_reader_cb_t) read,
                                             (void *) 0);

  pgp_cert_t cert = pgp_cert_from_reader (NULL, r);
  assert (cert);

  pgp_cert_free (cert);
  pgp_reader_free (r);
  return 0;
}
