#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <sequoia/openpgp.h>

int
main (int argv, char **argc)
{
  pgp_status_t rc;

  /* First, generate the key.  */
  pgp_cert_builder_t builder = pgp_cert_builder_new ();
  pgp_cert_builder_set_cipher_suite (&builder, PGP_CERT_CIPHER_SUITE_CV25519);

  pgp_cert_t cert;
  pgp_signature_t revocation;
  pgp_cert_builder_generate (NULL, builder, &cert, &revocation);
  assert (cert);
  assert (revocation);
  pgp_signature_free (revocation);    /* Free the generated revocation.  */

  /* As an example, use write(2) as the callback.  */
  pgp_writer_t w = pgp_writer_from_callback ((pgp_writer_cb_t) write,
					     (void *) 1);
  rc = pgp_cert_serialize (NULL, cert, w);
  assert (rc == PGP_STATUS_SUCCESS);

  pgp_cert_free (cert);
  pgp_writer_free (w);
  return 0;
}
