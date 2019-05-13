#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include <sequoia/openpgp.h>

int
main () {
  pgp_status_t rc;

  /* First, generate the key.  */
  pgp_tpk_builder_t builder = pgp_tpk_builder_new ();
  pgp_tpk_builder_set_cipher_suite (&builder, PGP_TPK_CIPHER_SUITE_CV25519);

  pgp_tpk_t tpk;
  pgp_signature_t revocation;
  pgp_tpk_builder_generate (NULL, builder, &tpk, &revocation);
  assert (tpk);
  assert (revocation);
  pgp_signature_free (revocation);    /* Free the generated revocation.  */

  /* Now, setup an armor writer for stdout.  */
  pgp_writer_t sink = pgp_writer_from_fd (STDOUT_FILENO);
  pgp_writer_t armor = pgp_armor_writer_new (NULL, sink,
					     PGP_ARMOR_KIND_SECRETKEY,
					     NULL, 0);
  assert (armor);

  /* Finally, derive a TSK object, and serialize it.  */
  pgp_tsk_t tsk = pgp_tpk_as_tsk (tpk);
  rc = pgp_tsk_serialize (NULL, tsk, armor);
  assert (rc == PGP_STATUS_SUCCESS);

  pgp_tsk_free (tsk);
  pgp_writer_free (armor);
  pgp_writer_free (sink);
  pgp_tpk_free (tpk);
}
