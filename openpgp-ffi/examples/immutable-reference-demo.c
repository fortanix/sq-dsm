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
  /* Create a new TSK.  */
  pgp_tsk_t tsk;
  pgp_signature_t revocation;
  pgp_tsk_new (NULL, "", &tsk, &revocation);
  pgp_signature_free (revocation);

  /* Let's borrow a immutable reference from it.  */
  pgp_tpk_t tpk = pgp_tsk_tpk (tsk);

  /* Let's violate The Rules and forge a mutable reference from
   * the immutable one!  */
  pgp_tpk_t tpk_mut = (pgp_tpk_t) tpk;

  /* And try to convert the TPK to a TSK, moving the ownership!  */
  pgp_tpk_into_tsk (tpk_mut);

  /* Always clean up though.  */
  pgp_tsk_free (tsk);
  return 0;
}
