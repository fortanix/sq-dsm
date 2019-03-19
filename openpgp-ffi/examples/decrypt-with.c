/* This example demonstrates how to use the low-level interface to
   decrypt a file.  */

#define _GNU_SOURCE
#include <assert.h>
#include <error.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sequoia/openpgp.h>

struct decrypt_cookie {
  pgp_tpk_t key;
  int get_secret_keys_called;
};

static pgp_status_t
get_public_keys_cb (void *cookie_raw,
                    pgp_keyid_t *keyids, size_t keyids_len,
                    pgp_tpk_t **tpks, size_t *tpk_len,
                    void (**our_free)(void *))
{
  /* Feed the TPKs to the verifier here.  */
  *tpks = NULL;
  *tpk_len = 0;
  *our_free = free;
  return PGP_STATUS_SUCCESS;
}

static pgp_status_t
check_signatures_cb(void *cookie_opaque,
                   pgp_verification_results_t results, size_t levels)
{
  /* Implement your verification policy here.  */
  return PGP_STATUS_SUCCESS;
}

static pgp_status_t
get_secret_keys_cb (void *cookie_opaque,
                    pgp_pkesk_t *pkesks, size_t pkesk_count,
                    pgp_skesk_t *skesks, size_t skesk_count,
                    pgp_secret_t *secret)
{
  pgp_error_t err;
  struct decrypt_cookie *cookie = cookie_opaque;

  /* Prevent iterations, we only have one key to offer.  */
  if (cookie->get_secret_keys_called)
    return PGP_STATUS_UNKNOWN_ERROR;
  cookie->get_secret_keys_called = 1;

  for (int i = 0; i < pkesk_count; i++) {
    pgp_pkesk_t pkesk = pkesks[i];
    pgp_keyid_t keyid = pgp_pkesk_recipient (pkesk);

    pgp_tpk_key_iter_t key_iter = pgp_tpk_key_iter_all (cookie->key);
    pgp_key_t key;
    while ((key = pgp_tpk_key_iter_next (key_iter, NULL, NULL))) {
      pgp_keyid_t this_keyid = pgp_key_keyid (key);
      int match = pgp_keyid_equal (this_keyid, keyid);
      pgp_keyid_free (this_keyid);
      if (match)
        break;
      pgp_key_free (key);
    }
    pgp_tpk_key_iter_free (key_iter);
    pgp_keyid_free (keyid);
    if (! key)
      continue;

    uint8_t algo;
    uint8_t session_key[1024];
    size_t session_key_len = sizeof session_key;
    if (pgp_pkesk_decrypt (&err,
                           pkesk, key, &algo,
                           session_key, &session_key_len)) {
      error (1, 0, "pgp_pkesk_decrypt: %s", pgp_error_to_string (err));
    }
    pgp_key_free (key);

    *secret = pgp_secret_cached (algo, session_key, session_key_len);
    return PGP_STATUS_SUCCESS;
  }

  return PGP_STATUS_UNKNOWN_ERROR;
}

int
main (int argc, char **argv)
{
  pgp_status_t rc;
  pgp_error_t err;
  pgp_tpk_t tpk;
  pgp_reader_t source;
  pgp_writer_t sink;

  if (argc != 2)
    error (1, 0, "Usage: %s <keyfile> <cipher >plain", argv[0]);

  tpk = pgp_tpk_from_file (&err, argv[1]);
  if (tpk == NULL)
    error (1, 0, "pgp_tpk_from_file: %s", pgp_error_to_string (err));

  source = pgp_reader_from_fd (STDIN_FILENO);
  assert (source);
  sink = pgp_writer_from_fd (STDOUT_FILENO);
  assert (sink);

  struct decrypt_cookie cookie = {
    .key = tpk,
    .get_secret_keys_called = 0,
  };
  rc = pgp_decrypt (&err, source, sink,
                    get_public_keys_cb, get_secret_keys_cb,
                    check_signatures_cb, &cookie);
  if (rc)
    error (1, 0, "pgp_decrypt: %s", pgp_error_to_string (err));

  pgp_writer_free (sink);
  pgp_reader_free (source);
  pgp_tpk_free (tpk);
  return 0;
}
