#ifndef SEQUOIA_OPENPGP_CRYPTO_H
#define SEQUOIA_OPENPGP_CRYPTO_H

#include <sequoia/openpgp/types.h>

typedef struct pgp_mpi *pgp_mpi_t;

/*/
/// Creates a signature.
///
/// This is a low-level mechanism to produce an arbitrary OpenPGP
/// signature.  Using this trait allows Sequoia to perform all
/// operations involving signing to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
/*/
typedef struct pgp_signer *pgp_signer_t;

/*/
/// Frees a signer.
/*/
void pgp_signer_free (pgp_signer_t s);

/*/
/// A cryptographic key pair.
///
/// A `KeyPair` is a combination of public and secret key.  If both
/// are available in memory, a `KeyPair` is a convenient
/*/
typedef struct pgp_key_pair *pgp_key_pair_t;

/*/
/// Creates a new key pair.
/*/
void pgp_key_pair_new (pgp_key_t public, pgp_mpi_t secret);

/*/
/// Frees a key pair.
/*/
void pgp_key_pair_free (pgp_key_pair_t kp);

/*/
/// Creates a signer from a key pair.
///
/// Note that the returned object merely references the key pair, and
/// must not outlive the key pair.
/*/
pgp_signer_t pgp_key_pair_as_signer (pgp_key_pair_t kp);

#endif /* SEQUOIA_OPENPGP_CRYPTO_H */
