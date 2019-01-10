#ifndef SEQUOIA_OPENPGP_CRYPTO_H
#define SEQUOIA_OPENPGP_CRYPTO_H

typedef struct sq_mpi *sq_mpi_t;

/*/
/// Creates a signature.
///
/// This is a low-level mechanism to produce an arbitrary OpenPGP
/// signature.  Using this trait allows Sequoia to perform all
/// operations involving signing to use a variety of secret key
/// storage mechanisms (e.g. smart cards).
/*/
typedef struct sq_signer *sq_signer_t;

/*/
/// Frees a signer.
/*/
void sq_signer_free (sq_signer_t s);

/*/
/// A cryptographic key pair.
///
/// A `KeyPair` is a combination of public and secret key.  If both
/// are available in memory, a `KeyPair` is a convenient
/*/
typedef struct sq_key_pair *sq_key_pair_t;

/* Forward declaration.  */
typedef struct sq_p_key *sq_p_key_t;

/*/
/// Creates a new key pair.
/*/
void sq_key_pair_new (sq_p_key_t public, sq_mpi_t secret);

/*/
/// Frees a key pair.
/*/
void sq_key_pair_free (sq_key_pair_t kp);

/*/
/// Creates a signer from a key pair.
///
/// Note that the returned object merely references the key pair, and
/// must not outlive the key pair.
/*/
sq_signer_t sq_key_pair_as_signer (sq_key_pair_t kp);

#endif /* SEQUOIA_OPENPGP_CRYPTO_H */
