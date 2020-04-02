#ifndef SEQUOIA_OPENPGP_CRYPTO_H
#define SEQUOIA_OPENPGP_CRYPTO_H

#include <sequoia/openpgp/types.h>

/*/
/// Creates a new session key.
/*/
pgp_session_key_t pgp_session_key_new (size_t size);

/*/
/// Creates a new session key from a buffer.
/*/
pgp_session_key_t pgp_session_key_from_bytes (uint8_t *buf, size_t size);

/*/
/// Frees a session key.
/*/
void pgp_session_key_free (pgp_session_key_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_session_key_debug (const pgp_session_key_t fp);

/*/
/// Clones the session key.
/*/
pgp_session_key_t pgp_session_key_clone (pgp_session_key_t session_key);

/*/
/// Compares session keys.
/*/
bool pgp_session_key_equal (const pgp_session_key_t a,
			   const pgp_session_key_t b);

/*/
/// Creates a new password from a buffer.
/*/
pgp_password_t pgp_password_from_bytes (uint8_t *buf, size_t size);

/*/
/// Frees a password.
/*/
void pgp_password_free (pgp_password_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_password_debug (const pgp_password_t fp);

/*/
/// Clones the password.
/*/
pgp_password_t pgp_password_clone (pgp_password_t password);

/*/
/// Compares passwords.
/*/
bool pgp_password_equal (const pgp_password_t a, const pgp_password_t b);

typedef struct pgp_key_unencrypted *pgp_key_unencrypted_t;

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
void pgp_key_pair_new (pgp_key_t pub, pgp_key_unencrypted_t secret);

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
