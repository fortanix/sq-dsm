#ifndef SEQUOIA_ERRORS_H
#define SEQUOIA_ERRORS_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

/* XXX: Reorder and name-space before release.  */
typedef enum pgp_status {
  /*/
  /// The operation was successful.
  /*/
  PGP_STATUS_SUCCESS = 0,

  /*/
  /// An unknown error occurred.
  /*/
  PGP_STATUS_UNKNOWN_ERROR = -1,

  /*/
  /// The network policy was violated by the given action.
  /*/
  PGP_STATUS_NETWORK_POLICY_VIOLATION = -2,

  /*/
  /// An IO error occurred.
  /*/
  PGP_STATUS_IO_ERROR = -3,

  /*/
  /// A given argument is invalid.
  /*/
  PGP_STATUS_INVALID_ARGUMENT = -15,

  /*/
  /// The requested operation is invalid.
  /*/
  PGP_STATUS_INVALID_OPERATION = -4,

  /*/
  /// The packet is malformed.
  /*/
  PGP_STATUS_MALFORMED_PACKET = -5,

  /*/
  /// Unsupported hash algorithm.
  /*/
  PGP_STATUS_UNSUPPORTED_HASH_ALGORITHM = -9,

  /*/
  /// Unsupported public key algorithm.
  /*/
  PGP_STATUS_UNSUPPORTED_PUBLICKEY_ALGORITHM = -18,

  /*/
  /// Unsupported elliptic curve.
  /*/
  PGP_STATUS_UNSUPPORTED_ELLIPTIC_CURVE = -21,

  /*/
  /// Unsupported symmetric algorithm.
  /*/
  PGP_STATUS_UNSUPPORTED_SYMMETRIC_ALGORITHM = -10,

  /*/
  /// Unsupported AEAD algorithm.
  /*/
  PGP_STATUS_UNSUPPORTED_AEAD_ALGORITHM = -26,

  /*/
  /// Unsupport signature type.
  /*/
  PGP_STATUS_UNSUPPORTED_SIGNATURE_TYPE = -20,

  /*/
  /// Invalid password.
  /*/
  PGP_STATUS_INVALID_PASSWORD = -11,

  /*/
  /// Invalid session key.
  /*/
  PGP_STATUS_INVALID_SESSION_KEY = -12,

  /*/
  /// Missing session key.
  /*/
  PGP_STATUS_MISSING_SESSION_KEY = -27,

  /*/
  /// Malformed TPK.
  /*/
  PGP_STATUS_MALFORMED_TPK = -13,

  /*/
  /// Bad signature.
  /*/
  PGP_STATUS_BAD_SIGNATURE = -19,

  /*/
  /// Message has been manipulated.
  /*/
  PGP_STATUS_MANIPULATED_MESSAGE = -25,

  /*/
  /// Malformed message.
  /*/
  PGP_STATUS_MALFORMED_MESSAGE = -22,

  /*/
  /// Index out of range.
  /*/
  PGP_STATUS_INDEX_OUT_OF_RANGE = -23,

  /*/
  /// TPK not supported.
  /*/
  PGP_STATUS_UNSUPPORTED_TPK = -24,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_STATUS_FORCE_WIDTH = INT_MAX,
} pgp_status_t;

/*/
/// Complex errors returned from Sequoia.
/*/
typedef struct pgp_error *pgp_error_t;

/*/
/// Frees an error.
/*/
void pgp_error_free (pgp_error_t error);

/*/
/// Returns the error message.
///
/// The returned value must be freed with `free(3)`.
/*/
char *pgp_error_string (const pgp_error_t err);

/*/
/// Returns the error status code.
/*/
pgp_status_t pgp_error_status (const pgp_error_t err);

#endif
