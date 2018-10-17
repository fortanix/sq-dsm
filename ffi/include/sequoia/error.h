#ifndef SEQUOIA_ERRORS_H
#define SEQUOIA_ERRORS_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

/* XXX: Reorder and name-space before release.  */
typedef enum sq_status {
  /*/
  /// The operation was successful.
  /*/
  SQ_STATUS_SUCCESS = 0,

  /*/
  /// An unknown error occurred.
  /*/
  SQ_STATUS_UNKNOWN_ERROR = -1,

  /*/
  /// The network policy was violated by the given action.
  /*/
  SQ_STATUS_NETWORK_POLICY_VIOLATION = -2,

  /*/
  /// An IO error occurred.
  /*/
  SQ_STATUS_IO_ERROR = -3,

  /*/
  /// A given argument is invalid.
  /*/
  SQ_STATUS_INVALID_ARGUMENT = -15,

  /*/
  /// The requested operation is invalid.
  /*/
  SQ_STATUS_INVALID_OPERATION = -4,

  /*/
  /// The packet is malformed.
  /*/
  SQ_STATUS_MALFORMED_PACKET = -5,

  /*/
  /// Unsupported hash algorithm.
  /*/
  SQ_STATUS_UNSUPPORTED_HASH_ALGORITHM = -9,

  /*/
  /// Unsupported public key algorithm.
  /*/
  SQ_STATUS_UNSUPPORTED_PUBLICKEY_ALGORITHM = -18,

  /*/
  /// Unsupported elliptic curve.
  /*/
  SQ_STATUS_UNSUPPORTED_ELLIPTIC_CURVE = -21,

  /*/
  /// Unsupported symmetric algorithm.
  /*/
  SQ_STATUS_UNSUPPORTED_SYMMETRIC_ALGORITHM = -10,

  /*/
  /// Unsupported AEAD algorithm.
  /*/
  SQ_STATUS_UNSUPPORTED_AEAD_ALGORITHM = -26,

  /*/
  /// Unsupport signature type.
  /*/
  SQ_STATUS_UNSUPPORTED_SIGNATURE_TYPE = -20,

  /*/
  /// Invalid password.
  /*/
  SQ_STATUS_INVALID_PASSWORD = -11,

  /*/
  /// Invalid session key.
  /*/
  SQ_STATUS_INVALID_SESSION_KEY = -12,

  /*/
  /// Malformed TPK.
  /*/
  SQ_STATUS_MALFORMED_TPK = -13,

  /*/
  /// Bad signature.
  /*/
  SQ_STATUS_BAD_SIGNATURE = -19,

  /*/
  /// Message has been manipulated.
  /*/
  SQ_STATUS_MANIPULATED_MESSAGE = -25,

  /*/
  /// Malformed message.
  /*/
  SQ_STATUS_MALFORMED_MESSAGE = -22,

  /*/
  /// Index out of range.
  /*/
  SQ_STATUS_INDEX_OUT_OF_RANGE = -23,

  /*/
  /// TPK not supported.
  /*/
  SQ_STATUS_UNSUPPORTED_TPK = -24,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_STATUS_FORCE_WIDTH = INT_MAX,
} sq_status_t;

/*/
/// Complex errors returned from Sequoia.
/*/
typedef struct sq_error *sq_error_t;

/*/
/// Frees an error.
/*/
void sq_error_free (sq_error_t error);

/*/
/// Returns the error message.
///
/// The returned value must be freed with `sq_string_free`.
/*/
char *sq_error_string (const sq_error_t err);

/*/
/// Returns the error status code.
/*/
sq_status_t sq_error_status (const sq_error_t err);

#endif
