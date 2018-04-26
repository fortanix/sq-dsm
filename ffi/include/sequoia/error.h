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
  /// Unknown packet type.
  /*/
  SQ_STATUS_UNKNOWN_PACKET_TAG = -6,

  /*/
  /// Unknown hash algorithm.
  /*/
  SQ_STATUS_UNKNOWN_HASH_ALGORITHM = -7,

  /*/
  /// Unknown symmetric algorithm.
  /*/
  SQ_STATUS_UNKNOWN_SYMMETRIC_ALGORITHM = -8,

  /*/
  /// Unsupported hash algorithm.
  /*/
  SQ_STATUS_UNSUPPORTED_HASH_ALGORITHM = -9,

  /*/
  /// Unsupported symmetric algorithm.
  /*/
  SQ_STATUS_UNSUPPORTED_SYMMETRIC_ALGORITHM = -10,

  /*/
  /// Invalid password.
  /*/
  SQ_STATUS_INVALID_PASSWORD = -11,

  /*/
  /// Invalid session key.
  /*/
  SQ_STATUS_INVALID_SESSION_KEY = -12,

  /*/
  /// Key not found.
  /*/
  SQ_STATUS_KEY_NOT_FOUND = -13,

  /*/
  /// User ID not found.
  /*/
  SQ_STATUS_USER_ID_NOT_FOUND = -14,

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
