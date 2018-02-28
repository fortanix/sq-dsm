#ifndef SEQUOIA_OPENPGP_H
#define SEQUOIA_OPENPGP_H

#include <sequoia/core.h>

/* sequoia::openpgp::KeyID.  */

/*/
/// Holds a KeyID.
/*/
typedef struct sq_keyid *sq_keyid_t;

/*/
/// Reads a binary key ID.
/*/
sq_keyid_t sq_keyid_from_bytes (const uint8_t *id);

/*/
/// Reads a hex-encoded Key ID.
/*/
sq_keyid_t sq_keyid_from_hex (const char *id);

/*/
/// Frees a sq_keyid_t.
/*/
void sq_keyid_free (sq_keyid_t keyid);

/*/
/// Converts the KeyID to its standard representation.
/*/
char *sq_keyid_to_string (const sq_keyid_t fp);

/*/
/// Converts the KeyID to a hexadecimal number.
/*/
char *sq_keyid_to_hex (const sq_keyid_t fp);

/*/
/// Compares KeyIDs.
/*/
int sq_keyid_equal (const sq_keyid_t a, const sq_keyid_t b);


/* sequoia::openpgp::Fingerprint.  */

/*/
/// Holds a fingerprint.
/*/
typedef struct sq_fingerprint *sq_fingerprint_t;

/*/
/// Reads a binary fingerprint.
/*/
sq_fingerprint_t sq_fingerprint_from_bytes (const uint8_t *buf, size_t len);

/*/
/// Reads a hexadecimal fingerprint.
/*/
sq_fingerprint_t sq_fingerprint_from_hex (const char *hex);

/*/
/// Frees a sq_fingerprint_t.
/*/
void sq_fingerprint_free (sq_fingerprint_t fp);

/*/
/// Converts the fingerprint to its standard representation.
/*/
char *sq_fingerprint_to_string (const sq_fingerprint_t fp);

/*/
/// Converts the fingerprint to a hexadecimal number.
/*/
char *sq_fingerprint_to_hex (const sq_fingerprint_t fp);

/*/
/// Converts the fingerprint to a key ID.
/*/
sq_keyid_t sq_fingerprint_to_keyid (const sq_fingerprint_t fp);

/*/
/// Compares Fingerprints.
/*/
int sq_fingerprint_equal (const sq_fingerprint_t a, const sq_fingerprint_t b);


/* openpgp::armor.  */

/*/
/// Specifies the type of data (see [RFC 4880, section 6.2]).
///
/// [RFC 4880, section 6.2]: https://tools.ietf.org/html/rfc4880#section-6.2
/*/
typedef enum sq_armor_kind {
  /*/
  /// A generic OpenPGP message.
  /*/
  SQ_ARMOR_KIND_MESSAGE,

  /*/
  /// A transferable public key.
  /*/
  SQ_ARMOR_KIND_PUBLICKEY,

  /*/
  /// A transferable secret key.
  /*/
  SQ_ARMOR_KIND_PRIVATEKEY,

  /*/
  /// Alias for PrivateKey.
  /*/
  SQ_ARMOR_KIND_SECRETKEY,

  /*/
  /// A detached signature.
  /*/
  SQ_ARMOR_KIND_SIGNATURE,

  /*/
  /// A generic file.  This is a GnuPG extension.
  /*/
  SQ_ARMOR_KIND_FILE,

  /*/
  /// When reading an Armored file, accept any type.
  /*/
  SQ_ARMOR_KIND_ANY,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_ARMOR_KIND_FORCE_WIDTH = INT_MAX,
} sq_armor_kind_t;

/*/
/// Constructs a new filter for the given type of data.
///
/// A filter that strips ASCII Armor from a stream of data.
/*/
sq_reader_t sq_armor_reader_new (sq_reader_t inner, sq_armor_kind_t kind);

/*/
/// Constructs a new filter for the given type of data.
///
/// A filter that applies ASCII Armor to the data written to it.
/*/
sq_writer_t sq_armor_writer_new (sq_writer_t inner, sq_armor_kind_t kind);


/* sequoia::keys.  */

/*/
/// A transferable public key (TPK).
///
/// A TPK (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
/*/
typedef struct sq_tpk *sq_tpk_t;

/*/
/// Returns the first TPK encountered in the reader.
/*/
sq_tpk_t sq_tpk_from_reader (sq_context_t ctx,
			     sq_reader_t reader);

/*/
/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP encoded message.
/*/
sq_tpk_t sq_tpk_from_bytes (sq_context_t ctx,
			    const char *b, size_t len);

/*/
/// Frees the TPK.
/*/
void sq_tpk_free (sq_tpk_t tpk);

/*/
/// Dumps the TPK.
/*/
void sq_tpk_dump (const sq_tpk_t tpk);

/*/
/// Returns the fingerprint.
/*/
sq_fingerprint_t sq_tpk_fingerprint (const sq_tpk_t tpk);

#endif
