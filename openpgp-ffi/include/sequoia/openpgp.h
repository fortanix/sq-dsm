#ifndef SEQUOIA_OPENPGP_H
#define SEQUOIA_OPENPGP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>

#include <sequoia/io.h>
#include <sequoia/openpgp/error.h>
#include <sequoia/openpgp/crypto.h>

/*/
/// A low-level OpenPGP message parser.
///
/// A `PacketParser` provides a low-level, iterator-like interface to
/// parse OpenPGP messages.
///
/// For each iteration, the user is presented with a [`Packet`]
/// corresponding to the last packet, a `PacketParser` for the next
/// packet, and their positions within the message.
///
/// Using the `PacketParser`, the user is able to configure how the
/// new packet will be parsed.  For instance, it is possible to stream
/// the packet's contents (a `PacketParser` implements the
/// `std::io::Read` and the `BufferedReader` traits), buffer them
/// within the [`Packet`], or drop them.  The user can also decide to
/// recurse into the packet, if it is a container, instead of getting
/// the following packet.
/*/
typedef struct pgp_packet_parser *pgp_packet_parser_t;

/*/
/// Like an `Option<PacketParser>`, but the `None` variant
/// (`PacketParserEOF`) contains some summary information.
/*/
typedef struct pgp_packet_parser_result *pgp_packet_parser_result_t;

/*/
/// The `None` variant of a `PacketParserResult`.
/*/
typedef struct pgp_packet_parser_eof *pgp_packet_parser_eof_t;

/* sequoia::openpgp::KeyID.  */

/*/
/// Holds a KeyID.
/*/
typedef struct pgp_keyid *pgp_keyid_t;

/*/
/// Reads a binary key ID.
/*/
pgp_keyid_t pgp_keyid_from_bytes (const uint8_t *id);

/*/
/// Reads a hex-encoded Key ID.
/*/
pgp_keyid_t pgp_keyid_from_hex (const char *id);

/*/
/// Frees a pgp_keyid_t.
/*/
void pgp_keyid_free (pgp_keyid_t keyid);

/*/
/// Clones the KeyID.
/*/
pgp_keyid_t pgp_keyid_clone (pgp_keyid_t keyid);

/*/
/// Hashes the KeyID.
/*/
uint64_t pgp_keyid_hash (pgp_keyid_t keyid);

/*/
/// Converts the KeyID to its standard representation.
/*/
char *pgp_keyid_to_string (const pgp_keyid_t fp);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_keyid_debug (const pgp_keyid_t fp);

/*/
/// Converts the KeyID to a hexadecimal number.
/*/
char *pgp_keyid_to_hex (const pgp_keyid_t keyid);

/*/
/// Compares KeyIDs.
/*/
int pgp_keyid_equal (const pgp_keyid_t a, const pgp_keyid_t b);


/* sequoia::openpgp::Fingerprint.  */

/*/
/// Holds a fingerprint.
/*/
typedef struct pgp_fingerprint *pgp_fingerprint_t;

/*/
/// Reads a binary fingerprint.
/*/
pgp_fingerprint_t pgp_fingerprint_from_bytes (const uint8_t *buf, size_t len);

/*/
/// Reads a hexadecimal fingerprint.
/*/
pgp_fingerprint_t pgp_fingerprint_from_hex (const char *hex);

/*/
/// Frees a pgp_fingerprint_t.
/*/
void pgp_fingerprint_free (pgp_fingerprint_t fp);

/*/
/// Clones the Fingerprint.
/*/
pgp_fingerprint_t pgp_fingerprint_clone (pgp_fingerprint_t fingerprint);

/*/
/// Hashes the Fingerprint.
/*/
uint64_t pgp_fingerprint_hash (pgp_fingerprint_t fingerprint);

/*/
/// Returns a reference to the raw Fingerprint.
///
/// This returns a reference to the internal buffer that is valid as
/// long as the fingerprint is.
/*/
uint8_t *pgp_fingerprint_as_bytes (const pgp_fingerprint_t fp, size_t *fp_len);

/*/
/// Converts the fingerprint to its standard representation.
/*/
char *pgp_fingerprint_to_string (const pgp_fingerprint_t fp);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_fingerprint_debug (const pgp_fingerprint_t fp);

/*/
/// Converts the fingerprint to a hexadecimal number.
/*/
char *pgp_fingerprint_to_hex (const pgp_fingerprint_t fp);

/*/
/// Converts the fingerprint to a key ID.
/*/
pgp_keyid_t pgp_fingerprint_to_keyid (const pgp_fingerprint_t fp);

/*/
/// Compares Fingerprints.
/*/
int pgp_fingerprint_equal (const pgp_fingerprint_t a, const pgp_fingerprint_t b);

/* sequoia::openpgp::RevocationStatus.  */

/*/
/// Holds a revocation status.
/*/
typedef struct pgp_revocation_status *pgp_revocation_status_t;

typedef enum pgp_revocation_status_variant {
  /*/
  /// The key is definitely revoked.
  ///
  /// All self-revocations are returned, the most recent revocation
  /// first.
  /*/
  PGP_REVOCATION_STATUS_REVOKED,

  /*/
  /// We have a third-party revocation certificate that is allegedly
  /// from a designated revoker, but we don't have the designated
  /// revoker's key to check its validity.
  ///
  /// All such certificates are returned.  The caller must check
  /// them manually.
  /*/
  PGP_REVOCATION_STATUS_COULD_BE,

  /*/
  /// The key does not appear to be revoked, but perhaps an attacker
  /// has performed a DoS, which prevents us from seeing the
  /// revocation certificate.
  /*/
  PGP_REVOCATION_STATUS_NOT_AS_FAR_AS_WE_KNOW,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_REVOCATION_STATUS_FORCE_WIDTH = INT_MAX,
} pgp_revocation_status_variant_t;

/*/
/// Returns the revocation status's variant.
/*/
pgp_revocation_status_variant_t pgp_revocation_status_variant (
    pgp_revocation_status_t rs);

/*/
/// Frees the revocation status.
/*/
void pgp_revocation_status_free (pgp_revocation_status_t rs);


/* openpgp::armor.  */

/*/
/// Specifies the type of data (see [RFC 4880, section 6.2]).
///
/// [RFC 4880, section 6.2]: https://tools.ietf.org/html/rfc4880#section-6.2
/*/
typedef enum pgp_armor_kind {
  /*/
  /// When reading an Armored file, accept any type.
  /*/
  PGP_ARMOR_KIND_ANY,

  /*/
  /// A generic OpenPGP message.
  /*/
  PGP_ARMOR_KIND_MESSAGE,

  /*/
  /// A transferable public key.
  /*/
  PGP_ARMOR_KIND_PUBLICKEY,

  /*/
  /// A transferable secret key.
  /*/
  PGP_ARMOR_KIND_SECRETKEY,

  /*/
  /// A detached signature.
  /*/
  PGP_ARMOR_KIND_SIGNATURE,

  /*/
  /// A generic file.  This is a GnuPG extension.
  /*/
  PGP_ARMOR_KIND_FILE,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_ARMOR_KIND_FORCE_WIDTH = INT_MAX,
} pgp_armor_kind_t;

/*/
/// Represents a (key, value) pair in an armor header.
/*/
typedef struct pgp_armor_header {
  char *key;
  char *value;
} pgp_armor_header_t;


/*/
/// Constructs a new filter for the given type of data.
///
/// A filter that strips ASCII Armor from a stream of data.
/*/
pgp_reader_t pgp_armor_reader_new (pgp_reader_t inner, pgp_armor_kind_t kind);

/*/
/// Creates a `Reader` from a file.
/*/
pgp_reader_t pgp_armor_reader_from_file (pgp_error_t *errp,
				       const char *filename,
				       pgp_armor_kind_t kind);

/*/
/// Creates a `Reader` from a buffer.
/*/
pgp_reader_t pgp_armor_reader_from_bytes (const uint8_t *b, size_t len,
					pgp_armor_kind_t kind);


/*/
/// Returns the kind of data this reader is for.
///
/// Useful if the kind of data is not known in advance.  If the header
/// has not been encountered yet (try reading some data first!), this
/// function returns PGP_ARMOR_KIND_ANY.
/*/
pgp_armor_kind_t pgp_armor_reader_kind (pgp_reader_t reader);

/*/
/// Returns the armored headers.
///
/// The tuples contain a key and a value.
///
/// Note: if a key occurs multiple times, then there are multiple
/// entries in the vector with the same key; values with the same
/// key are *not* combined.
///
/// The returned array and the strings in the headers have been
/// allocated with `malloc`, and the caller is responsible for freeing
/// both the array and the strings.
/*/
pgp_armor_header_t *pgp_armor_reader_headers (pgp_error_t *errp,
					    pgp_reader_t reader,
					    size_t *len);


/*/
/// Constructs a new filter for the given type of data.
///
/// A filter that applies ASCII Armor to the data written to it.
/*/
pgp_writer_t pgp_armor_writer_new (pgp_error_t *errp, pgp_writer_t inner,
				 pgp_armor_kind_t kind,
				 pgp_armor_header_t *header, size_t header_len);



/*/
/// The OpenPGP packet tags as defined in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
///
/// The values correspond to the serialized format.  The packet types
/// named `UnassignedXX` are not in use as of RFC 4880.
///
/// Use [`Tag::from_numeric`] to translate a numeric value to a symbolic
/// one.
///
///   [`Tag::from_numeric`]: enum.Tag.html#method.from_numeric
/*/
typedef enum pgp_tag {
    PGP_TAG_RESERVED0 = 0,
    /* Public-Key Encrypted Session Key Packet.  */
    PGP_TAG_PKESK = 1,
    PGP_TAG_SIGNATURE = 2,
    /* Symmetric-Key Encrypted Session Key Packet.  */
    PGP_TAG_SKESK = 3,
    /* One-Pass Signature Packet.  */
    PGP_TAG_ONE_PASS_SIG = 4,
    PGP_TAG_SECRET_KEY = 5,
    PGP_TAG_PUBLIC_KEY = 6,
    PGP_TAG_SECRET_SUBKEY = 7,
    PGP_TAG_COMPRESSED_DATA = 8,
    /* Symmetrically Encrypted Data Packet.  */
    PGP_TAG_SED = 9,
    PGP_TAG_MARKER = 10,
    PGP_TAG_LITERAL = 11,
    PGP_TAG_TRUST = 12,
    PGP_TAG_USER_ID = 13,
    PGP_TAG_PUBLIC_SUBKEY = 14,

    PGP_TAG_UNASSIGNED15 = 15,
    PGP_TAG_UNASSIGNED16 = 16,

    PGP_TAG_USER_ATTRIBUTE = 17,
    /* Sym. Encrypted and Integrity Protected Data Packet.  */
    PGP_TAG_SEIP = 18,
    /* Modification Detection Code Packet.  */
    PGP_TAG_MDC = 19,

    /* Unassigned packets (as of RFC4880).  */
    PGP_TAG_UNASSIGNED20 = 20,
    PGP_TAG_UNASSIGNED21 = 21,
    PGP_TAG_UNASSIGNED22 = 22,
    PGP_TAG_UNASSIGNED23 = 23,
    PGP_TAG_UNASSIGNED24 = 24,
    PGP_TAG_UNASSIGNED25 = 25,
    PGP_TAG_UNASSIGNED26 = 26,
    PGP_TAG_UNASSIGNED27 = 27,
    PGP_TAG_UNASSIGNED28 = 28,
    PGP_TAG_UNASSIGNED29 = 29,

    PGP_TAG_UNASSIGNED30 = 30,
    PGP_TAG_UNASSIGNED31 = 31,
    PGP_TAG_UNASSIGNED32 = 32,
    PGP_TAG_UNASSIGNED33 = 33,
    PGP_TAG_UNASSIGNED34 = 34,
    PGP_TAG_UNASSIGNED35 = 35,
    PGP_TAG_UNASSIGNED36 = 36,
    PGP_TAG_UNASSIGNED37 = 37,
    PGP_TAG_UNASSIGNED38 = 38,
    PGP_TAG_UNASSIGNED39 = 39,

    PGP_TAG_UNASSIGNED40 = 40,
    PGP_TAG_UNASSIGNED41 = 41,
    PGP_TAG_UNASSIGNED42 = 42,
    PGP_TAG_UNASSIGNED43 = 43,
    PGP_TAG_UNASSIGNED44 = 44,
    PGP_TAG_UNASSIGNED45 = 45,
    PGP_TAG_UNASSIGNED46 = 46,
    PGP_TAG_UNASSIGNED47 = 47,
    PGP_TAG_UNASSIGNED48 = 48,
    PGP_TAG_UNASSIGNED49 = 49,

    PGP_TAG_UNASSIGNED50 = 50,
    PGP_TAG_UNASSIGNED51 = 51,
    PGP_TAG_UNASSIGNED52 = 52,
    PGP_TAG_UNASSIGNED53 = 53,
    PGP_TAG_UNASSIGNED54 = 54,
    PGP_TAG_UNASSIGNED55 = 55,
    PGP_TAG_UNASSIGNED56 = 56,
    PGP_TAG_UNASSIGNED57 = 57,
    PGP_TAG_UNASSIGNED58 = 58,
    PGP_TAG_UNASSIGNED59 = 59,

    /* Experimental packets.  */
    PGP_TAG_PRIVATE0 = 60,
    PGP_TAG_PRIVATE1 = 61,
    PGP_TAG_PRIVATE2 = 62,
    PGP_TAG_PRIVATE3 = 63,
} pgp_tag_t;

/*/
/// Returns a human-readable tag name.
/*/
const char *pgp_tag_to_string (pgp_tag_t tag);

/*/
/// Opaque types for all the Packets that Sequoia understands.
/*/
typedef struct pgp_unknown *pgp_unknown_t;
typedef struct pgp_signature *pgp_signature_t;
typedef struct pgp_one_pass_sig *pgp_one_pass_sig_t;
typedef struct pgp_key *pgp_key_t;
typedef struct pgp_user_id *pgp_user_id_t;
typedef struct pgp_user_attribute *pgp_user_attribute_t;
typedef struct pgp_literal *pgp_literal_t;
typedef struct pgp_compressed_data *pgp_compressed_data_t;
typedef struct pgp_pkesk *pgp_pkesk_t;
typedef struct pgp_skesk *pgp_skesk_t;
typedef struct pgp_seip *pgp_seip_t;
typedef struct pgp_mdc *pgp_mdc_t;

/*/
/// The OpenPGP packets that Sequoia understands.
///
/// The different OpenPGP packets are detailed in [Section 5 of RFC 4880].
///
/// The `Unknown` packet allows Sequoia to deal with packets that it
/// doesn't understand.  The `Unknown` packet is basically a binary
/// blob that includes the packet's tag.
///
/// The unknown packet is also used for packets that are understood,
/// but use unsupported options.  For instance, when the packet parser
/// encounters a compressed data packet with an unknown compression
/// algorithm, it returns the packet in an `Unknown` packet rather
/// than a `CompressedData` packet.
///
///   [Section 5 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5
/*/
typedef union pgp_packet {
  pgp_unknown_t unknown;
  pgp_signature_t signature;
  pgp_one_pass_sig_t one_pass_sig;
  pgp_key_t key;
  pgp_user_id_t user_id;
  pgp_user_attribute_t user_attribute;
  pgp_literal_t literal;
  pgp_compressed_data_t compressed_data;
  pgp_pkesk_t pkesk;
  pgp_skesk_t skesk;
  pgp_seip_t seip;
  pgp_mdc_t mdc;
} pgp_packet_t;

/*/
/// Frees the Packet.
/*/
void pgp_packet_free (pgp_packet_t p);

/*/
/// Returns the `Packet's` corresponding OpenPGP tag.
///
/// Tags are explained in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
/*/
pgp_tag_t pgp_packet_tag (pgp_packet_t p);

/*/
/// Returns the parsed `Packet's` corresponding OpenPGP tag.
///
/// Returns the packets tag, but only if it was successfully
/// parsed into the corresponding packet type.  If e.g. a
/// Signature Packet uses some unsupported methods, it is parsed
/// into an `Packet::Unknown`.  `tag()` returns `PGP_TAG_SIGNATURE`,
/// whereas `kind()` returns `0`.
/*/
pgp_tag_t pgp_packet_kind (pgp_packet_t p);

/* openpgp::PacketPile.  */

/*/
/// A `PacketPile` holds a deserialized OpenPGP message.
/*/
typedef struct pgp_packet_pile *pgp_packet_pile_t;

/*/
/// Deserializes the OpenPGP message stored in a `std::io::Read`
/// object.
///
/// Although this method is easier to use to parse an OpenPGP
/// packet pile than a `PacketParser` or a `PacketPileParser`, this
/// interface buffers the whole packet pile in memory.  Thus, the
/// caller must be certain that the *deserialized* packet pile is not
/// too large.
///
/// Note: this interface *does* buffer the contents of packets.
/*/
pgp_packet_pile_t pgp_packet_pile_from_reader (pgp_error_t *errp,
					     pgp_reader_t reader);

/*/
/// Deserializes the OpenPGP packet pile stored in the file named by
/// `filename`.
///
/// See `pgp_packet_pile_from_reader` for more details and caveats.
/*/
pgp_packet_pile_t pgp_packet_pile_from_file (pgp_error_t *errp,
					   const char *filename);

/*/
/// Deserializes the OpenPGP packet pile stored in the provided buffer.
///
/// See `pgp_packet_pile_from_reader` for more details and caveats.
/*/
pgp_packet_pile_t pgp_packet_pile_from_bytes (pgp_error_t *errp,
					    const uint8_t *b, size_t len);

/*/
/// Frees the packet pile.
/*/
void pgp_packet_pile_free (pgp_packet_pile_t message);

/*/
/// Clones the packet pile.
/*/
pgp_packet_pile_t pgp_packet_pile_clone (pgp_packet_pile_t message);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_packet_pile_debug (const pgp_packet_pile_t);

/*/
/// Compares Packet Piles.
/*/
bool pgp_packet_pile_equal (const pgp_packet_pile_t a,
                            const pgp_packet_pile_t b);

/*/
/// Serializes the packet pile.
/*/
pgp_status_t pgp_packet_pile_serialize (pgp_error_t *errp,
				      const pgp_packet_pile_t message,
				      pgp_writer_t writer);

/*/
/// Frees the signature.
/*/
void pgp_signature_free (pgp_signature_t signature);

/*/
/// Converts the signature to a packet.
/*/
pgp_packet_t pgp_signature_to_packet (pgp_signature_t signature);

/*/
/// Returns the value of the `Signature` packet's Issuer subpacket.
///
/// If there is no Issuer subpacket, this returns NULL.  Note: if
/// there is no Issuer subpacket, but there is an IssuerFingerprint
/// subpacket, this still returns NULL.
/*/
pgp_keyid_t pgp_signature_issuer(pgp_signature_t sig);

/*/
/// Returns the value of the `Signature` packet's IssuerFingerprint subpacket.
///
/// If there is no IssuerFingerprint subpacket, this returns NULL.
/// Note: if there is no IssuerFingerprint subpacket, but there is an
/// Issuer subpacket, this still returns NULL.
/*/
pgp_fingerprint_t pgp_signature_issuer_fingerprint(pgp_signature_t sig);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// make certifications.
/*/
bool pgp_signature_can_certify(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// make signatures.
/*/
bool pgp_signature_can_sign(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data for transport.
/*/
bool pgp_signature_can_encrypt_for_transport(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data at rest.
/*/
bool pgp_signature_can_encrypt_at_rest(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used
/// for authentication.
/*/
bool pgp_signature_can_authenticate(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key is a split
/// key.
/*/
bool pgp_signature_is_split_key(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key is a group
/// key.
/*/
bool pgp_signature_is_group_key(pgp_signature_t signature);

/*/
/// Returns whether the signature is alive.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired.
/*/
bool pgp_signature_alive(pgp_signature_t signature);

/*/
/// Returns whether the signature is alive at the specified time.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired at the specified time.
/*/
bool pgp_signature_alive_at(pgp_signature_t signature, time_t when);

/*/
/// Returns whether the signature is expired.
/*/
bool pgp_signature_expired(pgp_signature_t signature);

/*/
/// Returns whether the signature is expired at the specified time.
/*/
bool pgp_signature_expired_at(pgp_signature_t signature, time_t when);

/*/
/// Returns the PKESK's recipient.
///
/// The return value is a reference ot a `KeyID`.  The caller must not
/// modify or free it.
/*/
pgp_keyid_t pgp_pkesk_recipient(pgp_pkesk_t pkesk);

/*/
/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
/*/
pgp_status_t pgp_pkesk_decrypt (pgp_error_t *errp, pgp_pkesk_t pkesk,
                              pgp_key_t secret_key,
                              uint8_t *algo, /* XXX */
                              uint8_t *key, size_t *key_len);

typedef enum pgp_reason_for_revocation {
  /*/
  /// No reason specified (key revocations or cert revocations)
  /*/
  PGP_REASON_FOR_REVOCATION_UNSPECIFIED,

  /*/
  /// Key is superseded (key revocations)
  /*/
  PGP_REASON_FOR_REVOCATION_KEY_SUPERSEDED,

  /*/
  /// Key material has been compromised (key revocations)
  /*/
  PGP_REASON_FOR_REVOCATION_KEY_COMPROMISED,

  /*/
  /// Key is retired and no longer used (key revocations)
  /*/
  PGP_REASON_FOR_REVOCATION_KEY_RETIRED,

  /*/
  /// User ID information is no longer valid (cert revocations)
  /*/
  PGP_REASON_FOR_REVOCATION_UID_RETIRED,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_REASON_FOR_REVOCATION_FORCE_WIDTH = INT_MAX,
} pgp_reason_for_revocation_t;

/* openpgp::tpk::UserIDBinding.  */

/*/
/// A `UserIDBinding`.
/*/
typedef struct pgp_user_id_binding *pgp_user_id_binding_t;

/*/
/// Returns the user id.
///
/// This function may fail and return NULL if the user id contains an
/// interior NUL byte.  We do this rather than complicate the API, as
/// there is no valid use for such user ids; they must be malicious.
///
/// The caller must free the returned value.
/*/
char *pgp_user_id_binding_user_id (pgp_user_id_binding_t binding);

/*/
/// Returns a reference to the self-signature, if any.
/*/
pgp_signature_t pgp_user_id_binding_selfsig(pgp_user_id_binding_t binding);

/* openpgp::tpk::UserIDBindingIter.  */

/*/
/// An iterator over `UserIDBinding`s.
/*/
typedef struct pgp_user_id_binding_iter *pgp_user_id_binding_iter_t;

/*/
/// Returns the next element in the iterator.
/*/
pgp_user_id_binding_t pgp_user_id_binding_iter_next (pgp_user_id_binding_iter_t iter);

/// Frees an pgp_user_id_binding_iter_t.
void pgp_user_id_binding_iter_free (pgp_user_id_binding_iter_t iter);

/* openpgp::tpk::KeyIter.  */

/*/
/// An iterator over keys in a TPK.
/*/
typedef struct pgp_tpk_key_iter *pgp_tpk_key_iter_t;

/*/
/// Returns the next key.  Returns NULL if there are no more elements.
///
/// If sigo is not NULL, stores the current self-signature (if any) in
/// *sigo.  (Note: subkeys always have signatures, but a primary key
/// may not have a direct signature, and there might not be any user
/// ids.)
///
/// If rso is not NULL, this stores the key's revocation status in
/// *rso.
/*/
pgp_key_t pgp_tpk_key_iter_next (pgp_tpk_key_iter_t iter,
                                 pgp_signature_t *signature,
                                 pgp_revocation_status_t *rev);

/// Frees an pgp_tpk_key_iter_t.
void pgp_tpk_key_iter_free (pgp_tpk_key_iter_t iter);

/* openpgp::tpk.  */

/*/
/// A transferable public key (TPK).
///
/// A TPK (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
/*/
typedef struct pgp_tpk *pgp_tpk_t;


/*/
/// A transferable secret key (TSK).
///
/// A TSK (see [RFC 4880, section 11.2]) can be used to create
/// signatures and decrypt data.
///
/// [RFC 4880, section 11.2]: https://tools.ietf.org/html/rfc4880#section-11.2
/*/
typedef struct pgp_tsk *pgp_tsk_t;


/*/
/// Returns the first TPK encountered in the reader.
/*/
pgp_tpk_t pgp_tpk_from_reader (pgp_error_t *errp,
			     pgp_reader_t reader);

/*/
/// Returns the first TPK encountered in the file.
/*/
pgp_tpk_t pgp_tpk_from_file (pgp_error_t *errp,
                           const char *filename);

/*/
/// Returns the first TPK found in `m`.
///
/// Consumes `m`.
/*/
pgp_tpk_t pgp_tpk_from_packet_pile (pgp_error_t *errp,
				  pgp_packet_pile_t m);

/*/
/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP-encoded TPK.
/*/
pgp_tpk_t pgp_tpk_from_bytes (pgp_error_t *errp,
			    const uint8_t *b, size_t len);

/*/
/// Returns the first TPK found in the packet parser.
///
/// Consumes the packet parser result.
/*/
pgp_tpk_t pgp_tpk_from_packet_parser (pgp_error_t *errp,
                                    pgp_packet_parser_result_t ppr);

/*/
/// Frees the TPK.
/*/
void pgp_tpk_free (pgp_tpk_t tpk);

/*/
/// Clones the TPK.
/*/
pgp_tpk_t pgp_tpk_clone (pgp_tpk_t tpk);

/*/
/// Compares TPKs.
/*/
int pgp_tpk_equal (const pgp_tpk_t a, const pgp_tpk_t b);

/*/
/// Returns a human readable description of this object intended for
/// communication with end users.
/*/
char *pgp_tpk_to_string (const pgp_tpk_t fp);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_tpk_debug (const pgp_tpk_t fp);

/*/
/// Serializes the TPK.
/*/
pgp_status_t pgp_tpk_serialize (pgp_error_t *errp,
                              const pgp_tpk_t tpk,
                              pgp_writer_t writer);

/*/
/// Merges `other` into `tpk`.
///
/// If `other` is a different key, then nothing is merged into
/// `tpk`, but `tpk` is still canonicalized.
///
/// Consumes `tpk` and `other`.
/*/
pgp_tpk_t pgp_tpk_merge (pgp_error_t *errp,
                       pgp_tpk_t tpk,
                       pgp_tpk_t other);

/*/
/// Adds packets to the TPK.
///
/// This recanonicalizes the TPK.  If the packets are invalid, they
/// are dropped.
///
/// Consumes `tpk` and the packets in `packets`.  The buffer, however,
/// must be freed by the caller.
/*/
pgp_tpk_t pgp_tpk_merge_packets (pgp_error_t *errp,
                               pgp_tpk_t tpk,
                               pgp_packet_t *packets,
                               size_t packets_len);

/*/
/// Returns the fingerprint.
/*/
pgp_fingerprint_t pgp_tpk_fingerprint (const pgp_tpk_t tpk);


/*/
/// Cast the public key into a secret key that allows using the secret
/// parts of the containing keys.
/*/
pgp_tsk_t pgp_tpk_into_tsk (pgp_tpk_t tpk);

/*/
/// Returns a reference to the TPK's primary key.
///
/// The tpk still owns the key.  The caller should neither modify nor
/// free the key.
/*/
pgp_key_t pgp_tpk_primary (pgp_tpk_t tpk);

/*/
/// Returns the TPK's revocation status.
///
/// Note: this only returns whether the TPK has been revoked, and does
/// not reflect whether an individual user id, user attribute or
/// subkey has been revoked.
/*/
pgp_revocation_status_t pgp_tpk_revocation_status (pgp_tpk_t tpk);

/*/
/// Writes a revocation certificate to the writer.
///
/// This function consumes the writer.  It does *not* consume tpk.
/*/
pgp_signature_t pgp_tpk_revoke (pgp_error_t *errp,
                              pgp_tpk_t tpk,
                              pgp_signer_t primary_signer,
                              pgp_reason_for_revocation_t code,
                              const char *reason);

/*/
/// Adds a revocation certificate to the tpk.
///
/// This function consumes the tpk.
/*/
pgp_tpk_t pgp_tpk_revoke_in_place (pgp_error_t *errp,
                                 pgp_tpk_t tpk,
                                 pgp_signer_t primary_signer,
                                 pgp_reason_for_revocation_t code,
                                 const char *reason);

/*/
/// Returns whether the TPK has expired.
/*/
int pgp_tpk_expired(pgp_tpk_t tpk);

/*/
/// Returns whether the TPK has expired at the specified time.
/*/
int pgp_tpk_expired_at(pgp_tpk_t tpk, time_t at);

/*/
/// Returns whether the TPK is alive.
/*/
int pgp_tpk_alive(pgp_tpk_t tpk);

/*/
/// Returns whether the TPK is alive at the specified time.
/*/
int pgp_tpk_alive_at(pgp_tpk_t tpk, time_t at);

/*/
/// Changes the TPK's expiration.
///
/// Expiry is when the key should expire in seconds relative to the
/// key's creation (not the current time).
///
/// This function consumes `tpk` and returns a new `TPK`.
/*/
pgp_tpk_t pgp_tpk_set_expiry(pgp_error_t *errp,
                           pgp_tpk_t tpk,
                           uint32_t expiry);

/*/
/// Returns whether the TPK includes any secret key material.
/*/
int pgp_tpk_is_tsk(pgp_tpk_t tpk);

/*/
/// Returns an iterator over the `UserIDBinding`s.
/*/
pgp_user_id_binding_iter_t pgp_tpk_user_id_binding_iter (pgp_tpk_t tpk);

/*/
/// Returns an iterator over all `Key`s (both the primary key and any
/// subkeys) in a TPK.
/*/
pgp_tpk_key_iter_t pgp_tpk_key_iter (pgp_tpk_t tpk);

/*/
/// Returns the TPK's primary user id (if any).
/*/
char *pgp_tpk_primary_user_id(pgp_tpk_t tpk);

/* TPKBuilder */

typedef struct pgp_tpk_builder *pgp_tpk_builder_t;

typedef enum pgp_tpk_cipher_suite {
  /*/
  /// EdDSA and ECDH over Curve25519 with SHA512 and AES256.
  /*/
  PGP_TPK_CIPHER_SUITE_CV25519,

  /*/
  /// 3072 bit RSA with SHA512 and AES256.
  /*/
  PGP_TPK_CIPHER_SUITE_RSA3K,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_TPK_CIPHER_SUITE_FORCE_WIDTH = INT_MAX,
} pgp_tpk_cipher_suite_t;

/*/
/// Creates a default `pgp_tpk_builder_t`.
/*/
pgp_tpk_builder_t pgp_tpk_builder_default(void);

/*/
/// Generates a key compliant to [Autocrypt Level 1].
///
///   [Autocrypt Level 1]: https://autocrypt.org/level1.html
/*/
pgp_tpk_builder_t pgp_tpk_builder_autocrypt(void);

/*/
/// Frees an `pgp_tpk_builder_t`.
/*/
void pgp_tpk_builder_free(pgp_tpk_builder_t tpkb);

/*/
/// Sets the encryption and signature algorithms for primary and all
/// subkeys.
/*/
void pgp_tpk_builder_set_cipher_suite(pgp_tpk_builder_t *tpkb,
				     pgp_tpk_cipher_suite_t cs);

/*/
/// Adds a new user ID. The first user ID added replaces the default
/// ID that is just the empty string.
/*/
void pgp_tpk_builder_add_userid(pgp_tpk_builder_t *tpkb, const char *uid);

/*/
/// Adds a signing capable subkey.
/*/
void pgp_tpk_builder_add_signing_subkey(pgp_tpk_builder_t *tpkb);

/*/
/// Adds an encryption capable subkey.
/*/
void pgp_tpk_builder_add_encryption_subkey(pgp_tpk_builder_t *tpkb);

/*/
/// Adds an certification capable subkey.
/*/
void pgp_tpk_builder_add_certification_subkey(pgp_tpk_builder_t *tpkb);

/*/
/// Generates the actual TPK.
///
/// Consumes `tpkb`.
/*/
pgp_tpk_t pgp_tpk_builder_generate(pgp_error_t *errp, pgp_tpk_builder_t tpkb,
                                 pgp_tpk_t *tpk, pgp_signature_t *revocation);


/* TSK */

/*/
/// Generates a new RSA 3072 bit key with UID `primary_uid`.
/*/
pgp_status_t pgp_tsk_new (pgp_error_t *errp, char *primary_uid,
                        pgp_tsk_t *tpk, pgp_signature_t *revocation);

/*/
/// Frees the TSK.
/*/
void pgp_tsk_free (pgp_tsk_t tsk);

/*/
/// Clones the TSK.
/*/
pgp_tsk_t pgp_tsk_clone (pgp_tsk_t message);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_tsk_debug (const pgp_tsk_t);

/*/
/// Compares TPKs.
/*/
bool pgp_tsk_equal (const pgp_tsk_t a, const pgp_tsk_t b);

/*/
/// Returns a reference to the corresponding TPK.
/*/
pgp_tpk_t pgp_tsk_tpk (pgp_tsk_t tsk);

/*/
/// Converts the TSK into a TPK.
/*/
pgp_tpk_t pgp_tsk_into_tpk (pgp_tsk_t tsk);

/*/
/// Serializes the TSK.
/*/
pgp_status_t pgp_tsk_serialize (pgp_error_t *errp,
                              const pgp_tsk_t tsk,
                              pgp_writer_t writer);

/*/
/// Clones the key.
/*/
pgp_key_t pgp_key_clone (pgp_key_t key);

/*/
/// Computes and returns the key's fingerprint as per Section 12.2
/// of RFC 4880.
/*/
pgp_fingerprint_t pgp_key_fingerprint (pgp_key_t p);

/*/
/// Computes and returns the key's key ID as per Section 12.2 of RFC
/// 4880.
/*/
pgp_keyid_t pgp_key_keyid (pgp_key_t p);

/*/
/// Returns whether the key is expired according to the provided
/// self-signature.
///
/// Note: this is with respect to the provided signature, which is not
/// checked for validity.  That is, we do not check whether the
/// signature is a valid self-signature for the given key.
/*/
bool pgp_key_expired(pgp_key_t key, pgp_signature_t self_signature);

/*/
/// Like pgp_key_expired, but at a specific time.
/*/
bool pgp_key_expired_at(pgp_key_t key, pgp_signature_t self_signature,
                        time_t when);

/*/
/// Returns whether the key is alive according to the provided
/// self-signature.
///
/// A key is alive if the creation date is in the past, and the key
/// has not expired.
///
/// Note: this is with respect to the provided signature, which is not
/// checked for validity.  That is, we do not check whether the
/// signature is a valid self-signature for the given key.
/*/
bool pgp_key_alive(pgp_key_t key, pgp_signature_t self_signature);

/*/
/// Like pgp_key_alive, but at a specific time.
/*/
bool pgp_key_alive_at(pgp_key_t key, pgp_signature_t self_signature,
                      time_t when);

typedef enum pgp_public_key_algorithm {
  /*/
  /// RSA (Encrypt or Sign)
  /*/
  PGP_PUBLIC_KEY_ALGO_RSA_ENCRYPT_SIGN,

  /*/
  /// RSA Encrypt-Only
  /*/
  PGP_PUBLIC_KEY_ALGO_RSA_ENCRYPT,

  /*/
  /// RSA Sign-Only
  /*/
  PGP_PUBLIC_KEY_ALGO_RSA_SIGN,

  /*/
  /// Elgamal (Encrypt-Only)
  /*/
  PGP_PUBLIC_KEY_ALGO_ELGAMAL_ENCRYPT,

  /*/
  /// DSA (Digital Signature Algorithm)
  /*/
  PGP_PUBLIC_KEY_ALGO_DSA,

  /*/
  /// Elliptic curve DH
  /*/
  PGP_PUBLIC_KEY_ALGO_ECDH,

  /*/
  /// Elliptic curve DSA
  /*/
  PGP_PUBLIC_KEY_ALGO_ECDSA,

  /*/
  /// Elgamal (Encrypt or Sign)
  /*/
  PGP_PUBLIC_KEY_ALGO_ELGAMAL_ENCRYPT_SIGN,

  /*/
  /// "Twisted" Edwards curve DSA
  /*/
  PGP_PUBLIC_KEY_ALGO_EDDSA,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_PUBLIC_KEY_ALGO_FORCE_WIDTH = INT_MAX,
} sq_public_key_algo_t;

/*/
/// Returns the key's public key algorithm.
/*/
sq_public_key_algo_t pgp_key_public_key_algo(pgp_key_t key);

/*/
/// Returns the public key's size in bits.
/*/
int pgp_key_public_key_bits(pgp_key_t key);

/*/
/// Creates a new key pair from a Key packet with an unencrypted
/// secret key.
///
/// # Errors
///
/// Fails if the secret key is missing, or encrypted.
/*/
pgp_key_pair_t pgp_key_into_key_pair (pgp_error_t *errp, pgp_key_t key);

/*/
/// Returns the value of the User ID Packet.
///
/// The returned pointer is valid until `uid` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
/*/
const uint8_t *pgp_user_id_value (pgp_user_id_t uid,
				 size_t *value_len);

/*/
/// Returns the value of the User Attribute Packet.
///
/// The returned pointer is valid until `ua` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
/*/
const uint8_t *pgp_user_attribute_value (pgp_user_attribute_t ua,
					size_t *value_len);

/*/
/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
/*/
pgp_status_t pgp_skesk_decrypt (pgp_error_t *errp, pgp_skesk_t skesk,
                              const uint8_t *password, size_t password_len,
                              uint8_t *algo, /* XXX */
                              uint8_t *key, size_t *key_len);

/*/
/// Returns the key's creation time.
/*/
uint32_t pgp_key_creation_time (pgp_key_t p);

/* openpgp::parse.  */

/*/
/// Starts parsing an OpenPGP message stored in a `pgp_reader_t` object.
/*/
pgp_packet_parser_result_t pgp_packet_parser_from_reader (pgp_error_t *errp,
                                                        pgp_reader_t reader);

/*/
/// Starts parsing an OpenPGP message stored in a file named `path`.
/*/
pgp_packet_parser_result_t pgp_packet_parser_from_file (pgp_error_t *errp,
                                                      const char *filename);

/*/
/// Starts parsing an OpenPGP message stored in a buffer.
/*/
pgp_packet_parser_result_t pgp_packet_parser_from_bytes (pgp_error_t *errp,
                                                       const uint8_t *b,
                                                       size_t len);

/// Returns the current packet's tag.
///
/// This is a convenience function to inspect the containing packet,
/// without turning the `PacketParserResult` into a `PacketParser`.
///
/// This function does not consume the ppr.
///
/// Returns 0 if the PacketParserResult does not contain a packet.
pgp_tag_t pgp_packet_parser_result_tag(pgp_packet_parser_result_t ppr);

/*/
/// If the `PacketParserResult` contains a `PacketParser`, returns it,
/// otherwise, returns NULL.
///
/// If the `PacketParser` reached EOF, then the `PacketParserResult`
/// contains a `PacketParserEOF` and you should use
/// `pgp_packet_parser_result_eof` to get it.
///
/// If this function returns a `PacketParser`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParser` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParser` is freed.
/*/
pgp_packet_parser_t pgp_packet_parser_result_packet_parser (
    pgp_packet_parser_result_t ppr);

/*/
/// If the `PacketParserResult` contains a `PacketParserEOF`, returns
/// it, otherwise, returns NULL.
///
/// If the `PacketParser` did not yet reach EOF, then the
/// `PacketParserResult` contains a `PacketParser` and you should use
/// `pgp_packet_parser_result_packet_parser` to get it.
///
/// If this function returns a `PacketParserEOF`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParserEOF` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParserEOF` is freed.
/*/
pgp_packet_parser_eof_t pgp_packet_parser_result_eof (
    pgp_packet_parser_result_t ppr);

/*/
/// Frees the packet parser result.
/*/
void pgp_packet_parser_result_free (pgp_packet_parser_result_t ppr);

/*/
/// Frees the packet parser.
/*/
void pgp_packet_parser_free (pgp_packet_parser_t pp);

/*/
/// Returns whether the message is a well-formed OpenPGP message.
/*/
bool pgp_packet_parser_eof_is_message(pgp_packet_parser_eof_t eof);

/*/
/// Frees the packet parser EOF object.
/*/
void pgp_packet_parser_eof_free (pgp_packet_parser_eof_t eof);

/*/
/// Returns a reference to the packet that is being parsed.
/*/
pgp_packet_t pgp_packet_parser_packet (pgp_packet_parser_t pp);

/*/
/// Returns the current packet's recursion depth.
///
/// A top-level packet has a recursion depth of 0.  Packets in a
/// top-level container have a recursion depth of 1, etc.
/*/
uint8_t pgp_packet_parser_recursion_depth (pgp_packet_parser_t pp);

/*/
/// Finishes parsing the current packet and starts parsing the
/// next one.
///
/// This function finishes parsing the current packet.  By
/// default, any unread content is dropped.  (See
/// [`PacketParsererBuilder`] for how to configure this.)  It then
/// creates a new packet parser for the next packet.  If the
/// current packet is a container, this function does *not*
/// recurse into the container, but skips any packets it contains.
/// To recurse into the container, use the [`recurse()`] method.
///
///   [`PacketParsererBuilder`]: parse/struct.PacketParserBuilder.html
///   [`recurse()`]: #method.recurse
///
/// The return value is a tuple containing:
///
///   - A `Packet` holding the fully processed old packet;
///
///   - A `PacketParser` holding the new packet;
///
/// To determine the two packet's position within the parse tree,
/// you can use `last_path()` and `path()`, respectively.  To
/// determine their depth, you can use `last_recursion_depth()`
/// and `recursion_depth()`, respectively.
///
/// Note: A recursion depth of 0 means that the packet is a
/// top-level packet, a recursion depth of 1 means that the packet
/// is an immediate child of a top-level-packet, etc.
///
/// Since the packets are serialized in depth-first order and all
/// interior nodes are visited, we know that if the recursion
/// depth is the same, then the packets are siblings (they have a
/// common parent) and not, e.g., cousins (they have a common
/// grandparent).  This is because, if we move up the tree, the
/// only way to move back down is to first visit a new container
/// (e.g., an aunt).
///
/// Using the two positions, we can compute the change in depth as
/// new_depth - old_depth.  Thus, if the change in depth is 0, the
/// two packets are siblings.  If the value is 1, the old packet
/// is a container, and the new packet is its first child.  And,
/// if the value is -1, the new packet is contained in the old
/// packet's grandparent.  The idea is illustrated below:
///
/// ```text
///             ancestor
///             |       \
///            ...      -n
///             |
///           grandparent
///           |          \
///         parent       -1
///         |      \
///      packet    0
///         |
///         1
/// ```
///
/// Note: since this function does not automatically recurse into
/// a container, the change in depth will always be non-positive.
/// If the current container is empty, this function DOES pop that
/// container off the container stack, and returns the following
/// packet in the parent container.
///
/// The items of the tuple are returned in out-parameters.  If you do
/// not wish to receive the value, pass `NULL` as the parameter.
///
/// Consumes the given packet parser.
/*/
pgp_status_t pgp_packet_parser_next (pgp_error_t *errp,
                                   pgp_packet_parser_t pp,
                                   pgp_packet_t *old_packet,
                                   pgp_packet_parser_result_t *ppr);

/*/
/// Finishes parsing the current packet and starts parsing the
/// next one, recursing if possible.
///
/// This method is similar to the [`next()`] method (see that
/// method for more details), but if the current packet is a
/// container (and we haven't reached the maximum recursion depth,
/// and the user hasn't started reading the packet's contents), we
/// recurse into the container, and return a `PacketParser` for
/// its first child.  Otherwise, we return the next packet in the
/// packet stream.  If this function recurses, then the new
/// packet's position will be old_position + 1; because we always
/// visit interior nodes, we can't recurse more than one level at
/// a time.
///
///   [`next()`]: #method.next
///
/// The items of the tuple are returned in out-parameters.  If you do
/// not wish to receive the value, pass `NULL` as the parameter.
///
/// Consumes the given packet parser.
/*/
pgp_status_t pgp_packet_parser_recurse (pgp_error_t *errp,
                                      pgp_packet_parser_t pp,
                                      pgp_packet_t *old_packet,
                                      pgp_packet_parser_result_t *ppr);

/*/
/// Causes the PacketParser to buffer the packet's contents.
///
/// The packet's contents are stored in `packet.content`.  In
/// general, you should avoid buffering a packet's content and
/// prefer streaming its content unless you are certain that the
/// content is small.
/*/
uint8_t *pgp_packet_parser_buffer_unread_content (pgp_error_t *errp,
                                                 pgp_packet_parser_t pp,
                                                 size_t *len);

/*/
/// Finishes parsing the current packet.
///
/// By default, this drops any unread content.  Use, for instance,
/// `PacketParserBuild` to customize the default behavior.
/*/
pgp_status_t pgp_packet_parser_finish (pgp_error_t *errp,
                                     pgp_packet_parser_t pp,
				     pgp_packet_t **packet);

/*/
/// Tries to decrypt the current packet.
///
/// On success, this function pushes one or more readers onto the
/// `PacketParser`'s reader stack, and sets the packet's
/// `decrypted` flag.
///
/// If this function is called on a packet that does not contain
/// encrypted data, or some of the data was already read, then it
/// returns `Error::InvalidOperation`.
/*/
pgp_status_t pgp_packet_parser_decrypt (pgp_error_t *errp,
                                      pgp_packet_parser_t pp,
                                      uint8_t algo, /* XXX */
                                      uint8_t *key, size_t key_len);

typedef struct pgp_writer_stack *pgp_writer_stack_t;

/*/
/// Streams an OpenPGP message.
/*/
pgp_writer_stack_t pgp_writer_stack_message (pgp_writer_t writer);

/*/
/// Writes up to `len` bytes of `buf` into `writer`.
/*/
ssize_t pgp_writer_stack_write (pgp_error_t *errp, pgp_writer_stack_t writer,
                               const uint8_t *buf, size_t len);

/*/
/// Writes up to `len` bytes of `buf` into `writer`.
///
/// Unlike pgp_writer_stack_write, unless an error occurs, the whole
/// buffer will be written.  Also, this version automatically catches
/// EINTR.
/*/
pgp_status_t pgp_writer_stack_write_all (pgp_error_t *errp,
                                       pgp_writer_stack_t writer,
                                       const uint8_t *buf, size_t len);

/*/
/// Finalizes this writer, returning the underlying writer.
/*/
pgp_writer_stack_t pgp_writer_stack_finalize_one (pgp_error_t *errp,
                                                pgp_writer_stack_t writer);

/*/
/// Finalizes all writers, tearing down the whole stack.
/*/
pgp_status_t pgp_writer_stack_finalize (pgp_error_t *errp,
                                      pgp_writer_stack_t writer);

/*/
/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
/*/
pgp_writer_stack_t pgp_arbitrary_writer_new (pgp_error_t *errp,
                                           pgp_writer_stack_t inner,
                                           pgp_tag_t tag);

/*/
/// Signs a packet stream.
///
/// For every signing key, a signer writes a one-pass-signature
/// packet, then hashes and emits the data stream, then for every key
/// writes a signature packet.
/*/
pgp_writer_stack_t pgp_signer_new (pgp_error_t *errp,
                                 pgp_writer_stack_t inner,
                                 pgp_tpk_t *signers, size_t signers_len);

/*/
/// Creates a signer for a detached signature.
/*/
pgp_writer_stack_t pgp_signer_new_detached (pgp_error_t *errp,
                                          pgp_writer_stack_t inner,
                                          pgp_tpk_t *signers,
                                          size_t signers_len);

/*/
/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
/*/
pgp_writer_stack_t pgp_literal_writer_new (pgp_error_t *errp,
                                         pgp_writer_stack_t inner);

/*/
/// Specifies whether to encrypt for archival purposes or for
/// transport.
/*/
typedef enum pgp_encryption_mode {
  /*/
  /// Encrypt data for long-term storage.
  ///
  /// This should be used for things that should be decryptable for
  /// a long period of time, e.g. backups, archives, etc.
  /*/
  PGP_ENCRYPTION_MODE_AT_REST = 0,

  /*/
  /// Encrypt data for transport.
  ///
  /// This should be used to protect a message in transit.  The
  /// recipient is expected to take additional steps if she wants to
  /// be able to decrypt it later on, e.g. store the decrypted
  /// session key, or re-encrypt the session key with a different
  /// key.
  /*/
  PGP_ENCRYPTION_MODE_FOR_TRANSPORT = 1,
} pgp_encryption_mode_t;

/*/
/// Creates a new encryptor.
///
/// The stream will be encrypted using a generated session key,
/// which will be encrypted using the given passwords, and all
/// encryption-capable subkeys of the given TPKs.
///
/// The stream is encrypted using AES256, regardless of any key
/// preferences.
/*/
pgp_writer_stack_t pgp_encryptor_new (pgp_error_t *errp,
                                    pgp_writer_stack_t inner,
                                    char **passwords,
                                    size_t passwords_len,
                                    pgp_tpk_t *recipients,
                                    size_t recipients_len,
                                    pgp_encryption_mode_t mode);

typedef struct pgp_secret *pgp_secret_t;

/*/
/// Creates an pgp_secret_t from a decrypted session key.
/*/
pgp_secret_t pgp_secret_cached(uint8_t algo,
                             uint8_t *session_key, size_t session_key_len);

typedef struct pgp_verification_results *pgp_verification_results_t;
typedef struct pgp_verification_result *pgp_verification_result_t;

void pgp_verification_results_at_level(pgp_verification_results_t results,
                                      size_t level,
                                      pgp_verification_result_t **r,
                                      size_t *r_count);


typedef enum pgp_verification_result_code {
  PGP_VERIFICATION_RESULT_CODE_GOOD_CHECKSUM = 1,
  PGP_VERIFICATION_RESULT_CODE_MISSING_KEY = 2,
  PGP_VERIFICATION_RESULT_CODE_BAD_CHECKSUM = 3,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_VERIFICATION_RESULT_CODE_FORCE_WIDTH = INT_MAX,
} pgp_verification_result_code_t;

/*/
/// Returns the verification result code.
/*/
pgp_verification_result_code_t pgp_verification_result_code(
    pgp_verification_result_t r);

/*/
/// Returns a reference to the signature.
///
/// Do not modify the signature nor free it.
/*/
pgp_signature_t pgp_verification_result_signature(
    pgp_verification_result_t r);

/*/
/// Returns the signature's level.
///
/// A level of zero means that the data was signed, a level of one
/// means that one or more signatures were notarized, etc.
/*/
int pgp_verification_result_level(pgp_verification_result_t r);

typedef pgp_status_t (*pgp_sequoia_decrypt_get_public_keys_cb_t) (void *,
                                                                pgp_keyid_t *, size_t,
                                                                pgp_tpk_t **, size_t *,
                                                                void (**free)(void *));

typedef pgp_status_t (*pgp_sequoia_decrypt_get_secret_keys_cb_t) (void *,
                                                                pgp_pkesk_t *, size_t,
                                                                pgp_skesk_t *, size_t,
                                                                pgp_secret_t *);

typedef pgp_status_t (*pgp_sequoia_decrypt_check_signatures_cb_t) (void *,
                                                                 pgp_verification_results_t,
                                                                 size_t);

pgp_status_t pgp_decrypt (pgp_error_t *errp, pgp_reader_t input, pgp_writer_t output,
                        pgp_sequoia_decrypt_get_public_keys_cb_t get_public_keys,
                        pgp_sequoia_decrypt_get_secret_keys_cb_t get_secret_keys,
                        pgp_sequoia_decrypt_check_signatures_cb_t check_signatures,
                        void *cookie);

pgp_status_t pgp_verify (pgp_error_t *errp,
                       pgp_reader_t input, pgp_reader_t dsig, pgp_writer_t output,
                       pgp_sequoia_decrypt_get_public_keys_cb_t get_public_keys,
                       pgp_sequoia_decrypt_check_signatures_cb_t check_signatures,
                       void *cookie);

#endif
