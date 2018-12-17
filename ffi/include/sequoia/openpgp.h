#ifndef SEQUOIA_OPENPGP_H
#define SEQUOIA_OPENPGP_H

#include <sequoia/core.h>
#include <time.h>

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
typedef struct sq_packet_parser *sq_packet_parser_t;

/*/
/// Like an `Option<PacketParser>`, but the `None` variant
/// (`PacketParserEOF`) contains some summary information.
/*/
typedef struct sq_packet_parser_result *sq_packet_parser_result_t;

/*/
/// The `None` variant of a `PacketParserResult`.
/*/
typedef struct sq_packet_parser_eof *sq_packet_parser_eof_t;

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
/// Clones the KeyID.
/*/
sq_keyid_t sq_keyid_clone (sq_keyid_t keyid);

/*/
/// Hashes the KeyID.
/*/
uint64_t sq_keyid_hash (sq_keyid_t keyid);

/*/
/// Converts the KeyID to its standard representation.
/*/
char *sq_keyid_to_string (const sq_keyid_t fp);

/*/
/// Converts the KeyID to a hexadecimal number.
/*/
char *sq_keyid_to_hex (const sq_keyid_t keyid);

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
/// Clones the Fingerprint.
/*/
sq_fingerprint_t sq_fingerprint_clone (sq_fingerprint_t fingerprint);

/*/
/// Hashes the Fingerprint.
/*/
uint64_t sq_fingerprint_hash (sq_fingerprint_t fingerprint);

/*/
/// Returns a reference to the raw Fingerprint.
///
/// This returns a reference to the internal buffer that is valid as
/// long as the fingerprint is.
/*/
uint8_t *sq_fingerprint_as_bytes (const sq_fingerprint_t fp, size_t *fp_len);

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

/* sequoia::openpgp::RevocationStatus.  */

/*/
/// Holds a revocation status.
/*/
typedef struct sq_revocation_status *sq_revocation_status_t;

typedef enum sq_revocation_status_variant {
  /*/
  /// The key is definitely revoked.
  ///
  /// All self-revocations are returned, the most recent revocation
  /// first.
  /*/
  SQ_REVOCATION_STATUS_REVOKED,

  /*/
  /// We have a third-party revocation certificate that is allegedly
  /// from a designated revoker, but we don't have the designated
  /// revoker's key to check its validity.
  ///
  /// All such certificates are returned.  The caller must check
  /// them manually.
  /*/
  SQ_REVOCATION_STATUS_COULD_BE,

  /*/
  /// The key does not appear to be revoked, but perhaps an attacker
  /// has performed a DoS, which prevents us from seeing the
  /// revocation certificate.
  /*/
  SQ_REVOCATION_STATUS_NOT_AS_FAR_AS_WE_KNOW,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_REVOCATION_STATUS_FORCE_WIDTH = INT_MAX,
} sq_revocation_status_variant_t;

/*/
/// Returns the revocation status's variant.
/*/
sq_revocation_status_variant_t sq_revocation_status_variant (
    sq_revocation_status_t rs);

/*/
/// Frees the revocation status.
/*/
void sq_revocation_status_free (sq_revocation_status_t rs);


/* openpgp::armor.  */

/*/
/// Specifies the type of data (see [RFC 4880, section 6.2]).
///
/// [RFC 4880, section 6.2]: https://tools.ietf.org/html/rfc4880#section-6.2
/*/
typedef enum sq_armor_kind {
  /*/
  /// When reading an Armored file, accept any type.
  /*/
  SQ_ARMOR_KIND_ANY,

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
  SQ_ARMOR_KIND_SECRETKEY,

  /*/
  /// A detached signature.
  /*/
  SQ_ARMOR_KIND_SIGNATURE,

  /*/
  /// A generic file.  This is a GnuPG extension.
  /*/
  SQ_ARMOR_KIND_FILE,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_ARMOR_KIND_FORCE_WIDTH = INT_MAX,
} sq_armor_kind_t;

/*/
/// Represents a (key, value) pair in an armor header.
/*/
typedef struct sq_armor_header {
  char *key;
  char *value;
} sq_armor_header_t;


/*/
/// Constructs a new filter for the given type of data.
///
/// A filter that strips ASCII Armor from a stream of data.
/*/
sq_reader_t sq_armor_reader_new (sq_reader_t inner, sq_armor_kind_t kind);

/*/
/// Creates a `Reader` from a file.
/*/
sq_reader_t sq_armor_reader_from_file (sq_context_t ctx,
				       const char *filename,
				       sq_armor_kind_t kind);

/*/
/// Creates a `Reader` from a buffer.
/*/
sq_reader_t sq_armor_reader_from_bytes (const uint8_t *b, size_t len,
					sq_armor_kind_t kind);


/*/
/// Returns the kind of data this reader is for.
///
/// Useful if the kind of data is not known in advance.  If the header
/// has not been encountered yet (try reading some data first!), this
/// function returns SQ_ARMOR_KIND_ANY.
/*/
sq_armor_kind_t sq_armor_reader_kind (sq_reader_t reader);

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
sq_armor_header_t *sq_armor_reader_headers (sq_context_t ctx,
					    sq_reader_t reader,
					    size_t *len);


/*/
/// Constructs a new filter for the given type of data.
///
/// A filter that applies ASCII Armor to the data written to it.
/*/
sq_writer_t sq_armor_writer_new (sq_context_t ctx, sq_writer_t inner,
				 sq_armor_kind_t kind,
				 sq_armor_header_t *header, size_t header_len);



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
typedef enum sq_tag {
    SQ_TAG_RESERVED0 = 0,
    /* Public-Key Encrypted Session Key Packet.  */
    SQ_TAG_PKESK = 1,
    SQ_TAG_SIGNATURE = 2,
    /* Symmetric-Key Encrypted Session Key Packet.  */
    SQ_TAG_SKESK = 3,
    /* One-Pass Signature Packet.  */
    SQ_TAG_ONE_PASS_SIG = 4,
    SQ_TAG_SECRET_KEY = 5,
    SQ_TAG_PUBLIC_KEY = 6,
    SQ_TAG_SECRET_SUBKEY = 7,
    SQ_TAG_COMPRESSED_DATA = 8,
    /* Symmetrically Encrypted Data Packet.  */
    SQ_TAG_SED = 9,
    SQ_TAG_MARKER = 10,
    SQ_TAG_LITERAL = 11,
    SQ_TAG_TRUST = 12,
    SQ_TAG_USER_ID = 13,
    SQ_TAG_PUBLIC_SUBKEY = 14,

    SQ_TAG_UNASSIGNED15 = 15,
    SQ_TAG_UNASSIGNED16 = 16,

    SQ_TAG_USER_ATTRIBUTE = 17,
    /* Sym. Encrypted and Integrity Protected Data Packet.  */
    SQ_TAG_SEIP = 18,
    /* Modification Detection Code Packet.  */
    SQ_TAG_MDC = 19,

    /* Unassigned packets (as of RFC4880).  */
    SQ_TAG_UNASSIGNED20 = 20,
    SQ_TAG_UNASSIGNED21 = 21,
    SQ_TAG_UNASSIGNED22 = 22,
    SQ_TAG_UNASSIGNED23 = 23,
    SQ_TAG_UNASSIGNED24 = 24,
    SQ_TAG_UNASSIGNED25 = 25,
    SQ_TAG_UNASSIGNED26 = 26,
    SQ_TAG_UNASSIGNED27 = 27,
    SQ_TAG_UNASSIGNED28 = 28,
    SQ_TAG_UNASSIGNED29 = 29,

    SQ_TAG_UNASSIGNED30 = 30,
    SQ_TAG_UNASSIGNED31 = 31,
    SQ_TAG_UNASSIGNED32 = 32,
    SQ_TAG_UNASSIGNED33 = 33,
    SQ_TAG_UNASSIGNED34 = 34,
    SQ_TAG_UNASSIGNED35 = 35,
    SQ_TAG_UNASSIGNED36 = 36,
    SQ_TAG_UNASSIGNED37 = 37,
    SQ_TAG_UNASSIGNED38 = 38,
    SQ_TAG_UNASSIGNED39 = 39,

    SQ_TAG_UNASSIGNED40 = 40,
    SQ_TAG_UNASSIGNED41 = 41,
    SQ_TAG_UNASSIGNED42 = 42,
    SQ_TAG_UNASSIGNED43 = 43,
    SQ_TAG_UNASSIGNED44 = 44,
    SQ_TAG_UNASSIGNED45 = 45,
    SQ_TAG_UNASSIGNED46 = 46,
    SQ_TAG_UNASSIGNED47 = 47,
    SQ_TAG_UNASSIGNED48 = 48,
    SQ_TAG_UNASSIGNED49 = 49,

    SQ_TAG_UNASSIGNED50 = 50,
    SQ_TAG_UNASSIGNED51 = 51,
    SQ_TAG_UNASSIGNED52 = 52,
    SQ_TAG_UNASSIGNED53 = 53,
    SQ_TAG_UNASSIGNED54 = 54,
    SQ_TAG_UNASSIGNED55 = 55,
    SQ_TAG_UNASSIGNED56 = 56,
    SQ_TAG_UNASSIGNED57 = 57,
    SQ_TAG_UNASSIGNED58 = 58,
    SQ_TAG_UNASSIGNED59 = 59,

    /* Experimental packets.  */
    SQ_TAG_PRIVATE0 = 60,
    SQ_TAG_PRIVATE1 = 61,
    SQ_TAG_PRIVATE2 = 62,
    SQ_TAG_PRIVATE3 = 63,
} sq_tag_t;

/*/
/// Returns a human-readable tag name.
/*/
const char *sq_tag_to_string (sq_tag_t tag);

/*/
/// Opaque types for all the Packets that Sequoia understands.
/*/
typedef struct sq_unknown *sq_unknown_t;
typedef struct sq_signature *sq_signature_t;
typedef struct sq_one_pass_sig *sq_one_pass_sig_t;
typedef struct sq_p_key *sq_p_key_t;
typedef struct sq_user_id *sq_user_id_t;
typedef struct sq_user_attribute *sq_user_attribute_t;
typedef struct sq_literal *sq_literal_t;
typedef struct sq_compressed_data *sq_compressed_data_t;
typedef struct sq_pkesk *sq_pkesk_t;
typedef struct sq_skesk *sq_skesk_t;
typedef struct sq_seip *sq_seip_t;
typedef struct sq_mdc *sq_mdc_t;

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
typedef union sq_packet {
  sq_unknown_t unknown;
  sq_signature_t signature;
  sq_one_pass_sig_t one_pass_sig;
  sq_p_key_t key;
  sq_user_id_t user_id;
  sq_user_attribute_t user_attribute;
  sq_literal_t literal;
  sq_compressed_data_t compressed_data;
  sq_pkesk_t pkesk;
  sq_skesk_t skesk;
  sq_seip_t seip;
  sq_mdc_t mdc;
} sq_packet_t;

/*/
/// Frees the Packet.
/*/
void sq_packet_free (sq_packet_t p);

/*/
/// Returns the `Packet's` corresponding OpenPGP tag.
///
/// Tags are explained in [Section 4.3 of RFC 4880].
///
///   [Section 4.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.3
/*/
sq_tag_t sq_packet_tag (sq_packet_t p);

/*/
/// Returns the parsed `Packet's` corresponding OpenPGP tag.
///
/// Returns the packets tag, but only if it was successfully
/// parsed into the corresponding packet type.  If e.g. a
/// Signature Packet uses some unsupported methods, it is parsed
/// into an `Packet::Unknown`.  `tag()` returns `SQ_TAG_SIGNATURE`,
/// whereas `kind()` returns `0`.
/*/
sq_tag_t sq_packet_kind (sq_packet_t p);

/* openpgp::PacketPile.  */

/*/
/// A `PacketPile` holds a deserialized OpenPGP message.
/*/
typedef struct sq_packet_pile *sq_packet_pile_t;

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
sq_packet_pile_t sq_packet_pile_from_reader (sq_context_t ctx,
					     sq_reader_t reader);

/*/
/// Deserializes the OpenPGP packet pile stored in the file named by
/// `filename`.
///
/// See `sq_packet_pile_from_reader` for more details and caveats.
/*/
sq_packet_pile_t sq_packet_pile_from_file (sq_context_t ctx,
					   const char *filename);

/*/
/// Deserializes the OpenPGP packet pile stored in the provided buffer.
///
/// See `sq_packet_pile_from_reader` for more details and caveats.
/*/
sq_packet_pile_t sq_packet_pile_from_bytes (sq_context_t ctx,
					    const uint8_t *b, size_t len);

/*/
/// Frees the packet pile.
/*/
void sq_packet_pile_free (sq_packet_pile_t message);

/*/
/// Clones the packet pile.
/*/
sq_packet_pile_t sq_packet_pile_clone (sq_packet_pile_t message);

/*/
/// Serializes the packet pile.
/*/
sq_status_t sq_packet_pile_serialize (sq_context_t ctx,
				      const sq_packet_pile_t message,
				      sq_writer_t writer);

/*/
/// Returns the value of the `Signature` packet's Issuer subpacket.
///
/// If there is no Issuer subpacket, this returns NULL.  Note: if
/// there is no Issuer subpacket, but there is an IssuerFingerprint
/// subpacket, this still returns NULL.
/*/
sq_keyid_t sq_signature_issuer(sq_signature_t sig);

/*/
/// Returns the value of the `Signature` packet's IssuerFingerprint subpacket.
///
/// If there is no IssuerFingerprint subpacket, this returns NULL.
/// Note: if there is no IssuerFingerprint subpacket, but there is an
/// Issuer subpacket, this still returns NULL.
/*/
sq_fingerprint_t sq_signature_issuer_fingerprint(sq_signature_t sig);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// make certifications.
/*/
int sq_signature_can_certify(sq_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// make signatures.
/*/
int sq_signature_can_sign(sq_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data for transport.
/*/
int sq_signature_can_encrypt_for_transport(sq_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data at rest.
/*/
int sq_signature_can_encrypt_at_rest(sq_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used
/// for authentication.
/*/
int sq_signature_can_authenticate(sq_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key is a split
/// key.
/*/
int sq_signature_is_split_key(sq_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key is a group
/// key.
/*/
int sq_signature_is_group_key(sq_signature_t signature);

/*/
/// Returns whether the signature is alive.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired.
/*/
int sq_signature_alive(sq_signature_t signature);

/*/
/// Returns whether the signature is alive at the specified time.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired at the specified time.
/*/
int sq_signature_alive_at(sq_signature_t signature, time_t when);

/*/
/// Returns whether the signature is expired.
/*/
int sq_signature_expired(sq_signature_t signature);

/*/
/// Returns whether the signature is expired at the specified time.
/*/
int sq_signature_expired_at(sq_signature_t signature, time_t when);

/*/
/// Returns the PKESK's recipient.
///
/// The return value is a reference ot a `KeyID`.  The caller must not
/// modify or free it.
/*/
sq_keyid_t sq_pkesk_recipient(sq_pkesk_t pkesk);

/*/
/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
/*/
sq_status_t sq_pkesk_decrypt (sq_context_t ctx, sq_pkesk_t pkesk,
                              sq_p_key_t secret_key,
                              uint8_t *algo, /* XXX */
                              uint8_t *key, size_t *key_len);

typedef enum sq_reason_for_revocation {
  /*/
  /// No reason specified (key revocations or cert revocations)
  /*/
  SQ_REASON_FOR_REVOCATION_UNSPECIFIED,

  /*/
  /// Key is superseded (key revocations)
  /*/
  SQ_REASON_FOR_REVOCATION_KEY_SUPERSEDED,

  /*/
  /// Key material has been compromised (key revocations)
  /*/
  SQ_REASON_FOR_REVOCATION_KEY_COMPROMISED,

  /*/
  /// Key is retired and no longer used (key revocations)
  /*/
  SQ_REASON_FOR_REVOCATION_KEY_RETIRED,

  /*/
  /// User ID information is no longer valid (cert revocations)
  /*/
  SQ_REASON_FOR_REVOCATION_UID_RETIRED,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_REASON_FOR_REVOCATION_FORCE_WIDTH = INT_MAX,
} sq_reason_for_revocation_t;

/* openpgp::tpk::UserIDBinding.  */

/*/
/// A `UserIDBinding`.
/*/
typedef struct sq_user_id_binding *sq_user_id_binding_t;

/*/
/// Returns the user id.
///
/// This function may fail and return NULL if the user id contains an
/// interior NUL byte.  We do this rather than complicate the API, as
/// there is no valid use for such user ids; they must be malicious.
///
/// The caller must free the returned value.
/*/
char *sq_user_id_binding_user_id (sq_user_id_binding_t binding);

/* openpgp::tpk::UserIDBindingIter.  */

/*/
/// An iterator over `UserIDBinding`s.
/*/
typedef struct sq_user_id_binding_iter *sq_user_id_binding_iter_t;

/*/
/// Returns the next element in the iterator.
/*/
sq_user_id_binding_t sq_user_id_binding_iter_next (sq_user_id_binding_iter_t iter);

/// Frees an sq_user_id_binding_iter_t.
void sq_user_id_binding_iter_free (sq_user_id_binding_iter_t iter);

/* openpgp::tpk::KeyIter.  */

/*/
/// An iterator over keys in a TPK.
/*/
typedef struct sq_tpk_key_iter *sq_tpk_key_iter_t;

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
sq_p_key_t sq_tpk_key_iter_next (sq_tpk_key_iter_t iter,
                                 sq_signature_t *signature,
                                 sq_revocation_status_t *rev);

/// Frees an sq_tpk_key_iter_t.
void sq_tpk_key_iter_free (sq_tpk_key_iter_t iter);

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
typedef struct sq_tpk *sq_tpk_t;


/*/
/// A transferable secret key (TSK).
///
/// A TSK (see [RFC 4880, section 11.2]) can be used to create
/// signatures and decrypt data.
///
/// [RFC 4880, section 11.2]: https://tools.ietf.org/html/rfc4880#section-11.2
/*/
typedef struct sq_tsk *sq_tsk_t;


/*/
/// Returns the first TPK encountered in the reader.
/*/
sq_tpk_t sq_tpk_from_reader (sq_context_t ctx,
			     sq_reader_t reader);

/*/
/// Returns the first TPK encountered in the file.
/*/
sq_tpk_t sq_tpk_from_file (sq_context_t ctx,
                           const char *filename);

/*/
/// Returns the first TPK found in `m`.
///
/// Consumes `m`.
/*/
sq_tpk_t sq_tpk_from_packet_pile (sq_context_t ctx,
				  sq_packet_pile_t m);

/*/
/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP-encoded TPK.
/*/
sq_tpk_t sq_tpk_from_bytes (sq_context_t ctx,
			    const uint8_t *b, size_t len);

/*/
/// Returns the first TPK found in the packet parser.
///
/// Consumes the packet parser result.
/*/
sq_tpk_t sq_tpk_from_packet_parser (sq_context_t ctx,
                                    sq_packet_parser_result_t ppr);

/*/
/// Frees the TPK.
/*/
void sq_tpk_free (sq_tpk_t tpk);

/*/
/// Clones the TPK.
/*/
sq_tpk_t sq_tpk_clone (sq_tpk_t tpk);

/*/
/// Compares TPKs.
/*/
int sq_tpk_equal (const sq_tpk_t a, const sq_tpk_t b);

/*/
/// Serializes the TPK.
/*/
sq_status_t sq_tpk_serialize (sq_context_t ctx,
                              const sq_tpk_t tpk,
                              sq_writer_t writer);

/*/
/// Merges `other` into `tpk`.
///
/// If `other` is a different key, then nothing is merged into
/// `tpk`, but `tpk` is still canonicalized.
///
/// Consumes `tpk` and `other`.
/*/
sq_tpk_t sq_tpk_merge (sq_context_t ctx,
                       sq_tpk_t tpk,
                       sq_tpk_t other);

/*/
/// Dumps the TPK.
/*/
void sq_tpk_dump (const sq_tpk_t tpk);

/*/
/// Returns the fingerprint.
/*/
sq_fingerprint_t sq_tpk_fingerprint (const sq_tpk_t tpk);


/*/
/// Cast the public key into a secret key that allows using the secret
/// parts of the containing keys.
/*/
sq_tsk_t sq_tpk_into_tsk (sq_tpk_t tpk);

/*/
/// Returns a reference to the TPK's primary key.
///
/// The tpk still owns the key.  The caller should neither modify nor
/// free the key.
/*/
sq_p_key_t sq_tpk_primary (sq_tpk_t tpk);

/*/
/// Returns the TPK's revocation status.
///
/// Note: this only returns whether the TPK has been revoked, and does
/// not reflect whether an individual user id, user attribute or
/// subkey has been revoked.
/*/
sq_revocation_status_t sq_tpk_revocation_status (sq_tpk_t tpk);

/*/
/// Writes a revocation certificate to the writer.
///
/// This function consumes the writer.  It does *not* consume tpk.
/*/
sq_status_t sq_tpk_revoke (sq_context_t ctx,
                           sq_tpk_t tpk, sq_reason_for_revocation_t code,
                           const char *reason, sq_writer_t writer);

/*/
/// Adds a revocation certificate to the tpk.
///
/// This function consumes the tpk.
/*/
sq_tpk_t sq_tpk_revoke_in_place (sq_context_t ctx,
                                 sq_tpk_t tpk,
                                 sq_reason_for_revocation_t code,
                                 const char *reason);

/*/
/// Returns whether the TPK has expired.
/*/
int sq_tpk_expired(sq_tpk_t tpk);

/*/
/// Returns whether the TPK has expired at the specified time.
/*/
int sq_tpk_expired_at(sq_tpk_t tpk, time_t at);

/*/
/// Returns whether the TPK is alive.
/*/
int sq_tpk_alive(sq_tpk_t tpk);

/*/
/// Returns whether the TPK is alive at the specified time.
/*/
int sq_tpk_alive_at(sq_tpk_t tpk, time_t at);

/*/
/// Changes the TPK's expiration.
///
/// Expiry is when the key should expire in seconds relative to the
/// key's creation (not the current time).
///
/// This function consumes `tpk` and returns a new `TPK`.
/*/
sq_tpk_t sq_tpk_set_expiry(sq_context_t ctx,
                           sq_tpk_t tpk,
                           uint32_t expiry);

/*/
/// Returns whether the TPK includes any secret key material.
/*/
int sq_tpk_is_tsk(sq_tpk_t tpk);

/*/
/// Returns an iterator over the `UserIDBinding`s.
/*/
sq_user_id_binding_iter_t sq_tpk_user_id_binding_iter (sq_tpk_t tpk);

/*/
/// Returns an iterator over all `Key`s (both the primary key and any
/// subkeys) in a TPK.
/*/
sq_tpk_key_iter_t sq_tpk_key_iter (sq_tpk_t tpk);

/* TPKBuilder */

typedef struct sq_tpk_builder *sq_tpk_builder_t;

typedef enum sq_tpk_cipher_suite {
  /*/
  /// EdDSA and ECDH over Curve25519 with SHA512 and AES256.
  /*/
  SQ_TPK_CIPHER_SUITE_CV25519,

  /*/
  /// 3072 bit RSA with SHA512 and AES256.
  /*/
  SQ_TPK_CIPHER_SUITE_RSA3K,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_TPK_CIPHER_SUITE_FORCE_WIDTH = INT_MAX,
} sq_tpk_cipher_suite_t;

/*/
/// Creates a default `sq_tpk_builder_t`.
/*/
sq_tpk_builder_t sq_tpk_builder_default(void);

/*/
/// Generates a key compliant to [Autocrypt Level 1].
///
///   [Autocrypt Level 1]: https://autocrypt.org/level1.html
/*/
sq_tpk_builder_t sq_tpk_builder_autocrypt(void);

/*/
/// Frees an `sq_tpk_builder_t`.
/*/
void sq_tpk_builder_free(sq_tpk_builder_t tpkb);

/*/
/// Sets the encryption and signature algorithms for primary and all
/// subkeys.
/*/
void sq_tpk_builder_set_cipher_suite(sq_tpk_builder_t *tpkb,
				     sq_tpk_cipher_suite_t cs);

/*/
/// Adds a new user ID. The first user ID added replaces the default
/// ID that is just the empty string.
/*/
void sq_tpk_builder_add_userid(sq_tpk_builder_t *tpkb, const char *uid);

/*/
/// Adds a signing capable subkey.
/*/
void sq_tpk_builder_add_signing_subkey(sq_tpk_builder_t *tpkb);

/*/
/// Adds an encryption capable subkey.
/*/
void sq_tpk_builder_add_encryption_subkey(sq_tpk_builder_t *tpkb);

/*/
/// Adds an certification capable subkey.
/*/
void sq_tpk_builder_add_certification_subkey(sq_tpk_builder_t *tpkb);

/*/
/// Generates the actual TPK.
///
/// Consumes `tpkb`.
/*/
sq_tpk_t sq_tpk_builder_generate(sq_context_t ctx, sq_tpk_builder_t tpkb,
                                 sq_tpk_t *tpk, sq_signature_t *revocation);


/* TSK */

/*/
/// Generates a new RSA 3072 bit key with UID `primary_uid`.
/*/
sq_status_t sq_tsk_new (sq_context_t ctx, char *primary_uid,
                        sq_tsk_t *tpk, sq_signature_t *revocation);

/*/
/// Frees the TSK.
/*/
void sq_tsk_free (sq_tsk_t tsk);

/*/
/// Returns a reference to the corresponding TPK.
/*/
sq_tpk_t sq_tsk_tpk (sq_tsk_t tsk);

/*/
/// Converts the TSK into a TPK.
/*/
sq_tpk_t sq_tsk_into_tpk (sq_tsk_t tsk);

/*/
/// Serializes the TSK.
/*/
sq_status_t sq_tsk_serialize (sq_context_t ctx,
                              const sq_tsk_t tsk,
                              sq_writer_t writer);

/*/
/// Computes and returns the key's fingerprint as per Section 12.2
/// of RFC 4880.
/*/
sq_fingerprint_t sq_p_key_fingerprint (sq_p_key_t p);

/*/
/// Computes and returns the key's key ID as per Section 12.2 of RFC
/// 4880.
/*/
sq_keyid_t sq_p_key_keyid (sq_p_key_t p);

/*/
/// Returns whether the key is expired according to the provided
/// self-signature.
///
/// Note: this is with respect to the provided signature, which is not
/// checked for validity.  That is, we do not check whether the
/// signature is a valid self-signature for the given key.
/*/
int sq_p_key_expired(sq_p_key_t key, sq_signature_t self_signature);

/*/
/// Like sq_p_key_expired, but at a specific time.
/*/
int sq_p_key_expired_at(sq_p_key_t key, sq_signature_t self_signature,
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
int sq_p_key_alive(sq_p_key_t key, sq_signature_t self_signature);

/*/
/// Like sq_p_key_alive, but at a specific time.
/*/
int sq_p_key_alive_at(sq_p_key_t key, sq_signature_t self_signature,
                      time_t when);

/*/
/// Returns the value of the User ID Packet.
///
/// The returned pointer is valid until `uid` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
/*/
const uint8_t *sq_user_id_value (sq_user_id_t uid,
				 size_t *value_len);

/*/
/// Returns the value of the User Attribute Packet.
///
/// The returned pointer is valid until `ua` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
/*/
const uint8_t *sq_user_attribute_value (sq_user_attribute_t ua,
					size_t *value_len);

/*/
/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
/*/
sq_status_t sq_skesk_decrypt (sq_context_t ctx, sq_skesk_t skesk,
                              const uint8_t *password, size_t password_len,
                              uint8_t *algo, /* XXX */
                              uint8_t *key, size_t *key_len);

/*/
/// Returns the key's creation time.
/*/
uint32_t sq_p_key_creation_time (sq_p_key_t p);

/* openpgp::parse.  */

/*/
/// Starts parsing an OpenPGP message stored in a `sq_reader_t` object.
/*/
sq_packet_parser_result_t sq_packet_parser_from_reader (sq_context_t ctx,
                                                        sq_reader_t reader);

/*/
/// Starts parsing an OpenPGP message stored in a file named `path`.
/*/
sq_packet_parser_result_t sq_packet_parser_from_file (sq_context_t ctx,
                                                      const char *filename);

/*/
/// Starts parsing an OpenPGP message stored in a buffer.
/*/
sq_packet_parser_result_t sq_packet_parser_from_bytes (sq_context_t ctx,
                                                       const uint8_t *b,
                                                       size_t len);

/*/
/// If the `PacketParserResult` contains a `PacketParser`, returns it,
/// otherwise, returns NULL.
///
/// If the `PacketParser` reached EOF, then the `PacketParserResult`
/// contains a `PacketParserEOF` and you should use
/// `sq_packet_parser_result_eof` to get it.
///
/// If this function returns a `PacketParser`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParser` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParser` is freed.
/*/
sq_packet_parser_t sq_packet_parser_result_packet_parser (
    sq_packet_parser_result_t ppr);

/*/
/// If the `PacketParserResult` contains a `PacketParserEOF`, returns
/// it, otherwise, returns NULL.
///
/// If the `PacketParser` did not yet reach EOF, then the
/// `PacketParserResult` contains a `PacketParser` and you should use
/// `sq_packet_parser_result_packet_parser` to get it.
///
/// If this function returns a `PacketParserEOF`, then it consumes the
/// `PacketParserResult` and ownership of the `PacketParserEOF` is
/// returned to the caller, i.e., the caller is responsible for
/// ensuring that the `PacketParserEOF` is freed.
/*/
sq_packet_parser_eof_t sq_packet_parser_result_eof (
    sq_packet_parser_result_t ppr);

/*/
/// Frees the packet parser result.
/*/
void sq_packet_parser_result_free (sq_packet_parser_result_t ppr);

/*/
/// Frees the packet parser.
/*/
void sq_packet_parser_free (sq_packet_parser_t pp);

/*/
/// Returns whether the message is a well-formed OpenPGP message.
/*/
int sq_packet_parser_eof_is_message(sq_packet_parser_eof_t eof);

/*/
/// Frees the packet parser EOF object.
/*/
void sq_packet_parser_eof_free (sq_packet_parser_eof_t eof);

/*/
/// Returns a reference to the packet that is being parsed.
/*/
sq_packet_t sq_packet_parser_packet (sq_packet_parser_t pp);

/*/
/// Returns the current packet's recursion depth.
///
/// A top-level packet has a recursion depth of 0.  Packets in a
/// top-level container have a recursion depth of 1, etc.
/*/
uint8_t sq_packet_parser_recursion_depth (sq_packet_parser_t pp);

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
sq_status_t sq_packet_parser_next (sq_context_t ctx,
                                   sq_packet_parser_t pp,
                                   sq_packet_t *old_packet,
                                   sq_packet_parser_result_t *ppr);

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
sq_status_t sq_packet_parser_recurse (sq_context_t ctx,
                                      sq_packet_parser_t pp,
                                      sq_packet_t *old_packet,
                                      sq_packet_parser_result_t *ppr);

/*/
/// Causes the PacketParser to buffer the packet's contents.
///
/// The packet's contents are stored in `packet.content`.  In
/// general, you should avoid buffering a packet's content and
/// prefer streaming its content unless you are certain that the
/// content is small.
/*/
uint8_t *sq_packet_parser_buffer_unread_content (sq_context_t ctx,
                                                 sq_packet_parser_t pp,
                                                 size_t *len);

/*/
/// Finishes parsing the current packet.
///
/// By default, this drops any unread content.  Use, for instance,
/// `PacketParserBuild` to customize the default behavior.
/*/
sq_status_t sq_packet_parser_finish (sq_context_t ctx,
                                     sq_packet_parser_t pp,
				     sq_packet_t **packet);

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
sq_status_t sq_packet_parser_decrypt (sq_context_t ctx,
                                      sq_packet_parser_t pp,
                                      uint8_t algo, /* XXX */
                                      uint8_t *key, size_t key_len);

typedef struct sq_writer_stack *sq_writer_stack_t;

/*/
/// Streams an OpenPGP message.
/*/
sq_writer_stack_t sq_writer_stack_message (sq_writer_t writer);

/*/
/// Writes up to `len` bytes of `buf` into `writer`.
/*/
ssize_t sq_writer_stack_write (sq_context_t ctx, sq_writer_stack_t writer,
                               const uint8_t *buf, size_t len);

/*/
/// Writes up to `len` bytes of `buf` into `writer`.
///
/// Unlike sq_writer_stack_write, unless an error occurs, the whole
/// buffer will be written.  Also, this version automatically catches
/// EINTR.
/*/
sq_status_t sq_writer_stack_write_all (sq_context_t ctx,
                                       sq_writer_stack_t writer,
                                       const uint8_t *buf, size_t len);

/*/
/// Finalizes this writer, returning the underlying writer.
/*/
sq_writer_stack_t sq_writer_stack_finalize_one (sq_context_t ctx,
                                                sq_writer_stack_t writer);

/*/
/// Finalizes all writers, tearing down the whole stack.
/*/
sq_status_t sq_writer_stack_finalize (sq_context_t ctx,
                                      sq_writer_stack_t writer);

/*/
/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
/*/
sq_writer_stack_t sq_arbitrary_writer_new (sq_context_t ctx,
                                           sq_writer_stack_t inner,
                                           sq_tag_t tag);

/*/
/// Signs a packet stream.
///
/// For every signing key, a signer writes a one-pass-signature
/// packet, then hashes and emits the data stream, then for every key
/// writes a signature packet.
/*/
sq_writer_stack_t sq_signer_new (sq_context_t ctx,
                                 sq_writer_stack_t inner,
                                 sq_tpk_t *signers, size_t signers_len);

/*/
/// Creates a signer for a detached signature.
/*/
sq_writer_stack_t sq_signer_new_detached (sq_context_t ctx,
                                          sq_writer_stack_t inner,
                                          sq_tpk_t *signers,
                                          size_t signers_len);

/*/
/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
/*/
sq_writer_stack_t sq_literal_writer_new (sq_context_t ctx,
                                         sq_writer_stack_t inner);

/*/
/// Specifies whether to encrypt for archival purposes or for
/// transport.
/*/
typedef enum sq_encryption_mode {
  /*/
  /// Encrypt data for long-term storage.
  ///
  /// This should be used for things that should be decryptable for
  /// a long period of time, e.g. backups, archives, etc.
  /*/
  SQ_ENCRYPTION_MODE_AT_REST = 0,

  /*/
  /// Encrypt data for transport.
  ///
  /// This should be used to protect a message in transit.  The
  /// recipient is expected to take additional steps if she wants to
  /// be able to decrypt it later on, e.g. store the decrypted
  /// session key, or re-encrypt the session key with a different
  /// key.
  /*/
  SQ_ENCRYPTION_MODE_FOR_TRANSPORT = 1,
} sq_encryption_mode_t;

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
sq_writer_stack_t sq_encryptor_new (sq_context_t ctx,
                                    sq_writer_stack_t inner,
                                    char **passwords,
                                    size_t passwords_len,
                                    sq_tpk_t *recipients,
                                    size_t recipients_len,
                                    sq_encryption_mode_t mode);

typedef struct sq_secret *sq_secret_t;

/*/
/// Creates an sq_secret_t from a decrypted session key.
/*/
sq_secret_t sq_secret_cached(uint8_t algo,
                             uint8_t *session_key, size_t session_key_len);

typedef struct sq_verification_results *sq_verification_results_t;
typedef struct sq_verification_result *sq_verification_result_t;

void sq_verification_results_at_level(sq_verification_results_t results,
                                      size_t level,
                                      sq_verification_result_t **r,
                                      size_t *r_count);


typedef enum sq_verification_result_code {
  SQ_VERIFICATION_RESULT_CODE_GOOD_CHECKSUM = 1,
  SQ_VERIFICATION_RESULT_CODE_MISSING_KEY = 2,
  SQ_VERIFICATION_RESULT_CODE_BAD_CHECKSUM = 3,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_VERIFICATION_RESULT_CODE_FORCE_WIDTH = INT_MAX,
} sq_verification_result_code_t;

/*/
/// Returns the verification result code.
/*/
sq_verification_result_code_t sq_verification_result_code(
    sq_verification_result_t r);

/*/
/// Returns a reference to the signature.
///
/// Do not modify the signature nor free it.
/*/
sq_signature_t sq_verification_result_signature(
    sq_verification_result_t r);

/*/
/// Returns the signature's level.
///
/// A level of zero means that the data was signed, a level of one
/// means that one or more signatures were notarized, etc.
/*/
int sq_verification_result_level(sq_verification_result_t r);

typedef sq_status_t (*sq_sequoia_decrypt_get_public_keys_cb_t) (void *,
                                                                sq_keyid_t *, size_t,
                                                                sq_tpk_t **, size_t *,
                                                                void (**free)(void *));

typedef sq_status_t (*sq_sequoia_decrypt_get_secret_keys_cb_t) (void *,
                                                                sq_pkesk_t *, size_t,
                                                                sq_skesk_t *, size_t,
                                                                sq_secret_t *);

typedef sq_status_t (*sq_sequoia_decrypt_check_signatures_cb_t) (void *,
                                                                 sq_verification_results_t,
                                                                 size_t);

sq_status_t sq_decrypt (sq_context_t ctx, sq_reader_t input, sq_writer_t output,
                        sq_sequoia_decrypt_get_public_keys_cb_t get_public_keys,
                        sq_sequoia_decrypt_get_secret_keys_cb_t get_secret_keys,
                        sq_sequoia_decrypt_check_signatures_cb_t check_signatures,
                        void *cookie);

sq_status_t sq_verify (sq_context_t ctx, sq_reader_t input, sq_writer_t output,
                       sq_sequoia_decrypt_get_public_keys_cb_t get_public_keys,
                       sq_sequoia_decrypt_check_signatures_cb_t check_signatures,
                       void *cookie);

#endif
