#ifndef SEQUOIA_OPENPGP_TYPES_H
#define SEQUOIA_OPENPGP_TYPES_H

/*/
/// Holds a session key.
///
/// The session key is cleared when dropped.
/*/
typedef struct pgp_session_key *pgp_session_key_t;

/*/
/// Holds a password.
///
/// The password is cleared when dropped.
/*/
typedef struct pgp_password *pgp_password_t;

/*/
/// Holds a fingerprint.
/*/
typedef struct pgp_fingerprint *pgp_fingerprint_t;

/*/
/// Holds a KeyID.
/*/
typedef struct pgp_keyid *pgp_keyid_t;

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
} *pgp_armor_header_t;


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
} pgp_public_key_algo_t;

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
typedef struct pgp_packet *pgp_packet_t;

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

/*/
/// A `PacketPile` holds a deserialized OpenPGP message.
/*/
typedef struct pgp_packet_pile *pgp_packet_pile_t;

/*/
/// A `UserIDBinding`.
/*/
typedef struct pgp_user_id_binding *pgp_user_id_binding_t;

/*/
/// An iterator over `UserIDBinding`s.
/*/
typedef struct pgp_user_id_binding_iter *pgp_user_id_binding_iter_t;

/*/
/// An iterator over keys in a TPK.
/*/
typedef struct pgp_tpk_key_iter *pgp_tpk_key_iter_t;

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
/// A parser for TPKs
///
/// A `TPKParser` parses a keyring, which is simply zero or more
/// binary TPKs concatenated together.
/*/
typedef struct pgp_tpk_parser *pgp_tpk_parser_t;

/*/
/// A transferable secret key (TSK).
///
/// A TSK (see [RFC 4880, section 11.2]) can be used to create
/// signatures and decrypt data.
///
/// [RFC 4880, section 11.2]: https://tools.ietf.org/html/rfc4880#section-11.2
/*/
typedef struct pgp_tsk *pgp_tsk_t;


typedef enum pgp_tpk_cipher_suite {
  /*/
  /// EdDSA and ECDH over Curve25519 with SHA512 and AES256.
  /*/
  PGP_TPK_CIPHER_SUITE_CV25519,

  /*/
  /// 3072 bit RSA with SHA512 and AES256.
  /*/
  PGP_TPK_CIPHER_SUITE_RSA3K,

  /*/
  /// EdDSA and ECDH over NIST P-256 with SHA256 and AES256
  /*/
  PGP_TPK_CIPHER_SUITE_P256,

  /*/
  /// EdDSA and ECDH over NIST P-384 with SHA384 and AES256
  /*/
  PGP_TPK_CIPHER_SUITE_P384,

  /*/
  /// EdDSA and ECDH over NIST P-521 with SHA512 and AES256
  /*/
  PGP_TPK_CIPHER_SUITE_P521,

  /*/
  /// 2048 bit RSA with SHA512 and AES256.
  /*/
  PGP_TPK_CIPHER_SUITE_RSA2K,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_TPK_CIPHER_SUITE_FORCE_WIDTH = INT_MAX,
} pgp_tpk_cipher_suite_t;

typedef struct pgp_tpk_builder *pgp_tpk_builder_t;

typedef struct pgp_writer_stack *pgp_writer_stack_t;

/*/
/// A recipient of an encrypted message.
/*/
typedef struct pgp_recipient *pgp_recipient_t;

/// Communicates the message structure to the VerificationHelper.
typedef struct pgp_message_structure *pgp_message_structure_t;

/// Iterates over the message structure.
typedef struct pgp_message_structure_iter *pgp_message_structure_iter_t;

/// Represents a layer of the message structure.
typedef struct pgp_message_layer *pgp_message_layer_t;

typedef enum pgp_message_layer_variant {
  PGP_MESSAGE_LAYER_COMPRESSION = 1,
  PGP_MESSAGE_LAYER_ENCRYPTION = 2,
  PGP_MESSAGE_LAYER_SIGNATURE_GROUP = 3,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_MESSAGE_LAYER_CODE_FORCE_WIDTH = INT_MAX,
} pgp_message_layer_variant_t;

typedef struct pgp_verification_result *pgp_verification_result_t;

typedef struct pgp_verification_result_iter *pgp_verification_result_iter_t;

typedef enum pgp_verification_result_variant {
  PGP_VERIFICATION_RESULT_GOOD_CHECKSUM = 1,
  PGP_VERIFICATION_RESULT_MISSING_KEY = 2,
  PGP_VERIFICATION_RESULT_BAD_CHECKSUM = 3,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  PGP_VERIFICATION_RESULT_CODE_FORCE_WIDTH = INT_MAX,
} pgp_verification_result_variant_t;

typedef pgp_status_t (*pgp_decryptor_get_public_keys_cb_t) (void *,
    pgp_keyid_t *, size_t,
    pgp_tpk_t **, size_t *,
    void (**free)(void *));

typedef pgp_status_t (pgp_decryptor_do_decrypt_cb_t) (
    void *,
    uint8_t,
    pgp_session_key_t);

typedef pgp_status_t (*pgp_decryptor_decrypt_cb_t) (void *,
    pgp_pkesk_t *, size_t,
    pgp_skesk_t *, size_t,
    pgp_decryptor_do_decrypt_cb_t *,
    void *,
    pgp_fingerprint_t *);

typedef pgp_status_t (*pgp_decryptor_check_cb_t) (void *,
    pgp_message_structure_t);

typedef pgp_status_t (*pgp_decryptor_inspect_cb_t) (void *,
    pgp_packet_parser_t);

#endif
