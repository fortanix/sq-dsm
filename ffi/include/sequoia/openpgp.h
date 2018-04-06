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
/// Clones the Fingerprint.
/*/
sq_fingerprint_t sq_fingerprint_clone (sq_fingerprint_t fingerprint);

/*/
/// Hashes the Fingerprint.
/*/
uint64_t sq_fingerprint_hash (sq_fingerprint_t fingerprint);

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


/* openpgp::Message.  */

/*/
/// A `Message` holds a deserialized OpenPGP message.
/*/
typedef struct sq_message *sq_message_t;

/*/
/// Deserializes the OpenPGP message stored in a `std::io::Read`
/// object.
///
/// Although this method is easier to use to parse an OpenPGP
/// message than a `PacketParser` or a `MessageParser`, this
/// interface buffers the whole message in memory.  Thus, the
/// caller must be certain that the *deserialized* message is not
/// too large.
///
/// Note: this interface *does* buffer the contents of packets.
/*/
sq_message_t sq_message_from_reader (sq_context_t ctx,
                                     sq_reader_t reader);

/*/
/// Deserializes the OpenPGP message stored in the file named by
/// `filename`.
///
/// See `sq_message_from_reader` for more details and caveats.
/*/
sq_message_t sq_message_from_file (sq_context_t ctx,
                                   const char *filename);

/*/
/// Deserializes the OpenPGP message stored in the provided buffer.
///
/// See `sq_message_from_reader` for more details and caveats.
/*/
sq_message_t sq_message_from_bytes (sq_context_t ctx,
                                    const char *b, size_t len);

/*/
/// Frees the message.
/*/
void sq_message_free (sq_message_t message);

/*/
/// Clones the Message.
/*/
sq_message_t sq_message_clone (sq_message_t message);

/*/
/// Serializes the message.
/*/
sq_status_t sq_message_serialize (sq_context_t ctx,
                                  const sq_message_t message,
                                  sq_writer_t writer);


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
sq_tpk_t sq_tpk_from_message (sq_context_t ctx,
                              sq_message_t m);

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
/// Opaque types for all the Packets that Sequoia understands.
/*/
typedef struct sq_unknown *sq_unknown_t;
typedef struct sq_signature *sq_signature_t;
typedef struct sq_literal *sq_literal_t;
typedef struct sq_compressed_data *sq_compressed_data_t;
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
  sq_literal_t literal;
  sq_compressed_data_t compressed_data;
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
/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
/*/
sq_status_t sq_skesk_decrypt (sq_context_t ctx, sq_skesk_t skesk,
                              const uint8_t *passphrase, size_t passphrase_len,
                              uint8_t *algo, /* XXX */
                              uint8_t *key, size_t *key_len);

/* openpgp::parse.  */

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
/// Starts parsing an OpenPGP message stored in a `sq_reader_t` object.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
/*/
sq_packet_parser_t sq_packet_parser_from_reader (sq_context_t ctx,
                                                 sq_reader_t reader);

/*/
/// Starts parsing an OpenPGP message stored in a file named `path`.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
/*/
sq_packet_parser_t sq_packet_parser_from_file (sq_context_t ctx,
                                               const char *filename);

/*/
/// Starts parsing an OpenPGP message stored in a buffer.
///
/// This function returns a `PacketParser` for the first packet in
/// the stream.
/*/
sq_packet_parser_t sq_packet_parser_from_bytes (sq_context_t ctx,
                                                const char *b, size_t len);

/*/
/// Frees the packet parser.
/*/
void sq_packet_parser_free (sq_packet_parser_t pp);

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
/// following one.
///
/// This function finishes parsing the current packet.  By
/// default, any unread content is dropped.  (See
/// [`PacketParsererBuilder`] for how to configure this.)  It then
/// creates a new packet parser for the following packet.  If the
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
///   - The old packet's recursion depth;
///
///   - A `PacketParser` holding the new packet;
///
///   - And, the recursion depth of the new packet.
///
/// A recursion depth of 0 means that the packet is a top-level
/// packet, a recursion depth of 1 means that the packet is an
/// immediate child of a top-level-packet, etc.
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
                                   uint8_t *old_recursion_level,
                                   sq_packet_parser_t *ppo,
                                   uint8_t *new_recursion_level);

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
                                      uint8_t *old_recursion_level,
                                      sq_packet_parser_t *ppo,
                                      uint8_t *new_recursion_level);

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
sq_packet_t sq_packet_parser_finish (sq_context_t ctx,
                                     sq_packet_parser_t pp);

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

#endif
