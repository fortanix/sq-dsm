#ifndef SEQUOIA_OPENPGP_H
#define SEQUOIA_OPENPGP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <time.h>

#include <sequoia/io.h>
#include <sequoia/openpgp/types.h>
#include <sequoia/openpgp/error.h>
#include <sequoia/openpgp/crypto.h>
#include <sequoia/openpgp/packet.h>
#include <sequoia/openpgp/serialize.h>

/* sequoia::openpgp::KeyID.  */

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
bool pgp_keyid_equal (const pgp_keyid_t a, const pgp_keyid_t b);


/* sequoia::openpgp::Fingerprint.  */

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
bool pgp_fingerprint_equal (const pgp_fingerprint_t a, const pgp_fingerprint_t b);

/* sequoia::openpgp::RevocationStatus.  */

/*/
/// Returns the revocation status's variant.
/*/
pgp_revocation_status_variant_t pgp_revocation_status_variant (
    pgp_revocation_status_t rs);

/*/
/// Frees the revocation status.
/*/
void pgp_revocation_status_free (pgp_revocation_status_t rs);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_revocation_status_debug (const pgp_revocation_status_t);

/* openpgp::armor.  */

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
pgp_armor_header_t pgp_armor_reader_headers (pgp_error_t *errp,
					    pgp_reader_t reader,
					    size_t *len);


/*/
/// Constructs a new filter for the given type of data.
///
/// A filter that applies ASCII Armor to the data written to it.
///
/// Note: You must call `pgp_armor_writer_finalize` to deallocate this
/// writer.
/*/
pgp_writer_t pgp_armor_writer_new (pgp_error_t *errp, pgp_writer_t inner,
				 pgp_armor_kind_t kind,
				 pgp_armor_header_t header, size_t header_len);

/*/
/// Finalizes the armor writer.
///
/// Consumes the writer.  No further deallocation of the writer is
/// required.
/*/
pgp_status_t pgp_armor_writer_finalize (pgp_error_t *errp, pgp_writer_t writer);

/* openpgp::PacketPile.  */

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
/// Clones the Signature.
/*/
pgp_signature_t pgp_signature_clone (pgp_signature_t signature);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_signature_debug (const pgp_signature_t signature);

/*/
/// Compares Signatures.
/*/
bool pgp_signature_equal (const pgp_signature_t a,
                          const pgp_signature_t b);

/*/
/// Parses an object from the given reader.
/*/
pgp_signature_t pgp_signature_from_reader (pgp_error_t *errp,
                                           pgp_reader_t reader);

/*/
/// Parses an object from the given file.
/*/
pgp_signature_t pgp_signature_from_file (pgp_error_t *errp,
                                         const char *filename);

/*/
/// Parses an object from the given buffer.
/*/
pgp_signature_t pgp_signature_from_bytes (pgp_error_t *errp,
                                          const uint8_t *b, size_t len);

/*/
/// Converts the signature to a packet.
/*/
pgp_packet_t pgp_signature_into_packet (pgp_signature_t signature);

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
bool pgp_signature_for_certification(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// make signatures.
/*/
bool pgp_signature_for_signing(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data for transport.
/*/
bool pgp_signature_for_transport_encryption(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used to
/// encrypt data at rest.
/*/
bool pgp_signature_for_storage_encryption(pgp_signature_t signature);

/*/
/// Returns whether the KeyFlags indicates that the key can be used
/// for authentication.
/*/
bool pgp_signature_for_authentication(pgp_signature_t signature);

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
/// Returns whether the signature is alive at the specified time.
///
/// A signature is considered to be alive if `creation time -
/// tolerance <= time` and `time <= expiration time`.
///
/// If `time` is 0, uses the current time.
///
/// This function uses the default tolerance.  If you want to specify
/// a different tolerance (or no tolerance), then use
/// `pgp_signature_alive_with_tolerance`.
///
/// Some tolerance for clock skew is sometimes necessary, because
/// although most computers synchronize their clock with a time
/// server, up to a few seconds of clock skew are not unusual in
/// practice.  And, even worse, several minutes of clock skew appear
/// to be not uncommon on virtual machines.
///
/// Not accounting for clock skew can result in signatures being
/// unexpectedly considered invalid.  Consider: computer A sends a
/// message to computer B at 9:00, but computer B, whose clock says
/// the current time is 8:59, rejects it, because the signature
/// appears to have been made in the future.  This is particularly
/// problematic for low-latency protocols built on top of OpenPGP,
/// e.g., state synchronization between two MUAs via a shared IMAP
/// folder.
///
/// Being tolerant to potential clock skew is not always appropriate.
/// For instance, when determining a User ID's current self signature
/// at time `t`, we don't ever want to consider a self-signature made
/// after `t` to be valid, even if it was made just a few moments
/// after `t`.  This goes doubly so for soft revocation certificates:
/// the user might send a message that she is retiring, and then
/// immediately create a soft revocation.  The soft revocation should
/// not invalidate the message.
///
/// Unfortunately, in many cases, whether we should account for clock
/// skew or not depends on application-specific context.  As a rule of
/// thumb, if the time and the timestamp come from different sources,
/// you probably want to account for clock skew.
///
/// Note that [Section 5.2.3.4 of RFC 4880] states that "[[A Signature
/// Creation Time subpacket]] MUST be present in the hashed area."
/// Consequently, if such a packet does not exist, but a "Signature
/// Expiration Time" subpacket exists, we conservatively treat the
/// signature as expired, because there is no way to evaluate the
/// expiration time.
///
///  [Section 5.2.3.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
/*/
pgp_status_t pgp_signature_alive(pgp_error_t *errp,
				 pgp_signature_t signature, time_t when);

/*/
/// Returns whether the signature is alive at the specified time.
///
/// A signature is considered to be alive if `creation time -
/// tolerance <= time` and `time <= expiration time`.
///
/// If `time` is 0, uses the current time.
///
/// If `tolerance` is 0, uses no tolerance.  To ensure consistency
/// across callers, you should use the default tolerance (i.e., use
/// `pgp_signature_alive`).
///
/// Some tolerance for clock skew is sometimes necessary, because
/// although most computers synchronize their clock with a time
/// server, up to a few seconds of clock skew are not unusual in
/// practice.  And, even worse, several minutes of clock skew appear
/// to be not uncommon on virtual machines.
///
/// Not accounting for clock skew can result in signatures being
/// unexpectedly considered invalid.  Consider: computer A sends a
/// message to computer B at 9:00, but computer B, whose clock says
/// the current time is 8:59, rejects it, because the signature
/// appears to have been made in the future.  This is particularly
/// problematic for low-latency protocols built on top of OpenPGP,
/// e.g., state synchronization between two MUAs via a shared IMAP
/// folder.
///
/// Being tolerant to potential clock skew is not always appropriate.
/// For instance, when determining a User ID's current self signature
/// at time `t`, we don't ever want to consider a self-signature made
/// after `t` to be valid, even if it was made just a few moments
/// after `t`.  This goes doubly so for soft revocation certificates:
/// the user might send a message that she is retiring, and then
/// immediately create a soft revocation.  The soft revocation should
/// not invalidate the message.
///
/// Unfortunately, in many cases, whether we should account for clock
/// skew or not depends on application-specific context.  As a rule of
/// thumb, if the time and the timestamp come from different sources,
/// you probably want to account for clock skew.
///
/// Note that [Section 5.2.3.4 of RFC 4880] states that "[[A Signature
/// Creation Time subpacket]] MUST be present in the hashed area."
/// Consequently, if such a packet does not exist, but a "Signature
/// Expiration Time" subpacket exists, we conservatively treat the
/// signature as expired, because there is no way to evaluate the
/// expiration time.
///
///  [Section 5.2.3.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.4
/*/
pgp_status_t pgp_signature_alive_with_tolerance(pgp_error_t *errp,
						pgp_signature_t signature,
						time_t time,
						unsigned int tolerance);

/*/
/// Returns whether the signature is alive at the specified time.
///
/// A signature is alive if the creation date is in the past, and the
/// signature has not expired at the specified time.
///
/// If `when` is 0, then the current time is used.
/*/
pgp_status_t pgp_signature_key_alive(pgp_error_t *errp,
				     pgp_signature_t signature, pgp_key_t key,
				     time_t when);

/*/
/// Returns the PKESK's recipient.
///
/// The return value is a reference to a `KeyID`.  The caller must not
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


/*/
/// Returns the filename as a c string.
///
/// If the filename is not set, returns NULL.
///
/// Note: the filename is *not* protected by any signature and thus
/// can be modified in transit without detection.
///
/// Note: the filename may contain embedded NULs.  This function
/// returns NULL in such cases.
/*/
char *pgp_literal_filename (pgp_literal_t literal);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_literal_debug (const pgp_literal_t literal);

/*/
/// Parses an object from the given reader.
/*/
pgp_literal_t pgp_literal_from_reader (pgp_error_t *errp,
                                       pgp_reader_t reader);

/*/
/// Parses an object from the given file.
/*/
pgp_literal_t pgp_literal_from_file (pgp_error_t *errp,
                                     const char *filename);

/*/
/// Parses an object from the given buffer.
/*/
pgp_literal_t pgp_literal_from_bytes (pgp_error_t *errp,
                                      const uint8_t *b, size_t len);

/*/
/// Converts the literal to a packet.
/*/
pgp_packet_t pgp_literal_into_packet (pgp_literal_t literal);

/*/
/// Frees the literal data packet.
/*/
void pgp_literal_free (pgp_literal_t literal);

/* openpgp::amalgamation::UserIDAmalgamation.  */

/*/
/// Returns the user id.
///
/// This function may fail and return NULL if the user id contains an
/// interior NUL byte.  We do this rather than complicate the API, as
/// there is no valid use for such user ids; they must be malicious.
///
/// The caller must free the returned value.
/*/
char *pgp_user_id_amalgamation_user_id (pgp_user_id_amalgamation_t ua);

/*/
/// Frees the User ID Amalgamation.
/*/
void pgp_user_id_amalgamation_free (pgp_user_id_amalgamation_t ua);

/*/
/// Clones the UserID Amalgamation.
/*/
pgp_user_id_amalgamation_t pgp_user_id_amalgamation_clone (pgp_user_id_amalgamation_t ua);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_user_id_amalgamation_debug (const pgp_user_id_amalgamation_t ua);

/*/
/// Returns the user id.
///
/// This function may fail and return NULL if the user id contains an
/// interior NUL byte.  We do this rather than complicate the API, as
/// there is no valid use for such user ids; they must be malicious.
///
/// The caller must free the returned value.
/*/
pgp_user_id_t pgp_valid_user_id_amalgamation_user_id
    (pgp_valid_user_id_amalgamation_t ua);

/*/
/// Returns the Valid UserID Amalgamation's revocation status.
/*/
pgp_revocation_status_t pgp_valid_user_id_amalgamation_revocation_status
    (pgp_valid_user_id_amalgamation_t ua);

/*/
/// Returns a reference to the self-signature.
/*/
pgp_signature_t pgp_valid_user_id_amalgamation_binding_signature
    (pgp_valid_user_id_amalgamation_t ua);

/*/
/// Changes the policy applied to the `ValidUserIDAmalgamation`.
///
/// This consumes the UserID amalgamation.
/*/
pgp_valid_user_id_amalgamation_t pgp_valid_user_id_amalgamation_with_policy
    (pgp_error_t *errp,
     pgp_valid_user_id_amalgamation_t ua,
     pgp_policy_t policy,
     time_t time);

/*/
/// Frees the User ID Amalgamation.
/*/
void pgp_valid_user_id_amalgamation_free (pgp_valid_user_id_amalgamation_t ua);

/*/
/// Clones the UserID Amalgamation.
/*/
pgp_valid_user_id_amalgamation_t pgp_valid_user_id_amalgamation_clone (pgp_valid_user_id_amalgamation_t ua);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_valid_user_id_amalgamation_debug (const pgp_valid_user_id_amalgamation_t ua);

/* openpgp::cert::UserIDIter.  */

/*/
/// Returns the next element in the iterator.
/*/
pgp_user_id_amalgamation_t pgp_cert_user_id_iter_next (pgp_cert_user_id_iter_t iter);

/*/
/// Sets a policy.
///
/// Only User IDs that are valid according to the policy at the
/// specified time are returned.
/*/
pgp_cert_valid_user_id_iter_t pgp_cert_user_id_iter_policy
    (pgp_cert_user_id_iter_t iter, pgp_policy_t policy, time_t when);

/*/
/// Frees a pgp_cert_user_id_iter_t.
/*/
void pgp_cert_user_id_iter_free (pgp_cert_user_id_iter_t iter);

/*/
/// Returns the next element in the iterator.
/*/
pgp_valid_user_id_amalgamation_t pgp_cert_valid_user_id_iter_next (pgp_cert_valid_user_id_iter_t iter);

/*/
/// Frees a pgp_cert_valid_user_id_iter_t.
/*/
void pgp_cert_valid_user_id_iter_free (pgp_cert_valid_user_id_iter_t iter);

/* openpgp::cert::KeyIter.  */

/*/
/// Changes the iterator to only return keys that have secret keys.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_key_iter_secret (pgp_cert_key_iter_t iter);

/*/
/// Changes the iterator to only return keys that have unencrypted
/// secret keys.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_key_iter_unencrypted_secret (pgp_cert_key_iter_t iter);

/*/
/// Sets a policy.
///
/// Only keys that are valid according to the policy at the specified
/// time are returned.
/*/
pgp_cert_valid_key_iter_t pgp_cert_key_iter_policy
    (pgp_cert_key_iter_t iter, pgp_policy_t policy, time_t when);

/*/
/// Returns a key amalgamation for the next key.  Returns NULL if there are no
/// more elements.
/*/
pgp_key_amalgamation_t pgp_cert_key_iter_next (pgp_cert_key_iter_t iter);

/*/
/// Frees an pgp_cert_key_iter_t.
/*/
void pgp_cert_key_iter_free (pgp_cert_key_iter_t iter);

/*/
/// Changes the iterator to only return keys that are certification
/// capable.
///
/// If you call this function and, e.g., the `for_signing`
/// function, the *union* of the values is used.  That is, the
/// iterator will return keys that are certification capable *or*
/// signing capable.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_valid_key_iter_for_certification (pgp_cert_valid_key_iter_t iter);

/*/
/// Changes the iterator to only return keys that are certification
/// capable.
///
/// If you call this function and, e.g., the `for_signing`
/// function, the *union* of the values is used.  That is, the
/// iterator will return keys that are certification capable *or*
/// signing capable.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_valid_key_iter_for_signing (pgp_cert_valid_key_iter_t iter);

/*/
/// Changes the iterator to only return keys that are capable of
/// encrypting data at rest.
///
/// If you call this function and, e.g., the `for_signing`
/// function, the *union* of the values is used.  That is, the
/// iterator will return keys that are certification capable *or*
/// signing capable.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_valid_key_iter_for_storage_encryption (pgp_cert_valid_key_iter_t);

/*/
/// Changes the iterator to only return keys that are capable of
/// encrypting data for transport.
///
/// If you call this function and, e.g., the `for_signing`
/// function, the *union* of the values is used.  That is, the
/// iterator will return keys that are certification capable *or*
/// signing capable.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_valid_key_iter_for_transport_encryption (pgp_cert_valid_key_iter_t);

/*/
/// Changes the iterator to only return keys that are alive.
///
/// If you call this function, only the last value is used.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_valid_key_iter_alive (pgp_cert_valid_key_iter_t iter);

/*/
/// Changes the iterator to only return keys that are revoked.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_valid_key_iter_revoked (pgp_cert_valid_key_iter_t iter, bool revoked);

/*/
/// Changes the iterator to only return keys that are not revoked.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_valid_key_iter_secret (pgp_cert_valid_key_iter_t iter);

/*/
/// Changes the iterator to only return keys that have unencrypted
/// secret keys.
///
/// Note: you may not call this function after starting to iterate.
/*/
void pgp_cert_valid_key_iter_unencrypted_secret (pgp_cert_valid_key_iter_t iter);

/*/
/// Returns a key amalgamation to the next key.  Returns NULL if there are no
/// more elements.
///
/// If signature is not NULL, stores the current self-signature (if
/// any) in *signature.  (Note: subkeys always have signatures, but a
/// primary key may not have a direct signature, and there might not
/// be any user ids.)
///
/// If rev is not NULL, this stores the key's revocation status in
/// *rev.
/*/
pgp_valid_key_amalgamation_t pgp_cert_valid_key_iter_next
    (pgp_cert_valid_key_iter_t iter,
     pgp_signature_t *signature,
     pgp_revocation_status_t *rev);

/*/
/// Frees an pgp_cert_valid_key_iter_t.
/*/
void pgp_cert_valid_key_iter_free (pgp_cert_valid_key_iter_t iter);

/* openpgp::cert.  */

/*/
/// Returns the first Cert encountered in the reader.
/*/
pgp_cert_t pgp_cert_from_reader (pgp_error_t *errp,
			     pgp_reader_t reader);

/*/
/// Returns the first Cert encountered in the file.
/*/
pgp_cert_t pgp_cert_from_file (pgp_error_t *errp,
                           const char *filename);

/*/
/// Returns the first Cert found in `m`.
///
/// Consumes `m`.
/*/
pgp_cert_t pgp_cert_from_packet_pile (pgp_error_t *errp,
				  pgp_packet_pile_t m);

/*/
/// Returns the first Cert found in `buf`.
///
/// `buf` must be an OpenPGP-encoded Cert.
/*/
pgp_cert_t pgp_cert_from_bytes (pgp_error_t *errp,
			    const uint8_t *b, size_t len);

/*/
/// Returns the first Cert found in the packet parser.
///
/// Consumes the packet parser result.
/*/
pgp_cert_t pgp_cert_from_packet_parser (pgp_error_t *errp,
                                    pgp_packet_parser_result_t ppr);

/*/
/// Frees the Cert.
/*/
void pgp_cert_free (pgp_cert_t cert);

/*/
/// Clones the Cert.
/*/
pgp_cert_t pgp_cert_clone (pgp_cert_t cert);

/*/
/// Compares Certs.
/*/
bool pgp_cert_equal (const pgp_cert_t a, const pgp_cert_t b);

/*/
/// Returns a human readable description of this object intended for
/// communication with end users.
/*/
char *pgp_cert_to_string (const pgp_cert_t fp);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_cert_debug (const pgp_cert_t cert);

/*/
/// Serializes the Cert.
/*/
pgp_status_t pgp_cert_serialize (pgp_error_t *errp,
                              const pgp_cert_t cert,
                              pgp_writer_t writer);

/*/
/// Merges `other` into `cert`.
///
/// If `other` is a different key, then nothing is merged into
/// `cert`, but `cert` is still canonicalized.
///
/// Consumes `cert` and `other`.
/*/
pgp_cert_t pgp_cert_merge (pgp_error_t *errp,
                       pgp_cert_t cert,
                       pgp_cert_t other);

/*/
/// Adds packets to the Cert.
///
/// This recanonicalizes the Cert.  If the packets are invalid, they
/// are dropped.
///
/// Consumes `cert` and the packets in `packets`.  The buffer, however,
/// must be freed by the caller.
/*/
pgp_cert_t pgp_cert_merge_packets (pgp_error_t *errp,
                               pgp_cert_t cert,
                               pgp_packet_t *packets,
                               size_t packets_len);

/*/
/// Returns the fingerprint.
/*/
pgp_fingerprint_t pgp_cert_fingerprint (const pgp_cert_t cert);


/*/
/// Derive a [`TSK`] object from this key.
///
/// This object writes out secret keys during serialization.
///
/// [`TSK`]: cert/struct.TSK.html
/*/
pgp_tsk_t pgp_cert_as_tsk (pgp_cert_t cert);

/*/
/// Returns a reference to the Cert's primary key.
///
/// The cert still owns the key.  The caller should neither modify nor
/// free the key.
/*/
pgp_key_t pgp_cert_primary_key (pgp_cert_t cert);

/*/
/// Returns the Cert's revocation status at the specified time.
///
/// Note: this only returns whether the Cert has been revoked, and does
/// not reflect whether an individual user id, user attribute or
/// subkey has been revoked.
///
/// If `when` is 0, then returns the Cert's revocation status as of the
/// time of the call.
/*/
pgp_revocation_status_t pgp_cert_revoked (pgp_cert_t cert,
                                          pgp_policy_t policy, time_t when);

/*/
/// Writes a revocation certificate to the writer.
///
/// This function consumes the writer.  It does *not* consume cert.
/*/
pgp_signature_t pgp_cert_revoke (pgp_error_t *errp,
                              pgp_cert_t cert,
                              pgp_signer_t primary_signer,
                              pgp_reason_for_revocation_t code,
                              const char *reason);

/*/
/// Adds a revocation certificate to the cert.
///
/// This function consumes the cert.
/*/
pgp_cert_t pgp_cert_revoke_in_place (pgp_error_t *errp,
                                 pgp_cert_t cert,
                                 pgp_signer_t primary_signer,
                                 pgp_reason_for_revocation_t code,
                                 const char *reason);

/*/
/// Returns whether the Cert is alive at the specified time.
///
/// If `when` is 0, then the current time is used.
/*/
pgp_status_t pgp_cert_alive(pgp_error_t *errp, pgp_cert_t cert,
                            pgp_policy_t policy, time_t when);

/*/
/// Sets the key to expire at the given time.
///
/// This function consumes `cert` and returns a new `Cert`.
/*/
pgp_cert_t pgp_cert_set_expiration_time(pgp_error_t *errp,
                               pgp_cert_t cert,
                               pgp_policy_t policy,
                               pgp_signer_t signer,
                               time_t expiry);

/*/
/// Returns whether the Cert includes any secret key material.
/*/
int pgp_cert_is_tsk(pgp_cert_t cert);

/*/
/// Returns an iterator over the `UserID`s.
/*/
pgp_cert_user_id_iter_t pgp_cert_user_id_iter (pgp_cert_t cert);

/*/
/// Returns an iterator over the valid `UserID`s.
/*/
pgp_cert_valid_user_id_iter_t pgp_cert_valid_user_id_iter (pgp_cert_t cert,
                                                           pgp_policy_t policy,
                                                           time_t when);

/*/
/// Returns an iterator over all `Key`s in a Cert.
///
/// That is, this returns an iterator over the primary key and any
/// subkeys.
/*/
pgp_cert_key_iter_t pgp_cert_key_iter (pgp_cert_t cert);

/*/
/// Returns an iterator over all valid `Key`s in a Cert.
///
/// That is, this returns an iterator over the primary key and any
/// subkeys that are valid (i.e., have a self-signature at time
/// `when`).
/*/
pgp_cert_valid_key_iter_t pgp_cert_valid_key_iter
    (pgp_cert_t cert, pgp_policy_t policy, time_t when);

/*/
/// Returns the Cert's primary user id (if any).
/*/
char *pgp_cert_primary_user_id(pgp_cert_t cert, pgp_policy_t policy,
                               time_t when);

/*/
/// Returns a CertParser.
///
/// A Cert parser parses a keyring, which is simply zero or more Certs
/// concatenated together.
/*/
pgp_cert_parser_t pgp_cert_parser_from_bytes(pgp_error_t *errp,
                                           char *buf, size_t len);

/*/
/// Returns a CertParser.
///
/// A Cert parser parses a keyring, which is simply zero or more Certs
/// concatenated together.
/*/
pgp_cert_parser_t pgp_cert_parser_from_packet_parser(pgp_packet_parser_result_t ppr);

/*/
/// Returns the next Cert, if any.
///
/// If there is an error parsing the Cert, it is returned in *errp.
///
/// If this function returns NULL and does not set *errp, then the end
/// of the file was reached.
/*/
pgp_cert_t pgp_cert_parser_next(pgp_error_t *errp, pgp_cert_parser_t parser);

/*/
/// Frees an pgp_cert_parser_t.
/*/
void pgp_cert_parser_free (pgp_cert_parser_t parser);

/* CertBuilder */

/*/
/// Creates a new `pgp_cert_builder_t`.
///
/// The returned CertBuilder is setup to only create a
/// certification-capable primary key using the default cipher suite.
/// You'll almost certainly want to add subkeys, and user ids.
/*/
pgp_cert_builder_t pgp_cert_builder_new(void);

/*/
/// Generates a general-purpose key.
///
/// The key's primary key is certification- and signature-capable.
/// The key has one subkey, an encryption-capable subkey.
/*/
pgp_cert_builder_t pgp_cert_builder_general_purpose(pgp_cert_cipher_suite_t cs,
                                                  const char *uid);

/*/
/// Frees an `pgp_cert_builder_t`.
/*/
void pgp_cert_builder_free(pgp_cert_builder_t certb);

/*/
/// Sets the encryption and signature algorithms for primary and all
/// subkeys.
/*/
void pgp_cert_builder_set_cipher_suite(pgp_cert_builder_t *certb,
				     pgp_cert_cipher_suite_t cs);

/*/
/// Adds a new user ID. The first user ID added replaces the default
/// ID that is just the empty string.
/*/
void pgp_cert_builder_add_userid(pgp_cert_builder_t *certb, const char *uid);

/*/
/// Adds a signing capable subkey.
/*/
void pgp_cert_builder_add_signing_subkey(pgp_cert_builder_t *certb);

/*/
/// Adds an encryption capable subkey.
/*/
void pgp_cert_builder_add_transport_encryption_subkey(pgp_cert_builder_t *certb);

/*/
/// Adds an certification capable subkey.
/*/
void pgp_cert_builder_add_certification_subkey(pgp_cert_builder_t *certb);

/*/
/// Sets the creation time.
/*/
void pgp_cert_builder_set_creation_time(pgp_cert_builder_t *certb,
                                        time_t when);

/*/
/// Generates the actual Cert.
///
/// Consumes `certb`.
/*/
pgp_status_t pgp_cert_builder_generate(pgp_error_t *errp,
                                      pgp_cert_builder_t certb,
                                      pgp_cert_t *cert,
                                      pgp_signature_t *revocation);


/* KeyAmalgamation */

/*/
/// Returns a reference to the Key Amalgamation's `Key`.
/*/
pgp_key_t pgp_key_amalgamation_key (pgp_key_amalgamation_t ka);

/*/
/// Frees the Key Amalgamation.
/*/
void pgp_key_amalgamation_free (pgp_key_amalgamation_t ka);

/*/
/// Clones the Key Amalgamation.
/*/
pgp_key_amalgamation_t pgp_key_amalgamation_clone (pgp_key_amalgamation_t ka);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_key_amalgamation_debug (const pgp_key_amalgamation_t ka);


/* ValidKeyAmalgamation */

/*/
/// Returns a reference to the Valid Key Amalgamation's `Key`.
/*/
pgp_key_t pgp_valid_key_amalgamation_key (pgp_valid_key_amalgamation_t ka);

/*/
/// Returns the Valid Key Amalgamation's revocation status.
/*/
pgp_revocation_status_t pgp_valid_key_amalgamation_revocation_status (pgp_valid_key_amalgamation_t ka);

/*/
/// Returns a reference to the Valid Key Amalgamation's binding signature.
/*/
pgp_signature_t pgp_valid_key_amalgamation_binding_signature (pgp_valid_key_amalgamation_t ka);

/*/
/// Creates one or more self-signatures that when merged with the
/// certificate cause the key to expire at the specified time.
///
/// The returned buffer must be freed using libc's allocator.
/*/
pgp_status_t pgp_valid_key_amalgamation_set_expiration_time
  (pgp_error_t *errp,
   pgp_valid_key_amalgamation_t ka,
   pgp_signer_t signer,
   time_t time,
   pgp_packet_t **packets,
   size_t *packet_count);

/*/
/// Changes the policy applied to the `ValidKeyAmalgamation`.
///
/// This consumes the key amalgamation.
/*/
pgp_valid_key_amalgamation_t pgp_valid_key_amalgamation_with_policy
    (pgp_error_t *errp,
     pgp_valid_key_amalgamation_t ka,
     pgp_policy_t policy,
     time_t time);

/*/
/// Frees the Valid Key Amalgamation.
/*/
void pgp_valid_key_amalgamation_free (pgp_valid_key_amalgamation_t ka);

/*/
/// Clones the Valid Key Amalgamation.
/*/
pgp_valid_key_amalgamation_t pgp_valid_key_amalgamation_clone (pgp_valid_key_amalgamation_t ka);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_valid_key_amalgamation_debug (const pgp_valid_key_amalgamation_t ka);


/* TSK */

/*/
/// Frees the TSK.
/*/
void pgp_tsk_free (pgp_tsk_t tsk);

/*/
/// Serializes the TSK.
/*/
pgp_status_t pgp_tsk_serialize (pgp_error_t *errp,
                              const pgp_tsk_t tsk,
                              pgp_writer_t writer);

/*/
/// Frees the key.
/*/
void pgp_key_free (pgp_key_t key);

/*/
/// Clones the Key.
/*/
pgp_key_t pgp_key_clone (pgp_key_t key);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_key_debug (const pgp_key_t key);

/*/
/// Compares Keys.
/*/
bool pgp_key_equal (const pgp_key_t a,
                    const pgp_key_t b);

/*/
/// Parses an object from the given reader.
/*/
pgp_key_t pgp_key_from_reader (pgp_error_t *errp,
                               pgp_reader_t reader);

/*/
/// Parses an object from the given file.
/*/
pgp_key_t pgp_key_from_file (pgp_error_t *errp,
                             const char *filename);

/*/
/// Parses an object from the given buffer.
/*/
pgp_key_t pgp_key_from_bytes (pgp_error_t *errp,
                              const uint8_t *b, size_t len);

/*/
/// Clones the key.
/*/
pgp_key_t pgp_key_clone (pgp_key_t key);

/*/
/// Computes and returns the key's fingerprint as per Section 12.2
/// of RFC 4880.
/*/
pgp_fingerprint_t pgp_key_fingerprint (pgp_key_t key);

/*/
/// Computes and returns the key's key ID as per Section 12.2 of RFC
/// 4880.
/*/
pgp_keyid_t pgp_key_keyid (pgp_key_t key);

/*/
/// Returns the key's public key algorithm.
/*/
pgp_public_key_algo_t pgp_key_public_key_algo(pgp_key_t key);

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
/// Constructs a User ID.
///
/// This does a basic check and any necessary escaping to form a de
/// facto User ID.  Only the address is required.
/*/
pgp_packet_t pgp_user_id_from_address (pgp_error_t *errp,
                                       const char *name,
                                       const char *comment,
                                       const char *address);

/*/
/// Constructs a User ID.
///
/// This does a basic check and any necessary escaping to form a de
/// facto User ID.  The address is not checked.
///
/// This is useful when you want to specify a URI instead of an
/// email address.
/*/
pgp_packet_t pgp_user_id_from_unchecked_address (pgp_error_t *errp,
                                                 const char *name,
                                                 const char *comment,
                                                 const char *address);

/*/
/// Create a new User ID with the value `value`.
/*/
pgp_packet_t pgp_user_id_new (const char *value);

/*/
/// Create a new User ID with the value `value`.
/*/
pgp_packet_t pgp_user_id_from_raw (const char *value, size_t len);

/*/
/// Returns the value of the User ID Packet.
///
/// The returned pointer is valid until `uid` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
/*/
const uint8_t *pgp_user_id_value (pgp_packet_t uid,
				 size_t *value_len);

/*/
/// Returns the User ID's name component, if any.
///
/// The User ID is parsed according to de facto convention, and the
/// name component is extracted.
///
/// If the User ID cannot be parsed, then an error is returned.
///
/// If the User ID does not contain a name component, *namep is set to
/// NULL.
/*/
pgp_status_t pgp_user_id_name(pgp_error_t *errp, pgp_packet_t uid,
                              char **namep);

/*/
/// Returns the User ID's comment field, if any.
///
/// The User ID is parsed according to de facto convention, and the
/// comment field is extracted.
///
/// If the User ID cannot be parsed, then an error is returned.
///
/// If the User ID does not contain a comment, *commentp is set
/// to NULL.
/*/
pgp_status_t pgp_user_id_comment(pgp_error_t *errp, pgp_packet_t uid,
                                 char **commentp);

/*/
/// Returns the User ID's email address, if any.
///
/// The User ID is parsed according to de facto convention, and the
/// email address is extracted.
///
/// If the User ID cannot be parsed, then an error is returned.
///
/// If the User ID does not contain an email address, *addressp is set
/// to NULL.
/*/
pgp_status_t pgp_user_id_email(pgp_error_t *errp, pgp_packet_t uid,
                               char **emailp);

/*/
/// Returns a normalized version of the UserID's email address.
///
/// Normalized email addresses are primarily needed when email
/// addresses are compared.
///
/// Note: normalized email addresses are still valid email
/// addresses.
///
/// This function normalizes an email address by doing [puny-code
/// normalization] on the domain, and lowercasing the local part in
/// the so-called [empty locale].
///
/// Note: this normalization procedure is the same as the
/// normalization procedure recommended by [Autocrypt].
///
///   [puny-code normalization]: https://tools.ietf.org/html/rfc5891.html#section-4.4
///   [empty locale]: https://www.w3.org/International/wiki/Case_folding
///   [Autocryt]: https://autocrypt.org/level1.html#e-mail-address-canonicalization
/*/
pgp_status_t pgp_user_id_email_normalized(pgp_error_t *errp, pgp_packet_t uid,
                                          char **emailp);

/*/
/// Returns the User ID's URI, if any.
///
/// The User ID is parsed according to de facto convention, and the
/// URI is extracted.
///
/// If the User ID cannot be parsed, then an error is returned.
///
/// If the User ID does not contain a URI, *urip is set to NULL.
/*/
pgp_status_t pgp_user_id_uri(pgp_error_t *errp, pgp_packet_t uid,
                             char **uri);

/*/
/// Returns the value of the User Attribute Packet.
///
/// The returned pointer is valid until `ua` is deallocated.  If
/// `value_len` is not `NULL`, the size of value is stored there.
/*/
const uint8_t *pgp_user_attribute_value (pgp_packet_t ua,
					size_t *value_len);

/*/
/// Frees a pgp_user_id_t.
/*/
void pgp_user_id_free (pgp_user_id_t userid);

/*/
/// Clones the UserID.
/*/
pgp_user_id_t pgp_user_id_clone (pgp_user_id_t userid);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_user_id_debug (const pgp_user_id_t userid);

/*/
/// Compares passwords.
/*/
bool pgp_user_id_equal (const pgp_user_id_t a, const pgp_user_id_t b);

/*/
/// Returns the session key.
///
/// `key` of size `key_len` must be a buffer large enough to hold the
/// session key.  If `key` is NULL, or not large enough, then the key
/// is not written to it.  Either way, `key_len` is set to the size of
/// the session key.
/*/
pgp_status_t pgp_skesk_decrypt (pgp_error_t *errp, pgp_packet_t skesk,
                              const uint8_t *password, size_t password_len,
                              uint8_t *algo, /* XXX */
                              uint8_t *key, size_t *key_len);

/*/
/// Returns the key's creation time.
/*/
time_t pgp_key_creation_time (pgp_key_t p);

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
///
/// If the message is not well-formed, `*errp` explains why this is
/// not the case.
/*/
bool pgp_packet_parser_eof_is_message(pgp_error_t *errp,
                                      pgp_packet_parser_eof_t eof);

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
///
/// The signers are consumed.
///
/// The hash is performed using the algorithm specified in
/// `hash_algo`.  Pass 0 for the default (which is what you usually
/// want).
/*/
pgp_writer_stack_t pgp_signer_new (pgp_error_t *errp,
                                   pgp_writer_stack_t inner,
                                   pgp_signer_t *signers, size_t signers_len,
				   uint8_t hash_algo);

/*/
/// Creates a signer for a detached signature.
/*/
pgp_writer_stack_t pgp_signer_new_detached (pgp_error_t *errp,
                                            pgp_writer_stack_t inner,
                                            pgp_signer_t *signers,
                                            size_t signers_len,
					    uint8_t hash_algo);

/*/
/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
/*/
pgp_writer_stack_t pgp_literal_writer_new (pgp_error_t *errp,
                                         pgp_writer_stack_t inner);

/*/
/// Creates a new encryptor.
///
/// The stream will be encrypted using a generated session key,
/// which will be encrypted using the given passwords, and all
/// encryption-capable subkeys of the given Certs.
/*/
pgp_writer_stack_t pgp_encryptor_new (pgp_error_t *errp,
				      pgp_writer_stack_t inner,
				      char **passwords,
				      size_t passwords_len,
				      pgp_recipient_t *recipients,
				      size_t recipients_len,
				      uint8_t cipher_algo,
				      uint8_t aead_algo);

/*/
/// Frees this object.
/*/
void pgp_message_structure_free (pgp_message_structure_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_message_structure_debug (const pgp_message_structure_t);

pgp_message_structure_iter_t
pgp_message_structure_iter (pgp_message_structure_t);

/*/
/// Frees this object.
/*/
void pgp_message_structure_iter_free (pgp_message_structure_iter_t);

pgp_message_layer_t
pgp_message_structure_iter_next (pgp_message_structure_iter_t);

/*/
/// Frees this object.
/*/
void pgp_message_layer_free (pgp_message_layer_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_message_layer_debug (const pgp_message_layer_t);

/*/
/// Returns the message layer variant.
/*/
pgp_message_layer_variant_t
pgp_message_layer_variant (pgp_message_layer_t);

/*/
/// Return the fields of the variants.
/*/
bool pgp_message_layer_compression (pgp_message_layer_t, uint8_t *);
bool pgp_message_layer_encryption (pgp_message_layer_t, uint8_t *, uint8_t *);
bool pgp_message_layer_signature_group (pgp_message_layer_t,
					pgp_verification_result_iter_t *);

/*/
/// Frees this object.
/*/
void pgp_verification_result_iter_free (pgp_verification_result_iter_t);

pgp_verification_result_t
pgp_verification_result_iter_next (pgp_verification_result_iter_t);

/*/
/// Frees this object.
/*/
void pgp_verification_result_free (pgp_verification_result_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_verification_result_debug (const pgp_verification_result_t);

/*/
/// Returns the verification result variant.
/*/
pgp_verification_result_variant_t pgp_verification_result_variant (
    pgp_verification_result_t r);

/*/
/// Return the fields of the variants.
/*/
bool pgp_verification_result_good_checksum (pgp_verification_result_t,
					    pgp_signature_t *,
					    pgp_cert_t *,
					    pgp_key_t *,
					    pgp_signature_t *,
					    pgp_revocation_status_t *);
bool pgp_verification_result_malformed_signature (pgp_verification_result_t,
                                                  pgp_signature_t *,
                                                  pgp_error_t *);
bool pgp_verification_result_missing_key (pgp_verification_result_t,
                                          pgp_signature_t *);
bool pgp_verification_result_unbound_key (pgp_verification_result_t,
                                          pgp_signature_t *,
                                          pgp_cert_t *,
                                          pgp_error_t *);
bool pgp_verification_result_bad_key (pgp_verification_result_t,
                                      pgp_signature_t *,
                                      pgp_cert_t *,
                                      pgp_key_t *,
                                      pgp_signature_t *,
                                      pgp_revocation_status_t *,
                                      pgp_error_t *);
bool pgp_verification_result_bad_signature (pgp_verification_result_t,
                                            pgp_signature_t *,
                                            pgp_cert_t *,
                                            pgp_key_t *,
                                            pgp_signature_t *,
                                            pgp_revocation_status_t *,
                                            pgp_error_t *);

/*/
/// Decrypts an OpenPGP message.
///
/// The message is read from `input` and the content of the
/// `LiteralData` packet is written to output.  Note: the content is
/// written even if the message is not encrypted.  You can determine
/// whether the message was actually decrypted by recording whether
/// the get_secret_keys callback was called in the cookie.
///
/// The function takes three callbacks.  The `cookie` is passed as the
/// first parameter to each of them.
///
/// Note: all of the parameters are required; none may be NULL.
/*/
pgp_reader_t pgp_decryptor_new (pgp_error_t *errp,
    pgp_policy_t policy,
    pgp_reader_t input,
    pgp_decryptor_get_public_keys_cb_t get_public_keys,
    pgp_decryptor_decrypt_cb_t decrypt,
    pgp_decryptor_check_cb_t check,
    pgp_decryptor_inspect_cb_t inspect,
    void *cookie, time_t time);

/*/
/// Verifies an OpenPGP message.
///
/// No attempt is made to decrypt any encryption packets.  These are
/// treated as opaque containers.
/*/
pgp_reader_t pgp_verifier_new (pgp_error_t *errp,
    pgp_policy_t policy,
    pgp_reader_t input,
    pgp_decryptor_get_public_keys_cb_t get_public_keys,
    pgp_decryptor_check_cb_t check,
    void *cookie, time_t time);

/*/
/// Verifies a detached OpenPGP signature.
/*/
pgp_detached_verifier_t pgp_detached_verifier_new (pgp_error_t *errp,
    pgp_policy_t policy,
    pgp_reader_t signature_input,
    pgp_decryptor_get_public_keys_cb_t get_public_keys,
    pgp_decryptor_check_cb_t check,
    void *cookie, time_t time);

/*/
/// Frees this object.
/*/
void pgp_detached_verifier_free (pgp_detached_verifier_t);

/*/
/// Verifies `data` using `verifier`.
/*/
pgp_status_t pgp_detached_verifier_verify (pgp_error_t *errp,
                                           pgp_detached_verifier_t verifier,
                                           pgp_reader_t data);

/*/
/// Returns a new standard policy.
/*/
pgp_policy_t pgp_standard_policy ();

/*/
/// Clones the object.
/*/
pgp_policy_t pgp_standard_policy_clone (pgp_standard_policy_t);

/*/
/// Frees this object.
/*/
void pgp_standard_policy_free (pgp_standard_policy_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_standard_policy_debug (const pgp_standard_policy_t);

/*/
/// Returns a new null policy.
/*/
pgp_policy_t pgp_null_policy ();

/*/
/// Clones the object.
/*/
pgp_policy_t pgp_null_policy_clone (pgp_null_policy_t);

/*/
/// Frees this object.
/*/
void pgp_null_policy_free (pgp_null_policy_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_null_policy_debug (const pgp_null_policy_t);

/*/
/// Clones the object.
/*/
pgp_policy_t pgp_policy_clone (pgp_policy_t);

/*/
/// Frees this object.
/*/
void pgp_policy_free (pgp_policy_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_policy_debug (const pgp_policy_t);

#endif
