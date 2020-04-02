#ifndef SEQUOIA_OPENPGP_PACKET_H
#define SEQUOIA_OPENPGP_PACKET_H

/*/
/// Frees the Packet.
/*/
void pgp_packet_free (pgp_packet_t p);

/*/
/// Clones this object.
/*/
pgp_packet_t pgp_packet_clone (pgp_packet_t keyid);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_packet_debug (const pgp_packet_t fp);

/*/
/// Compares objects of this kind.
/*/
bool pgp_packet_equal (const pgp_packet_t a, const pgp_packet_t b);

/*/
/// Hashes this object.
/*/
uint64_t pgp_packet_hash (pgp_packet_t keyid);

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

/*/
/// Returns a human-readable tag name.
/*/
const char *pgp_tag_to_string (pgp_tag_t tag);

/*/
/// Given a packet references the contained signature, if any.
///
/// If the Packet is not of the `Packet::Signature` variant, this
/// function returns `NULL`.  Objects returned from this function must
/// be deallocated using `pgp_signature_free` even though they only
/// reference the given packet.
/*/
pgp_signature_t pgp_packet_ref_signature (pgp_packet_t p);

/*/
/// Given a packet references the contained literal data packet, if
/// any.
///
/// If the Packet is not of the `Packet::Literal` variant, this
/// function returns `NULL`.  Objects returned from this function must
/// be deallocated using `pgp_literal_data_free` even though they only
/// reference the given packet.
/*/
pgp_literal_t pgp_packet_ref_literal (pgp_packet_t p);

#endif
