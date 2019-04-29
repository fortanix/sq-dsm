#ifndef SEQUOIA_OPENPGP_PACKET_H
#define SEQUOIA_OPENPGP_PACKET_H

/*/
/// Returns a human-readable tag name.
/*/
const char *pgp_tag_to_string (pgp_tag_t tag);

/*/
/// Frees the Packet.
/*/
void pgp_packet_free (pgp_packet_t p);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_packet_debug (const pgp_packet_t fp);

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

#endif
