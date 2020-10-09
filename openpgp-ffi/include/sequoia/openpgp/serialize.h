#ifndef SEQUOIA_OPENPGP_SERIALIZE_H
#define SEQUOIA_OPENPGP_SERIALIZE_H

/*/
/// Creates a new recipient with an explicit recipient keyid.
///
/// Consumes `keyid`, references `key`.
/*/
pgp_recipient_t pgp_recipient_new (pgp_keyid_t keyid, pgp_key_t key);

/*/
/// Frees this object.
/*/
void pgp_recipient_free (pgp_recipient_t);

/*/
/// Returns a human readable description of this object suitable for
/// debugging.
/*/
char *pgp_recipient_debug (const pgp_recipient_t);

/*/
/// Gets the KeyID.
/*/
pgp_keyid_t pgp_recipient_keyid (const pgp_recipient_t);

/*/
/// Sets the KeyID.
/*/
void pgp_recipient_set_keyid (pgp_recipient_t *, pgp_keyid_t);

/*/
/// Collects recipients from a `pgp_cert_key_iter_t`.
///
/// Consumes the iterator.  The returned buffer must be freed using
/// libc's allocator.
/*/
pgp_recipient_t *pgp_recipients_from_key_iter (pgp_cert_key_iter_t, size_t *);

/*/
/// Collects recipients from a `pgp_cert_valid_key_iter_t`.
///
/// Consumes the iterator.  The returned buffer must be freed using
/// libc's allocator.
/*/
pgp_recipient_t *pgp_recipients_from_valid_key_iter (pgp_cert_valid_key_iter_t, size_t *);

#endif
