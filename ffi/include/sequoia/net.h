#ifndef SEQUOIA_NET_H
#define SEQUOIA_NET_H

#include <sequoia/core.h>

/*/
/// For accessing keyservers using HKP.
/*/
typedef struct sq_keyserver *sq_keyserver_t;

/*/
/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.
///
/// Returns `NULL` on errors.
/*/
sq_keyserver_t sq_keyserver_new (sq_context_t ctx,
				 const char *uri);

/*/
/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.  `cert` is a DER encoded certificate of
/// size `len` used to authenticate the server.
///
/// Returns `NULL` on errors.
/*/
sq_keyserver_t sq_keyserver_with_cert (sq_context_t ctx,
				       const char *uri,
				       const uint8_t *cert,
				       size_t len);

/*/
/// Returns a handle for the SKS keyserver pool.
///
/// The pool `hkps://hkps.pool.sks-keyservers.net` provides HKP
/// services over https.  It is authenticated using a certificate
/// included in this library.  It is a good default choice.
///
/// Returns `NULL` on errors.
/*/
sq_keyserver_t sq_keyserver_sks_pool (sq_context_t ctx);

/*/
/// Frees a keyserver object.
/*/
void sq_keyserver_free (sq_keyserver_t ks);

/*/
/// Retrieves the key with the given `keyid`.
///
/// Returns `NULL` on errors.
/*/
pgp_tpk_t sq_keyserver_get (sq_context_t ctx,
			   sq_keyserver_t ks,
			   const pgp_keyid_t id);

/*/
/// Sends the given key to the server.
///
/// Returns != 0 on errors.
/*/
pgp_status_t sq_keyserver_send (sq_context_t ctx,
			       sq_keyserver_t ks,
			       const pgp_tpk_t tpk);

#endif
