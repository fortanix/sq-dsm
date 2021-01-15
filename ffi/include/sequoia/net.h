#ifndef SEQUOIA_NET_H
#define SEQUOIA_NET_H

#include <sequoia/core.h>

/*/
/// For accessing keyservers using HKP.
/*/
typedef struct sq_keyserver *sq_keyserver_t;

/*/
/// Network policy for Sequoia.
///
/// With this policy you can control how Sequoia accesses remote
/// systems.
/*/
typedef enum sq_network_policy {
  /* Do not contact remote systems.  */
  SQ_NETWORK_POLICY_OFFLINE = 0,

  /* Only contact remote systems using anonymization techniques like
   * TOR.  */
  SQ_NETWORK_POLICY_ANONYMIZED = 1,

  /* Only contact remote systems using transports offering
   * encryption and authentication like TLS.  */
  SQ_NETWORK_POLICY_ENCRYPTED = 2,

  /* Contact remote systems even with insecure transports.  */
  SQ_NETWORK_POLICY_INSECURE = 3,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_NETWORK_POLICY_FORCE_WIDTH = INT_MAX,
} sq_network_policy_t;


/*/
/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.
///
/// Returns `NULL` on errors.
/*/
sq_keyserver_t sq_keyserver_new (sq_context_t ctx,
				 sq_network_policy_t policy,
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
				       sq_network_policy_t policy,
				       const char *uri,
				       const uint8_t *cert,
				       size_t len);

/*/
/// Returns a handle for keys.openpgp.org.
///
/// The server at `hkps://keys.openpgp.org` distributes updates for
/// OpenPGP certificates.  It is a good default choice.
///
/// Returns `NULL` on errors.
/*/
sq_keyserver_t sq_keyserver_keys_openpgp_org (sq_context_t ctx,
					      sq_network_policy_t policy);

/*/
/// Frees a keyserver object.
/*/
void sq_keyserver_free (sq_keyserver_t ks);

/*/
/// Retrieves the key with the given `keyid`.
///
/// Returns `NULL` on errors.
/*/
pgp_cert_t sq_keyserver_get (sq_context_t ctx,
			   sq_keyserver_t ks,
			   const pgp_keyid_t id);

/*/
/// Sends the given key to the server.
///
/// Returns != 0 on errors.
/*/
pgp_status_t sq_keyserver_send (sq_context_t ctx,
			       sq_keyserver_t ks,
			       const pgp_cert_t cert);

#endif
