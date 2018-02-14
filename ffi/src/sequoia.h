#ifndef SEQUOIA_H
#define SEQUOIA_H

#include <stddef.h>
#include <stdint.h>


/* sequoia::Context.  */

/*/
/// A `struct sq_context *` is required for many operations.
///
/// # Example
///
/// ```c
/// struct sq_context *ctx sq_context_new("org.sequoia-pgp.example");
/// if (ctx == NULL) { ... }
/// ```
/*/
typedef struct sq_context *sq_context_t;

/*/
/// Returns the last error message.
///
/// The returned value must be freed with `sq_string_free`.
/*/
char *sq_last_strerror (const sq_context_t ctx);

/*/
/// Frees a string returned from Sequoia.
/*/
void sq_string_free (char *s);

/*/
/// Represents a `Context` configuration.
/*/
typedef struct sq_config *sq_config_t;

/*/
/// Network policy for Sequoia.
///
/// With this policy you can control how Sequoia accesses remote
/// systems.
/*/

/* Do not contact remote systems.  */
#define SQ_NETWORK_POLICY_OFFLINE	0

/* Only contact remote systems using anonymization techniques
 * like TOR.  */
#define SQ_NETWORK_POLICY_ANONYMIZED	1

/* Only contact remote systems using transports offering
 * encryption and authentication like TLS.  */
#define SQ_NETWORK_POLICY_ENCRYPTED	2

/* Contact remote systems even with insecure transports.  */
#define SQ_NETWORK_POLICY_INSECURE	3

/*/
/// IPC policy for Sequoia.
///
/// With this policy you can control how Sequoia starts background
/// servers.
/*/

/*/
/// External background servers only.
///
/// We will always use external background servers.  If starting
/// one fails, the operation will fail.
///
/// The advantage is that we never spawn a thread.
///
/// The disadvantage is that we need to locate the background
/// server to start.  If you are distribute Sequoia with your
/// application, make sure to include the binaries, and to
/// configure the Context so that `context.lib()` points to the
/// directory containing the binaries.
/*/
#define SQ_IPC_POLICY_EXTERNAL	0

/*/
/// Internal background servers only.
///
/// We will always use internal background servers.  It is very
/// unlikely that this fails.
///
/// The advantage is that this method is very robust.  If you
/// distribute Sequoia with your application, you do not need to
/// ship the binary, and it does not matter what `context.lib()`
/// points to.  This is very robust and convenient.
///
/// The disadvantage is that we spawn a thread in your
/// application.  Threads may play badly with `fork(2)`, file
/// handles, and locks.  If you are not doing anything fancy,
/// however, and only use fork-then-exec, you should be okay.
/*/
#define SQ_IPC_POLICY_INTERNAL	1

/*/
/// Prefer external, fall back to internal.
///
/// We will first try to use an external background server, but
/// fall back on an internal one should that fail.
///
/// The advantage is that if Sequoia is properly set up to find
/// the background servers, we will use these and get the
/// advantages of that approach.  Because we fail back on using an
/// internal server, we gain the robustness of that approach.
///
/// The disadvantage is that we may or may not spawn a thread in
/// your application.  If this is unacceptable in your
/// environment, use the `External` policy.
/*/
#define SQ_IPC_POLICY_ROBUST	2


/*/
/// Creates a Context with reasonable defaults.
///
/// `domain` should uniquely identify your application, it is strongly
/// suggested to use a reversed fully qualified domain name that is
/// associated with your application.  `domain` must not be `NULL`.
///
/// Returns `NULL` on errors.
/*/
sq_context_t sq_context_new(const char *domain);

/*/
/// Frees a context.
/*/
void sq_context_free(sq_context_t context);

/*/
/// Creates a Context that can be configured.
///
/// `domain` should uniquely identify your application, it is strongly
/// suggested to use a reversed fully qualified domain name that is
/// associated with your application.  `domain` must not be `NULL`.
///
/// The configuration is seeded like in `sq_context_new`, but can be
/// modified.  A configuration has to be finalized using
/// `sq_config_build()` in order to turn it into a Context.
/*/
sq_config_t sq_context_configure(const char *domain);

/*/
/// Returns the domain of the context.
/*/
const char *sq_context_domain(const sq_context_t ctx);

/*/
/// Returns the directory containing shared state.
/*/
const char *sq_context_home(const sq_context_t ctx);

/*/
/// Returns the directory containing backend servers.
/*/
const char *sq_context_lib(const sq_context_t ctx);

/*/
/// Returns the network policy.
/*/
uint8_t sq_context_network_policy(const sq_context_t ctx);

/*/
/// Returns whether or not this is an ephemeral context.
/*/
uint8_t sq_context_ephemeral(const sq_context_t ctx);


/* sequoia::Config.  */

/*/
/// Finalizes the configuration and return a `Context`.
///
/// Consumes `cfg`.  Returns `NULL` on errors.
/*/
sq_context_t sq_config_build(sq_config_t cfg);

/*/
/// Sets the directory containing shared state.
/*/
void sq_config_home(sq_config_t cfg, const char *home);

/*/
/// Sets the directory containing backend servers.
/*/
void sq_config_lib(sq_config_t cfg, const char *lib);

/*/
/// Sets the network policy.
/*/
void sq_config_network_policy(sq_config_t cfg, uint8_t policy);

/*/
/// Makes this context ephemeral.
/*/
void sq_config_ephemeral(sq_config_t cfg);


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
/// Converts the KeyID to its standard representation.
/*/
char *sq_keyid_to_string (const sq_keyid_t fp);

/*/
/// Converts the KeyID to a hexadecimal number.
/*/
char *sq_keyid_to_hex (const sq_keyid_t fp);


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


/* sequoia::keys.  */

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
/// Dumps the TPK.
/*/
void sq_tpk_dump (const sq_tpk_t tpk);


/* sequoia::net.  */

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
sq_tpk_t sq_keyserver_get (sq_context_t ctx,
			   sq_keyserver_t ks,
			   const sq_keyid_t id);

/*/
/// Sends the given key to the server.
///
/// Returns != 0 on errors.
/*/
int sq_keyserver_send (sq_context_t ctx,
		       sq_keyserver_t ks,
		       const sq_tpk_t tpk);


/* sequoia::store.  */

/*/
/// A public key store.
/*/
typedef struct sq_store *sq_store_t;

/*/
/// Frees a sq_store_t.
/*/
void sq_store_free (sq_store_t store);

/*/
/// Represents an entry in a Store.
///
/// Stores map labels to TPKs.  A `Binding` represents a pair in this
/// relation.  We make this explicit because we associate metadata
/// with these pairs.
/*/
typedef struct sq_binding *sq_binding_t;

/*/
/// Frees a sq_binding_t.
/*/
void sq_binding_free (sq_binding_t binding);

/*/
/// Represents a key in a store.
///
/// A `Key` is a handle to a stored TPK.  We make this explicit
/// because we associate metadata with TPKs.
/*/
typedef struct sq_key *sq_key_t;

/*/
/// Frees a sq_key_t.
/*/
void sq_key_free (sq_key_t key);

/*/
/// Represents a log entry.
/*/
typedef struct sq_log *sq_log_t;

/*/
/// Frees a sq_log_t.
/*/
void sq_log_free (sq_log_t log);

/*/
/// Represents binding or key stats.
/*/
typedef struct sq_stats *sq_stats_t;

/*/
/// Frees a sq_stats_t.
/*/
void sq_stats_free (sq_stats_t stats);

/*/
/// Iterates over stores.
/*/
typedef struct sq_store_iter *sq_store_iter_t;

/*/
/// Returns the next store.
///
/// Returns `NULL` on exhaustion.  If `domainp` is not `NULL`, the
/// stores domain is stored there.  If `namep` is not `NULL`, the
/// stores name is stored there.  If `policyp` is not `NULL`, the
/// stores network policy is stored there.
/*/
sq_store_t sq_store_iter_next (sq_store_iter_t iter,
			       char **domainp,
			       char **namep,
			       uint8_t *policyp);


/*/
/// Frees a sq_store_iter_t.
/*/
void sq_store_iter_free (sq_store_iter_t iter);

/*/
/// Iterates over bindings in a store.
/*/
typedef struct sq_binding_iter *sq_binding_iter_t;

/*/
/// Returns the next binding.
///
/// Returns `NULL` on exhaustion.  If `labelp` is not `NULL`, the
/// bindings label is stored there.  If `fpp` is not `NULL`, the
/// bindings fingerprint is stored there.
/*/
sq_binding_t sq_binding_iter_next (sq_binding_iter_t iter,
				   char **labelp,
				   sq_fingerprint_t *fpp);

/*/
/// Frees a sq_binding_iter_t.
/*/
void sq_binding_iter_free (sq_binding_iter_t iter);

/*/
/// Iterates over keys in the common key pool.
/*/
typedef struct sq_key_iter *sq_key_iter_t;

/*/
/// Returns the next key.
///
/// Returns `NULL` on exhaustion.  If `fpp` is not `NULL`, the keys
/// fingerprint is stored there.
/*/
sq_key_t sq_key_iter_next (sq_key_iter_t iter,
			   sq_fingerprint_t *fpp);

/*/
/// Frees a sq_key_iter_t.
/*/
void sq_key_iter_free (sq_key_iter_t iter);

/*/
/// Iterates over logs.
/*/
typedef struct sq_log_iter *sq_log_iter_t;

/*/
/// Returns the next log entry.
///
/// Returns `NULL` on exhaustion.
/*/
sq_log_t sq_log_iter_next (sq_log_iter_t iter);

/*/
/// Frees a sq_log_iter_t.
/*/
void sq_log_iter_free (sq_log_iter_t iter);

/*/
/// Lists all log entries.
/*/
sq_log_iter_t sq_store_server_log (sq_context_t ctx);

/*/
/// Opens a store.
///
/// Opens a store with the given name.  If the store does not
/// exist, it is created.  Stores are handles for objects
/// maintained by a background service.  The background service
/// associates state with this name.
///
/// The store updates TPKs in compliance with the network policy
/// of the context that created the store in the first place.
/// Opening the store with a different network policy is
/// forbidden.
/*/
sq_store_t sq_store_open (sq_context_t ctx, const char *name);

/*/
/// Adds a key identified by fingerprint to the store.
/*/
sq_binding_t sq_store_add (sq_context_t ctx, sq_store_t store,
			   const char *label, sq_fingerprint_t fp);

/*/
/// Imports a key into the store.
/*/
sq_tpk_t sq_store_import (sq_context_t ctx, sq_store_t store,
			  const char *label, sq_tpk_t tpk);

/*/
/// Returns the binding for the given label.
/*/
sq_binding_t sq_store_lookup (sq_context_t ctx, sq_store_t store,
			      const char *label);

/*/
/// Deletes this store.
///
/// Consumes `store`.  Returns != 0 on error.
/*/
long sq_store_delete (sq_store_t store);

/*/
/// Lists all bindings.
/*/
sq_binding_iter_t sq_store_iter (sq_context_t ctx, sq_store_t store);

/*/
/// Lists all log entries related to this store.
/*/
sq_log_iter_t sq_store_log (sq_context_t ctx, sq_store_t store);

/*/
/// Returns the `sq_stats_t` of this binding.
/*/
sq_stats_t sq_binding_stats (sq_context_t ctx, sq_binding_t binding);

/*/
/// Returns the `sq_key_t` of this binding.
/*/
sq_key_t sq_binding_key (sq_context_t ctx, sq_binding_t binding);

/*/
/// Returns the `sq_tpk_t` of this binding.
/*/
sq_tpk_t sq_binding_tpk (sq_context_t ctx, sq_binding_t binding);

/*/
/// Updates this binding with the given TPK.
///
/// If the new key `tpk` matches the current key, i.e. they have
/// the same fingerprint, both keys are merged and normalized.
/// The returned key contains all packets known to Sequoia, and
/// should be used instead of `tpk`.
///
/// If the new key does not match the current key, but carries a
/// valid signature from the current key, it replaces the current
/// key.  This provides a natural way for key rotations.
///
/// If the new key does not match the current key, and it does not
/// carry a valid signature from the current key, an
/// `Error::Conflict` is returned, and you have to resolve the
/// conflict, either by ignoring the new key, or by using
/// `sq_binding_rotate` to force a rotation.
/*/
sq_tpk_t sq_binding_import (sq_context_t ctx, sq_binding_t binding,
			    sq_tpk_t tpk);

/*/
/// Forces a keyrotation to the given TPK.
///
/// The current key is replaced with the new key `tpk`, even if
/// they do not have the same fingerprint.  If a key with the same
/// fingerprint as `tpk` is already in the store, is merged with
/// `tpk` and normalized.  The returned key contains all packets
/// known to Sequoia, and should be used instead of `tpk`.
///
/// Use this function to resolve conflicts returned from
/// `sq_binding_import`.  Make sure that you have authenticated
/// `tpk` properly.  How to do that depends on your thread model.
/// You could simply ask Alice to call her communication partner
/// Bob and confirm that he rotated his keys.
/*/
sq_tpk_t sq_binding_rotate (sq_context_t ctx, sq_binding_t binding,
			    sq_tpk_t tpk);

/*/
/// Deletes this binding.
///
/// Consumes `binding`.  Returns != 0 on error.
/*/
long sq_binding_delete (sq_binding_t binding);

/*/
/// Lists all log entries related to this binding.
/*/
sq_log_iter_t sq_binding_log (sq_context_t ctx, sq_binding_t binding);

/*/
/// Returns the `sq_stats_t` of this key.
/*/
sq_stats_t sq_key_stats (sq_context_t ctx, sq_key_t key);

/*/
/// Returns the `sq_tpk_t` of this key.
/*/
sq_tpk_t sq_key_tpk (sq_context_t ctx, sq_key_t key);

/*/
/// Updates this stored key with the given TPK.
///
/// If the new key `tpk` matches the current key, i.e. they have
/// the same fingerprint, both keys are merged and normalized.
/// The returned key contains all packets known to Sequoia, and
/// should be used instead of `tpk`.
///
/// If the new key does not match the current key,
/// `Error::Conflict` is returned.
/*/
sq_tpk_t sq_key_import (sq_context_t ctx, sq_key_t key,
			sq_tpk_t tpk);

/*/
/// Lists all log entries related to this key.
/*/
sq_log_iter_t sq_key_log (sq_context_t ctx, sq_key_t key);

#endif
