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
struct sq_context;

/*/
/// Returns the last error message.
///
/// The returned value must be freed with `sq_string_free`.
/*/
char *sq_last_strerror (const struct sq_context *ctx);

/*/
/// Frees a string returned from Sequoia.
/*/
void sq_string_free (char *s);

/*/
/// Represents a `Context` configuration.
/*/
struct sq_config;

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
struct sq_context *sq_context_new(const char *domain);

/*/
/// Frees a context.
/*/
void sq_context_free(struct sq_context *context);

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
struct sq_config *sq_context_configure(const char *domain);

/*/
/// Returns the domain of the context.
/*/
const char *sq_context_domain(const struct sq_context *ctx);

/*/
/// Returns the directory containing shared state.
/*/
const char *sq_context_home(const struct sq_context *ctx);

/*/
/// Returns the directory containing backend servers.
/*/
const char *sq_context_lib(const struct sq_context *ctx);

/*/
/// Returns the network policy.
/*/
uint8_t sq_context_network_policy(const struct sq_context *ctx);

/*/
/// Returns whether or not this is an ephemeral context.
/*/
uint8_t sq_context_ephemeral(const struct sq_context *ctx);


/* sequoia::Config.  */

/*/
/// Finalizes the configuration and return a `Context`.
///
/// Consumes `cfg`.  Returns `NULL` on errors.
/*/
struct sq_context *sq_config_build(struct sq_config *cfg);

/*/
/// Sets the directory containing shared state.
/*/
void sq_config_home(struct sq_config *cfg, const char *home);

/*/
/// Sets the directory containing backend servers.
/*/
void sq_config_lib(struct sq_config *cfg, const char *lib);

/*/
/// Sets the network policy.
/*/
void sq_config_network_policy(struct sq_config *cfg, uint8_t policy);

/*/
/// Makes this context ephemeral.
/*/
void sq_config_ephemeral(struct sq_config *cfg);


/* sequoia::openpgp::KeyID.  */

/*/
/// Holds a KeyID.
/*/
struct sq_keyid;

/*/
/// Reads a binary key ID.
/*/
struct sq_keyid *sq_keyid_from_bytes (const uint8_t *id);

/*/
/// Reads a hex-encoded Key ID.
/*/
struct sq_keyid *sq_keyid_from_hex (const char *id);

/*/
/// Frees a keyid object.
/*/
void sq_keyid_free (struct sq_keyid *keyid);


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
struct sq_tpk;

/*/
/// Returns the first TPK found in `buf`.
///
/// `buf` must be an OpenPGP encoded message.
/*/
struct sq_tpk *sq_tpk_from_bytes (struct sq_context *ctx,
				  const char *b, size_t len);

/*/
/// Frees the TPK.
/*/
void sq_tpk_free (struct sq_tpk *tpk);

/*/
/// Dumps the TPK.
/*/
void sq_tpk_dump (const struct sq_tpk *tpk);


/* sequoia::net.  */

/*/
/// For accessing keyservers using HKP.
/*/
struct sq_keyserver;

/*/
/// Returns a handle for the given URI.
///
/// `uri` is a UTF-8 encoded value of a keyserver URI,
/// e.g. `hkps://examle.org`.
///
/// Returns `NULL` on errors.
/*/
struct sq_keyserver *sq_keyserver_new (const struct sq_context *ctx,
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
struct sq_keyserver *sq_keyserver_with_cert (const struct sq_context *ctx,
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
struct sq_keyserver *sq_keyserver_sks_pool (const struct sq_context *ctx);

/*/
/// Frees a keyserver object.
/*/
void sq_keyserver_free (struct sq_keyserver *ks);

/*/
/// Retrieves the key with the given `keyid`.
///
/// Returns `NULL` on errors.
/*/
struct sq_tpk *sq_keyserver_get (struct sq_keyserver *ks,
				 const struct sq_keyid *id);

#endif
