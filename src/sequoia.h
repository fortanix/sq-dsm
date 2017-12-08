#ifndef SEQUOIA_H
#define SEQUOIA_H

#include <stddef.h>
#include <stdint.h>

/*/
/// A `&Context` is required for many operations.
///
/// # Example
///
/// ```c
/// struct sq_context *ctx sq_context_new("org.sequoia-pgp.example");
/// if (ctx == 0) { ... }
/// ```
/*/
struct sq_context;

/*/
/*/
struct sq_config;

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

/*  sequoia::Config.  */

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
/// Set the directory containing backend servers.
/*/
void sq_config_lib(struct sq_config *cfg, const char *lib);

struct sq_keyid;
struct sq_keyid *sq_keyid_new (uint64_t id);
struct sq_keyid *sq_keyid_from_hex (const char *id);
void sq_keyid_free (struct sq_keyid *keyid);

struct sq_tpk;
struct sq_tpk *sq_tpk_from_bytes (const char *b, size_t len);
void sq_tpk_dump (const struct sq_tpk *tpk);
void sq_tpk_free (struct sq_tpk *tpk);

#endif
