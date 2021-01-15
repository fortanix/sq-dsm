#ifndef SEQUOIA_CORE_H
#define SEQUOIA_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>

/* sequoia::Context.  */

/*/
/// A `struct sq_context *` is required for many operations.
///
/// # Example
///
/// ```c
/// struct sq_context *ctx sq_context_new();
/// if (ctx == NULL) { ... }
/// ```
/*/
typedef struct sq_context *sq_context_t;

/*/
/// Returns the last error.
///
/// Returns and removes the last error from the context.
/*/
pgp_error_t sq_context_last_error (sq_context_t ctx);

/*/
/// Represents a `Context` configuration.
/*/
typedef struct sq_config *sq_config_t;

/*/
/// IPC policy for Sequoia.
///
/// With this policy you can control how Sequoia starts background
/// servers.
/*/
typedef enum sq_ipc_policy {
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
  SQ_IPC_POLICY_EXTERNAL = 0,

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
  SQ_IPC_POLICY_INTERNAL = 1,

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
  SQ_IPC_POLICY_ROBUST = 2,

  /* Dummy value to make sure the enumeration has a defined size.  Do
     not use this value.  */
  SQ_IPC_POLICY_FORCE_WIDTH = INT_MAX,
} sq_ipc_policy_t;


/*/
/// Creates a Context with reasonable defaults.
///
/// Returns `NULL` on errors.  If `errp` is not `NULL`, the error is
/// stored there.
/*/
sq_context_t sq_context_new(pgp_error_t *errp);

/*/
/// Frees a context.
/*/
void sq_context_free(sq_context_t context);

/*/
/// Creates a Context that can be configured.
///
/// The configuration is seeded like in `sq_context_new`, but can be
/// modified.  A configuration has to be finalized using
/// `sq_config_build()` in order to turn it into a Context.
/*/
sq_config_t sq_context_configure(void);

/*/
/// Returns the directory containing shared state.
/*/
const char *sq_context_home(const sq_context_t ctx);

/*/
/// Returns the directory containing backend servers.
/*/
const char *sq_context_lib(const sq_context_t ctx);

/*/
/// Returns the IPC policy.
/*/
sq_ipc_policy_t sq_context_ipc_policy(const sq_context_t ctx);

/*/
/// Returns whether or not this is an ephemeral context.
/*/
uint8_t sq_context_ephemeral(const sq_context_t ctx);


/* sequoia::Config.  */

/*/
/// Finalizes the configuration and return a `Context`.
///
/// Consumes `cfg`.  Returns `NULL` on errors. Returns `NULL` on
/// errors.  If `errp` is not `NULL`, the error is stored there.
/*/
sq_context_t sq_config_build(sq_config_t cfg, pgp_error_t *errp);

/*/
/// Sets the directory containing shared state.
/*/
void sq_config_home(sq_config_t cfg, const char *home);

/*/
/// Sets the directory containing backend servers.
/*/
void sq_config_lib(sq_config_t cfg, const char *lib);

/*/
/// Sets the IPC policy.
/*/
void sq_config_ipc_policy(sq_config_t cfg, sq_ipc_policy_t policy);

/*/
/// Makes this context ephemeral.
/*/
void sq_config_ephemeral(sq_config_t cfg);

#endif
