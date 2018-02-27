#ifndef SEQUOIA_STORE_H
#define SEQUOIA_STORE_H

#include <sequoia/core.h>

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
struct sq_log {
  /*/
  /// Records the time of the entry.
  /*/
  uint64_t timestamp;

  /*/
  /// Relates the entry to a store.
  ///
  /// May be `NULL`.
  /*/
  sq_store_t store;

  /*/
  /// Relates the entry to a binding.
  ///
  /// May be `NULL`.
  /*/
  sq_binding_t binding;

  /*/
  /// Relates the entry to a key.
  ///
  /// May be `NULL`.
  /*/
  sq_key_t key;

  /*/
  /// Relates the entry to some object.
  ///
  /// This is a human-readable description of what this log entry is
  /// mainly concerned with.
  /*/
  char *slug;

  /*/
  /// Holds the log message.
  /*/
  char *status;

  /*/
  /// Holds the error message, if any.
  ///
  /// May be `NULL`.
  /*/
  char *error;
};
typedef struct sq_log *sq_log_t;

/*/
/// Frees a sq_log_t.
/*/
void sq_log_free (sq_log_t log);

/*/
/// Counter and timestamps.
/*/
struct sq_stamps {
  /*/
  /// Counts how many times this has been used.
  /*/
  uint64_t count;

  /*/
  /// Records the time when this has been used first.
  /*/
  uint64_t first;

  /*/
  /// Records the time when this has been used last.
  /*/
  uint64_t last;
};

/*/
/// Represents binding or key stats.
/*/
struct sq_stats {
  /*/
  /// Records the time this item was created.
  /*/
  uint64_t created;

  /*/
  /// Records the time this item was last updated.
  /*/
  uint64_t updated;

  /*/
  /// Records counters and timestamps of encryptions.
  /*/
  struct sq_stamps encryption;

  /*/
  /// Records counters and timestamps of verifications.
  /*/
  struct sq_stamps verification;
};
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
/// Lists all keys in the common key pool.
/*/
sq_key_iter_t sq_store_list_keys (sq_context_t ctx);

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
