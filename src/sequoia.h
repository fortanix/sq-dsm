#ifndef SEQUOIA_H
#define SEQUOIA_H

#include <stdint.h>

struct sq_context;
struct sq_context *sq_context_new(const char *domain, const char *home,
				  const char *lib);
void sq_context_free(struct sq_context *context);

struct sq_keyid;
struct sq_keyid *sq_keyid_new (uint64_t id);
struct sq_keyid *sq_keyid_from_hex (const char *id);
void sq_keyid_free (struct sq_keyid *keyid);

struct sq_tpk;
struct sq_tpk *sq_tpk_from_bytes (const char *b, size_t len);
void sq_tpk_dump (const struct sq_tpk *tpk);
void sq_tpk_free (struct sq_tpk *tpk);

#endif
