/*
 * prem-hash instantiation for gitrs.
 * sha_map: u64 (hash of 20-byte SHA1) -> u64 (index into object array).
 */
#include "hash_table8.h"

#define EMH_NAME    sha_map
#define EMH_KEY     uint64_t
#define EMH_VAL     uint64_t
#define EMH_HASH(k) emh_hash_u64(k)
#define EMH_POD_KV
#include "hash_table8.h"

void   dhasht_sm_init(sha_map* m, size_t b)                     { sha_map_init(m, b); }
void   dhasht_sm_deinit(sha_map* m)                             { sha_map_deinit(m); }
int    dhasht_sm_set(sha_map* m, uint64_t k, uint64_t v)        { return sha_map_set(m, k, v); }
int    dhasht_sm_get(const sha_map* m, uint64_t k, uint64_t* o) { return sha_map_get(m, k, o); }
int    dhasht_sm_contains(const sha_map* m, uint64_t k)         { return sha_map_contains(m, k); }
size_t dhasht_sm_erase(sha_map* m, uint64_t k)                  { return sha_map_erase(m, k); }
int    dhasht_sm_reserve(sha_map* m, uint64_t n, int f)         { return sha_map_reserve(m, n, f); }

/* offset_map: u64 (pack byte offset) -> u32 (slab index).
 * Used as the base-object cache in the sequential pack scanner. */
#define EMH_NAME    offset_map
#define EMH_KEY     uint64_t
#define EMH_VAL     uint32_t
#define EMH_HASH(k) emh_hash_u64(k)
#define EMH_POD_KV
#include "hash_table8.h"

void   dhasht_om_init(offset_map* m, size_t b)                      { offset_map_init(m, b); }
void   dhasht_om_deinit(offset_map* m)                              { offset_map_deinit(m); }
int    dhasht_om_set(offset_map* m, uint64_t k, uint32_t v)         { return offset_map_set(m, k, v); }
int    dhasht_om_get(const offset_map* m, uint64_t k, uint32_t* o)  { return offset_map_get(m, k, o); }
int    dhasht_om_reserve(offset_map* m, uint64_t n, int f)          { return offset_map_reserve(m, n, f); }
