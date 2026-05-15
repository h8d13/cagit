/*
 * emhash8 instantiation for ghash.
 * offset_map: u64 (pack byte offset) -> u32 (slab index).
 * Used as the OFS_DELTA base cache in the sequential pack scanner.
 */
#include "hash_table8.h"

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
