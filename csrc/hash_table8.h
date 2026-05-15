/* C port of emhash8::HashMap 
 * Source: ktprime/emhash
 * MIT, Copyright (c) 2021-2026
 * C port follows same algorithm and probe strategy, missing quite a few features. 
 * Added absl inspired ctrl bytes.
 *
 * Style: include-twice (stb-style). First include defines common helpers and
 * macros. Subsequent includes with EMH_NAME/EMH_KEY/EMH_VAL/EMH_HASH defined
 * emit one type-specialized map. Each specialization is a struct plus a set
 * of prefixed functions, all static inline so the header is header-only.
 *
 * Optional defines (global, before first include):
 *   EMH_MALLOC(sz)       custom allocator
 *   EMH_FREE(p)          custom deallocator
 *   EMH_CACHE_LINE_SIZE  (default 64)
 *
 * Per-specialization inputs (before each include past the first):
 *   EMH_NAME    map type name (also struct + function prefix)
 *   EMH_KEY     key type (trivially-copyable POD recommended)
 *   EMH_VAL     value type (trivially-copyable POD recommended)
 *   EMH_HASH(k) -> uint64_t   hash function or macro
 *   EMH_EQ(a,b) -> int        equality, default `((a) == (b))` if undef
 *
 * Convention for the index linked list:
 *   _index[b].next = INACTIVE (high bit set) -> bucket empty
 *   _index[b].next == b                      -> tail of chain (self-loop)
 *   otherwise                                -> index of next bucket in chain
 *   _index[b].slot low bits  = slot index in _pairs
 *   _index[b].slot high bits = fingerprint (key_hash & ~_mask)
 *
 * */

#ifndef EMH_HASH_TABLE8_H
#define EMH_HASH_TABLE8_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
#  include <xmmintrin.h>
#endif

/* SIMD ctrl byte group scan.
 * Each bucket has a 1-byte ctrl: 0x80=empty, 0x00=occupied.
 * emh_ctrl_mask_empty returns a bitmask where bit i is set if ctrl[i] is empty.
 * AVX2: 32-wide groups. SSE2: 16-wide. Portable: 8-wide via 64-bit bithack. */
#if defined(__AVX2__)
#  include <immintrin.h>
#  define EMH_GROUP_WIDTH 32u
   static inline uint32_t emh_ctrl_mask_empty(const uint8_t* p) {
       /* movemask extracts bit 7 of each byte. Empty = 0x80, so bit 7 = 1. */
       return (uint32_t)_mm256_movemask_epi8(_mm256_loadu_si256((const __m256i*)p));
   }
#elif defined(__SSE2__)
#  include <emmintrin.h>
#  define EMH_GROUP_WIDTH 16u
   static inline uint32_t emh_ctrl_mask_empty(const uint8_t* p) {
       return (uint32_t)_mm_movemask_epi8(_mm_loadu_si128((const __m128i*)p));
   }
#else
#  define EMH_GROUP_WIDTH 8u
   static inline uint32_t emh_ctrl_mask_empty(const uint8_t* p) {
       uint64_t v; memcpy(&v, p, 8);
       uint64_t m = v & UINT64_C(0x8080808080808080);
       /* Gather bit 7 of each byte into the low 8 bits of result. */
       return (uint32_t)((m * UINT64_C(0x0002040810204081)) >> 56);
   }
#endif
#define EMH_CTRL_EMPTY ((uint8_t)0x80)
/* 2-bit encoding for occupancy + is_main: bit 7 = empty when set;
 * bit 0 = is_main when set (occupant is in its own main bucket).
 * EMH_CTRL_FULL (0x00): occupied, foreigner (kicked here from another class).
 * EMH_CTRL_MAIN (0x01): occupied, in own main bucket. */
#define EMH_CTRL_FULL  ((uint8_t)0x00)
#define EMH_CTRL_MAIN  ((uint8_t)0x01)

#if defined(__GNUC__) || defined(__clang__)
#  define EMH_LIKELY(c)   __builtin_expect(!!(c), 1)
#  define EMH_UNLIKELY(c) __builtin_expect(!!(c), 0)
#  define EMH_PREFETCH(p) __builtin_prefetch((const void*)(p))
#  define EMH_AINLINE     __attribute__((always_inline))
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#  define EMH_LIKELY(c)   (c)
#  define EMH_UNLIKELY(c) (c)
#  define EMH_PREFETCH(p) _mm_prefetch((const char*)(p), _MM_HINT_T0)
#  define EMH_AINLINE     __forceinline
#else
#  define EMH_LIKELY(c)   (c)
#  define EMH_UNLIKELY(c) (c)
#  define EMH_PREFETCH(p) ((void)0)
#  define EMH_AINLINE
#endif
/* Force-inline on hot paths. gcc -O3 already inlines most, but the
 * cache-resident insert at N=~1M was sensitive to leaving any leaf
 * call un-inlined (notably __emit and __check_expand_need). */
#define EMH_HOT static inline EMH_AINLINE

#ifndef EMH_MALLOC
#  define EMH_MALLOC(sz) malloc(sz)
#endif
#ifndef EMH_FREE
#  define EMH_FREE(p)    free(p)
#endif

#ifndef EMH_CACHE_LINE_SIZE
#  define EMH_CACHE_LINE_SIZE 64u
#endif

/* restrict on the probe and lookup loops is always enabled on GCC/Clang. */
#if defined(__GNUC__) || defined(__clang__)
#  define EMH__RESTRICT __restrict__
#else
#  define EMH__RESTRICT
#endif

/* Width for in-table bucket/slot indices and counts. Default uint32_t
 * matches upstream emhash8::HashMap<...>::size_type and keeps the Index
 * array at 8 bytes per entry for cache density. Override to uint64_t
 * if you need maps with >= 2^31 entries.                                */
#ifndef EMH_SIZE_T
#  define EMH_SIZE_T uint32_t
#endif

#define EMH_EAD                   ((EMH_SIZE_T)2)
#define EMH_DEFAULT_LOAD_FACTOR   0.80f
#define EMH_MIN_LOAD_FACTOR       0.25f
/* Sign-bit detection: works for both uint32_t and uint64_t storage.
 * (int)(uint32_t)-1 == -1; (int)(uint64_t)-1 truncates to (int)-1.    */
#define EMH_NEG(x)                ((int)(x) < 0)

/* AES-NI hash: two rounds, ~8-cycle latency, higher throughput than splitmix64
 * on the AES execution unit. Auto-selected when __AES__ is defined (compiler
 * sets this with -maes or -march=native on AES-capable CPUs). */
#if defined(__AES__)
#  include <wmmintrin.h>
static inline uint64_t emh_hash_u64(uint64_t key)
{
    __m128i v = _mm_cvtsi64_si128((int64_t)key);
    __m128i k = _mm_set_epi64x((int64_t)0x9e3779b97f4a7c15ULL,
                                (int64_t)0x6c62272e07bb0142ULL);
    v = _mm_aesenc_si128(v, k);
    v = _mm_aesenc_si128(v, k);
    return (uint64_t)_mm_cvtsi128_si64(v);
}
#else
/* splitmix64, the upstream EMH_INT_HASH=0 default */
static inline uint64_t emh_hash_u64(uint64_t key)
{
    uint64_t x = key;
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}
#endif
static inline uint64_t emh_hash_u32(uint32_t k) { return emh_hash_u64((uint64_t)k); }
static inline uint64_t emh_hash_i32(int32_t  k) { return emh_hash_u64((uint64_t)(uint32_t)k); }
static inline uint64_t emh_hash_i64(int64_t  k) { return emh_hash_u64((uint64_t)k); }
static inline uint64_t emh_hash_ptr(const void* p) { return emh_hash_u64((uint64_t)(uintptr_t)p); }

/* wyhash, faithful port of emhash8::HashMap::wyhashstr */
static inline uint64_t emh_wymix(uint64_t A, uint64_t B)
{
#if defined(__SIZEOF_INT128__)
    __uint128_t r = (__uint128_t)A * (__uint128_t)B;
    A = (uint64_t)r; B = (uint64_t)(r >> 64);
#else
    uint64_t ha = A >> 32, hb = B >> 32;
    uint64_t la = (uint32_t)A, lb = (uint32_t)B;
    uint64_t rh = ha * hb, rm0 = ha * lb, rm1 = hb * la, rl = la * lb;
    uint64_t t  = rl + (rm0 << 32), c = t < rl;
    uint64_t lo = t + (rm1 << 32);  c += lo < t;
    uint64_t hi = rh + (rm0 >> 32) + (rm1 >> 32) + c;
    A = lo; B = hi;
#endif
    return A ^ B;
}
static inline uint64_t emh__wyr8(const uint8_t* p) { uint64_t v; memcpy(&v, p, 8); return v; }
static inline uint64_t emh__wyr4(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint64_t emh__wyr3(const uint8_t* p, size_t k) {
    return (((uint64_t)p[0]) << 16) | (((uint64_t)p[k >> 1]) << 8) | p[k - 1];
}
static inline uint64_t emh_hash_str(const char* key, size_t len)
{
    static const uint64_t secret[4] = {
        0x2d358dccaa6c78a5ull, 0x8bb84b93962eacc9ull,
        0x4b33a62ed433d4a3ull, 0x4d5a2da51de1aa47ull };
    uint64_t a = 0, b = 0, seed = secret[0];
    const uint8_t* p = (const uint8_t*)key;
    if (EMH_LIKELY(len <= 16)) {
        if (EMH_LIKELY(len >= 4)) {
            const size_t half = (len >> 3) << 2;
            a = (emh__wyr4(p) << 32U) | emh__wyr4(p + half); p += len - 4;
            b = (emh__wyr4(p) << 32U) | emh__wyr4(p - half);
        } else if (len) {
            a = emh__wyr3(p, len);
        }
    } else {
        size_t i = len;
        if (EMH_UNLIKELY(i > 48)) {
            uint64_t see1 = seed, see2 = seed;
            do {
                seed = emh_wymix(emh__wyr8(p +  0) ^ secret[1], emh__wyr8(p +  8) ^ seed);
                see1 = emh_wymix(emh__wyr8(p + 16) ^ secret[2], emh__wyr8(p + 24) ^ see1);
                see2 = emh_wymix(emh__wyr8(p + 32) ^ secret[3], emh__wyr8(p + 40) ^ see2);
                p += 48; i -= 48;
            } while (EMH_LIKELY(i > 48));
            seed ^= see1 ^ see2;
        }
        while (i > 16) {
            seed = emh_wymix(emh__wyr8(p) ^ secret[1], emh__wyr8(p + 8) ^ seed);
            i -= 16; p += 16;
        }
        a = emh__wyr8(p + i - 16);
        b = emh__wyr8(p + i - 8);
    }
    return emh_wymix(secret[1] ^ len, emh_wymix(a ^ secret[1], b ^ seed));
}

#endif /* EMH_HASH_TABLE8_H */


/* =====================================================================
 * Templated section. Re-included once per (NAME, KEY, VAL, HASH, EQ).
 * ===================================================================== */

#ifdef EMH_NAME

#ifndef EMH_KEY
#  error "Define EMH_KEY before including hash_table8.h"
#endif
#ifndef EMH_VAL
#  error "Define EMH_VAL before including hash_table8.h"
#endif
#ifndef EMH_HASH
#  error "Define EMH_HASH(k) -> uint64_t before including hash_table8.h"
#endif
#ifndef EMH_EQ
#  define EMH_EQ(a, b) ((a) == (b))
#  define EMH__EQ_WAS_DEFAULT
#endif

/* POD invariant: rehash moves pairs via raw memcpy. This is unsafe for
 * types containing pointers to themselves (SSO strings, intrusive nodes,
 * refcounted handles). To use this header you MUST opt in via one of:
 *   #define EMH_POD_KV      // I confirm K and V are bitwise-copyable
 * OR
 *   #define EMH_KEY_COPY/EMH_KEY_DESTROY (and VAL_*)  // owned-type hooks
 * The owned-type hooks must implement deep-copy semantics; rehash will
 * memcpy the raw bytes, which is correct for ownership models where the
 * bitwise copy transfers ownership (strdup-style: pointer moves, old
 * struct is forgotten). Pre-`_reserve` to skip rehash if your owned-type
 * is not memcpy-move-safe.                                              */
#if !defined(EMH_POD_KV) && !defined(EMH_KEY_COPY)
#  error "Define EMH_POD_KV for trivially-copyable K/V, or EMH_KEY_COPY/EMH_KEY_DESTROY for owned types. See hash_table8.h comment for details."
#endif
#ifndef EMH_KEY_COPY
#  define EMH_KEY_COPY(dst, src) ((dst) = (src))
#  define EMH__KEY_COPY_WAS_DEFAULT
#endif
#ifndef EMH_VAL_COPY
#  define EMH_VAL_COPY(dst, src) ((dst) = (src))
#  define EMH__VAL_COPY_WAS_DEFAULT
#endif
#ifndef EMH_KEY_DESTROY
#  define EMH_KEY_DESTROY(k) ((void)(k))
#  define EMH__KEY_DESTROY_WAS_DEFAULT
#endif
#ifndef EMH_VAL_DESTROY
#  define EMH_VAL_DESTROY(v) ((void)(v))
#  define EMH__VAL_DESTROY_WAS_DEFAULT
#endif

#define EMH__CAT_(a, b) a##b
#define EMH__CAT(a, b)  EMH__CAT_(a, b)
#define EMH__FN(suffix) EMH__CAT(EMH_NAME, suffix)
#define EMH__T          EMH_NAME
#define EMH__TI         EMH__FN(_index_t)
#define EMH__TP         EMH__FN(_pair_t)
#define EMH__SZ         EMH_SIZE_T
#define EMH__INACTIVE   ((EMH__SZ)-1)

/* Index = 2 * sizeof(EMH__SZ). With default uint32_t -> 8 bytes / entry. */
typedef struct EMH__FN(__index) { EMH__SZ next; EMH__SZ slot; } EMH__TI;
typedef struct EMH__FN(__pair)  { EMH_KEY first; EMH_VAL second; } EMH__TP;

typedef struct EMH_NAME {
    EMH__TI* _index;
    EMH__TP* _pairs;
    uint8_t* _ctrl;              /* 1 byte/bucket: 0x80=empty, 0x00=foreigner, 0x01=main */
    uint32_t _mlf;               /* (1<<28) / max_load_factor */
    EMH__SZ  _mask;              /* num_buckets - 1 */
    EMH__SZ  _num_buckets;
    EMH__SZ  _num_filled;
    EMH__SZ  _last;              /* probe cursor for find_empty_bucket */
    EMH__SZ  _etail;             /* last bucket assigned, or INACTIVE */
    EMH__SZ  _pairs_capacity;
    EMH__SZ  _growth_left;       /* inserts remaining before rehash */
} EMH__T;

/* ---- index-cell predicates ------------------------------------------ */
#define EMH__EMPTY(m, n)         EMH_NEG((m)->_index[(n)].next)

/* ---- allocation ----------------------------------------------------- */
/* OOM policy: alloc failure aborts via abort(). assert(p) was unsafe under
 * NDEBUG (compiles away, leaves caller dereferencing NULL). If you need
 * propagating error returns, wrap EMH_MALLOC and handle NULL upstream.   */
static inline EMH__TP* EMH__FN(__alloc_pairs)(EMH__SZ cap)
{
    if (!cap) return NULL;
    EMH__TP* p = (EMH__TP*)EMH_MALLOC((size_t)cap * sizeof(EMH__TP));
    if (!p) abort();
    return p;
}

static inline EMH__TI* EMH__FN(__alloc_index)(EMH__SZ num_buckets)
{
    EMH__TI* p = (EMH__TI*)EMH_MALLOC(((size_t)num_buckets + EMH_EAD) * sizeof(EMH__TI));
    if (!p) abort();
    return p;
}

static inline void EMH__FN(__dealloc_pairs)(EMH__TP* p)  { if (p) EMH_FREE(p); }
static inline void EMH__FN(__dealloc_index)(EMH__TI* p)  { if (p) EMH_FREE(p); }

static inline uint8_t* EMH__FN(__alloc_ctrl)(EMH__SZ num_buckets)
{
    /* +EMH_GROUP_WIDTH: safe overflow guard for SIMD loads past the last bucket. */
    uint8_t* p = (uint8_t*)EMH_MALLOC((size_t)num_buckets + EMH_GROUP_WIDTH);
    if (!p) abort();
    return p;
}
static inline void EMH__FN(__dealloc_ctrl)(uint8_t* p) { if (p) EMH_FREE(p); }

/* ---- small accessors ------------------------------------------------ */
static inline size_t EMH__FN(_size)         (const EMH__T* m) { return (size_t)m->_num_filled; }
static inline int    EMH__FN(_empty)        (const EMH__T* m) { return m->_num_filled == 0; }
static inline size_t EMH__FN(_bucket_count) (const EMH__T* m) { return (size_t)m->_num_buckets; }
static inline float  EMH__FN(_load_factor)  (const EMH__T* m) {
    return (float)m->_num_filled / ((float)m->_mask + 1.0f);
}
static inline float  EMH__FN(_max_load_factor)(const EMH__T* m) {
    return (float)(1u << 28) / (float)m->_mlf;
}
static inline void   EMH__FN(_set_max_load_factor)(EMH__T* m, float mlf) {
    if (mlf <= 0.999f && mlf > EMH_MIN_LOAD_FACTOR)
        m->_mlf = (uint32_t)((float)(1u << 28) / mlf);
}

static inline size_t EMH__FN(_max_size)(void) {
    return (size_t)1 << (sizeof(EMH__SZ) * 8 - 1);
}

/* Raw pair-array accessors. Iteration: for (i=0; i<size; ++i) pairs[i]. */
static inline const EMH__TP* EMH__FN(_values)(const EMH__T* m) { return m->_pairs; }
static inline       EMH__TP* EMH__FN(_pairs_mut)(EMH__T* m)    { return m->_pairs; }

/* ---- hash helpers --------------------------------------------------- */
EMH_HOT uint64_t EMH__FN(__hash_key)(EMH_KEY key) {
    return (uint64_t)EMH_HASH(key);
}

EMH_HOT EMH__SZ EMH__FN(__hash_bucket)(const EMH__T* m, EMH_KEY key) {
    return (EMH__SZ)EMH__FN(__hash_key)(key) & m->_mask;
}

/* ---- probe: find an empty bucket ------------------------------------ */
/* 3-way probe: 2 immediate neighbors, then SIMD group scan, then scalar
 * walk. Returns an empty bucket index (one whose .next == INACTIVE).
 * EMH_SIMD_PROBE_GROUPS bounds how many groups the SIMD scan tries
 * before falling back to the scalar cursor walk over _index.             */
#ifndef EMH_SIMD_PROBE_GROUPS
#  define EMH_SIMD_PROBE_GROUPS 4u
#endif

EMH_HOT EMH__SZ EMH__FN(__find_empty_bucket)(EMH__T* m, EMH__SZ bucket_from)
{
    const uint8_t* EMH__RESTRICT ctrl = m->_ctrl;
    const EMH__TI* EMH__RESTRICT idx  = m->_index;
    const EMH__SZ mask        = m->_mask;
    const EMH__SZ num_buckets = m->_num_buckets;
    EMH__SZ b, r;
    uint32_t empty;

    /* Fast: check the 2 immediate neighbors.  ctrl may be stale for erased
     * slots; a false-negative just falls through to SIMD/scalar.         */
    b = (bucket_from + 1) & mask;
    if (ctrl[b] & 0x80) return b;
    b = (b + 1) & mask;
    if (ctrl[b] & 0x80) return b;

    /* Small table scalar path: use _index directly (ctrl may be stale). */
    if (EMH_UNLIKELY(num_buckets <= EMH_GROUP_WIDTH)) {
        m->_last = (m->_last + 1) & mask;
        for (;;) {
            if (idx[m->_last].next == EMH__INACTIVE) return m->_last;
            m->_last = (m->_last + 1) & mask;
        }
    }

    /* One SIMD group scan just past the immediate neighbors. */
    b = (bucket_from + 3) & mask;
    empty = emh_ctrl_mask_empty(ctrl + b);
    if (empty) {
        r = (b + (EMH__SZ)__builtin_ctz(empty)) & mask;
        if (ctrl[r] & 0x80) return r;
    }

    /* Bounded SIMD scan from m->_last.  If ctrl is stale (erase without
     * ctrl update), we bail after EMH_SIMD_PROBE_GROUPS steps and fall
     * through to the scalar cursor loop, which uses _index as truth. */
    m->_last &= mask;
    EMH_PREFETCH(ctrl + m->_last);
#if defined(__GNUC__)
#  pragma GCC unroll 4
#endif
    for (uint32_t tries = 0; tries < EMH_SIMD_PROBE_GROUPS; ++tries) {
        b     = m->_last;
        empty = emh_ctrl_mask_empty(ctrl + b);
        if (empty) {
            r = (b + (EMH__SZ)__builtin_ctz(empty)) & mask;
            if (EMH_LIKELY(ctrl[r] & 0x80)) {
                m->_last = r;
                return r;
            }
        }
        m->_last += EMH_GROUP_WIDTH;
        if (m->_last >= num_buckets) m->_last = 0;
    }

    /* Scalar fallback: walk _index with cursor for O(1) amortised. Handles
     * slots freed by erase whose ctrl bytes were not updated.            */
    for (;;) {
        if (idx[m->_last].next == EMH__INACTIVE) return m->_last;
        m->_last = (m->_last + 1) & mask;
    }
}

/* ---- chain walks ---------------------------------------------------- */
EMH_HOT EMH__SZ EMH__FN(__find_last_bucket)(const EMH__T* m, EMH__SZ main_bucket)
{
    EMH__SZ next_bucket = m->_index[main_bucket].next;
    if (next_bucket == main_bucket) return main_bucket;
    for (;;) {
        const EMH__SZ nbucket = m->_index[next_bucket].next;
        if (nbucket == next_bucket) return next_bucket;
        next_bucket = nbucket;
    }
}

EMH_HOT EMH__SZ EMH__FN(__find_prev_bucket)(const EMH__T* m, EMH__SZ main_bucket, EMH__SZ bucket)
{
    EMH__SZ next_bucket = m->_index[main_bucket].next;
    if (next_bucket == bucket) return main_bucket;
    for (;;) {
        const EMH__SZ nbucket = m->_index[next_bucket].next;
        if (nbucket == bucket) return next_bucket;
        next_bucket = nbucket;
    }
}

/* Find which bucket points at this slot. Returns the bucket; writes
 * the main bucket out-param. Walks the chain. O(chain). */
static inline EMH__SZ EMH__FN(__find_slot_bucket)(const EMH__T* m, EMH__SZ slot, EMH__SZ* main_out)
{
    const uint64_t key_hash = EMH__FN(__hash_key)(m->_pairs[slot].first);
    const EMH__SZ bucket = (EMH__SZ)key_hash & m->_mask;
    *main_out = bucket;
    if (slot == (m->_index[bucket].slot & m->_mask))
        return bucket;

    {
        EMH__SZ next_bucket = m->_index[bucket].next;
        for (;;) {
            if (EMH_LIKELY(slot == (m->_index[next_bucket].slot & m->_mask)))
                return next_bucket;
            next_bucket = m->_index[next_bucket].next;
        }
    }
}

static inline EMH__SZ EMH__FN(__slot_to_bucket)(const EMH__T* m, EMH__SZ slot)
{
    EMH__SZ main_bucket;
    return EMH__FN(__find_slot_bucket)(m, slot, &main_bucket);
}

/* ---- lookup --------------------------------------------------------- */
/* Returns bucket index containing key, or EMH__INACTIVE. */
EMH_HOT EMH__SZ EMH__FN(__find_filled_bucket)(const EMH__T* m, EMH_KEY key, uint64_t key_hash)
{
    const EMH__TI* EMH__RESTRICT idx   = m->_index;
    const EMH__TP* EMH__RESTRICT pairs = m->_pairs;
    const EMH__SZ mask = m->_mask;
    const EMH__SZ fp_mask = ~mask;
    const EMH__SZ fp_key  = (EMH__SZ)key_hash & fp_mask;
    const EMH__SZ bucket  = (EMH__SZ)key_hash & mask;
    EMH__SZ next_bucket   = idx[bucket].next;
    if (EMH_UNLIKELY(EMH_NEG(next_bucket)))
        return EMH__INACTIVE;

    {
        const EMH__SZ entry = idx[bucket].slot;
        if (fp_key == (entry & fp_mask)) {
            if (EMH_LIKELY(EMH_EQ(key, pairs[entry & mask].first)))
                return bucket;
        }
    }
    if (next_bucket == bucket)
        return EMH__INACTIVE;

    for (;;) {
        const EMH__SZ entry = idx[next_bucket].slot;
        if (fp_key == (entry & fp_mask)) {
            if (EMH_LIKELY(EMH_EQ(key, pairs[entry & mask].first)))
                return next_bucket;
        }
        {
            const EMH__SZ nbucket = idx[next_bucket].next;
            if (nbucket == next_bucket) return EMH__INACTIVE;
            next_bucket = nbucket;
        }
    }
}

/* Pair-pointer-returning lookup with pre-computed hash (for find_batch).
 * Returns NULL if absent. No ctrl check; uses INACTIVE sentinel on idx.next.
 * Returning the pair pointer directly avoids a second m->_pairs dereference
 * in the caller (the compiler cannot keep m->_pairs in a register across the
 * function boundary without this). */
EMH_HOT const EMH__TP* EMH__FN(__find_pair_h)(const EMH__T* m, EMH_KEY key, uint64_t key_hash)
{
    const EMH__TI* EMH__RESTRICT idx = m->_index;
    const EMH__SZ mask    = m->_mask;
    const EMH__SZ fp_mask = ~mask;
    const EMH__SZ fp_key  = (EMH__SZ)key_hash & fp_mask;
    const EMH__SZ bucket  = (EMH__SZ)key_hash & mask;
    EMH__SZ next_bucket   = idx[bucket].next;
    if (EMH_UNLIKELY(EMH_NEG(next_bucket)))
        return NULL;

    {
        const EMH__SZ entry = idx[bucket].slot;
        if (fp_key == (entry & fp_mask)) {
            const EMH__SZ eslot = entry & mask;
            if (EMH_LIKELY(EMH_EQ(key, m->_pairs[eslot].first)))
                return &m->_pairs[eslot];
        }
    }
    if (next_bucket == bucket)
        return NULL;

    for (;;) {
        const EMH__SZ entry = idx[next_bucket].slot;
        if (fp_key == (entry & fp_mask)) {
            const EMH__SZ eslot = entry & mask;
            if (EMH_LIKELY(EMH_EQ(key, m->_pairs[eslot].first)))
                return &m->_pairs[eslot];
        }
        const EMH__SZ nbucket = idx[next_bucket].next;
        if (nbucket == next_bucket) return NULL;
        next_bucket = nbucket;
    }
}

/* Returns slot index containing key, or _num_filled (= sentinel "not found"). */
EMH_HOT EMH__SZ EMH__FN(__find_filled_slot)(const EMH__T* m, EMH_KEY key)
{
    const EMH__TI* EMH__RESTRICT idx   = m->_index;
    const EMH__TP* EMH__RESTRICT pairs = m->_pairs;
    const EMH__SZ mask = m->_mask;
    const EMH__SZ fp_mask = ~mask;
    const EMH__SZ num_filled = m->_num_filled;
    const uint64_t key_hash  = EMH__FN(__hash_key)(key);
    const EMH__SZ fp_key = (EMH__SZ)key_hash & fp_mask;
    const EMH__SZ bucket = (EMH__SZ)key_hash & mask;
    EMH__SZ next_bucket  = idx[bucket].next;
    if (EMH_UNLIKELY(EMH_NEG(next_bucket)))
        return num_filled;

    {
        const EMH__SZ entry = idx[bucket].slot;
        if (fp_key == (entry & fp_mask)) {
            if (EMH_LIKELY(EMH_EQ(key, pairs[entry & mask].first)))
                return entry & mask;
        }
    }
    if (next_bucket == bucket)
        return num_filled;

    for (;;) {
        const EMH__SZ entry = idx[next_bucket].slot;
        if (fp_key == (entry & fp_mask)) {
            const EMH__SZ eslot = entry & mask;
            if (EMH_LIKELY(EMH_EQ(key, pairs[eslot].first)))
                return eslot;
        }
        {
            const EMH__SZ nbucket = idx[next_bucket].next;
            if (nbucket == next_bucket) return num_filled;
            next_bucket = nbucket;
        }
    }
}

/* ---- kickout: relocate non-main occupant to an empty slot ----------- */
/* Caller guarantees occupant of `bucket` is a foreigner (ctrl bit-0 clear).
 * kmain is computed internally from pairs.first (one pairs load on this
 * cold path only). Returns the freed bucket index (now empty-ready).    */
EMH_HOT EMH__SZ EMH__FN(__kickout_bucket)(EMH__T* m, EMH__SZ bucket)
{
    EMH__TI* EMH__RESTRICT idx = m->_index;
    const EMH__SZ occ_slot = idx[bucket].slot & m->_mask;
    const EMH__SZ kmain    = (EMH__SZ)EMH__FN(__hash_key)(m->_pairs[occ_slot].first) & m->_mask;
    const EMH__SZ next_bucket = idx[bucket].next;
    const EMH__SZ new_bucket  = EMH__FN(__find_empty_bucket)(m, next_bucket);
    const EMH__SZ prev_bucket = EMH__FN(__find_prev_bucket)(m, kmain, bucket);

    const EMH__SZ last = (next_bucket == bucket) ? new_bucket : next_bucket;
    idx[new_bucket].next = last;
    idx[new_bucket].slot = idx[bucket].slot;

    idx[prev_bucket].next = new_bucket;
    idx[bucket].next      = EMH__INACTIVE;
    m->_ctrl[new_bucket]  = EMH_CTRL_FULL;   /* relocated foreigner */
    m->_ctrl[bucket]      = EMH_CTRL_EMPTY;
    return bucket;
}

/* ---- find_or_allocate: lookup-or-reserve a bucket for `key` --------- */
EMH_HOT EMH__SZ EMH__FN(__find_or_allocate)(EMH__T* m, EMH_KEY key, uint64_t key_hash)
{
    EMH__TI* EMH__RESTRICT       idx   = m->_index;
    const EMH__TP* EMH__RESTRICT pairs = m->_pairs;
    const EMH__SZ mask    = m->_mask;
    const EMH__SZ fp_mask = ~mask;
    const EMH__SZ fp_key  = (EMH__SZ)key_hash & fp_mask;
    const EMH__SZ bucket  = (EMH__SZ)key_hash & mask;
    EMH__SZ next_bucket   = idx[bucket].next;
    if (EMH_NEG(next_bucket))
        return bucket;

    /* Cached is_main bit in ctrl skips the pairs.first load on no-kickout. */
    if (!(m->_ctrl[bucket] & EMH_CTRL_MAIN))
        return EMH__FN(__kickout_bucket)(m, bucket);

    {
        const EMH__SZ entry = idx[bucket].slot;
        const EMH__SZ slot  = entry & mask;
        if (fp_key == (entry & fp_mask))
            if (EMH_LIKELY(EMH_EQ(key, pairs[slot].first)))
                return bucket;
    }
    if (next_bucket == bucket) {
        const EMH__SZ new_bucket = EMH__FN(__find_empty_bucket)(m, next_bucket);
        idx[next_bucket].next = new_bucket;
        return new_bucket;
    }

    for (;;) {
        const EMH__SZ entry = idx[next_bucket].slot;
        const EMH__SZ eslot = entry & mask;
        if (fp_key == (entry & fp_mask))
            if (EMH_LIKELY(EMH_EQ(key, pairs[eslot].first)))
                return next_bucket;

        const EMH__SZ nbucket = idx[next_bucket].next;
        if (nbucket == next_bucket) break;
        next_bucket = nbucket;
    }
    {
        const EMH__SZ new_bucket = EMH__FN(__find_empty_bucket)(m, next_bucket);
        idx[next_bucket].next = new_bucket;
        return new_bucket;
    }
}

/* Unique-insert variant. Used by rehash and insert_unique. */
EMH_HOT EMH__SZ EMH__FN(__find_unique_bucket)(EMH__T* m, uint64_t key_hash)
{
    const EMH__SZ bucket = (EMH__SZ)key_hash & m->_mask;
    EMH__SZ next_bucket  = m->_index[bucket].next;
    if (EMH_NEG(next_bucket))
        return bucket;

    {
        if (EMH_UNLIKELY(!(m->_ctrl[bucket] & EMH_CTRL_MAIN)))
            return EMH__FN(__kickout_bucket)(m, bucket);
        if (EMH_UNLIKELY(next_bucket != bucket))
            next_bucket = EMH__FN(__find_last_bucket)(m, next_bucket);
    }
    {
        const EMH__SZ new_bucket = EMH__FN(__find_empty_bucket)(m, next_bucket);
        m->_index[next_bucket].next = new_bucket;
        return new_bucket;
    }
}

/* ---- emit a new entry at bucket, at slot=_num_filled++ -------------- */
EMH_HOT void EMH__FN(__emit)(EMH__T* m, EMH_KEY key, EMH_VAL val,
                                   EMH__SZ bucket, uint64_t key_hash)
{
    EMH__TI* EMH__RESTRICT idx   = m->_index;
    EMH__TP* EMH__RESTRICT pairs = m->_pairs;
    const EMH__SZ slot = m->_num_filled;
    EMH_KEY_COPY(pairs[slot].first,  key);
    EMH_VAL_COPY(pairs[slot].second, val);
    /* is_main: this entry's true home equals the bucket it's stored at */
    const EMH__SZ main_bucket = (EMH__SZ)key_hash & m->_mask;
    m->_ctrl[bucket] = (bucket == main_bucket) ? EMH_CTRL_MAIN : EMH_CTRL_FULL;
    m->_etail = bucket;
    idx[bucket].next = bucket;
    idx[bucket].slot = slot | ((EMH__SZ)key_hash & ~m->_mask);
    m->_num_filled = slot + 1;
    --m->_growth_left;
}

/* ---- erase ---------------------------------------------------------- */
/* Unlink `bucket` from chain rooted at `main_bucket`. Returns the bucket
 * index that should be reset to EMPTY by the caller.                    */
EMH_HOT EMH__SZ EMH__FN(__erase_bucket)(EMH__T* m, EMH__SZ bucket, EMH__SZ main_bucket)
{
    const EMH__SZ next_bucket = m->_index[bucket].next;
    if (bucket == main_bucket) {
        if (main_bucket != next_bucket) {
            const EMH__SZ nbucket = m->_index[next_bucket].next;
            m->_index[main_bucket].next = (nbucket == next_bucket) ? main_bucket : nbucket;
            m->_index[main_bucket].slot = m->_index[next_bucket].slot;
        }
        return next_bucket;
    }
    {
        const EMH__SZ prev_bucket = EMH__FN(__find_prev_bucket)(m, main_bucket, bucket);
        m->_index[prev_bucket].next = (bucket == next_bucket) ? prev_bucket : next_bucket;
        return bucket;
    }
}

/* Remove the entry at sbucket (whose main is main_bucket). Replaces it
 * with the last-stored entry to keep _pairs dense.                     */
EMH_HOT void EMH__FN(__erase_slot)(EMH__T* m, EMH__SZ sbucket, EMH__SZ main_bucket)
{
    const EMH__SZ slot      = m->_index[sbucket].slot & m->_mask;
    const EMH__SZ ebucket   = EMH__FN(__erase_bucket)(m, sbucket, main_bucket);
    const EMH__SZ last_slot = --m->_num_filled;

    /* Destroy old contents of the slot being erased. For owned types
     * (strdup'd keys etc.) this releases the memory. For POD the macros
     * are no-ops and the compiler erases the calls.                      */
    EMH_KEY_DESTROY(m->_pairs[slot].first);
    EMH_VAL_DESTROY(m->_pairs[slot].second);

    if (EMH_LIKELY(slot != last_slot)) {
        const EMH__SZ last_bucket = (m->_etail == EMH__INACTIVE || ebucket == m->_etail)
            ? EMH__FN(__slot_to_bucket)(m, last_slot)
            : m->_etail;
        /* Move-by-memcpy: bytes from last_slot transfer to slot, ownership
         * follows. last_slot's bytes are stale but unused (num_filled decr). */
        m->_pairs[slot] = m->_pairs[last_slot];
        m->_index[last_bucket].slot = slot | (m->_index[last_bucket].slot & ~m->_mask);
    }

    m->_etail = EMH__INACTIVE;
    m->_index[ebucket].next = EMH__INACTIVE;
    m->_index[ebucket].slot = 0;
    m->_ctrl[ebucket]       = EMH_CTRL_EMPTY;
    ++m->_growth_left;
}

/* ---- rebuild & rehash ---------------------------------------------- */
/* Reallocate _pairs / _index to fit num_buckets. Pairs are
 * memcpy'd; index is reset to INACTIVE. Caller rebuilds index entries. */
static inline void EMH__FN(__rebuild)(EMH__T* m, EMH__SZ num_buckets, EMH__SZ required_buckets)
{
    EMH__FN(__dealloc_index)(m->_index);

    EMH__SZ need_size = (EMH__SZ)((double)num_buckets * EMH__FN(_max_load_factor)(m)) + 4;
    if (required_buckets + 2 > need_size) need_size = required_buckets + 2;

    EMH__TP* new_pairs = EMH__FN(__alloc_pairs)(need_size);
    if (m->_pairs && m->_num_filled)
        memcpy(new_pairs, m->_pairs, (size_t)m->_num_filled * sizeof(EMH__TP));
    EMH__FN(__dealloc_pairs)(m->_pairs);

    m->_pairs = new_pairs;
    m->_pairs_capacity = need_size;
    m->_index = EMH__FN(__alloc_index)(num_buckets);

    memset(m->_index, (int)0xFF, sizeof(EMH__TI) * (size_t)num_buckets);
    memset(m->_index + num_buckets, 0,  sizeof(EMH__TI) * EMH_EAD);

    EMH__FN(__dealloc_ctrl)(m->_ctrl);
    m->_ctrl = EMH__FN(__alloc_ctrl)(num_buckets);
    memset(m->_ctrl, EMH_CTRL_EMPTY, (size_t)num_buckets + EMH_GROUP_WIDTH);
}

static inline void EMH__FN(_rehash)(EMH__T* m, uint64_t required_buckets)
{
    if (required_buckets < m->_num_filled)
        return;

    uint64_t buckets = m->_num_filled > (1u << 16) ? (1u << 16) : 4u;
    while (buckets < required_buckets) buckets *= 2;
    if (buckets > (uint64_t)EMH__FN(_max_size)() || buckets < m->_num_filled)
        abort();

    const EMH__SZ num_buckets = (EMH__SZ)buckets;
    m->_last = 0;
    m->_mask = num_buckets - 1;
    m->_num_buckets = num_buckets;

    EMH__FN(__rebuild)(m, num_buckets, (EMH__SZ)required_buckets);

    m->_etail = EMH__INACTIVE;
    for (EMH__SZ slot = 0; slot < m->_num_filled; ++slot) {
        const uint64_t key_hash = EMH__FN(__hash_key)(m->_pairs[slot].first);
        const EMH__SZ  bucket   = EMH__FN(__find_unique_bucket)(m, key_hash);
        const EMH__SZ  mb       = (EMH__SZ)key_hash & m->_mask;
        m->_index[bucket].next = bucket;
        m->_index[bucket].slot = slot | ((EMH__SZ)key_hash & ~m->_mask);
        m->_ctrl[bucket] = (bucket == mb) ? EMH_CTRL_MAIN : EMH_CTRL_FULL;
    }
    /* growth_left mirrors _reserve threshold: rehash when num_filled * mlf >> 28
     * >= num_buckets. Smallest triggering N = ceil(num_buckets * 2^28 / mlf).
     * Floor would underestimate by one for non-integral nb/lf (e.g. nb=4,
     * lf=0.8 -> floor=3, ceil=4) and cause uint underflow in __emit.       */
    {
        const uint64_t thresh =
            (((uint64_t)num_buckets << 28) + m->_mlf - 1) / m->_mlf;
        m->_growth_left = (thresh > m->_num_filled)
            ? (EMH__SZ)(thresh - m->_num_filled) : 0;
    }
}

/* Grow if needed. Returns 1 if rehash happened. */
EMH_HOT int EMH__FN(_reserve)(EMH__T* m, uint64_t num_elems, int force)
{
    (void)force;
    const uint64_t required_buckets = num_elems * m->_mlf >> 28;
    if (EMH_LIKELY(required_buckets < m->_num_buckets))
        return 0;
    EMH__FN(_rehash)(m, required_buckets + 2);
    return 1;
}

/* Fast path on insert: one cmp. Slow path falls through to mul-based _reserve. */
EMH_HOT int EMH__FN(__check_expand_need)(EMH__T* m)
{
    if (EMH_LIKELY(m->_growth_left > 0))
        return 0;
    return EMH__FN(_reserve)(m, m->_num_filled, 0);
}

/* ---- lifecycle ------------------------------------------------------ */
static inline void EMH__FN(_init_mlf)(EMH__T* m, size_t bucket, float mlf)
{
    m->_pairs = NULL;
    m->_index = NULL;
    m->_ctrl  = NULL;
    m->_mask = 0;
    m->_num_buckets = 0;
    m->_num_filled = 0;
    m->_pairs_capacity = 0;
    m->_last = 0;
    m->_etail = EMH__INACTIVE;
    m->_growth_left = 0;
    m->_mlf = (uint32_t)((float)(1u << 28) / EMH_DEFAULT_LOAD_FACTOR);
    EMH__FN(_set_max_load_factor)(m, mlf);
    EMH__FN(_rehash)(m, bucket ? bucket : 2);
}

static inline void EMH__FN(_init)(EMH__T* m, size_t bucket)
{
    EMH__FN(_init_mlf)(m, bucket, EMH_DEFAULT_LOAD_FACTOR);
}

static inline void EMH__FN(_clear)(EMH__T* m)
{
    /* Destroy every live entry. For POD the macro body is a no-op and the
     * loop is eliminated by the optimizer.                                */
    for (EMH__SZ i = 0; i < m->_num_filled; ++i) {
        EMH_KEY_DESTROY(m->_pairs[i].first);
        EMH_VAL_DESTROY(m->_pairs[i].second);
    }
    if (m->_num_filled > 0 && m->_index) {
        memset(m->_index, (int)0xFF, sizeof(EMH__TI) * (size_t)m->_num_buckets);
        memset(m->_ctrl, EMH_CTRL_EMPTY, (size_t)m->_num_buckets + EMH_GROUP_WIDTH);
    }
    m->_last = 0;
    m->_num_filled = 0;
    m->_etail = EMH__INACTIVE;
    m->_growth_left = (m->_num_buckets > 0)
        ? (EMH__SZ)((((uint64_t)m->_num_buckets << 28) + m->_mlf - 1) / m->_mlf)
        : 0;
}

static inline void EMH__FN(_deinit)(EMH__T* m)
{
    EMH__FN(_clear)(m);
    EMH__FN(__dealloc_pairs)(m->_pairs);
    EMH__FN(__dealloc_index)(m->_index);
    EMH__FN(__dealloc_ctrl)(m->_ctrl);
    m->_pairs = NULL;
    m->_index = NULL;
    m->_ctrl  = NULL;
    m->_num_buckets = 0;
    m->_mask = 0;
    m->_pairs_capacity = 0;
}

static inline void EMH__FN(_shrink_to_fit)(EMH__T* m, float min_factor)
{
    if (min_factor <= 0.0f) min_factor = EMH_DEFAULT_LOAD_FACTOR / 4.0f;
    if (EMH__FN(_load_factor)(m) < min_factor && EMH__FN(_bucket_count)(m) > 10)
        EMH__FN(_rehash)(m, m->_num_filled + 1);
}

/* ---- public lookup -------------------------------------------------- */
static inline size_t EMH__FN(_find_slot)(const EMH__T* m, EMH_KEY key)
{
    return (size_t)EMH__FN(__find_filled_slot)(m, key);
}

EMH_HOT int EMH__FN(_contains)(const EMH__T* m, EMH_KEY key)
{
    return EMH__FN(__find_filled_slot)(m, key) != m->_num_filled;
}

EMH_HOT EMH_VAL* EMH__FN(_try_get)(const EMH__T* m, EMH_KEY key)
{
    const EMH__SZ slot = EMH__FN(__find_filled_slot)(m, key);
    return (slot != m->_num_filled) ? &m->_pairs[slot].second : NULL;
}

EMH_HOT int EMH__FN(_get)(const EMH__T* m, EMH_KEY key, EMH_VAL* out)
{
    const EMH__SZ slot = EMH__FN(__find_filled_slot)(m, key);
    if (slot == m->_num_filled) return 0;
    *out = m->_pairs[slot].second;
    return 1;
}

/* Mirror of try_set in upstream: only writes if key exists. */
static inline int EMH__FN(_try_set)(EMH__T* m, EMH_KEY key, EMH_VAL val)
{
    const EMH__SZ slot = EMH__FN(__find_filled_slot)(m, key);
    if (slot == m->_num_filled) return 0;
    EMH_VAL_DESTROY(m->_pairs[slot].second);
    EMH_VAL_COPY(m->_pairs[slot].second, val);
    return 1;
}

/* ---- public insert -------------------------------------------------- */
/* Returns 1 if inserted, 0 if key already present (value unchanged). */
EMH_HOT int EMH__FN(_insert)(EMH__T* m, EMH_KEY key, EMH_VAL val)
{
    EMH__FN(__check_expand_need)(m);
    const uint64_t key_hash = EMH__FN(__hash_key)(key);
    const EMH__SZ  bucket   = EMH__FN(__find_or_allocate)(m, key, key_hash);
    if (EMH__EMPTY(m, bucket)) {
        EMH__FN(__emit)(m, key, val, bucket, key_hash);
        return 1;
    }
    return 0;
}

/* Always assigns; returns 1 if inserted, 0 if overwritten. */
EMH_HOT int EMH__FN(_set)(EMH__T* m, EMH_KEY key, EMH_VAL val)
{
    EMH__FN(__check_expand_need)(m);
    const uint64_t key_hash = EMH__FN(__hash_key)(key);
    const EMH__SZ  bucket   = EMH__FN(__find_or_allocate)(m, key, key_hash);
    if (EMH__EMPTY(m, bucket)) {
        EMH__FN(__emit)(m, key, val, bucket, key_hash);
        return 1;
    }
    {
        const EMH__SZ slot = m->_index[bucket].slot & m->_mask;
        EMH_VAL_DESTROY(m->_pairs[slot].second);
        EMH_VAL_COPY(m->_pairs[slot].second, val);
    }
    return 0;
}

/* Returns pointer to existing-or-just-inserted value. */
EMH_HOT EMH_VAL* EMH__FN(_get_or_insert)(EMH__T* m, EMH_KEY key, EMH_VAL default_val)
{
    EMH__FN(__check_expand_need)(m);
    const uint64_t key_hash = EMH__FN(__hash_key)(key);
    const EMH__SZ  bucket   = EMH__FN(__find_or_allocate)(m, key, key_hash);
    if (EMH__EMPTY(m, bucket))
        EMH__FN(__emit)(m, key, default_val, bucket, key_hash);
    return &m->_pairs[m->_index[bucket].slot & m->_mask].second;
}

/* Caller asserts key not present. UB if violated. */
static inline size_t EMH__FN(_insert_unique)(EMH__T* m, EMH_KEY key, EMH_VAL val)
{
    EMH__FN(__check_expand_need)(m);
    const uint64_t key_hash = EMH__FN(__hash_key)(key);
    const EMH__SZ  bucket   = EMH__FN(__find_unique_bucket)(m, key_hash);
    EMH__FN(__emit)(m, key, val, bucket, key_hash);
    return (size_t)bucket;
}

/* ---- public erase --------------------------------------------------- */
EMH_HOT size_t EMH__FN(_erase)(EMH__T* m, EMH_KEY key)
{
    const uint64_t key_hash = EMH__FN(__hash_key)(key);
    const EMH__SZ sbucket = EMH__FN(__find_filled_bucket)(m, key, key_hash);
    if (sbucket == EMH__INACTIVE)
        return 0;
    const EMH__SZ main_bucket = (EMH__SZ)key_hash & m->_mask;
    EMH__FN(__erase_slot)(m, sbucket, main_bucket);
    return 1;
}

/* Erase by slot index (e.g. while iterating). Note: this swaps the
 * last entry into `slot`, so iteration must NOT advance past `slot`
 * unconditionally after a successful erase.                          */
static inline void EMH__FN(_erase_at)(EMH__T* m, size_t slot)
{
    assert(slot < m->_num_filled);
    EMH__SZ main_bucket;
    const EMH__SZ sbucket = EMH__FN(__find_slot_bucket)(m, (EMH__SZ)slot, &main_bucket);
    EMH__FN(__erase_slot)(m, sbucket, main_bucket);
}

/* ---- prefetch / batched lookup (your patch) ------------------------- */
static inline void EMH__FN(_prefetch)(const EMH__T* m, EMH_KEY key)
{
    const EMH__SZ bucket = (EMH__SZ)EMH__FN(__hash_key)(key) & m->_mask;
    EMH_PREFETCH(&m->_index[bucket]);
}

/* out[i] = pointer to pair or NULL if absent. Stride 40 near-peak on x86.
 * `EMH_KEY const*` (not `const EMH_KEY*`) so const binds to the element
 * even when EMH_KEY is a pointer type like `char*`.
 * Uses __find_slot_h: takes pre-computed hash (shared with prefetch),
 * returns slot directly (no second _index[bucket].slot reload after call). */
static inline void EMH__FN(_find_batch)(const EMH__T* m, EMH_KEY const* keys, size_t n,
                                        const EMH__TP* EMH__RESTRICT * EMH__RESTRICT out)
{
    enum { STRIDE = 40 };
    const EMH__TI* EMH__RESTRICT idx = m->_index;
    const EMH__SZ mask = m->_mask;
    for (size_t i = 0; i < n; ++i) {
        if (i + STRIDE < n) {
            const EMH__SZ b = (EMH__SZ)EMH__FN(__hash_key)(keys[i + STRIDE]) & mask;
            EMH_PREFETCH(&idx[b]);
        }
        const uint64_t h = EMH__FN(__hash_key)(keys[i]);
        out[i] = EMH__FN(__find_pair_h)(m, keys[i], h);
    }
}

/* ---- copy (deep) ---------------------------------------------------- */
/* Deep copy of src into dst. dst must not be aliased to src. Each pair is
 * copied through EMH_KEY_COPY/EMH_VAL_COPY so owned types get fresh storage.
 * For POD the COPY macros are plain assignment and the loop compiles to
 * a memcpy-equivalent sequence.                                          */
static inline void EMH__FN(_clone)(EMH__T* dst, const EMH__T* src)
{
    /* If dst already holds entries, drop them first. */
    if (dst->_pairs) EMH__FN(_clear)(dst);
    EMH__FN(__dealloc_pairs)(dst->_pairs);
    EMH__FN(__dealloc_index)(dst->_index);
    EMH__FN(__dealloc_ctrl)(dst->_ctrl);

    dst->_num_buckets    = src->_num_buckets;
    dst->_num_filled     = src->_num_filled;
    dst->_pairs_capacity = src->_pairs_capacity;
    dst->_mlf            = src->_mlf;
    dst->_last           = src->_last;
    dst->_mask           = src->_mask;
    dst->_etail          = src->_etail;
    dst->_growth_left    = src->_growth_left;

    dst->_pairs = EMH__FN(__alloc_pairs)(src->_pairs_capacity);
    dst->_index = EMH__FN(__alloc_index)(src->_num_buckets);
    dst->_ctrl  = EMH__FN(__alloc_ctrl)(src->_num_buckets);

    memcpy(dst->_index, src->_index, ((size_t)src->_num_buckets + EMH_EAD) * sizeof(EMH__TI));
    memcpy(dst->_ctrl,  src->_ctrl,  (size_t)src->_num_buckets + EMH_GROUP_WIDTH);

    for (EMH__SZ i = 0; i < src->_num_filled; ++i) {
        EMH_KEY_COPY(dst->_pairs[i].first,  src->_pairs[i].first);
        EMH_VAL_COPY(dst->_pairs[i].second, src->_pairs[i].second);
    }
}

/* ---- erase_if: predicate-driven mass erase -------------------------- */
/* Walks pairs and erases entries where pred() returns nonzero. Pred sees
 * key/value by value plus user ctx. Returns count erased. The internal
 * erase_at swaps the last entry into the freed slot, so we don't advance
 * i when an erase happens (re-test the new occupant).                   */
static inline size_t EMH__FN(_erase_if)(EMH__T* m,
    int (*pred)(EMH_KEY key, EMH_VAL val, void* ctx), void* ctx)
{
    const EMH__SZ before = m->_num_filled;
    EMH__SZ i = 0;
    while (i < m->_num_filled) {
        if (pred(m->_pairs[i].first, m->_pairs[i].second, ctx))
            EMH__FN(_erase_at)(m, (size_t)i);
        else
            ++i;
    }
    return (size_t)(before - m->_num_filled);
}

/* ---- cleanup macros ------------------------------------------------- */
#undef EMH__EMPTY
#undef EMH__CAT_
#undef EMH__CAT
#undef EMH__FN
#undef EMH__T
#undef EMH__TI
#undef EMH__TP
#undef EMH__SZ
#undef EMH__INACTIVE

#undef EMH_NAME
#undef EMH_KEY
#undef EMH_VAL
#undef EMH_HASH
#ifdef EMH_POD_KV
#  undef EMH_POD_KV
#endif
#ifdef EMH__EQ_WAS_DEFAULT
#  undef EMH__EQ_WAS_DEFAULT
#endif
#undef EMH_EQ

#ifdef EMH__KEY_COPY_WAS_DEFAULT
#  undef EMH__KEY_COPY_WAS_DEFAULT
#endif
#undef EMH_KEY_COPY

#ifdef EMH__VAL_COPY_WAS_DEFAULT
#  undef EMH__VAL_COPY_WAS_DEFAULT
#endif
#undef EMH_VAL_COPY

#ifdef EMH__KEY_DESTROY_WAS_DEFAULT
#  undef EMH__KEY_DESTROY_WAS_DEFAULT
#endif
#undef EMH_KEY_DESTROY

#ifdef EMH__VAL_DESTROY_WAS_DEFAULT
#  undef EMH__VAL_DESTROY_WAS_DEFAULT
#endif
#undef EMH_VAL_DESTROY

#endif /* EMH_NAME */
