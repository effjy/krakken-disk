/*
 * sector_cache.c — sector-level encrypted-I/O cache
 *
 * Bug fixes applied in this rewrite:
 *   Bug 1  – Invalidate cache slot BEFORE loading so a failed load leaves a
 *             consistent (empty) state instead of valid=true / data=NULL.
 *   Bug 2  – decrypt_sector_at() issues its own fseeko() for every attempt,
 *             so the master_key fallback always reads from the right offset.
 *   Bug 3  – total_sectors is now passed in by the caller (volume_open),
 *             not computed from the whole file size (which includes the
 *             crypto header).
 *   Bug 4  – lru_victim() returns SIZE_MAX when every slot is pinned instead
 *             of returning slot 0 (a pinned slot).
 *   Bug 5  – All VFS_SECTOR_SIZE buffers are pre-allocated in cache_init()
 *             so the hot path never calls malloc / free.
 *
 * Portable large-file support: define _FILE_OFFSET_BITS before any system
 * header so that off_t and fseeko() handle offsets > 2 GB on 32-bit targets.
 */
#define _FILE_OFFSET_BITS 64

#include "sector_cache.h"
#include "utils.h"
#include "permut2048.h"
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <sys/mman.h>

#define DEFAULT_CACHE_SIZE  4096
#define PER_SECTOR_MAC_SIZE 32

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

static void sector_nonce(uint64_t idx, uint8_t *nonce, size_t nonce_len) {
    memset(nonce, 0, nonce_len);
    for (size_t i = 0; i < 8 && i < nonce_len; i++)
        nonce[i] = (uint8_t)((idx >> (i * 8)) & 0xFF);
}

/*
 * apply_keystream – XOR-decrypt `cipher` into `out_plain` using the
 * per-sector stream derived from `sector_key` and `sector_idx`.
 * Extracted as a helper so both decrypt attempts can share it.
 */
static void apply_keystream(sector_cache_t *cache, const uint8_t *sector_key, uint64_t sector_idx,
                             const uint8_t *cipher, uint8_t *out_plain) {
    uint8_t nonce[NONCE_SIZE];
    sector_nonce(sector_idx, nonce, NONCE_SIZE);

    permut2048_ctx sponge = { .rate = PERMUT2048_RATE };
    permut2048_absorb(&sponge, sector_key, KEY_SIZE);
    permut2048_absorb(&sponge, nonce, NONCE_SIZE);
    if (cache->use_domain_separator) {
        permut2048_absorb(&sponge, (const uint8_t*)"\x00", 1);
    }
    permut2048_finalize(&sponge);

    uint8_t keystream[VFS_SECTOR_SIZE];
    permut2048_squeeze(&sponge, keystream, VFS_SECTOR_SIZE);
    for (size_t i = 0; i < VFS_SECTOR_SIZE; i++)
        out_plain[i] = cipher[i] ^ keystream[i];
    secure_zero(keystream, VFS_SECTOR_SIZE);
}

/*
 * encrypt_sector_at – encrypt `plain` and write ciphertext+MAC to the file
 * at the correct offset for `sector_idx`.  Performs its own fseeko().
 */
static int encrypt_sector_at(sector_cache_t *cache, uint64_t sector_idx,
                              const uint8_t *plain) {
    const size_t sector_with_mac = VFS_SECTOR_SIZE + PER_SECTOR_MAC_SIZE;
    const off_t  file_off = (off_t)cache->data_offset
                          + (off_t)sector_idx * (off_t)sector_with_mac;

    if (fseeko(cache->file, file_off, SEEK_SET) != 0)
        return -1;

    uint8_t sector_key[KEY_SIZE];
    crypto_generichash(sector_key, KEY_SIZE,
                       cache->file_key, KEY_SIZE,
                       (const uint8_t *)&sector_idx, sizeof(sector_idx));

    uint8_t nonce[NONCE_SIZE];
    sector_nonce(sector_idx, nonce, NONCE_SIZE);

    permut2048_ctx sponge = { .rate = PERMUT2048_RATE };
    permut2048_absorb(&sponge, sector_key, KEY_SIZE);
    permut2048_absorb(&sponge, nonce, NONCE_SIZE);
    if (cache->use_domain_separator) {
        permut2048_absorb(&sponge, (const uint8_t*)"\x00", 1);
    }
    permut2048_finalize(&sponge);

    uint8_t cipher[VFS_SECTOR_SIZE], keystream[VFS_SECTOR_SIZE];
    permut2048_squeeze(&sponge, keystream, VFS_SECTOR_SIZE);
    for (size_t i = 0; i < VFS_SECTOR_SIZE; i++)
        cipher[i] = plain[i] ^ keystream[i];
    secure_zero(keystream, VFS_SECTOR_SIZE);

    uint8_t tag[PER_SECTOR_MAC_SIZE];
    crypto_generichash_state mac;
    crypto_generichash_init(&mac, sector_key, KEY_SIZE, PER_SECTOR_MAC_SIZE);
    crypto_generichash_update(&mac, (const uint8_t *)&sector_idx, sizeof(sector_idx));
    crypto_generichash_update(&mac, cipher, VFS_SECTOR_SIZE);
    crypto_generichash_final(&mac, tag, PER_SECTOR_MAC_SIZE);
    secure_zero(sector_key, KEY_SIZE);

    if (fwrite(cipher, 1, VFS_SECTOR_SIZE, cache->file) != VFS_SECTOR_SIZE)
        return -1;
    if (fwrite(tag, 1, PER_SECTOR_MAC_SIZE, cache->file) != PER_SECTOR_MAC_SIZE)
        return -1;
    return 0;
}

/*
 * decrypt_sector_at – read and authenticate the sector at `sector_idx`,
 * then decrypt into `out_plain`.
 *
 * Bug 2 fix: each attempt calls fseeko() itself before reading.  The
 * master_key fallback therefore always reads from `file_off`, never from
 * wherever the file pointer ended up after the first failed read.
 *
 * Tries file_key first (all new volumes).  On MAC mismatch it seeks back and
 * retries with master_key for backward compatibility with old volumes.
 */
static int decrypt_sector_at(sector_cache_t *cache, uint64_t sector_idx,
                              uint8_t *out_plain) {
    const size_t sector_with_mac = VFS_SECTOR_SIZE + PER_SECTOR_MAC_SIZE;
    const off_t  file_off = (off_t)cache->data_offset
                          + (off_t)sector_idx * (off_t)sector_with_mac;

    /* Reused across both attempts (overwritten each time). */
    uint8_t sector_key[KEY_SIZE];
    uint8_t cipher[VFS_SECTOR_SIZE], stored_tag[PER_SECTOR_MAC_SIZE];
    uint8_t computed_tag[PER_SECTOR_MAC_SIZE];
    crypto_generichash_state mac;

    /* ---- Attempt 1: file_key ---- */
    if (fseeko(cache->file, file_off, SEEK_SET) != 0)
        return -1;

    crypto_generichash(sector_key, KEY_SIZE,
                       cache->file_key, KEY_SIZE,
                       (const uint8_t *)&sector_idx, sizeof(sector_idx));

    if (fread(cipher, 1, VFS_SECTOR_SIZE, cache->file) != VFS_SECTOR_SIZE ||
        fread(stored_tag, 1, PER_SECTOR_MAC_SIZE, cache->file) != PER_SECTOR_MAC_SIZE) {
        secure_zero(sector_key, KEY_SIZE);
        return -1;
    }

    crypto_generichash_init(&mac, sector_key, KEY_SIZE, PER_SECTOR_MAC_SIZE);
    crypto_generichash_update(&mac, (const uint8_t *)&sector_idx, sizeof(sector_idx));
    crypto_generichash_update(&mac, cipher, VFS_SECTOR_SIZE);
    crypto_generichash_final(&mac, computed_tag, PER_SECTOR_MAC_SIZE);

    if (ct_memcmp(stored_tag, computed_tag, PER_SECTOR_MAC_SIZE) == 0) {
        apply_keystream(cache, sector_key, sector_idx, cipher, out_plain);
        secure_zero(sector_key, KEY_SIZE);
        return 0;
    }

    /* ---- Attempt 2: master_key (backward compatibility) ---- */
    /* Seek back to the same sector — the first read advanced the pointer. */
    if (fseeko(cache->file, file_off, SEEK_SET) != 0) {
        secure_zero(sector_key, KEY_SIZE);
        return -1;
    }

    crypto_generichash(sector_key, KEY_SIZE,
                       cache->master_key, 32,
                       (const uint8_t *)&sector_idx, sizeof(sector_idx));

    if (fread(cipher, 1, VFS_SECTOR_SIZE, cache->file) != VFS_SECTOR_SIZE ||
        fread(stored_tag, 1, PER_SECTOR_MAC_SIZE, cache->file) != PER_SECTOR_MAC_SIZE) {
        secure_zero(sector_key, KEY_SIZE);
        return -1;
    }

    crypto_generichash_init(&mac, sector_key, KEY_SIZE, PER_SECTOR_MAC_SIZE);
    crypto_generichash_update(&mac, (const uint8_t *)&sector_idx, sizeof(sector_idx));
    crypto_generichash_update(&mac, cipher, VFS_SECTOR_SIZE);
    crypto_generichash_final(&mac, computed_tag, PER_SECTOR_MAC_SIZE);

    if (ct_memcmp(stored_tag, computed_tag, PER_SECTOR_MAC_SIZE) != 0) {
        secure_zero(sector_key, KEY_SIZE);
        return -1;
    }

    apply_keystream(cache, sector_key, sector_idx, cipher, out_plain);
    secure_zero(sector_key, KEY_SIZE);
    return 0;
}

/*
 * lru_victim – return the index of the best slot to evict.
 *
 * Bug 4 fix: returns SIZE_MAX when every slot is pinned so the caller can
 * detect the "no evictable slot" condition without silently overwriting a
 * pinned entry.
 */
static size_t lru_victim(sector_cache_t *cache) {
    size_t   victim        = SIZE_MAX;
    uint64_t oldest_access = UINT64_MAX;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (!cache->entries[i].valid)
            return i;  /* Empty slot is always preferable */
        if (!cache->entries[i].pinned &&
            cache->entries[i].last_access < oldest_access) {
            oldest_access = cache->entries[i].last_access;
            victim = i;
        }
    }
    return victim;  /* SIZE_MAX when every slot is pinned */
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/*
 * cache_init – allocate and initialise the sector cache.
 *
 * Bug 3 fix: data_offset and total_sectors are provided by the caller
 * (volume_open), which already knows the precise data region boundaries.
 * We no longer call ftell/fseek internally, so the arithmetic based on
 * the full file size (which includes the crypto header) is avoided.
 *
 * All VFS_SECTOR_SIZE buffers are pre-allocated here via posix_memalign so
 * the hot path (cache_get_sector) never calls malloc or free.
 */
sector_cache_t *cache_init(FILE *file, const uint8_t *master_key,
                            const uint8_t *file_key, size_t max_entries,
                            size_t data_offset, uint64_t total_sectors,
                            int use_domain_separator) {
    if (!file || !master_key || !file_key)
        return NULL;

    sector_cache_t *cache = calloc(1, sizeof(sector_cache_t));
    if (!cache)
        return NULL;
    lock_sensitive(cache, sizeof(sector_cache_t));

    cache->file          = file;
    cache->data_offset   = data_offset;
    cache->total_sectors = total_sectors;
    cache->use_domain_separator = use_domain_separator;
    cache->cache_size    = 0;  /* unused; zeroed for ABI compatibility */
    memcpy(cache->master_key, master_key, KEY_SIZE);
    memcpy(cache->file_key,   file_key,   KEY_SIZE);

    cache->max_cache_size = max_entries ? max_entries : DEFAULT_CACHE_SIZE;
    cache->entries = calloc(cache->max_cache_size, sizeof(cache_entry_t));
    if (!cache->entries) {
        free(cache);
        return NULL;
    }

    /* Pre-allocate every sector buffer so the hot path never calls malloc. */
    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (posix_memalign((void **)&cache->entries[i].data,
                           64, VFS_SECTOR_SIZE) != 0) {
            /* Roll back already-allocated buffers. */
            for (size_t j = 0; j < i; j++) {
                secure_zero(cache->entries[j].data, VFS_SECTOR_SIZE);
                free(cache->entries[j].data);
            }
            free(cache->entries);
            free(cache);
            return NULL;
        }
        memset(cache->entries[i].data, 0, VFS_SECTOR_SIZE);
        cache->entries[i].valid      = false;
        cache->entries[i].sector_idx = UINT64_MAX;
        cache->entries[i].dirty      = false;
        cache->entries[i].pinned     = false;
        cache->entries[i].last_access = 0;
    }

    cache->access_counter = 0;
    cache->header_sectors = 0;
    return cache;
}

/*
 * cache_destroy – flush dirty sectors, wipe all buffers and keys, free memory.
 */
void cache_destroy(sector_cache_t *cache) {
    if (!cache)
        return;

    cache_flush_all(cache);

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].data) {
            cache_wipe_sector(cache->entries[i].data);
            munlock(cache->entries[i].data, VFS_SECTOR_SIZE);
            free(cache->entries[i].data);
            cache->entries[i].data = NULL;
        }
    }

    /* Wipe cryptographic keys before releasing the struct. */
    secure_zero(cache->master_key, KEY_SIZE);
    secure_zero(cache->file_key,   KEY_SIZE);

    free(cache->entries);
    free(cache);
}

/*
 * cache_get_sector – return a pointer to the decrypted sector data for
 * `sector_idx`, loading it from disk if not already cached.
 *
 * Bug 1 fix: the evicted slot is marked invalid (valid=false,
 * sector_idx=UINT64_MAX) BEFORE decrypt_sector_at() is called.  If the
 * decrypt fails, the slot is left in a clean, empty state so a subsequent
 * cache-hit scan for the same sector cannot return a NULL data pointer.
 */
int cache_get_sector(sector_cache_t *cache, uint64_t sector_idx, uint8_t **data) {
    if (!cache || !data || sector_idx >= cache->total_sectors)
        return -1;

    /* Fast path: sector already cached. */
    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx) {
            *data = cache->entries[i].data;
            cache->entries[i].last_access = cache->access_counter++;
            return 0;
        }
    }

    /* Select an eviction candidate. */
    size_t slot = lru_victim(cache);
    if (slot == SIZE_MAX)
        return -1;  /* Every slot is pinned — should not happen in practice. */

    cache_entry_t *e = &cache->entries[slot];

    /* Flush dirty data before evicting the old occupant. */
    if (e->valid && !e->pinned && e->dirty) {
        if (cache_flush_sector(cache, e->sector_idx) != 0)
            return -1;
    }

    /*
     * Wipe the buffer and mark the slot invalid BEFORE the load.
     * Any I/O or authentication failure in decrypt_sector_at() will leave
     * the slot in a clean, reusable state (valid=false, data zeroed).
     * This prevents a subsequent cache-hit from returning a NULL or stale
     * data pointer (Bug 1 fix).
     */
    cache_wipe_sector(e->data);
    e->valid      = false;
    e->sector_idx = UINT64_MAX;
    e->dirty      = false;
    e->pinned     = false;

    /*
     * Load and authenticate the sector.  decrypt_sector_at() issues its own
     * fseeko() for each attempt, so the master_key fallback always reads from
     * the correct file offset (Bug 2 fix).
     */
    if (decrypt_sector_at(cache, sector_idx, e->data) != 0)
        return -1;

    /* Commit the loaded entry. */
    e->sector_idx  = sector_idx;
    e->valid       = true;
    e->dirty       = false;
    e->pinned      = false;
    e->last_access = cache->access_counter++;

    mlock(e->data, VFS_SECTOR_SIZE);  /* best-effort; non-fatal on failure */

    *data = e->data;
    return 0;
}

/* Mark a cached sector as dirty (will be flushed on eviction or explicit flush). */
int cache_mark_dirty(sector_cache_t *cache, uint64_t sector_idx) {
    if (!cache || sector_idx >= cache->total_sectors)
        return -1;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx) {
            cache->entries[i].dirty       = true;
            cache->entries[i].last_access = cache->access_counter++;
            return 0;
        }
    }
    return -1;  /* Sector not found in cache */
}

/* Pin a sector so it is never evicted. */
int cache_pin_sector(sector_cache_t *cache, uint64_t sector_idx) {
    if (!cache || sector_idx >= cache->total_sectors)
        return -1;

    /* Ensure the sector is in the cache first. */
    uint8_t *data_ptr;
    if (cache_get_sector(cache, sector_idx, &data_ptr) != 0)
        return -1;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx) {
            cache->entries[i].pinned = true;
            cache->header_sectors++;
            return 0;
        }
    }
    return -1;
}

/*
 * cache_flush_sector – write a dirty sector back to the encrypted volume.
 * encrypt_sector_at() performs its own fseeko().
 */
int cache_flush_sector(sector_cache_t *cache, uint64_t sector_idx) {
    if (!cache || sector_idx >= cache->total_sectors)
        return -1;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx &&
            cache->entries[i].dirty) {

            if (encrypt_sector_at(cache, sector_idx,
                                  cache->entries[i].data) != 0)
                return -1;

            cache->entries[i].dirty = false;
            return 0;
        }
    }
    return 0;  /* Sector not dirty or not found — nothing to do. */
}

/* Flush every dirty sector to disk. */
int cache_flush_all(sector_cache_t *cache) {
    if (!cache)
        return -1;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid && cache->entries[i].dirty) {
            if (cache_flush_sector(cache, cache->entries[i].sector_idx) != 0)
                return -1;
        }
    }
    fflush(cache->file);
    return 0;
}

/* Securely zero a sector-sized buffer. */
void cache_wipe_sector(uint8_t *data) {
    if (data)
        secure_zero(data, VFS_SECTOR_SIZE);
}

/* Report total memory consumed by the cache (all buffers pre-allocated). */
size_t cache_get_memory_usage(sector_cache_t *cache) {
    if (!cache)
        return 0;

    return sizeof(sector_cache_t)
         + cache->max_cache_size * sizeof(cache_entry_t)
         + cache->max_cache_size * VFS_SECTOR_SIZE;  /* all pre-allocated */
}
