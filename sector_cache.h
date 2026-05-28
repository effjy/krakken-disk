#ifndef SECTOR_CACHE_H
#define SECTOR_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include "config.h"

/* Cache entry for a single sector */
typedef struct {
    uint64_t sector_idx;           /* Sector index in volume */
    uint8_t *data;                 /* Decrypted sector data (VFS_SECTOR_SIZE) */
    bool dirty;                    /* Sector has been modified */
    bool pinned;                   /* Sector is pinned (never evicted) */
    uint64_t last_access;          /* LRU timestamp */
    bool valid;                    /* Entry contains valid data */
} cache_entry_t;

/* Sector cache context */
typedef struct {
    FILE *file;                    /* Volume file handle */
    uint8_t master_key[KEY_SIZE];         /* Master encryption key */
    uint8_t file_key[KEY_SIZE];     /* File encryption key */
    
    cache_entry_t *entries;         /* Cache entries array */
    size_t cache_size;              /* Number of cache entries */
    size_t max_cache_size;          /* Maximum cache entries (e.g., 4096) */
    
    uint64_t access_counter;        /* Monotonically increasing counter for LRU */
    size_t header_sectors;          /* Number of header sectors (pinned) */
    
    uint64_t total_sectors;         /* Total sectors in volume */
    size_t data_offset;             /* Offset in file where data area begins */
    int use_domain_separator;       /* If true, absorb 0x00 domain separator */
} sector_cache_t;

/* Cache operations */
sector_cache_t* cache_init(FILE *file, const uint8_t *master_key,
                           const uint8_t *file_key, size_t max_entries,
                           size_t data_offset,      /* byte offset where sectors begin */
                           uint64_t total_sectors,  /* total encrypted sectors in volume */
                           int use_domain_separator);
void cache_destroy(sector_cache_t *cache);

/* Sector access operations */
int cache_get_sector(sector_cache_t *cache, uint64_t sector_idx, uint8_t **data);
int cache_mark_dirty(sector_cache_t *cache, uint64_t sector_idx);
int cache_pin_sector(sector_cache_t *cache, uint64_t sector_idx);

/* Cache management */
int cache_flush_all(sector_cache_t *cache);
int cache_flush_sector(sector_cache_t *cache, uint64_t sector_idx);

/* Utility functions */
void cache_wipe_sector(uint8_t *data);
size_t cache_get_memory_usage(sector_cache_t *cache);

#endif /* SECTOR_CACHE_H */
