#ifndef VFS_H
#define VFS_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "config.h"
#include "sector_cache.h"

/* VFS file entry structure */
typedef struct {
    uint32_t magic;              /* VFS_MAGIC */
    uint32_t version;            /* VFS_VERSION */
    uint32_t total_sectors;      /* Total sectors in volume */
    uint32_t used_sectors;       /* Used sectors */
    uint32_t file_count;         /* Number of files */
    uint32_t reserved[4];        /* Reserved for future use */
} vfs_header_t;

/* File entry in the file table */
typedef struct {
    char filename[VFS_MAX_FILENAME_LEN];
    uint64_t offset;             /* Offset in data area */
    uint64_t size;               /* File size in bytes */
    uint64_t sectors;            /* Number of sectors used */
    time_t created;              /* Creation timestamp */
    time_t modified;             /* Modification timestamp */
    uint32_t flags;              /* File flags */
    uint32_t reserved;           /* Reserved */
} vfs_file_entry_t;

/* VFS context */
typedef struct {
    vfs_header_t header;
    vfs_file_entry_t files[VFS_MAX_FILES];
    sector_cache_t *cache;       /* Sector cache for data access */
    size_t data_size;             /* Size of data area */
    int is_mounted;              /* Mount status */
} vfs_context_t;

/* VFS operations */
int vfs_create_volume(const char *path, size_t size_mb);
int vfs_open_volume(const char *path, vfs_context_t *ctx);
int vfs_close_volume(vfs_context_t *ctx);
int vfs_format_volume(vfs_context_t *ctx);

/* File operations */
int vfs_add_file(vfs_context_t *ctx, const char *filename, 
                 const uint8_t *data, size_t size);
int vfs_get_file(vfs_context_t *ctx, const char *filename,
                 uint8_t *data, size_t *size);
int vfs_delete_file(vfs_context_t *ctx, const char *filename);
int vfs_list_files(vfs_context_t *ctx, vfs_file_entry_t *entries, 
                   int *count);
int vfs_rename_file(vfs_context_t *ctx, const char *old_name, const char *new_name);
int vfs_resize_file(vfs_context_t *ctx, const char *filename, size_t new_size);
int vfs_update_timestamps(vfs_context_t *ctx, const char *filename, time_t created, time_t modified);
int vfs_create_empty_file(vfs_context_t *ctx, const char *filename);

/* Cache-based data access functions */
int vfs_read_data(vfs_context_t *ctx, uint64_t offset, uint8_t *buffer, size_t size);
int vfs_write_data(vfs_context_t *ctx, uint64_t offset, const uint8_t *buffer, size_t size);

/* Utility functions */
int vfs_find_file(vfs_context_t *ctx, const char *filename);
int vfs_validate_header(vfs_header_t *header);
size_t vfs_get_available_space(vfs_context_t *ctx);
size_t vfs_get_total_space(vfs_context_t *ctx);

#endif /* VFS_H */
