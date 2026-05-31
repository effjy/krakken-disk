#include "vfs.h"
#include "config.h"
#include "sector_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Validate VFS header */
int vfs_validate_header(vfs_header_t *header) {
    return (header->magic == VFS_MAGIC && header->version == VFS_VERSION);
}

/* Create a new volume file */
int vfs_create_volume(const char *path, size_t size_mb) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("Failed to create volume file");
        return -1;
    }

    size_t total_size = size_mb * 1024 * 1024;
    uint8_t *zero = calloc(1, VFS_SECTOR_SIZE);
    if (!zero) {
        fclose(f);
        return -1;
    }

    /* Write zeros to fill the volume */
    size_t sectors = total_size / VFS_SECTOR_SIZE;
    for (size_t i = 0; i < sectors; i++) {
        fwrite(zero, 1, VFS_SECTOR_SIZE, f);
    }

    free(zero);
    fclose(f);
    return 0;
}

/* Open an existing volume */
int vfs_open_volume(const char *path, vfs_context_t *ctx) {
    FILE *f = fopen(path, "rb+");
    if (!f) {
        perror("Failed to open volume file");
        return -1;
    }

    /* Read header */
    if (fread(&ctx->header, sizeof(vfs_header_t), 1, f) != 1) {
        fclose(f);
        return -1;
    }

    if (!vfs_validate_header(&ctx->header)) {
        fclose(f);
        return -1;
    }

    /* Read file table */
    if (fread(ctx->files, sizeof(vfs_file_entry_t), VFS_MAX_FILES, f) != VFS_MAX_FILES) {
        fclose(f);
        return -1;
    }

    /* Calculate data area size */
    size_t header_size = sizeof(vfs_header_t) + (sizeof(vfs_file_entry_t) * VFS_MAX_FILES);
    ctx->data_size = ctx->header.total_sectors * VFS_SECTOR_SIZE - header_size;
    
    /* Note: Cache will be initialized by volume.c with proper keys */
    ctx->cache = NULL;

    fclose(f);
    ctx->is_mounted = 1;
    return 0;
}

/* Close and save volume */
int vfs_close_volume(vfs_context_t *ctx) {
    if (!ctx->is_mounted) {
        return -1;
    }

    /* Flush and destroy cache */
    if (ctx->cache) {
        cache_destroy(ctx->cache);
        ctx->cache = NULL;
    }
    
    ctx->is_mounted = 0;
    return 0;
}

/* Format a volume with empty filesystem */
int vfs_format_volume(vfs_context_t *ctx) {
    memset(&ctx->header, 0, sizeof(vfs_header_t));
    ctx->header.magic = VFS_MAGIC;
    ctx->header.version = VFS_VERSION;
    
    /* Calculate actual data area size (minus VFS header and file table) */
    size_t vfs_metadata_size = sizeof(vfs_header_t) + (sizeof(vfs_file_entry_t) * VFS_MAX_FILES);
    size_t actual_data_size = ctx->data_size - vfs_metadata_size;
    ctx->header.total_sectors = actual_data_size / VFS_SECTOR_SIZE;
    ctx->header.used_sectors = 0;
    ctx->header.file_count = 0;

    memset(ctx->files, 0, sizeof(ctx->files));
    
    /* Note: Cache will be zeroed as sectors are accessed */

    return 0;
}

/* Calculate available space in volume */
size_t vfs_get_available_space(vfs_context_t *ctx) {
    if (!ctx->is_mounted) return 0;
    
    uint32_t free_sectors = ctx->header.total_sectors - ctx->header.used_sectors;
    return (size_t)free_sectors * VFS_SECTOR_SIZE;
}

/* Calculate total space in volume */
size_t vfs_get_total_space(vfs_context_t *ctx) {
    if (!ctx->is_mounted) return 0;
    
    return (size_t)ctx->header.total_sectors * VFS_SECTOR_SIZE;
}

/* Find a file by name */
int vfs_find_file(vfs_context_t *ctx, const char *filename) {
    for (uint32_t i = 0; i < ctx->header.file_count; i++) {
        if (strcmp(ctx->files[i].filename, filename) == 0) {
            return i;
        }
    }
    return -1;
}

/* Add a file to the volume */
int vfs_add_file(vfs_context_t *ctx, const char *filename,
                 const uint8_t *data, size_t size) {
    if (!ctx->is_mounted) return -1;
    if (ctx->header.file_count >= VFS_MAX_FILES) return -1;
    if (vfs_find_file(ctx, filename) >= 0) return -1; /* File exists */

    /* Calculate required sectors */
    size_t sectors_needed = (size + VFS_SECTOR_SIZE - 1) / VFS_SECTOR_SIZE;
    
    /* Check if enough space */
    if (ctx->header.used_sectors + sectors_needed > ctx->header.total_sectors) {
        return -1;
    }

    /* Calculate base offset for file data (after VFS header and file table) */
    size_t vfs_metadata_size = sizeof(vfs_header_t) + (sizeof(vfs_file_entry_t) * VFS_MAX_FILES);
    uint64_t base_offset = vfs_metadata_size;

    /* Find free space using best-fit gap allocation */
    uint64_t offset = base_offset;
    uint64_t best_gap_start = UINT64_MAX;
    uint64_t best_gap_size = 0;
    
    /* Sort files by offset for gap analysis */
    vfs_file_entry_t sorted_files[VFS_MAX_FILES];
    memcpy(sorted_files, ctx->files, sizeof(vfs_file_entry_t) * ctx->header.file_count);
    
    /* Simple bubble sort by offset (small array, acceptable performance) */
    for (uint32_t i = 0; i + 1 < ctx->header.file_count; i++) {
        for (uint32_t j = 0; j + 1 < ctx->header.file_count - i; j++) {
            if (sorted_files[j].offset > sorted_files[j + 1].offset) {
                vfs_file_entry_t temp = sorted_files[j];
                sorted_files[j] = sorted_files[j + 1];
                sorted_files[j + 1] = temp;
            }
        }
    }
    
    /* data_end: end of the usable user-data area, sector-aligned.
     * Consistent with the sector-based space check already done above. */
    uint64_t data_end = base_offset
                      + (uint64_t)ctx->header.total_sectors * VFS_SECTOR_SIZE;

    /* Find gaps between files */
    uint64_t current_pos = base_offset;
    for (uint32_t i = 0; i < ctx->header.file_count; i++) {
        uint64_t file_start = sorted_files[i].offset;
        uint64_t file_end = file_start + (sorted_files[i].sectors * VFS_SECTOR_SIZE);
        
        /* Check for gap before this file */
        if (file_start > current_pos) {
            uint64_t gap_size = file_start - current_pos;
            if (gap_size >= size && (best_gap_size == 0 || gap_size < best_gap_size)) {
                best_gap_start = current_pos;
                best_gap_size = gap_size;
            }
        }
        
        /* Update current position */
        if (file_end > current_pos) {
            current_pos = file_end;
        }
    }
    
    /* Check gap after last file */
    if (current_pos < data_end) {
        uint64_t gap_size = data_end - current_pos;
        if (gap_size >= size && (best_gap_size == 0 || gap_size < best_gap_size)) {
            best_gap_start = current_pos;
            best_gap_size = gap_size;
        }
    }
    
    /* Use best gap if found, otherwise append at end */
    if (best_gap_start != UINT64_MAX) {
        offset = best_gap_start;
    } else {
        offset = current_pos;
    }

    /* Check if data fits */
    if (offset + size > data_end) {
        return -1;
    }

    /* Copy data to volume through cache */
    if (vfs_write_data(ctx, offset, data, size) != 0) {
        return -1;
    }

    /* Add file entry */
    uint32_t idx = ctx->header.file_count;
    strncpy(ctx->files[idx].filename, filename, VFS_MAX_FILENAME_LEN - 1);
    ctx->files[idx].filename[VFS_MAX_FILENAME_LEN - 1] = '\0';
    ctx->files[idx].offset = offset;
    ctx->files[idx].size = size;
    ctx->files[idx].sectors = sectors_needed;
    ctx->files[idx].created = time(NULL);
    ctx->files[idx].modified = time(NULL);
    ctx->files[idx].flags = 0;
    ctx->files[idx].reserved = 0;

    ctx->header.file_count++;
    ctx->header.used_sectors += sectors_needed;

    return 0;
}

/* Get a file from the volume */
int vfs_get_file(vfs_context_t *ctx, const char *filename,
                 uint8_t *data, size_t *size) {
    if (!ctx->is_mounted) return -1;

    int idx = vfs_find_file(ctx, filename);
    if (idx < 0) return -1;

    uint8_t *temp_buffer = malloc(ctx->files[idx].size);
    if (!temp_buffer) {
        return -1;
    }

    if (vfs_read_data(ctx, ctx->files[idx].offset, temp_buffer, ctx->files[idx].size) != 0) {
        free(temp_buffer);
        return -1;
    }

    if (ctx->files[idx].size > *size) {
        free(temp_buffer);
        return -1;
    }

    memcpy(data, temp_buffer, ctx->files[idx].size);
    *size = ctx->files[idx].size;
    free(temp_buffer);

    return 0;
}

/* Delete a file from the volume */
int vfs_delete_file(vfs_context_t *ctx, const char *filename) {
    if (!ctx->is_mounted) return -1;

    int idx = vfs_find_file(ctx, filename);
    if (idx < 0) return -1;

    /* Securely wipe file data from cache */
    uint64_t file_offset = ctx->files[idx].offset;
    size_t file_size = ctx->files[idx].size;
    
    /* Create zero buffer for wiping */
    uint8_t *zero_buffer = calloc(1, file_size);
    if (!zero_buffer) {
        return -1;
    }
    
    int wipe_ok = (vfs_write_data(ctx, file_offset, zero_buffer, file_size) == 0);
    free(zero_buffer);

    if (!wipe_ok) {
        /* Secure wipe failed — refuse to remove the file entry.
         * Removing the entry without wiping would leave raw ciphertext
         * of the deleted file sitting in unallocated space on disk. */
        return -1;
    }

    /* Force flush of wiped sectors to disk before updating the file table */
    if (ctx->cache) {
        uint64_t start_sector = file_offset / VFS_SECTOR_SIZE;
        uint64_t end_sector   = (file_offset + file_size + VFS_SECTOR_SIZE - 1) / VFS_SECTOR_SIZE;
        for (uint64_t sector = start_sector; sector < end_sector; sector++) {
            cache_flush_sector(ctx->cache, sector);
        }
    }

    /* Safe to free sectors now that wipe is confirmed on disk */
    ctx->header.used_sectors -= ctx->files[idx].sectors;

    /* Shift remaining files */
    for (uint32_t i = idx; i < ctx->header.file_count - 1; i++) {
        memcpy(&ctx->files[i], &ctx->files[i + 1], sizeof(vfs_file_entry_t));
    }

    /* Clear last entry */
    memset(&ctx->files[ctx->header.file_count - 1], 0, sizeof(vfs_file_entry_t));
    ctx->header.file_count--;

    /* Note: Gaps from deleted files are now reused by the allocation algorithm */
    /* Files are placed using best-fit gap allocation to minimize fragmentation */

    return 0;
}

/* List all files in the volume */
int vfs_list_files(vfs_context_t *ctx, vfs_file_entry_t *entries, int *count) {
    if (!ctx->is_mounted) return -1;

    int max_entries = *count;
    *count = ctx->header.file_count;

    if (entries && max_entries > 0) {
        uint32_t file_count = ctx->header.file_count;
        uint32_t to_copy = (file_count < (uint32_t)max_entries) ? 
                          file_count : (uint32_t)max_entries;
        memcpy(entries, ctx->files, to_copy * sizeof(vfs_file_entry_t));
    }

    return 0;
}

/* Read data through cache */
int vfs_read_data(vfs_context_t *ctx, uint64_t offset, uint8_t *buffer, size_t size) {
    if (!ctx->is_mounted || !ctx->cache || !buffer) {
        return -1;
    }

    if (offset + size > ctx->data_size) {
        return -1;
    }

    size_t bytes_read = 0;
    while (bytes_read < size) {
        uint64_t current_offset = offset + bytes_read;
        uint64_t sector_idx = current_offset / VFS_SECTOR_SIZE;
        size_t sector_offset = current_offset % VFS_SECTOR_SIZE;
        size_t bytes_to_copy = VFS_SECTOR_SIZE - sector_offset;
        
        if (bytes_to_copy > size - bytes_read) {
            bytes_to_copy = size - bytes_read;
        }

        uint8_t *sector_data;
        if (cache_get_sector(ctx->cache, sector_idx, &sector_data) != 0) {
            return -1;
        }

        memcpy(buffer + bytes_read, sector_data + sector_offset, bytes_to_copy);
        bytes_read += bytes_to_copy;
    }

    return 0;
}

/* Write data through cache */
int vfs_write_data(vfs_context_t *ctx, uint64_t offset, const uint8_t *buffer, size_t size) {
    if (!ctx->is_mounted || !ctx->cache || !buffer) {
        return -1;
    }

    if (offset + size > ctx->data_size) {
        return -1;
    }

    size_t bytes_written = 0;
    while (bytes_written < size) {
        uint64_t current_offset = offset + bytes_written;
        uint64_t sector_idx = current_offset / VFS_SECTOR_SIZE;
        size_t sector_offset = current_offset % VFS_SECTOR_SIZE;
        size_t bytes_to_copy = VFS_SECTOR_SIZE - sector_offset;
        
        if (bytes_to_copy > size - bytes_written) {
            bytes_to_copy = size - bytes_written;
        }

        uint8_t *sector_data;
        if (cache_get_sector(ctx->cache, sector_idx, &sector_data) != 0) {
            return -1;
        }

        memcpy(sector_data + sector_offset, buffer + bytes_written, bytes_to_copy);
        
        if (cache_mark_dirty(ctx->cache, sector_idx) != 0) {
            return -1;
        }

        bytes_written += bytes_to_copy;
    }

    return 0;
}

/* vfs_create_empty_file */
int vfs_create_empty_file(vfs_context_t *ctx, const char *filename) {
    return vfs_add_file(ctx, filename, (const uint8_t *)"", 0);
}

/* vfs_rename_file */
int vfs_rename_file(vfs_context_t *ctx, const char *old_name, const char *new_name) {
    if (!ctx->is_mounted) return -1;
    int idx = vfs_find_file(ctx, old_name);
    if (idx < 0) return -1;
    if (vfs_find_file(ctx, new_name) >= 0) {
        vfs_delete_file(ctx, new_name);
        idx = vfs_find_file(ctx, old_name); /* Re-find since index may shift */
        if (idx < 0) return -1;
    }
    
    strncpy(ctx->files[idx].filename, new_name, VFS_MAX_FILENAME_LEN - 1);
    ctx->files[idx].filename[VFS_MAX_FILENAME_LEN - 1] = '\0';
    ctx->files[idx].modified = time(NULL);
    return 0;
}

/* vfs_update_timestamps */
int vfs_update_timestamps(vfs_context_t *ctx, const char *filename, time_t created, time_t modified) {
    if (!ctx->is_mounted) return -1;
    int idx = vfs_find_file(ctx, filename);
    if (idx < 0) return -1;
    
    ctx->files[idx].created = created;
    ctx->files[idx].modified = modified;
    return 0;
}

/* vfs_resize_file */
int vfs_resize_file(vfs_context_t *ctx, const char *filename, size_t new_size) {
    if (!ctx->is_mounted) return -1;
    int idx = vfs_find_file(ctx, filename);
    if (idx < 0) return -1;

    size_t old_size = ctx->files[idx].size;
    if (new_size == old_size) return 0;
    
    size_t new_sectors = (new_size + VFS_SECTOR_SIZE - 1) / VFS_SECTOR_SIZE;
    if (new_size == 0) new_sectors = 0;
    size_t old_sectors = ctx->files[idx].sectors;

    if (new_sectors <= old_sectors) {
        /* Shrinking or staying within allocated sectors */
        if (new_size < old_size) {
            /* Zero out the remaining part of the file to securely delete data */
            size_t bytes_to_wipe = old_size - new_size;
            uint8_t *zeros = calloc(1, 4096);
            if (zeros) {
                size_t wiped = 0;
                while (wiped < bytes_to_wipe) {
                    size_t chunk = bytes_to_wipe - wiped;
                    if (chunk > 4096) chunk = 4096;
                    vfs_write_data(ctx, ctx->files[idx].offset + new_size + wiped, zeros, chunk);
                    wiped += chunk;
                }
                free(zeros);
            }
        }
        
        ctx->header.used_sectors -= (old_sectors - new_sectors);
        ctx->files[idx].size = new_size;
        ctx->files[idx].sectors = new_sectors;
        ctx->files[idx].modified = time(NULL);
        return 0;
    }

    /* Expanding, need more sectors */
    size_t additional_sectors = new_sectors - old_sectors;
    if (ctx->header.used_sectors + additional_sectors > ctx->header.total_sectors) {
        return -1; /* Not enough space */
    }

    /* Check if we can expand in place (contiguous free space after file) */
    uint64_t file_end_offset = ctx->files[idx].offset + old_sectors * VFS_SECTOR_SIZE;
    uint64_t next_file_offset = UINT64_MAX;
    
    size_t vfs_metadata_size = sizeof(vfs_header_t) + (sizeof(vfs_file_entry_t) * VFS_MAX_FILES);
    uint64_t data_end = vfs_metadata_size + (uint64_t)ctx->header.total_sectors * VFS_SECTOR_SIZE;

    for (uint32_t i = 0; i < ctx->header.file_count; i++) {
        if (i == (uint32_t)idx) continue;
        if (ctx->files[i].offset >= file_end_offset) {
            if (ctx->files[i].offset < next_file_offset) {
                next_file_offset = ctx->files[i].offset;
            }
        }
    }
    
    if (next_file_offset == UINT64_MAX) {
        next_file_offset = data_end;
    }

    uint64_t available_contiguous_bytes = next_file_offset - file_end_offset;
    if (available_contiguous_bytes >= additional_sectors * VFS_SECTOR_SIZE) {
        /* Can expand in place */
        ctx->header.used_sectors += additional_sectors;
        ctx->files[idx].size = new_size;
        ctx->files[idx].sectors = new_sectors;
        ctx->files[idx].modified = time(NULL);
        
        /* Zero out the new expanded gap */
        size_t gap = new_size - old_size;
        if (gap > 0) {
            uint8_t *zeros = calloc(1, 4096);
            if (zeros) {
                size_t written = 0;
                while (written < gap) {
                    size_t chunk = gap - written;
                    if (chunk > 4096) chunk = 4096;
                    vfs_write_data(ctx, ctx->files[idx].offset + old_size + written, zeros, chunk);
                    written += chunk;
                }
                free(zeros);
            }
        }
        return 0;
    }

    /* Cannot expand in place. Must relocate the file. */
    /* Find a gap large enough for new_sectors */
    uint64_t best_gap_start = UINT64_MAX;
    uint64_t best_gap_size = 0;

    vfs_file_entry_t sorted_files[VFS_MAX_FILES];
    memcpy(sorted_files, ctx->files, sizeof(vfs_file_entry_t) * ctx->header.file_count);
    
    for (uint32_t i = 0; i + 1 < ctx->header.file_count; i++) {
        for (uint32_t j = 0; j + 1 < ctx->header.file_count - i; j++) {
            if (sorted_files[j].offset > sorted_files[j + 1].offset) {
                vfs_file_entry_t temp = sorted_files[j];
                sorted_files[j] = sorted_files[j + 1];
                sorted_files[j + 1] = temp;
            }
        }
    }

    uint64_t current_pos = vfs_metadata_size;
    for (uint32_t i = 0; i < ctx->header.file_count; i++) {
        uint32_t orig_idx = 0;
        for (uint32_t k = 0; k < ctx->header.file_count; k++) {
            if (ctx->files[k].offset == sorted_files[i].offset) {
                orig_idx = k; break;
            }
        }
        
        uint64_t file_start = sorted_files[i].offset;
        uint64_t file_end = file_start + (sorted_files[i].sectors * VFS_SECTOR_SIZE);
        
        if (orig_idx == (uint32_t)idx) {
            /* Treat old allocation as free space for gap analysis */
            continue;
        }

        if (file_start > current_pos) {
            uint64_t gap_size = file_start - current_pos;
            if (gap_size >= new_sectors * VFS_SECTOR_SIZE && (best_gap_size == 0 || gap_size < best_gap_size)) {
                best_gap_start = current_pos;
                best_gap_size = gap_size;
            }
        }
        
        if (file_end > current_pos) {
            current_pos = file_end;
        }
    }

    if (current_pos < data_end) {
        uint64_t gap_size = data_end - current_pos;
        if (gap_size >= new_sectors * VFS_SECTOR_SIZE && (best_gap_size == 0 || gap_size < best_gap_size)) {
            best_gap_start = current_pos;
            best_gap_size = gap_size;
        }
    }

    if (best_gap_start == UINT64_MAX) {
        return -1; /* Space is heavily fragmented or full, relocation failed */
    }

    /* Found a new gap. Relocate data. */
    uint64_t new_offset = best_gap_start;
    
    /* Copy existing data to new offset */
    uint8_t *copy_buf = malloc(old_size);
    if (!copy_buf) return -1;
    
    if (old_size > 0) {
        if (vfs_read_data(ctx, ctx->files[idx].offset, copy_buf, old_size) != 0) {
            free(copy_buf);
            return -1;
        }
        if (vfs_write_data(ctx, new_offset, copy_buf, old_size) != 0) {
            free(copy_buf);
            return -1;
        }
    }
    
    /* Securely wipe old sectors */
    if (old_size > 0) {
        memset(copy_buf, 0, old_size);
        vfs_write_data(ctx, ctx->files[idx].offset, copy_buf, old_size);
        /* Force flush of wiped sectors */
        if (ctx->cache) {
            uint64_t start_sector = ctx->files[idx].offset / VFS_SECTOR_SIZE;
            uint64_t end_sector = start_sector + old_sectors;
            for (uint64_t s = start_sector; s < end_sector; s++) {
                cache_flush_sector(ctx->cache, s);
            }
        }
    }
    free(copy_buf);

    /* Update entry */
    ctx->header.used_sectors += additional_sectors;
    ctx->files[idx].offset = new_offset;
    ctx->files[idx].size = new_size;
    ctx->files[idx].sectors = new_sectors;
    ctx->files[idx].modified = time(NULL);

    /* Zero out the new expanded gap */
    size_t gap = new_size - old_size;
    if (gap > 0) {
        uint8_t *zeros = calloc(1, 4096);
        if (zeros) {
            size_t written = 0;
            while (written < gap) {
                size_t chunk = gap - written;
                if (chunk > 4096) chunk = 4096;
                vfs_write_data(ctx, ctx->files[idx].offset + old_size + written, zeros, chunk);
                written += chunk;
            }
            free(zeros);
        }
    }

    return 0;
}
