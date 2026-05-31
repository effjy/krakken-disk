/* vfs_create_empty_file */
int vfs_create_empty_file(vfs_context_t *ctx, const char *filename) {
    return vfs_add_file(ctx, filename, (const uint8_t *)"", 0);
}

/* vfs_rename_file */
int vfs_rename_file(vfs_context_t *ctx, const char *old_name, const char *new_name) {
    if (!ctx->is_mounted) return -1;
    int idx = vfs_find_file(ctx, old_name);
    if (idx < 0) return -1;
    if (vfs_find_file(ctx, new_name) >= 0) return -1; /* New name exists */
    
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

    return 0;
}
