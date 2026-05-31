#ifndef VOLUME_H
#define VOLUME_H

#include <stdint.h>
#include <stddef.h>
#include "config.h"
#include "vfs.h"

/* Volume context - combines VFS with encryption */
typedef struct {
    vfs_context_t vfs;
    char path[512];
    FILE *file_handle;  /* File handle for cache operations */
    uint8_t master_key[KEY_SIZE];
    uint8_t file_key[KEY_SIZE];
    int is_open;
    int is_mounted;
} volume_context_t;

/* Progress callback type */
typedef void (*progress_callback_t)(const char *label, size_t cur, size_t total, void *user_data);

/* Volume operations */
int volume_create(const char *path, size_t size_mb, const char *password,
                  progress_callback_t progress_cb, void *user_data);
int volume_open(const char *path, const char *password, volume_context_t *vol, 
                progress_callback_t progress_cb, void *user_data);
int volume_close(volume_context_t *vol, progress_callback_t progress_cb, void *user_data);
int volume_mount(volume_context_t *vol);
int volume_unmount(volume_context_t *vol);

#endif /* VOLUME_H */
