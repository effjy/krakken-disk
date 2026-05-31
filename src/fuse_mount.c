#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <fuse3/fuse_opt.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fuse_mount.h"

static volume_context_t *g_vol = NULL;
static struct fuse *g_fuse = NULL;
static pthread_t g_fuse_thread;
static int g_fuse_thread_started = 0;
static char g_mountpoint[1024] = {0};

struct fuse_thread_data {
    struct fuse_args args;
    char mountpoint[1024];
};

static int tsuki_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));
    
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    
    int idx = vfs_find_file(&g_vol->vfs, path + 1);
    if (idx < 0) return -ENOENT;
    
    stbuf->st_mode = S_IFREG | 0666;
    stbuf->st_nlink = 1;
    stbuf->st_size = g_vol->vfs.files[idx].size;
    stbuf->st_mtime = g_vol->vfs.files[idx].modified;
    stbuf->st_ctime = g_vol->vfs.files[idx].created;
    stbuf->st_atime = g_vol->vfs.files[idx].modified;
    
    return 0;
}

static int tsuki_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t offset, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    if (strcmp(path, "/") != 0) return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    for (uint32_t i = 0; i < g_vol->vfs.header.file_count; i++) {
        filler(buf, g_vol->vfs.files[i].filename, NULL, 0, 0);
    }

    return 0;
}

static int tsuki_open(const char *path, struct fuse_file_info *fi) {
    (void)fi;
    if (vfs_find_file(&g_vol->vfs, path + 1) < 0) {
        return -ENOENT;
    }
    return 0;
}

static int tsuki_read(const char *path, char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void) fi;
    int idx = vfs_find_file(&g_vol->vfs, path + 1);
    if (idx < 0) return -ENOENT;
    
    size_t file_size = g_vol->vfs.files[idx].size;
    if (offset < 0) return 0;
    if ((size_t)offset >= file_size) return 0;
    if ((size_t)offset + size > file_size) size = file_size - (size_t)offset;
    
    uint64_t file_offset = g_vol->vfs.files[idx].offset;
    if (vfs_read_data(&g_vol->vfs, file_offset + offset, (uint8_t *)buf, size) != 0) {
        return -EIO;
    }
    
    return size;
}

static int tsuki_write(const char *path, const char *buf, size_t size,
                       off_t offset, struct fuse_file_info *fi) {
    (void) fi;
    int idx = vfs_find_file(&g_vol->vfs, path + 1);
    if (idx < 0) return -ENOENT;
    
    size_t file_size = g_vol->vfs.files[idx].size;
    if (offset + size > file_size) {
        if (vfs_resize_file(&g_vol->vfs, path + 1, offset + size) != 0) {
            return -ENOSPC;
        }
        idx = vfs_find_file(&g_vol->vfs, path + 1);
    }
    
    uint64_t file_offset = g_vol->vfs.files[idx].offset;
    if (vfs_write_data(&g_vol->vfs, file_offset + offset, (const uint8_t *)buf, size) != 0) {
        return -EIO;
    }
    
    return size;
}

static int tsuki_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void)fi;
    if (vfs_resize_file(&g_vol->vfs, path + 1, size) != 0) return -ENOSPC;
    return 0;
}

static int tsuki_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode;
    (void)fi;
    if (strlen(path + 1) >= VFS_MAX_FILENAME_LEN) return -ENAMETOOLONG;
    if (vfs_create_empty_file(&g_vol->vfs, path + 1) != 0) return -ENOSPC;
    return 0;
}

static int tsuki_unlink(const char *path) {
    if (vfs_delete_file(&g_vol->vfs, path + 1) != 0) return -ENOENT;
    return 0;
}

static int tsuki_rename(const char *from, const char *to, unsigned int flags) {
    if (flags) return -EINVAL;
    if (strlen(to + 1) >= VFS_MAX_FILENAME_LEN) return -ENAMETOOLONG;
    if (vfs_rename_file(&g_vol->vfs, from + 1, to + 1) != 0) return -ENOENT;
    return 0;
}

static int tsuki_utimens(const char *path, const struct timespec tv[2], struct fuse_file_info *fi) {
    (void)fi;
    if (vfs_update_timestamps(&g_vol->vfs, path + 1, tv[0].tv_sec, tv[1].tv_sec) != 0) return -ENOENT;
    return 0;
}

static int tsuki_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)path; (void)mode; (void)fi;
    return 0;
}

static int tsuki_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    (void)path; (void)uid; (void)gid; (void)fi;
    return 0;
}

static const struct fuse_operations tsuki_oper = {
    .getattr    = tsuki_getattr,
    .readdir    = tsuki_readdir,
    .open       = tsuki_open,
    .read       = tsuki_read,
    .write      = tsuki_write,
    .truncate   = tsuki_truncate,
    .create     = tsuki_create,
    .unlink     = tsuki_unlink,
    .rename     = tsuki_rename,
    .utimens    = tsuki_utimens,
    .chmod      = tsuki_chmod,
    .chown      = tsuki_chown,
};

static void *fuse_thread_func(void *arg) {
    struct fuse_thread_data *tdata = (struct fuse_thread_data *)arg;
    
    if (fuse_mount(g_fuse, tdata->mountpoint) == 0) {
        fuse_loop(g_fuse); /* Use single-threaded loop for thread safety */
        fuse_unmount(g_fuse);
    }
    
    fuse_opt_free_args(&tdata->args);
    free(tdata);
    return NULL;
}

int start_fuse_mount(volume_context_t *vol, const char *mountpoint) {
    g_vol = vol;
    
    strncpy(g_mountpoint, mountpoint, sizeof(g_mountpoint) - 1);
    g_mountpoint[sizeof(g_mountpoint) - 1] = '\0';
    
    struct fuse_thread_data *tdata = calloc(1, sizeof(struct fuse_thread_data));
    tdata->args = (struct fuse_args)FUSE_ARGS_INIT(0, NULL);
    strncpy(tdata->mountpoint, mountpoint, sizeof(tdata->mountpoint) - 1);
    
    fuse_opt_add_arg(&tdata->args, "krakken-disk");
    
    g_fuse = fuse_new(&tdata->args, &tsuki_oper, sizeof(tsuki_oper), NULL);
    if (!g_fuse) {
        fuse_opt_free_args(&tdata->args);
        free(tdata);
        return -1;
    }
    
    if (pthread_create(&g_fuse_thread, NULL, fuse_thread_func, tdata) != 0) {
        fuse_destroy(g_fuse);
        g_fuse = NULL;
        fuse_opt_free_args(&tdata->args);
        free(tdata);
        return -1;
    }
    
    g_fuse_thread_started = 1;
    return 0;
}

int stop_fuse_mount(volume_context_t *vol) {
    (void)vol;
    if (g_fuse_thread_started) {
        if (g_fuse) {
            fuse_exit(g_fuse);
        }
        
        if (g_mountpoint[0] != '\0') {
            char cmd[2048];
            snprintf(cmd, sizeof(cmd), "fusermount3 -q -u \"%s\"", g_mountpoint);
            int ret = system(cmd);
            (void)ret;
            g_mountpoint[0] = '\0';
        }
        
        pthread_join(g_fuse_thread, NULL);
        
        if (g_fuse) {
            fuse_destroy(g_fuse);
            g_fuse = NULL;
        }
        g_fuse_thread_started = 0;
    }
    return 0;
}
