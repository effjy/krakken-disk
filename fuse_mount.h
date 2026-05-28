#ifndef FUSE_MOUNT_H
#define FUSE_MOUNT_H

#include "volume.h"

/* Starts FUSE mount in a background thread.
 * Returns 0 on success, -1 on failure. */
int start_fuse_mount(volume_context_t *vol, const char *mountpoint);

/* Stops FUSE mount and joins the background thread.
 * Returns 0 on success, -1 on failure. */
int stop_fuse_mount(volume_context_t *vol);

#endif /* FUSE_MOUNT_H */
