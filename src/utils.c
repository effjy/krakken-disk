#include "utils.h"
#include <sodium.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>

static int mlock_available = 1;

void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) *p++ = 0;
    __asm__ __volatile__("" ::: "memory");
}

int lock_sensitive(void *ptr, size_t len) {
    if (!mlock_available) return -1;
    if (sodium_mlock(ptr, len) != 0) { 
        mlock_available = 0; 
        return -1; 
    }
#ifdef MADV_DONTDUMP
    madvise(ptr, len, MADV_DONTDUMP);
#endif
#ifdef MADV_WIPEONFORK
    madvise(ptr, len, MADV_WIPEONFORK);
#endif
    return 0;
}

int ct_memcmp(const void *a, const void *b, size_t n) {
    const volatile uint8_t *pa = a, *pb = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= pa[i] ^ pb[i];
    return diff;
}

void random_bytes(uint8_t *buf, size_t len) {
    randombytes_buf(buf, len);
}

int secure_shred_file(const char *path) {
    FILE *f = fopen(path, "rb+");
    if (!f) return -1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t *buf = malloc(65536);
    if (!buf) {
        fclose(f);
        return -1;
    }
    
    /* Three-pass overwrite: zeros, ones, random */
    for (int pass = 0; pass < 3; pass++) {
        fseek(f, 0, SEEK_SET);
        long remaining = size;
        while (remaining > 0) {
            size_t chunk = (remaining > 65536) ? 65536 : remaining;
            if (pass == 0) memset(buf, 0, chunk);
            else if (pass == 1) memset(buf, 0xFF, chunk);
            else random_bytes(buf, chunk);
            fwrite(buf, 1, chunk, f);
            remaining -= chunk;
        }
        fflush(f);
        fsync(fileno(f));
    }
    
    free(buf);
    fclose(f);
    return 0;
}

int check_swap_security(void) {
    FILE *swaps = fopen("/proc/swaps", "r");
    if (!swaps) return 0; /* Can't check, assume safe */
    
    char line[512];
    int has_unencrypted_swap = 0;
    
    /* Skip header line */
    if (fgets(line, sizeof(line), swaps)) {
        /* Process each swap entry */
        while (fgets(line, sizeof(line), swaps)) {
            char device[256], type[64], size[64], used[64], priority[64];
            if (sscanf(line, "%255s %63s %63s %63s %63s", 
                      device, type, size, used, priority) == 5) {
                /* Check if it's a partition (not a file) and not encrypted */
                if (strncmp(device, "/dev/", 5) == 0 && 
                    strstr(device, "crypt") == NULL) {
                    has_unencrypted_swap = 1;
                    break;
                }
            }
        }
    }
    
    fclose(swaps);
    return has_unencrypted_swap ? 1 : 0;
}
