/*
 * aead.c — Tsuki-Disk parallel AEAD encrypt / decrypt
 *
 * Encryption model:
 *   The file is split into fixed-size segments (ENCRYPT_SEGMENT_SIZE = 4 MB).
 *   Each segment i has its own independent keystream derived as:
 *
 *       keystream_i = Tsuki-Sponge(key || nonce || LE64(i)) → squeeze(segment_len)
 *
 *   Because segment indices are distinct, all segments are fully independent
 *   and can be processed in parallel using one thread per segment.
 *   The number of threads is taken from the TSUKI_THREADS environment variable
 *   (default: number of online CPUs, capped at ENCRYPT_MAX_THREADS = 8).
 *
 * Wire format (incompatible with v1 sequential sponge):
 *   [nonce  12 B]
 *   [ciphertext  N * segment_size  B  (last segment may be shorter)]
 *   [BLAKE2b-256 tag  32 B  over nonce || ciphertext]
 *
 * Authentication:
 *   A BLAKE2b-256 MAC keyed with the file key is computed over:
 *   nonce || ciphertext
 *   The tag is written after the ciphertext and verified before any plaintext
 *   is made available to the caller.  Decryption output is written to a
 *   RAM-backed temp file and atomically renamed only after tag verification.
 *
 * Thread safety:
 *   Each worker thread owns its sponge state entirely on its stack.
 *   The shared io_buf / ct_buf are partitioned into disjoint slices — one per
 *   thread — so no locks are needed during the encryption/decryption loop.
 */

#define _POSIX_C_SOURCE 200809L

#include "aead.h"
#include "config.h"
#include "permut2048.h"
#include "utils.h"

#include <sodium.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* =========================================================================
 * Parallel encryption constants
 * ========================================================================= */

#define ENCRYPT_SEGMENT_SIZE  (4 * 1024 * 1024)   /* 4 MB per thread */
#define ENCRYPT_MAX_THREADS   8

/* =========================================================================
 * Helpers
 * ========================================================================= */

/* Little-endian 64-bit store (portable) */
static void store_le64(uint8_t p[8], uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

static int get_n_threads(void) {
    const char *e = getenv("TSUKI_THREADS");
    if (e && *e) {
        int v = atoi(e);
        if (v >= 1 && v <= ENCRYPT_MAX_THREADS) return v;
    }
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n <= 0) return 4;
    if (n > ENCRYPT_MAX_THREADS) return ENCRYPT_MAX_THREADS;
    return (int)n;
}

/* Verify directory is RAM-backed (tmpfs) */
static int is_tmpfs(const char *path) {
    if (strstr(path, "/dev/shm")) return 1;
    FILE *m = fopen("/proc/mounts", "r");
    if (!m) return 0;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), m)) {
        char mp[512], ft[64];
        if (sscanf(line, "%*s %511s %63s", mp, ft) == 2)
            if (strcmp(mp, path) == 0 && strcmp(ft, "tmpfs") == 0)
                { found = 1; break; }
    }
    fclose(m);
    return found;
}

/* Copy a file by reading src and writing dst in 64KB chunks.
 * Returns 0 on success, -1 on any I/O error. */
static int copy_file(const char *src, const char *dst) {
    FILE *in  = fopen(src, "rb");
    FILE *out = fopen(dst, "wb");
    if (!in || !out) {
        if (in)  fclose(in);
        if (out) fclose(out);
        return -1;
    }
    uint8_t *buf = malloc(65536);
    if (!buf) { fclose(in); fclose(out); return -1; }
    int ret = 0;
    size_t n;
    while ((n = fread(buf, 1, 65536, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { ret = -1; break; }
    }
    if (ferror(in)) ret = -1;
    free(buf);
    fclose(in);
    if (fclose(out) != 0) ret = -1; /* flush errors show up here */
    return ret;
}

/* Three-pass file shred */
static void secure_shred(const char *path) {
    FILE *f = fopen(path, "rb+");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(65536);
    if (!buf) { fclose(f); return; }
    for (int pass = 0; pass < 3; pass++) {
        fseek(f, 0, SEEK_SET);
        long rem = sz;
        while (rem > 0) {
            size_t c = (rem > 65536) ? 65536 : (size_t)rem;
            if (pass == 0) memset(buf, 0x00, c);
            else if (pass == 1) memset(buf, 0xFF, c);
            else random_bytes(buf, c);
            fwrite(buf, 1, c, f);
            rem -= (long)c;
        }
        fflush(f);
    }
    free(buf);
    fclose(f);
}

/* =========================================================================
 * Segment worker
 *
 * Each thread runs this function for one segment of ENCRYPT_SEGMENT_SIZE
 * (or less for the final segment).  It derives an independent keystream from
 * key || nonce || LE64(seg_idx), squeezes it into out[], then XORs with in[].
 * All state is on the thread stack — no heap allocation, no shared mutation.
 * ========================================================================= */

typedef struct {
    const uint8_t *key;
    size_t         key_len;
    const uint8_t  nonce[NONCE_SIZE];
    uint64_t       seg_idx;     /* global segment counter */
    const uint8_t *in;          /* slice of io_buf  (read-only) */
    uint8_t       *out;         /* slice of ct_buf  (write-only, disjoint) */
    size_t         len;         /* bytes in this segment */
    int            use_parallel_mac;
    int            is_decrypt;
    uint8_t        mac[TAG_SIZE];
} seg_worker_t;

static void *seg_worker(void *arg) {
    seg_worker_t *w = arg;

    /* Set up a fresh sponge seeded with key || nonce || segment-index.
     * This sponge is entirely local to this thread — zero sharing. */
    permut2048_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rate = PERMUT2048_RATE;

    uint8_t idx[8];
    store_le64(idx, w->seg_idx);

    permut2048_absorb(&ctx, w->key,   w->key_len);
    permut2048_absorb(&ctx, w->nonce, NONCE_SIZE);
    permut2048_absorb(&ctx, idx,      8);
    if (w->use_parallel_mac) {
        permut2048_absorb(&ctx, (const uint8_t*)"\x01", 1);
    }
    permut2048_finalize(&ctx);

    /* Squeeze keystream directly into out[], then XOR with in[].
     * permut2048_squeeze permutes the state internally every RATE bytes,
     * so the full segment is covered without any extra allocation. */
    permut2048_squeeze(&ctx, w->out, w->len);
    for (size_t i = 0; i < w->len; i++)
        w->out[i] ^= w->in[i];

    /* Parallel MAC: Hash the ciphertext.
     * Encrypting: w->out is the ciphertext.
     * Decrypting: w->in is the ciphertext. */
    if (w->use_parallel_mac) {
        crypto_generichash_state st;
        crypto_generichash_init(&st, w->key, w->key_len, TAG_SIZE);
        crypto_generichash_update(&st, w->nonce, NONCE_SIZE);
        crypto_generichash_update(&st, idx, 8);
        if (w->is_decrypt) {
            crypto_generichash_update(&st, w->in, w->len);
        } else {
            crypto_generichash_update(&st, w->out, w->len);
        }
        crypto_generichash_final(&st, w->mac, TAG_SIZE);
    }

    /* Wipe sponge state off the stack */
    volatile uint8_t *vp = (volatile uint8_t *)&ctx;
    for (size_t i = 0; i < sizeof(ctx); i++) vp[i] = 0;
    return NULL;
}

/* =========================================================================
 * Parallel batch helper
 *
 * Processes one batch of `n_segs` contiguous segments.
 *   io   — input  buffer, partitioned as io  + t * ENCRYPT_SEGMENT_SIZE
 *   out  — output buffer, partitioned as out + t * ENCRYPT_SEGMENT_SIZE
 *   batch_len  — total bytes in this batch (sum of all segment lengths)
 *   seg_base   — global index of the first segment in this batch
 * ========================================================================= */
static int run_parallel_batch(seg_worker_t *workers, pthread_t *tids,
                               int n_segs) {
    for (int t = 0; t < n_segs; t++) {
        if (pthread_create(&tids[t], NULL, seg_worker, &workers[t]) != 0) {
            /* fall back: run remaining segments on this thread */
            for (int j = t; j < n_segs; j++) seg_worker(&workers[j]);
            /* join the threads that did start */
            for (int j = 0; j < t; j++) pthread_join(tids[j], NULL);
            return 0;
        }
    }
    for (int t = 0; t < n_segs; t++) pthread_join(tids[t], NULL);
    return 0;
}

/* =========================================================================
 * Encrypt stream
 * ========================================================================= */

int permut2048_aead_encrypt_stream(FILE *fout, const char *in_path,
                                    const uint8_t *key, size_t key_len,
                                    progress_callback_t progress_cb,
                                    void *user_data) {
    int n_threads = get_n_threads();
    size_t batch_size = (size_t)n_threads * ENCRYPT_SEGMENT_SIZE;

    FILE *fin = fopen(in_path, "rb");
    if (!fin) return -1;

    fseek(fin, 0, SEEK_END);
    size_t file_size = (size_t)ftell(fin);
    fseek(fin, 0, SEEK_SET);

    /* V3: Random Nonce */
    uint8_t nonce[NONCE_SIZE];
    random_bytes(nonce, NONCE_SIZE);
    fwrite(nonce, 1, NONCE_SIZE, fout);

    /* V3: Encrypted Magic */
    permut2048_ctx hdr_ctx;
    memset(&hdr_ctx, 0, sizeof(hdr_ctx));
    hdr_ctx.rate = PERMUT2048_RATE;
    uint8_t hdr_idx[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    permut2048_absorb(&hdr_ctx, key, key_len);
    permut2048_absorb(&hdr_ctx, nonce, NONCE_SIZE);
    permut2048_absorb(&hdr_ctx, hdr_idx, 8);
    permut2048_finalize(&hdr_ctx);
    
    uint8_t enc_magic[8];
    permut2048_squeeze(&hdr_ctx, enc_magic, 8);
    const uint8_t v3_magic[8] = "KRAKKEN3";
    for (int i = 0; i < 8; i++) enc_magic[i] ^= v3_magic[i];
    fwrite(enc_magic, 1, 8, fout);
    
    volatile uint8_t *vp = (volatile uint8_t *)&hdr_ctx;
    for (size_t i = 0; i < sizeof(hdr_ctx); i++) vp[i] = 0;

    /* MAC state (over nonce || encrypted_magic || ciphertext_MACs) */
    crypto_generichash_state mac;
    crypto_generichash_init(&mac, key, key_len, TAG_SIZE);
    crypto_generichash_update(&mac, nonce, NONCE_SIZE);
    crypto_generichash_update(&mac, enc_magic, 8);

    /* I/O buffers — one batch at a time */
    uint8_t *io_buf = malloc(batch_size);
    uint8_t *ct_buf = malloc(batch_size);
    if (!io_buf || !ct_buf) {
        free(io_buf); free(ct_buf); fclose(fin); return -1;
    }
    lock_sensitive(io_buf, batch_size);
    lock_sensitive(ct_buf, batch_size);

    seg_worker_t *workers = malloc((size_t)n_threads * sizeof(seg_worker_t));
    pthread_t    *tids    = malloc((size_t)n_threads * sizeof(pthread_t));
    if (!workers || !tids) {
        free(workers); free(tids);
        free(io_buf);  free(ct_buf);
        fclose(fin); return -1;
    }

    uint64_t seg_base  = 0;
    size_t   processed = 0;
    int      ret       = 0;

    while (processed < file_size) {
        size_t to_read = file_size - processed;
        if (to_read > batch_size) to_read = batch_size;

        size_t n_read = fread(io_buf, 1, to_read, fin);
        if (!n_read) { ret = -1; break; }

        /* Carve out per-thread segments */
        int n_segs = 0;
        size_t seg_off = 0;
        while (seg_off < n_read) {
            size_t seg_len = n_read - seg_off;
            if (seg_len > ENCRYPT_SEGMENT_SIZE) seg_len = ENCRYPT_SEGMENT_SIZE;

            workers[n_segs].key     = key;
            workers[n_segs].key_len = key_len;
            memcpy((void*)workers[n_segs].nonce, nonce, NONCE_SIZE);
            workers[n_segs].seg_idx = seg_base + (uint64_t)n_segs;
            workers[n_segs].in      = io_buf + seg_off;
            workers[n_segs].out     = ct_buf + seg_off;
            workers[n_segs].len     = seg_len;
            workers[n_segs].use_parallel_mac = 1;
            workers[n_segs].is_decrypt       = 0;

            seg_off += seg_len;
            n_segs++;
        }

        run_parallel_batch(workers, tids, n_segs);

        /* Write ciphertext and update MAC.
         * Check fwrite: a disk-full error here produces a truncated output
         * file that would fail authentication on decrypt. */
        if (fwrite(ct_buf, 1, n_read, fout) != n_read) { ret = -1; break; }
        for (int i = 0; i < n_segs; i++) {
            crypto_generichash_update(&mac, workers[i].mac, TAG_SIZE);
        }

        seg_base  += (uint64_t)n_segs;
        processed += n_read;

        if (progress_cb)
            progress_cb("Encrypting", processed, file_size, user_data);
    }

    /* Append authentication tag */
    uint8_t tag[TAG_SIZE];
    crypto_generichash_final(&mac, tag, TAG_SIZE);
    /* Check both the tag write and the final flush */
    if (fwrite(tag, 1, TAG_SIZE, fout) != TAG_SIZE) ret = -1;
    if (fflush(fout) != 0) ret = -1;

    secure_zero(io_buf, batch_size);
    secure_zero(ct_buf, batch_size);
    free(workers); free(tids);
    free(io_buf);  free(ct_buf);
    fclose(fin);
    return ret;
}

/* =========================================================================
 * Decrypt stream
 * ========================================================================= */

int permut2048_aead_decrypt_stream(FILE *fin, const char *out_path,
                                    const uint8_t *key, size_t key_len,
                                    progress_callback_t progress_cb,
                                    void *user_data) {
    int n_threads = get_n_threads();
    size_t batch_size = (size_t)n_threads * ENCRYPT_SEGMENT_SIZE;

    long original_start = ftell(fin);

    /* Check for V2, V3 or V1 */
    uint8_t magic_or_nonce[8];
    uint8_t nonce[NONCE_SIZE];
    uint8_t enc_magic[8];
    int is_v2 = 0;
    int is_v3 = 0;

    if (fread(magic_or_nonce, 1, 8, fin) != 8) return -1;
    
    if (memcmp(magic_or_nonce, "KRAKKEN1", 8) == 0) {
        /* V2 legacy format */
        is_v2 = 1;
        if (fread(nonce, 1, NONCE_SIZE, fin) != NONCE_SIZE) return -1;
    } else {
        /* Could be V1 or V3. Read 4 more bytes to complete a 12-byte nonce */
        uint8_t nonce_remainder[4];
        if (fread(nonce_remainder, 1, 4, fin) == 4) {
            memcpy(nonce, magic_or_nonce, 8);
            memcpy(nonce + 8, nonce_remainder, 4);
            
            /* Try to read 8 more bytes for V3 encrypted magic */
            if (fread(enc_magic, 1, 8, fin) == 8) {
                /* Test if it's V3 by decrypting enc_magic */
                permut2048_ctx hdr_ctx;
                memset(&hdr_ctx, 0, sizeof(hdr_ctx));
                hdr_ctx.rate = PERMUT2048_RATE;
                uint8_t hdr_idx[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
                permut2048_absorb(&hdr_ctx, key, key_len);
                permut2048_absorb(&hdr_ctx, nonce, NONCE_SIZE);
                permut2048_absorb(&hdr_ctx, hdr_idx, 8);
                permut2048_finalize(&hdr_ctx);
                
                uint8_t dec_magic[8];
                permut2048_squeeze(&hdr_ctx, dec_magic, 8);
                for (int i = 0; i < 8; i++) dec_magic[i] ^= enc_magic[i];
                
                volatile uint8_t *vp = (volatile uint8_t *)&hdr_ctx;
                for (size_t i = 0; i < sizeof(hdr_ctx); i++) vp[i] = 0;
                
                if (memcmp(dec_magic, "KRAKKEN3", 8) == 0) {
                    is_v3 = 1;
                }
            }
        }
        
        if (!is_v3) {
            /* Fallback to V1: The first 12 bytes are the nonce. Rewind. */
             fseek(fin, original_start + 12, SEEK_SET);
        }
    }

    long start_pos = ftell(fin);
    fseek(fin, 0, SEEK_END);
    long total = ftell(fin);
    fseek(fin, start_pos, SEEK_SET);
    if (total < start_pos + (long)TAG_SIZE) return -1;
    size_t cipher_len = (size_t)(total - start_pos - (long)TAG_SIZE);

    /* Secure temp file in RAM (tmpfs) */
    const char *tmpdir = getenv("TMPDIR");
    if (!tmpdir) tmpdir = "/dev/shm";
    if (!is_tmpfs(tmpdir)) {
        if (is_tmpfs("/dev/shm")) tmpdir = "/dev/shm";
        else                      tmpdir = "/tmp";
    }
    char tmp_path[PATH_MAX];
    snprintf(tmp_path, sizeof(tmp_path), "%s/krakken_decrypt_XXXXXX", tmpdir);
    int tmp_fd = mkstemp(tmp_path);
    if (tmp_fd == -1) return -1;
    FILE *ftmp = fdopen(tmp_fd, "wb");
    if (!ftmp) { close(tmp_fd); unlink(tmp_path); return -1; }

    /* I/O buffers */
    uint8_t *io_buf = malloc(batch_size);
    uint8_t *pt_buf = malloc(batch_size);
    if (!io_buf || !pt_buf) {
        free(io_buf); free(pt_buf);
        fclose(ftmp); secure_shred(tmp_path); unlink(tmp_path);
        return -1;
    }
    lock_sensitive(io_buf, batch_size);
    lock_sensitive(pt_buf, batch_size);

    seg_worker_t *workers = malloc((size_t)n_threads * sizeof(seg_worker_t));
    pthread_t    *tids    = malloc((size_t)n_threads * sizeof(pthread_t));
    if (!workers || !tids) {
        free(workers); free(tids);
        free(io_buf);  free(pt_buf);
        fclose(ftmp); secure_shred(tmp_path); unlink(tmp_path);
        return -1;
    }

    /* MAC verified over header || ciphertext */
    crypto_generichash_state mac;
    crypto_generichash_init(&mac, key, key_len, TAG_SIZE);
    if (is_v2) {
        crypto_generichash_update(&mac, (const uint8_t *)"KRAKKEN1", 8);
        crypto_generichash_update(&mac, nonce, NONCE_SIZE);
    } else if (is_v3) {
        crypto_generichash_update(&mac, nonce, NONCE_SIZE);
        crypto_generichash_update(&mac, enc_magic, 8);
    } else {
        /* V1 legacy */
        crypto_generichash_update(&mac, nonce, NONCE_SIZE);
    }

    uint64_t seg_base  = 0;
    size_t   processed = 0;
    int      failed    = 0;

    while (processed < cipher_len && !failed) {
        size_t to_read = cipher_len - processed;
        if (to_read > batch_size) to_read = batch_size;

        size_t n_read = fread(io_buf, 1, to_read, fin);
        if (!n_read) { failed = 1; break; }

        /* Update MAC over ciphertext BEFORE decrypting */
        if (!is_v2 && !is_v3) {
            crypto_generichash_update(&mac, io_buf, n_read);
        }

        /* Carve per-thread segments */
        int n_segs = 0;
        size_t seg_off = 0;
        while (seg_off < n_read) {
            size_t seg_len = n_read - seg_off;
            if (seg_len > ENCRYPT_SEGMENT_SIZE) seg_len = ENCRYPT_SEGMENT_SIZE;

            workers[n_segs].key     = key;
            workers[n_segs].key_len = key_len;
            memcpy((void*)workers[n_segs].nonce, nonce, NONCE_SIZE);
            workers[n_segs].seg_idx = seg_base + (uint64_t)n_segs;
            workers[n_segs].in      = io_buf + seg_off;
            workers[n_segs].out     = pt_buf + seg_off;
            workers[n_segs].len     = seg_len;
            workers[n_segs].use_parallel_mac = is_v2 || is_v3;
            workers[n_segs].is_decrypt       = 1;

            seg_off += seg_len;
            n_segs++;
        }

        run_parallel_batch(workers, tids, n_segs);

        if (is_v2 || is_v3) {
            for (int i = 0; i < n_segs; i++) {
                crypto_generichash_update(&mac, workers[i].mac, TAG_SIZE);
            }
        }

        if (fwrite(pt_buf, 1, n_read, ftmp) != n_read) failed = 1;

        seg_base  += (uint64_t)n_segs;
        processed += n_read;

        if (progress_cb)
            progress_cb("Decrypting", processed, cipher_len, user_data);
    }

    /* Read and verify authentication tag */
    uint8_t tag[TAG_SIZE], computed[TAG_SIZE];
    if (fread(tag, 1, TAG_SIZE, fin) != TAG_SIZE) failed = 1;
    crypto_generichash_final(&mac, computed, TAG_SIZE);
    if (ct_memcmp(tag, computed, TAG_SIZE) != 0) failed = 1;

    fclose(ftmp);
    secure_zero(io_buf, batch_size);
    secure_zero(pt_buf, batch_size);
    free(workers); free(tids);
    free(io_buf);  free(pt_buf);

    if (failed) {
        secure_shred(tmp_path);
        unlink(tmp_path);
        return -1;
    }

    /* Make plaintext visible only after authentication passes.
     *
     * rename(2) is atomic when src and dst are on the same filesystem.
     * When they are on different filesystems it fails with EXDEV — this is
     * the common case when the temp file lives in /dev/shm (tmpfs) and
     * out_path is on ext4/btrfs/xfs/NFS/etc.
     *
     * On EXDEV: copy the plaintext to out_path, then securely shred the
     * temp file.  Any other rename error is a hard failure. */
    if (rename(tmp_path, out_path) != 0) {
        if (errno == EXDEV) {
            /* Cross-device: copy then destroy the temp file */
            int copy_ok = copy_file(tmp_path, out_path);
            secure_shred(tmp_path);
            unlink(tmp_path);
            if (copy_ok != 0) {
                /* Copy failed: remove the partial output */
                secure_shred(out_path);
                unlink(out_path);
                return -1;
            }
        } else {
            secure_shred(tmp_path);
            unlink(tmp_path);
            return -1;
        }
    }
    return 0;
}
