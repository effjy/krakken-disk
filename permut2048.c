/*
 * permut2048.c — sponge API backed by krakken_multi permutation engine
 *
 * This file contains only the sponge construction (absorb / finalize / squeeze).
 * All permutation work is delegated to krakken_permute_avx2() which lives in
 * krakken_multi.c, giving us:
 *   - 16 rounds Abyssal S-box (NL=112)
 *   - Register-only MDS (no memory spill)
 *   - 128-bit ARX intra-column pressure step
 *   - pthread_once thread-safe RC initialisation
 *   - Little-endian RC derivation (portable)
 */

#include "permut2048.h"
#include "config.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* -------------------------------------------------------------------------
 * Permutation engine — provided by krakken_multi.c
 * ---------------------------------------------------------------------- */
extern void init_rc_vectors_avx2(void);
extern void krakken_permute_avx2(uint64_t state[32]);

/* Public alias so callers that use the old name keep working */
void init_rc_vectors(void) {
    init_rc_vectors_avx2();
}

/* Wrapper with the name used inside this translation unit */
static inline void krakken_permute(uint64_t state[32]) {
    krakken_permute_avx2(state);
}

/* -------------------------------------------------------------------------
 * Secure zero — volatile function-pointer trick, same as tsuki_avx2_multi.c
 * ---------------------------------------------------------------------- */
static void p_memset_wrap(void *p, int c, size_t n) { memset(p, c, n); }
static void (* volatile p_memset_vol)(void *, int, size_t) = p_memset_wrap;
static void p_secure_zero(void *ptr, size_t n) { p_memset_vol(ptr, 0, n); }

/* =========================================================================
 * Sponge absorb
 *
 * Buffers incoming bytes.  When the buffer fills to PERMUT2048_RATE (160 B)
 * it XORs into state[0..19] (the rate lanes) and calls the permutation.
 * ========================================================================= */
void permut2048_absorb(permut2048_ctx *ctx, const uint8_t *input, size_t len) {
    if (!ctx || (!input && len)) return;
    init_rc_vectors_avx2();     /* idempotent via pthread_once */

    size_t i = 0;
    while (i < len) {
        size_t space = PERMUT2048_RATE - ctx->pos;
        size_t chunk = (len - i < space) ? len - i : space;
        memcpy(ctx->buffer + ctx->pos, input + i, chunk);
        ctx->pos += chunk;
        i        += chunk;
        if (ctx->pos == PERMUT2048_RATE) {
            /* XOR rate portion into state */
            const uint64_t *b64 = (const uint64_t*)ctx->buffer;
            for (int j = 0; j < (int)(PERMUT2048_RATE / 8); j++)
                ctx->state[j] ^= b64[j];
            krakken_permute(ctx->state);
            ctx->pos = 0;
        }
    }
}

/* =========================================================================
 * Sponge finalize
 *
 * Applies Keccak-style multi-rate padding: 0x06 … 0x80.
 * ========================================================================= */
void permut2048_finalize(permut2048_ctx *ctx) {
    if (!ctx) return;
    init_rc_vectors_avx2();

    /* Pad byte at current position */
    memset(ctx->buffer + ctx->pos, 0, PERMUT2048_RATE - ctx->pos);
    ctx->buffer[ctx->pos]              = PERMUT2048_PAD_BYTE;
    ctx->buffer[PERMUT2048_RATE - 1]  ^= PERMUT2048_PAD_FINAL;

    const uint64_t *b64 = (const uint64_t*)ctx->buffer;
    for (int j = 0; j < (int)(PERMUT2048_RATE / 8); j++)
        ctx->state[j] ^= b64[j];
    krakken_permute(ctx->state);
    ctx->pos = 0;
}

/* =========================================================================
 * Sponge squeeze
 *
 * Outputs bytes from state[0..RATE-1].  Each RATE bytes consumed triggers
 * another permutation call.
 * ========================================================================= */
void permut2048_squeeze(permut2048_ctx *ctx, uint8_t *output, size_t out_len) {
    if (!ctx || (!output && out_len)) return;
    if (!out_len) return;

    size_t done = 0;
    while (done < out_len) {
        size_t remaining = out_len - done;
        size_t chunk = (remaining > PERMUT2048_RATE) ? PERMUT2048_RATE : remaining;
        memcpy(output + done, ctx->state, chunk);
        done += chunk;
        if (done < out_len) krakken_permute(ctx->state);
    }
}

/* =========================================================================
 * One-shot hash
 * ========================================================================= */
void permut2048_hash(const uint8_t *input, size_t in_len,
                     uint8_t *output, size_t out_len) {
    permut2048_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rate = PERMUT2048_RATE;
    permut2048_absorb(&ctx, input, in_len);
    permut2048_finalize(&ctx);
    permut2048_squeeze(&ctx, output, out_len);
    p_secure_zero(&ctx, sizeof(ctx));
}

/* =========================================================================
 * XOF (alias for hash — same construction, arbitrary output length)
 * ========================================================================= */
void permut2048_xof(const uint8_t *input, size_t in_len,
                    uint8_t *output, size_t out_len) {
    permut2048_hash(input, in_len, output, out_len);
}

/* =========================================================================
 * Duplex-style Encrypt (Absorb ciphertext)
 * ========================================================================= */
void permut2048_encrypt(permut2048_ctx *ctx, const uint8_t *plain, uint8_t *cipher, size_t len) {
    if (!ctx || !plain || !cipher || !len) return;

    size_t i = 0;
    while (i < len) {
        size_t space = PERMUT2048_RATE - ctx->pos;
        size_t chunk = (len - i < space) ? len - i : space;
        
        uint8_t *state_bytes = (uint8_t *)ctx->state;
        for (size_t j = 0; j < chunk; j++) {
            cipher[i + j] = plain[i + j] ^ state_bytes[ctx->pos + j];
            state_bytes[ctx->pos + j] = cipher[i + j];
        }
        
        ctx->pos += chunk;
        i += chunk;
        
        if (ctx->pos == PERMUT2048_RATE) {
            krakken_permute(ctx->state);
            ctx->pos = 0;
        }
    }
}

/* =========================================================================
 * Duplex-style Decrypt (Absorb ciphertext)
 * ========================================================================= */
void permut2048_decrypt(permut2048_ctx *ctx, const uint8_t *cipher, uint8_t *plain, size_t len) {
    if (!ctx || !cipher || !plain || !len) return;

    size_t i = 0;
    while (i < len) {
        size_t space = PERMUT2048_RATE - ctx->pos;
        size_t chunk = (len - i < space) ? len - i : space;
        
        uint8_t *state_bytes = (uint8_t *)ctx->state;
        for (size_t j = 0; j < chunk; j++) {
            uint8_t c = cipher[i + j];
            plain[i + j] = c ^ state_bytes[ctx->pos + j];
            state_bytes[ctx->pos + j] = c;
        }
        
        ctx->pos += chunk;
        i += chunk;
        
        if (ctx->pos == PERMUT2048_RATE) {
            krakken_permute(ctx->state);
            ctx->pos = 0;
        }
    }
}
