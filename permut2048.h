#ifndef PERMUT2048_H
#define PERMUT2048_H

#include <stdint.h>
#include <stddef.h>

/* Permut-2048 context */
typedef struct {
    uint64_t state[32];
    uint8_t  buffer[160];
    size_t   pos, rate;
} permut2048_ctx;

/* Initialize round constants (call once at startup) */
void init_rc_vectors(void);

/* Sponge functions */
void permut2048_absorb(permut2048_ctx *ctx, const uint8_t *input, size_t len);
void permut2048_squeeze(permut2048_ctx *ctx, uint8_t *output, size_t out_len);
void permut2048_finalize(permut2048_ctx *ctx);
void permut2048_hash(const uint8_t *input, size_t in_len, uint8_t *output, size_t out_len);
void permut2048_xof(const uint8_t *input, size_t in_len, uint8_t *output, size_t out_len);
void permut2048_encrypt(permut2048_ctx *ctx, const uint8_t *plain, uint8_t *cipher, size_t len);
void permut2048_decrypt(permut2048_ctx *ctx, const uint8_t *cipher, uint8_t *plain, size_t len);

#endif /* PERMUT2048_H */
