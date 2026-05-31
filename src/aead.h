#ifndef AEAD_H
#define AEAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "utils.h"

/* AEAD encryption/decryption with progress callback */
int permut2048_aead_encrypt_stream(FILE *fout, const char *in_path,
                                   const uint8_t *key, size_t key_len,
                                   progress_callback_t progress_cb, void *user_data);
int permut2048_aead_decrypt_stream(FILE *fin, const char *out_path,
                                   const uint8_t *key, size_t key_len,
                                   progress_callback_t progress_cb, void *user_data);

#endif /* AEAD_H */
