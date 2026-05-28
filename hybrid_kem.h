#ifndef HYBRID_KEM_H
#define HYBRID_KEM_H

#include <stdint.h>
#include <stddef.h>

/* Hybrid KEM functions */
int derive_master_key(const char *password, const uint8_t *salt, uint8_t *master_key);
int derive_master_key_v4(const char *password, const uint8_t *salt, uint8_t *master_key);
void generate_hybrid_keypair(uint8_t *kyber_pk, uint8_t *kyber_sk,
                              uint8_t *x448_pk, uint8_t *x448_sk);
void wrap_hybrid_sk(const uint8_t *hybrid_sk, const uint8_t *master_key,
                    uint8_t *nonce_out, uint8_t *ciphertext_out, int use_krakken);
int unwrap_hybrid_sk(uint8_t *hybrid_sk, const uint8_t *master_key,
                     const uint8_t *nonce, const uint8_t *ciphertext, int use_krakken);
int hybrid_encapsulate(uint8_t *shared_secret, uint8_t *kem_ct,
                        const uint8_t *kyber_pk, const uint8_t *x448_pk);
int hybrid_decapsulate(uint8_t *shared_secret, const uint8_t *kem_ct,
                        const uint8_t *kyber_sk, const uint8_t *x448_sk);

#endif /* HYBRID_KEM_H */
