#include "hybrid_kem.h"
#include "config.h"
#include "utils.h"
#include "permut2048.h"
#include <sodium.h>
#include <string.h>
#include <openssl/evp.h>

/* Kyber K is defined in Makefile */

#pragma push_macro("randombytes")
#define randombytes kyber_randombytes
#include "kyber/params.h"
#include "kyber/kem.h"
#pragma pop_macro("randombytes")

/* Function declarations for Kyber-1024 (when KYBER_K=4) */
extern int pqcrystals_kyber1024_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int pqcrystals_kyber1024_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqcrystals_kyber1024_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

void kyber_randombytes(uint8_t *out, size_t outlen) {
    randombytes_buf(out, outlen);
}

int derive_master_key(const char *password, const uint8_t *salt, uint8_t *master_key) {
    return crypto_pwhash(master_key, 32, password, strlen(password), salt,
                         ARGON2_TIME_COST, ARGON2_MEM_COST,
                         crypto_pwhash_ALG_ARGON2ID13);
}

int derive_master_key_v4(const char *password, const uint8_t *salt, uint8_t *master_key) {
    return crypto_pwhash(master_key, 64, password, strlen(password), salt,
                         ARGON2_TIME_COST, ARGON2_MEM_COST,
                         crypto_pwhash_ALG_ARGON2ID13);
}

static int generate_x448_keypair(uint8_t *pub, uint8_t *priv) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL);
    if (!pctx) return -1;
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);
    
    size_t pub_len = X448_PUBKEY_LEN;
    size_t priv_len = X448_PRIVKEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) <= 0 ||
        EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) <= 0) {
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_free(pkey);
    return 0;
}

static int x448_scalarmult(uint8_t *shared_secret, const uint8_t *priv, const uint8_t *pub) {
    EVP_PKEY *priv_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL, priv, X448_PRIVKEY_LEN);
    EVP_PKEY *pub_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL, pub, X448_PUBKEY_LEN);
    if (!priv_pkey || !pub_pkey) {
        if (priv_pkey) EVP_PKEY_free(priv_pkey);
        if (pub_pkey) EVP_PKEY_free(pub_pkey);
        return -1;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(priv_pkey);
        EVP_PKEY_free(pub_pkey);
        return -1;
    }
    
    int ret = -1;
    if (EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_derive_set_peer(ctx, pub_pkey) > 0) {
        size_t secret_len = X448_PUBKEY_LEN;
        if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) > 0 && secret_len == X448_PUBKEY_LEN) {
            ret = 0;
        }
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv_pkey);
    EVP_PKEY_free(pub_pkey);
    return ret;
}

void generate_hybrid_keypair(uint8_t *kyber_pk, uint8_t *kyber_sk,
                              uint8_t *x448_pk, uint8_t *x448_sk) {
    pqcrystals_kyber1024_ref_keypair(kyber_pk, kyber_sk);
    generate_x448_keypair(x448_pk, x448_sk);
}

void wrap_hybrid_sk(const uint8_t *hybrid_sk, const uint8_t *master_key,
                    uint8_t *nonce_out, uint8_t *ciphertext_out, int use_krakken) {
    random_bytes(nonce_out, WRAP_NONCE_LEN);
    if (use_krakken) {
        permut2048_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.rate = PERMUT2048_RATE;
        permut2048_absorb(&ctx, master_key, 64);
        permut2048_absorb(&ctx, nonce_out, WRAP_NONCE_LEN);
        permut2048_absorb(&ctx, (const uint8_t *)"WRAP", 4);
        permut2048_finalize(&ctx);
        permut2048_encrypt(&ctx, hybrid_sk, ciphertext_out, HYBRID_SK_LEN);
        permut2048_squeeze(&ctx, ciphertext_out + HYBRID_SK_LEN, WRAP_ABYTES);
        secure_zero(&ctx, sizeof(ctx));
    } else {
        crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext_out, NULL,
                                                    hybrid_sk, HYBRID_SK_LEN,
                                                    NULL, 0, NULL, nonce_out, master_key);
    }
}

int unwrap_hybrid_sk(uint8_t *hybrid_sk, const uint8_t *master_key,
                     const uint8_t *nonce, const uint8_t *ciphertext, int use_krakken) {
    if (use_krakken) {
        permut2048_ctx ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.rate = PERMUT2048_RATE;
        permut2048_absorb(&ctx, master_key, 64);
        permut2048_absorb(&ctx, nonce, WRAP_NONCE_LEN);
        permut2048_absorb(&ctx, (const uint8_t *)"WRAP", 4);
        permut2048_finalize(&ctx);
        permut2048_decrypt(&ctx, ciphertext, hybrid_sk, HYBRID_SK_LEN);
        uint8_t computed_tag[WRAP_ABYTES];
        permut2048_squeeze(&ctx, computed_tag, WRAP_ABYTES);
        int ret = ct_memcmp(computed_tag, ciphertext + HYBRID_SK_LEN, WRAP_ABYTES);
        secure_zero(&ctx, sizeof(ctx));
        return ret;
    } else {
        return crypto_aead_xchacha20poly1305_ietf_decrypt(hybrid_sk, NULL, NULL,
                                                           ciphertext, WRAP_CIPHERTEXT_LEN,
                                                           NULL, 0, nonce, master_key);
    }
}

int hybrid_encapsulate(uint8_t *shared_secret, uint8_t *kem_ct,
                        const uint8_t *kyber_pk, const uint8_t *x448_pk) {
    uint8_t ct_kyber[KYBER_CIPHERTEXTBYTES], ss_kyber[KYBER_SSBYTES];
    uint8_t eph_priv[X448_PRIVKEY_LEN], eph_pub[X448_PUBKEY_LEN], ss_x[X448_PUBKEY_LEN];
    
    if (pqcrystals_kyber1024_ref_enc(ct_kyber, ss_kyber, kyber_pk) != 0) return -1;
    if (generate_x448_keypair(eph_pub, eph_priv) != 0) {
        secure_zero(ss_kyber, KYBER_SSBYTES);
        return -1;
    }
    
    if (x448_scalarmult(ss_x, eph_priv, x448_pk) != 0) {
        secure_zero(eph_priv, X448_PRIVKEY_LEN);
        secure_zero(ss_kyber, KYBER_SSBYTES);
        return -1;
    }
    
    crypto_generichash_state st;
    crypto_generichash_init(&st, (const uint8_t*)"HYBRID", 6, KEY_SIZE);
    crypto_generichash_update(&st, ss_kyber, KYBER_SSBYTES);
    crypto_generichash_update(&st, ss_x, X448_PUBKEY_LEN);
    crypto_generichash_final(&st, shared_secret, KEY_SIZE);
    
    memcpy(kem_ct, ct_kyber, KYBER_CIPHERTEXTBYTES);
    memcpy(kem_ct + KYBER_CIPHERTEXTBYTES, eph_pub, X448_PUBKEY_LEN);
    
    secure_zero(eph_priv, X448_PRIVKEY_LEN);
    secure_zero(ss_kyber, KYBER_SSBYTES);
    secure_zero(ss_x, X448_PUBKEY_LEN);
    return 0;
}

int hybrid_decapsulate(uint8_t *shared_secret, const uint8_t *kem_ct,
                        const uint8_t *kyber_sk, const uint8_t *x448_sk) {
    uint8_t ct_kyber[KYBER_CIPHERTEXTBYTES], eph_pub[X448_PUBKEY_LEN];
    memcpy(ct_kyber, kem_ct, KYBER_CIPHERTEXTBYTES);
    memcpy(eph_pub, kem_ct + KYBER_CIPHERTEXTBYTES, X448_PUBKEY_LEN);
    
    uint8_t ss_kyber[KYBER_SSBYTES], ss_x[X448_PUBKEY_LEN];
    if (pqcrystals_kyber1024_ref_dec(ss_kyber, ct_kyber, kyber_sk) != 0) return -1;
    if (x448_scalarmult(ss_x, x448_sk, eph_pub) != 0) {
        secure_zero(ss_kyber, KYBER_SSBYTES);
        return -1;
    }
    
    crypto_generichash_state st;
    crypto_generichash_init(&st, (const uint8_t*)"HYBRID", 6, KEY_SIZE);
    crypto_generichash_update(&st, ss_kyber, KYBER_SSBYTES);
    crypto_generichash_update(&st, ss_x, X448_PUBKEY_LEN);
    crypto_generichash_final(&st, shared_secret, KEY_SIZE);
    
    secure_zero(ss_kyber, KYBER_SSBYTES);
    secure_zero(ss_x, X448_PUBKEY_LEN);
    return 0;
}
