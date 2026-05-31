#include "volume.h"
#include "config.h"
#include "hybrid_kem.h"
#include "permut2048.h"
#include "utils.h"
#include "sector_cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <unistd.h>
#include <limits.h>

#define VOLUME_VERSION 4
#define SECTOR_SIZE VFS_SECTOR_SIZE
#define PER_SECTOR_MAC_SIZE 32
#define HEADER_RESERVE 8192

/* sector_nonce: encode sector index as little-endian into a zeroed nonce buffer */
static void sector_nonce(uint64_t idx, uint8_t *nonce, size_t nonce_len) {
    memset(nonce, 0, nonce_len);
    for (size_t i = 0; i < 8 && i < nonce_len; i++)
        nonce[i] = (idx >> (i * 8)) & 0xFF;
}

static int encrypt_sector(FILE *f, uint64_t idx, const uint8_t *plain,
                          const uint8_t *master_key, size_t master_key_len, int use_domain_separator) {
    /* Derive per-sector key using BLAKE2b */
    uint8_t sector_key[KEY_SIZE];
    crypto_generichash(sector_key, KEY_SIZE, master_key, master_key_len, 
                      (const uint8_t*)&idx, sizeof(idx));

    uint8_t nonce[NONCE_SIZE];
    sector_nonce(idx, nonce, NONCE_SIZE);

    permut2048_ctx sponge = { .rate = PERMUT2048_RATE };
    permut2048_absorb(&sponge, sector_key, KEY_SIZE);
    permut2048_absorb(&sponge, nonce, NONCE_SIZE);
    if (use_domain_separator) {
        permut2048_absorb(&sponge, (const uint8_t*)"\x00", 1);
    }
    permut2048_finalize(&sponge); /* canonical sponge padding — replaces old manual loop */

    uint8_t cipher[SECTOR_SIZE], keystream[SECTOR_SIZE];
    permut2048_squeeze(&sponge, keystream, SECTOR_SIZE);
    for (size_t i = 0; i < SECTOR_SIZE; i++) cipher[i] = plain[i] ^ keystream[i];
    secure_zero(keystream, SECTOR_SIZE);

    uint8_t tag[PER_SECTOR_MAC_SIZE];
    crypto_generichash_state mac;
    crypto_generichash_init(&mac, sector_key, KEY_SIZE, PER_SECTOR_MAC_SIZE);
    crypto_generichash_update(&mac, (uint8_t*)&idx, sizeof(idx));
    crypto_generichash_update(&mac, cipher, SECTOR_SIZE);
    crypto_generichash_final(&mac, tag, PER_SECTOR_MAC_SIZE);

    if (fwrite(cipher, 1, SECTOR_SIZE, f) != SECTOR_SIZE) {
        secure_zero(sector_key, KEY_SIZE);
        return -1;
    }
    if (fwrite(tag, 1, PER_SECTOR_MAC_SIZE, f) != PER_SECTOR_MAC_SIZE) {
        secure_zero(sector_key, KEY_SIZE);
        return -1;
    }
    
    secure_zero(sector_key, KEY_SIZE);
    return 0;
}


int volume_create(const char *path, size_t size_mb, const char *password,
                  progress_callback_t progress_cb, void *user_data) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* Clear salt and header nonce will be written at the beginning */
    uint8_t salt[SALT_SIZE];
    random_bytes(salt, SALT_SIZE);
    uint8_t header_nonce[HEADER_NONCE_LEN];
    random_bytes(header_nonce, HEADER_NONCE_LEN);
    fwrite(salt, 1, SALT_SIZE, f);
    fwrite(header_nonce, 1, HEADER_NONCE_LEN, f);
    /* Reserve space for encrypted header (will seek back) */
    long header_start = ftell(f);
    uint8_t *header_placeholder = calloc(1, HEADER_RESERVE + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    if (!header_placeholder) { fclose(f); return -1; }
    fwrite(header_placeholder, 1, HEADER_RESERVE + crypto_aead_xchacha20poly1305_ietf_ABYTES, f);
    free(header_placeholder);

    /* Derive master key (V4) */
    uint8_t master_key[KEY_SIZE];
    if (derive_master_key_v4(password, salt, master_key) != 0) {
        fclose(f); return -1;
    }

    /* Hybrid keypair */
    uint8_t kyber_pk[KYBER_PUBLICKEYBYTES], kyber_sk[KYBER_SECRETKEYBYTES];
    uint8_t x448_pk[X448_PUBKEY_LEN], x448_sk[X448_PRIVKEY_LEN];
    generate_hybrid_keypair(kyber_pk, kyber_sk, x448_pk, x448_sk);

    /* Wrap hybrid secret key (V4 uses Krakken) */
    uint8_t wrap_nonce[WRAP_NONCE_LEN], wrap_ct[WRAP_CIPHERTEXT_LEN];
    uint8_t hybrid_sk[HYBRID_SK_LEN];
    memcpy(hybrid_sk, kyber_sk, KYBER_SECRETKEYBYTES);
    memcpy(hybrid_sk + KYBER_SECRETKEYBYTES, x448_sk, X448_PRIVKEY_LEN);
    wrap_hybrid_sk(hybrid_sk, master_key, wrap_nonce, wrap_ct, 1);
    secure_zero(hybrid_sk, HYBRID_SK_LEN);
    secure_zero(kyber_sk, KYBER_SECRETKEYBYTES);
    secure_zero(x448_sk, X448_PRIVKEY_LEN);

    /* Encapsulate file key */
    uint8_t file_key[KEY_SIZE];
    uint8_t kem_ct[KYBER_CIPHERTEXTBYTES + X448_PUBKEY_LEN];
    if (hybrid_encapsulate(file_key, kem_ct, kyber_pk, x448_pk) != 0) {
        secure_zero(master_key, KEY_SIZE);
        fclose(f); return -1;
    }

    /* Build plain header */
    uint8_t plain_header[HEADER_RESERVE];
    memset(plain_header, 0, HEADER_RESERVE);
    size_t pos = 0;
    memcpy(plain_header + pos, KRAKKEN4_MAGIC, 8); pos += 8;
    memcpy(plain_header + pos, wrap_nonce, WRAP_NONCE_LEN); pos += WRAP_NONCE_LEN;
    memcpy(plain_header + pos, wrap_ct, WRAP_CIPHERTEXT_LEN); pos += WRAP_CIPHERTEXT_LEN;
    memcpy(plain_header + pos, kyber_pk, KYBER_PUBLICKEYBYTES); pos += KYBER_PUBLICKEYBYTES;
    memcpy(plain_header + pos, x448_pk, X448_PUBKEY_LEN); pos += X448_PUBKEY_LEN;
    memcpy(plain_header + pos, kem_ct, sizeof(kem_ct)); pos += sizeof(kem_ct);
    uint32_t version = VOLUME_VERSION;
    memcpy(plain_header + pos, &version, sizeof(version)); pos += sizeof(version);

    /* Encrypt header (V4 uses Krakken) */
    uint8_t encrypted_header[HEADER_RESERVE + TAG_SIZE];
    permut2048_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rate = PERMUT2048_RATE;
    permut2048_absorb(&ctx, master_key, KEY_SIZE);
    permut2048_absorb(&ctx, header_nonce, HEADER_NONCE_LEN);
    permut2048_absorb(&ctx, (const uint8_t *)"HEADER", 6);
    permut2048_finalize(&ctx);
    permut2048_encrypt(&ctx, plain_header, encrypted_header, HEADER_RESERVE);
    permut2048_squeeze(&ctx, encrypted_header + HEADER_RESERVE, TAG_SIZE);
    
    secure_zero(&ctx, sizeof(ctx));
    secure_zero(master_key, KEY_SIZE);

    /* Write encrypted header at the reserved location */
    fseek(f, header_start, SEEK_SET);
    fwrite(encrypted_header, 1, sizeof(encrypted_header), f);
    fflush(f);
    fseek(f, 0, SEEK_END);

    /* Setup VFS in memory using temporary data area */
    vfs_context_t vfs;
    size_t total_bytes = size_mb * 1024 * 1024 - (SALT_SIZE + HEADER_NONCE_LEN + sizeof(encrypted_header));
    size_t total_sectors = total_bytes / (SECTOR_SIZE + PER_SECTOR_MAC_SIZE);
    vfs.data_size = total_sectors * SECTOR_SIZE;
    
    /* Use temporary data area for volume creation */
    uint8_t *temp_data_area = calloc(1, vfs.data_size);
    if (!temp_data_area) { fclose(f); return -1; }
    lock_sensitive(temp_data_area, vfs.data_size);
    
    vfs.cache = NULL;  /* No cache during creation */
    vfs_format_volume(&vfs);
    
    /* Create temporary data area with VFS header and file table */
    memcpy(temp_data_area, &vfs.header, sizeof(vfs_header_t));
    memcpy(temp_data_area + sizeof(vfs_header_t), vfs.files, sizeof(vfs_file_entry_t) * VFS_MAX_FILES);

    /* Write sectors with MACs using file_key for consistency with opening logic */
    for (size_t i = 0; i < total_sectors; i++) {
        if (encrypt_sector(f, i, temp_data_area + i * SECTOR_SIZE, file_key, KEY_SIZE, 1) != 0) {
            secure_zero(file_key, KEY_SIZE);
            secure_zero(temp_data_area, vfs.data_size);
            free(temp_data_area); fclose(f); return -1;
        }
        if (progress_cb && (i % 256 == 0)) {
            int percent = 60 + (int)((i * 40) / total_sectors);
            progress_cb("Encrypting volume", percent, 100, user_data);
        }
    }
    fclose(f);

    /* Report completion */
    if (progress_cb) progress_cb("Volume created", 100, 100, user_data);

    /* Scrub temporary data area before freeing */
    secure_zero(temp_data_area, vfs.data_size);
    free(temp_data_area);
    return 0;
}

int volume_open(const char *path, const char *password, volume_context_t *vol, 
                progress_callback_t progress_cb, void *user_data) {
    FILE *f = fopen(path, "rb+");
    if (!f) return -1;

    /* Report initial progress */
    if (progress_cb) progress_cb("Opening volume", 0, 100, user_data);

    /* Read salt and header nonce from clear */
    uint8_t salt[SALT_SIZE];
    uint8_t header_nonce[HEADER_NONCE_LEN];
    if (fread(salt, 1, SALT_SIZE, f) != SALT_SIZE ||
        fread(header_nonce, 1, HEADER_NONCE_LEN, f) != HEADER_NONCE_LEN) {
        fclose(f); return -1;
    }

    /* Trial Decryption: Try V4 first, then fallback to V3 */
    int is_v4 = 0;
    uint8_t plain_header[HEADER_RESERVE];
    
    /* Attempt V4 (Krakken) */
    if (derive_master_key_v4(password, salt, vol->master_key) == 0) {
        uint8_t encrypted_header[HEADER_RESERVE + TAG_SIZE];
        if (fread(encrypted_header, 1, sizeof(encrypted_header), f) == sizeof(encrypted_header)) {
            permut2048_ctx ctx;
            memset(&ctx, 0, sizeof(ctx));
            ctx.rate = PERMUT2048_RATE;
            permut2048_absorb(&ctx, vol->master_key, KEY_SIZE);
            permut2048_absorb(&ctx, header_nonce, HEADER_NONCE_LEN);
            permut2048_absorb(&ctx, (const uint8_t *)"HEADER", 6);
            permut2048_finalize(&ctx);
            permut2048_decrypt(&ctx, encrypted_header, plain_header, HEADER_RESERVE);
            uint8_t computed_tag[TAG_SIZE];
            permut2048_squeeze(&ctx, computed_tag, TAG_SIZE);
            
            if (ct_memcmp(computed_tag, encrypted_header + HEADER_RESERVE, TAG_SIZE) == 0) {
                /* Check for magic inside the decrypted buffer to confirm correct password */
                if (memcmp(plain_header, KRAKKEN4_MAGIC, 8) == 0) {
                    is_v4 = 1;
                }
            }
            secure_zero(&ctx, sizeof(ctx));
        }
    }

    if (!is_v4) {
        /* Fallback to V3 (XChaCha20) */
        if (derive_master_key(password, salt, vol->master_key) != 0) {
            fclose(f); return -1;
        }
        
        fseek(f, SALT_SIZE + HEADER_NONCE_LEN, SEEK_SET);
        uint8_t encrypted_header_v3[HEADER_RESERVE + crypto_aead_xchacha20poly1305_ietf_ABYTES];
        if (fread(encrypted_header_v3, 1, sizeof(encrypted_header_v3), f) != sizeof(encrypted_header_v3)) {
            fclose(f); return -1;
        }

        uint8_t header_key[HEADER_KEY_LEN];
        crypto_generichash(header_key, HEADER_KEY_LEN, vol->master_key, 32, (const uint8_t*)"HEADER", 6);
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain_header, NULL, NULL,
                                                        encrypted_header_v3, sizeof(encrypted_header_v3),
                                                        NULL, 0, header_nonce,
                                                        header_key) != 0) {
            secure_zero(header_key, HEADER_KEY_LEN);
            secure_zero(vol->master_key, KEY_SIZE);
            fclose(f); return -1;
        }
        secure_zero(header_key, HEADER_KEY_LEN);
    }

    /* Parse plain header */
    size_t pos = is_v4 ? 8 : 0;
    uint8_t wrap_nonce[WRAP_NONCE_LEN], wrap_ct[WRAP_CIPHERTEXT_LEN];
    uint8_t kyber_pk[KYBER_PUBLICKEYBYTES], x448_pk[X448_PUBKEY_LEN];
    uint8_t kem_ct[KYBER_CIPHERTEXTBYTES + X448_PUBKEY_LEN];
    memcpy(wrap_nonce, plain_header + pos, WRAP_NONCE_LEN); pos += WRAP_NONCE_LEN;
    memcpy(wrap_ct, plain_header + pos, WRAP_CIPHERTEXT_LEN); pos += WRAP_CIPHERTEXT_LEN;
    memcpy(kyber_pk, plain_header + pos, KYBER_PUBLICKEYBYTES); pos += KYBER_PUBLICKEYBYTES;
    memcpy(x448_pk, plain_header + pos, X448_PUBKEY_LEN); pos += X448_PUBKEY_LEN;
    memcpy(kem_ct, plain_header + pos, sizeof(kem_ct)); pos += sizeof(kem_ct);
    uint32_t version;
    memcpy(&version, plain_header + pos, sizeof(version));
    
    if (is_v4) {
        if (version != 4) { secure_zero(vol->master_key, KEY_SIZE); fclose(f); return -1; }
    } else {
        if (version != 2 && version != 3) { secure_zero(vol->master_key, KEY_SIZE); fclose(f); return -1; }
    }

    /* Unwrap hybrid secret key */
    uint8_t hybrid_sk[HYBRID_SK_LEN];
    if (unwrap_hybrid_sk(hybrid_sk, vol->master_key, wrap_nonce, wrap_ct, is_v4) != 0) {
        secure_zero(vol->master_key, KEY_SIZE);
        fclose(f); return -1;
    }
    uint8_t *kyber_sk = hybrid_sk;
    uint8_t *x448_sk = hybrid_sk + KYBER_SECRETKEYBYTES;

    /* Decapsulate file key */
    if (hybrid_decapsulate(vol->file_key, kem_ct, kyber_sk, x448_sk) != 0) {
        secure_zero(vol->master_key, KEY_SIZE);
        secure_zero(hybrid_sk, HYBRID_SK_LEN);
        fclose(f); return -1;
    }
    secure_zero(hybrid_sk, HYBRID_SK_LEN);

    /* Report progress for header processing */
    if (progress_cb) progress_cb("Processing volume header", 10, 100, user_data);

    /* Initialize sector cache instead of loading all sectors */
    long data_start = ftell(f);
    fseek(f, 0, SEEK_END);
    long file_end = ftell(f);
    size_t data_bytes = file_end - data_start;
    size_t total_sectors = data_bytes / (SECTOR_SIZE + PER_SECTOR_MAC_SIZE);
    vol->vfs.data_size = total_sectors * SECTOR_SIZE;
    
    /* Initialize cache with the file handle and keys.
     * data_offset and total_sectors are passed directly so cache_init
     * does not need to re-derive them from the file size (Bug 3 fix). */
    vol->vfs.cache = cache_init(f, vol->master_key, vol->file_key, 4096,
                                (size_t)data_start, (uint64_t)total_sectors,
                                (version >= 3 ? 1 : 0));
    if (!vol->vfs.cache) {
        fclose(f); return -1;
    }
    /* data_offset and total_sectors are now set correctly inside cache_init */
    
    /* Report progress for cache initialization */
    if (progress_cb) progress_cb("Initializing sector cache", 50, 100, user_data);
    
    /* Load and pin header sectors (VFS header and file table) */
    size_t header_sectors_needed = (sizeof(vfs_header_t) + sizeof(vfs_file_entry_t) * VFS_MAX_FILES + SECTOR_SIZE - 1) / SECTOR_SIZE;
    for (size_t i = 0; i < header_sectors_needed && i < total_sectors; i++) {
        uint8_t *sector_data;
        if (cache_get_sector(vol->vfs.cache, i, &sector_data) != 0) {
            cache_destroy(vol->vfs.cache);
            vol->vfs.cache = NULL;
            fclose(f); return -1;
        }
        
        if (cache_pin_sector(vol->vfs.cache, i) != 0) {
            cache_destroy(vol->vfs.cache);
            vol->vfs.cache = NULL;
            fclose(f); return -1;
        }
    }
    
    /* Extract VFS header and file table from cached sectors */
    uint8_t *header_sector;
    if (cache_get_sector(vol->vfs.cache, 0, &header_sector) != 0) {
        cache_destroy(vol->vfs.cache);
        vol->vfs.cache = NULL;
        fclose(f); return -1;
    }
    memcpy(&vol->vfs.header, header_sector, sizeof(vfs_header_t));
    if (!vfs_validate_header(&vol->vfs.header)) {
        cache_destroy(vol->vfs.cache);
        vol->vfs.cache = NULL;
        fclose(f); return -1;
    }
    
    /* Read file table from cached sectors */
    size_t file_table_offset = sizeof(vfs_header_t);
    size_t file_table_size = sizeof(vfs_file_entry_t) * VFS_MAX_FILES;
    size_t bytes_copied = 0;
    
    while (bytes_copied < file_table_size) {
        size_t sector_idx = (file_table_offset + bytes_copied) / SECTOR_SIZE;
        size_t sector_offset = (file_table_offset + bytes_copied) % SECTOR_SIZE;
        size_t bytes_to_copy = SECTOR_SIZE - sector_offset;
        
        if (bytes_to_copy > file_table_size - bytes_copied) {
            bytes_to_copy = file_table_size - bytes_copied;
        }
        
        uint8_t *sector_data;
        if (cache_get_sector(vol->vfs.cache, sector_idx, &sector_data) != 0) {
            cache_destroy(vol->vfs.cache);
            vol->vfs.cache = NULL;
            fclose(f); return -1;
        }
        
        memcpy((uint8_t*)vol->vfs.files + bytes_copied, sector_data + sector_offset, bytes_to_copy);
        bytes_copied += bytes_to_copy;
    }

    /* Report completion */
    if (progress_cb) progress_cb("Volume opened", 100, 100, user_data);

    vol->vfs.is_mounted = 0;
    vol->is_open = 1;
    strncpy(vol->path, path, sizeof(vol->path) - 1);
    vol->file_handle = f;  /* Store file handle for cache operations */
    return 0;
}

int volume_close(volume_context_t *vol, progress_callback_t progress_cb, void *user_data) {
    if (!vol->is_open) return -1;
    
    /* Handle cache operations before unmounting */
    if (vol->vfs.cache) {
        /* Write back VFS header and file table into cache */
        uint8_t *header_sector;
        if (cache_get_sector(vol->vfs.cache, 0, &header_sector) == 0) {
            memcpy(header_sector, &vol->vfs.header, sizeof(vfs_header_t));
            cache_mark_dirty(vol->vfs.cache, 0);
        }
        
        /* Write file table to cached sectors */
        size_t file_table_offset = sizeof(vfs_header_t);
        size_t file_table_size = sizeof(vfs_file_entry_t) * VFS_MAX_FILES;
        size_t bytes_copied = 0;
        
        while (bytes_copied < file_table_size) {
            size_t sector_idx = (file_table_offset + bytes_copied) / SECTOR_SIZE;
            size_t sector_offset = (file_table_offset + bytes_copied) % SECTOR_SIZE;
            size_t bytes_to_copy = SECTOR_SIZE - sector_offset;
            
            if (bytes_to_copy > file_table_size - bytes_copied) {
                bytes_to_copy = file_table_size - bytes_copied;
            }
            
            uint8_t *sector_data;
            if (cache_get_sector(vol->vfs.cache, sector_idx, &sector_data) == 0) {
                memcpy(sector_data + sector_offset, (uint8_t*)vol->vfs.files + bytes_copied, bytes_to_copy);
                cache_mark_dirty(vol->vfs.cache, sector_idx);
            }
            bytes_copied += bytes_to_copy;
        }

        /* Report initial progress */
        if (progress_cb) progress_cb("Closing volume", 0, 100, user_data);
        
        /* Flush all dirty sectors to file */
        if (cache_flush_all(vol->vfs.cache) != 0) {
            return -1;
        }
        
        /* Report completion */
        if (progress_cb) progress_cb("Volume closed", 100, 100, user_data);
    }
    
    if (vol->vfs.is_mounted) volume_unmount(vol);
    
    /* Destroy cache (which wipes all cached sectors) after unmount */
    if (vol->vfs.cache) {
        cache_destroy(vol->vfs.cache);
        vol->vfs.cache = NULL;
    }
    
    /* Close file handle now that cache is destroyed */
    if (vol->file_handle) {
        fclose(vol->file_handle);
        vol->file_handle = NULL;
    }
    
    vol->is_open = 0;
    secure_zero(vol->master_key, KEY_SIZE);
    secure_zero(vol->file_key, KEY_SIZE);
    return 0;
}

int volume_mount(volume_context_t *vol) {
    if (!vol->is_open || vol->vfs.is_mounted) return -1;
    vol->vfs.is_mounted = 1;
    vol->is_mounted = 1;
    return 0;
}

int volume_unmount(volume_context_t *vol) {
    if (!vol->vfs.is_mounted) return -1;
    vol->vfs.is_mounted = 0;
    vol->is_mounted = 0;
    return 0;
}
