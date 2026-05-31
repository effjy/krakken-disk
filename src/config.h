#ifndef CONFIG_H
#define CONFIG_H

/* Application configuration */
#define APP_NAME "Krakken-Disk"
#define APP_VERSION "4.5.0"
#define APP_TITLE "Krakken-2048 Encrypted Disk Manager"

/* Kyber K is defined in Makefile */
#include "kyber/params.h"

/* Cryptography constants */
#define KEY_SIZE       64
#define NONCE_SIZE     12
#define TAG_SIZE       32
#define SALT_SIZE      16
#define STREAM_BUFFER_SIZE (1024*1024)

/* KEM constants */
#define X448_PUBKEY_LEN    56
#define X448_PRIVKEY_LEN   56
#define HYBRID_SK_LEN      (KYBER_SECRETKEYBYTES + X448_PRIVKEY_LEN)
#define WRAP_NONCE_LEN     crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define WRAP_ABYTES        crypto_aead_xchacha20poly1305_ietf_ABYTES
#define WRAP_CIPHERTEXT_LEN (HYBRID_SK_LEN + WRAP_ABYTES)
#define HEADER_NONCE_LEN   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define HEADER_KEY_LEN     32
#define HEADER_ABYTES      crypto_aead_xchacha20poly1305_ietf_ABYTES
#define HEADER_PLAIN_LEN   (WRAP_NONCE_LEN + WRAP_CIPHERTEXT_LEN + \
                            KYBER_PUBLICKEYBYTES + X448_PUBKEY_LEN + \
                            KYBER_CIPHERTEXTBYTES + X448_PUBKEY_LEN)
#define HEADER_CIPHER_LEN  (HEADER_PLAIN_LEN + HEADER_ABYTES)

/* Argon2id parameters */
#define ARGON2_TIME_COST  6
#define ARGON2_MEM_COST   (1024ULL * 1024 * 1024)
#define ARGON2_PARALLEL   4

/* Permut-2048 constants */
#define PERMUT2048_RATE        160
#define PERMUT2048_PAD_BYTE    0x06
#define PERMUT2048_PAD_FINAL   0x80

/* Volume filesystem constants */
#define VFS_MAGIC              0x54534B44  /* "TSKD" */
#define VFS_VERSION            1
#define VFS_MAX_FILES          1024
#define VFS_MAX_FILENAME_LEN   256
#define VFS_SECTOR_SIZE        4096

#define KRAKKEN4_MAGIC         "KRAKKEN4"

#endif /* CONFIG_H */
