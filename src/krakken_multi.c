#include <assert.h>
#include <immintrin.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define KRAKKEN_ROUNDS 10

static void krakken_memset_wrap(void *p, int c, size_t n) { memset(p, c, n); }
static void (*volatile krakken_memset_vol)(void *, int,
                                           size_t) = krakken_memset_wrap;
static void krakken_secure_zero(void *ptr, size_t n) {
  krakken_memset_vol(ptr, 0, n);
}

static inline uint64_t rotl64(uint64_t x, int n) {
  n &= 63;
  if (n == 0)
    return x;
  return (x << n) | (x >> (64 - n));
}

#define MM256_ROTR_EPI64_IMM(x, n)                                             \
  _mm256_or_si256(_mm256_srli_epi64((x), (n)), _mm256_slli_epi64((x), 64 - (n)))

#define MM256_ROTL_EPI64_IMM(x, n)                                             \
  _mm256_or_si256(_mm256_slli_epi64((x), (n)), _mm256_srli_epi64((x), 64 - (n)))

#define MM256_ROT32_EPI64(x) _mm256_shuffle_epi32((x), 0xB1)

static inline __m256i mm256_rotl_var_epi64(__m256i x, int n) {
  n &= 63;
  if (n == 0)
    return x;
  return _mm256_or_si256(_mm256_slli_epi64(x, n), _mm256_srli_epi64(x, 64 - n));
}

static const uint8_t __attribute__((aligned(32))) SBOX_LUT[16][32] = {
    {0xA5,0xB6,0xDE,0xF7,0x18,0x37,0x8C,0xC1,0x89,0xDA,0x1E,0x85,0x31,0xF0,0x97,0x77,0xA5,0xB6,0xDE,0xF7,0x18,0x37,0x8C,0xC1,0x89,0xDA,0x1E,0x85,0x31,0xF0,0x97,0x77},
    {0x41,0x14,0xE8,0xC8,0x8A,0x04,0xB5,0x69,0x1D,0x2B,0x0F,0x2C,0x4E,0x19,0xCC,0x79,0x41,0x14,0xE8,0xC8,0x8A,0x04,0xB5,0x69,0x1D,0x2B,0x0F,0x2C,0x4E,0x19,0xCC,0x79},
    {0xD7,0x4D,0x7D,0x43,0x03,0x3A,0x13,0x92,0x32,0xD9,0x75,0xDF,0xAD,0x81,0xC3,0xF1,0xD7,0x4D,0x7D,0x43,0x03,0x3A,0x13,0x92,0x32,0xD9,0x75,0xDF,0xAD,0x81,0xC3,0xF1},
    {0xF9,0xA7,0xE2,0x35,0x02,0xDD,0x61,0xA2,0x50,0xE1,0x09,0xC5,0xE3,0x71,0xCB,0x99,0xF9,0xA7,0xE2,0x35,0x02,0xDD,0x61,0xA2,0x50,0xE1,0x09,0xC5,0xE3,0x71,0xCB,0x99},
    {0x9C,0xB1,0x23,0x86,0x3B,0x93,0x24,0xE9,0xF6,0xB4,0x6A,0x66,0xFE,0x7A,0x3E,0x28,0x9C,0xB1,0x23,0x86,0x3B,0x93,0x24,0xE9,0xF6,0xB4,0x6A,0x66,0xFE,0x7A,0x3E,0x28},
    {0x6E,0xF2,0x9B,0xF8,0x3F,0x2A,0x98,0x10,0xA1,0xFB,0x45,0x36,0x64,0x57,0x8F,0x72,0x6E,0xF2,0x9B,0xF8,0x3F,0x2A,0x98,0x10,0xA1,0xFB,0x45,0x36,0x64,0x57,0x8F,0x72},
    {0x8B,0x29,0x56,0xFD,0xF4,0xA4,0xED,0xA6,0x76,0xEB,0x6B,0x4A,0xC7,0x5E,0x26,0xD0,0x8B,0x29,0x56,0xFD,0xF4,0xA4,0xED,0xA6,0x76,0xEB,0x6B,0x4A,0xC7,0x5E,0x26,0xD0},
    {0x5F,0xCA,0x87,0x52,0x01,0x16,0x67,0xB9,0x74,0x4B,0xCF,0xD2,0x60,0x2F,0x49,0x6F,0x5F,0xCA,0x87,0x52,0x01,0x16,0x67,0xB9,0x74,0x4B,0xCF,0xD2,0x60,0x2F,0x49,0x6F},
    {0x39,0x1C,0x5D,0x53,0xE6,0x3C,0xC6,0x7F,0xEA,0xE5,0xBE,0x00,0x65,0x88,0x83,0xE4,0x39,0x1C,0x5D,0x53,0xE6,0x3C,0xC6,0x7F,0xEA,0xE5,0xBE,0x00,0x65,0x88,0x83,0xE4},
    {0x0C,0x38,0x2D,0x80,0xB0,0xAB,0x44,0x84,0x08,0x0D,0xB8,0x51,0x9A,0x2E,0x91,0x68,0x0C,0x38,0x2D,0x80,0xB0,0xAB,0x44,0x84,0x08,0x0D,0xB8,0x51,0x9A,0x2E,0x91,0x68},
    {0x40,0x0A,0xFC,0x82,0xBA,0xCE,0x0B,0xFA,0x1A,0x5B,0x62,0x22,0xC9,0x3D,0x8D,0x06,0x40,0x0A,0xFC,0x82,0xBA,0xCE,0x0B,0xFA,0x1A,0x5B,0x62,0x22,0xC9,0x3D,0x8D,0x06},
    {0x55,0xD5,0x78,0xAE,0x27,0x9D,0x9E,0xAF,0xB7,0x4F,0xDC,0x9F,0x42,0xA3,0xBC,0x15,0x55,0xD5,0x78,0xAE,0x27,0x9D,0x9E,0xAF,0xB7,0x4F,0xDC,0x9F,0x42,0xA3,0xBC,0x15},
    {0xB2,0xDB,0x11,0xA9,0x5C,0xE7,0x7B,0xEF,0xFF,0xC2,0x25,0xEE,0x73,0xF5,0xD6,0x48,0xB2,0xDB,0x11,0xA9,0x5C,0xE7,0x7B,0xEF,0xFF,0xC2,0x25,0xEE,0x73,0xF5,0xD6,0x48},
    {0x4C,0x21,0x70,0xD1,0x30,0x54,0xA0,0xB3,0x94,0x07,0x58,0xAA,0x96,0x1B,0x1F,0x0E,0x4C,0x21,0x70,0xD1,0x30,0x54,0xA0,0xB3,0x94,0x07,0x58,0xAA,0x96,0x1B,0x1F,0x0E},
    {0xD8,0x17,0xE0,0xBB,0x46,0x6C,0xAC,0xA8,0x05,0x7E,0x8E,0x33,0xC4,0xD4,0x59,0xBD,0xD8,0x17,0xE0,0xBB,0x46,0x6C,0xAC,0xA8,0x05,0x7E,0x8E,0x33,0xC4,0xD4,0x59,0xBD},
    {0xBF,0xF3,0x20,0x34,0x90,0xCD,0xEC,0x63,0x47,0x95,0x12,0x6D,0xD3,0x5A,0xC0,0x7C,0xBF,0xF3,0x20,0x34,0x90,0xCD,0xEC,0x63,0x47,0x95,0x12,0x6D,0xD3,0x5A,0xC0,0x7C}};

static inline __m256i sbox8_abyssal256(__m256i x) {
  __m256i mask = _mm256_set1_epi8(0x0F);
  __m256i lo = _mm256_and_si256(x, mask);
  __m256i hi = _mm256_and_si256(_mm256_srli_epi64(x, 4), mask);

  __m256i b0 = _mm256_slli_epi16(hi, 7);
  __m256i b1 = _mm256_slli_epi16(hi, 6);
  __m256i b2 = _mm256_slli_epi16(hi, 5);
  __m256i b3 = _mm256_slli_epi16(hi, 4);

  __m256i l0 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[0]), lo);
  __m256i l1 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[1]), lo);
  __m256i m00 = _mm256_blendv_epi8(l0, l1, b0);

  __m256i l2 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[2]), lo);
  __m256i l3 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[3]), lo);
  __m256i m01 = _mm256_blendv_epi8(l2, l3, b0);
  __m256i m10 = _mm256_blendv_epi8(m00, m01, b1);

  __m256i l4 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[4]), lo);
  __m256i l5 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[5]), lo);
  __m256i m02 = _mm256_blendv_epi8(l4, l5, b0);

  __m256i l6 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[6]), lo);
  __m256i l7 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[7]), lo);
  __m256i m03 = _mm256_blendv_epi8(l6, l7, b0);
  __m256i m11 = _mm256_blendv_epi8(m02, m03, b1);

  __m256i m20 = _mm256_blendv_epi8(m10, m11, b2);

  __m256i l8 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[8]), lo);
  __m256i l9 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[9]), lo);
  __m256i m04 = _mm256_blendv_epi8(l8, l9, b0);

  __m256i l10 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[10]), lo);
  __m256i l11 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[11]), lo);
  __m256i m05 = _mm256_blendv_epi8(l10, l11, b0);
  __m256i m12 = _mm256_blendv_epi8(m04, m05, b1);

  __m256i l12 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[12]), lo);
  __m256i l13 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[13]), lo);
  __m256i m06 = _mm256_blendv_epi8(l12, l13, b0);

  __m256i l14 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[14]), lo);
  __m256i l15 =
      _mm256_shuffle_epi8(_mm256_load_si256((const __m256i *)SBOX_LUT[15]), lo);
  __m256i m07 = _mm256_blendv_epi8(l14, l15, b0);
  __m256i m13 = _mm256_blendv_epi8(m06, m07, b1);

  __m256i m21 = _mm256_blendv_epi8(m12, m13, b2);
  return _mm256_blendv_epi8(m20, m21, b3);
}

static const uint64_t rho[32] __attribute__((aligned(32))) = {
    32, 1,  62, 28, 36, 44, 15, 61, 6,  19, 24, 55, 3, 10, 43, 17,
    25, 39, 41, 59, 47, 8,  56, 14, 18, 35, 21, 33, 2, 49, 22, 51};

static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

static void keccakf1600(uint64_t st[25]) {
  static const int rho_off[24] = {1,  3,  6,  10, 15, 21, 28, 36,
                                  45, 55, 2,  14, 27, 41, 56, 8,
                                  25, 43, 62, 18, 39, 61, 20, 44};
  static const int pi_idx[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                                 15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};
  for (int r = 0; r < 24; r++) {
    uint64_t bc[5], t;
    for (int i = 0; i < 5; i++)
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (int i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (int j = 0; j < 25; j += 5)
        st[j + i] ^= t;
    }
    t = st[1];
    for (int i = 0; i < 24; i++) {
      int j = pi_idx[i];
      bc[0] = st[j];
      st[j] = rotl64(t, rho_off[i]);
      t = bc[0];
    }
    for (int j = 0; j < 25; j += 5) {
      for (int i = 0; i < 5; i++)
        bc[i] = st[j + i];
      for (int i = 0; i < 5; i++)
        st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
    st[0] ^= keccak_rc[r];
  }
}

static void shake128_squeeze(const char *domain, uint8_t *out, size_t outlen) {
  uint64_t st[25] = {0};
  const size_t rate = 168;
  uint8_t *st8 = (uint8_t *)st;
  size_t dlen = strlen(domain);
  for (size_t i = 0; i < dlen; i++)
    st8[i] ^= (uint8_t)domain[i];
  st8[dlen] ^= 0x1F;
  st8[rate - 1] ^= 0x80;
  keccakf1600(st);
  size_t done = 0;
  while (done < outlen) {
    size_t take = outlen - done < rate ? outlen - done : rate;
    memcpy(out + done, st8, take);
    done += take;
    if (done < outlen)
      keccakf1600(st);
  }
}

static uint64_t rc[KRAKKEN_ROUNDS][32] __attribute__((aligned(32)));
static __m256i RC_VEC[KRAKKEN_ROUNDS][8] __attribute__((aligned(32)));
static __m256i RHO_VEC[8] __attribute__((aligned(32)));
static __m256i RHO_INV_VEC[8] __attribute__((aligned(32)));
static pthread_once_t g_rc_once = PTHREAD_ONCE_INIT;
static __m256i MDS_TBL_LO[16] __attribute__((aligned(32)));
static __m256i MDS_TBL_HI[16] __attribute__((aligned(32)));

static uint8_t gf28_mul_impl(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1)
      p ^= a;
    uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi)
      a ^= 0x1d;
    b >>= 1;
  }
  return p;
}

static void _rc_init_impl(void) {
  uint8_t buf[KRAKKEN_ROUNDS * 32 * 8];
  shake128_squeeze("Krakken-2048 Abyssal v1 - Primary ", buf, sizeof(buf));
  for (int ir = 0; ir < KRAKKEN_ROUNDS; ir++) {
    for (int i = 0; i < 32; i++) {
      const uint8_t *p = buf + (ir * 32 + i) * 8;
      uint64_t v = (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
                   ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
                   ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
                   ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
      rc[ir][i] = v ? v : 0xDEADBEEFCAFEBABEULL;
    }
    for (int c = 0; c < 8; c++)
      RC_VEC[ir][c] = _mm256_load_si256((const __m256i *)&rc[ir][c * 4]);
  }
  __m256i c64 = _mm256_set1_epi64x(64);
  for (int c = 0; c < 8; c++) {
    RHO_VEC[c] = _mm256_load_si256((const __m256i *)&rho[c * 4]);
    RHO_INV_VEC[c] = _mm256_sub_epi64(c64, RHO_VEC[c]);
  }

  static const uint8_t coeffs[8] = {0x01, 0x01, 0x04, 0x01,
                                    0x08, 0x05, 0x02, 0x09};
  for (int i = 0; i < 8; i++) {
    uint8_t k = coeffs[i];
    uint8_t tlo[16], thi[16];
    for (int j = 0; j < 16; j++) {
      tlo[j] = gf28_mul_impl((uint8_t)j, k);
      thi[j] = gf28_mul_impl((uint8_t)(j << 4), k);
    }
    MDS_TBL_LO[i] = _mm256_setr_epi8(
        tlo[0], tlo[1], tlo[2], tlo[3], tlo[4], tlo[5], tlo[6], tlo[7], tlo[8],
        tlo[9], tlo[10], tlo[11], tlo[12], tlo[13], tlo[14], tlo[15], tlo[0],
        tlo[1], tlo[2], tlo[3], tlo[4], tlo[5], tlo[6], tlo[7], tlo[8], tlo[9],
        tlo[10], tlo[11], tlo[12], tlo[13], tlo[14], tlo[15]);
    MDS_TBL_HI[i] = _mm256_setr_epi8(
        thi[0], thi[1], thi[2], thi[3], thi[4], thi[5], thi[6], thi[7], thi[8],
        thi[9], thi[10], thi[11], thi[12], thi[13], thi[14], thi[15], thi[0],
        thi[1], thi[2], thi[3], thi[4], thi[5], thi[6], thi[7], thi[8], thi[9],
        thi[10], thi[11], thi[12], thi[13], thi[14], thi[15]);
  }
}

void init_rc_vectors_avx2(void) { pthread_once(&g_rc_once, _rc_init_impl); }

static inline __attribute__((always_inline)) void theta_regs(__m256i cols[8]) {
  __m256i P[8];
  for (int c = 0; c < 8; c++) {
    __m256i t = _mm256_xor_si256(cols[c], _mm256_shuffle_epi32(cols[c], 0x4E));
    P[c] = _mm256_xor_si256(t, _mm256_permute2x128_si256(t, t, 0x01));
  }
  for (int c = 0; c < 8; c++) {
    __m256i d = _mm256_xor_si256(MM256_ROTL_EPI64_IMM(P[(c + 7) & 7], 63),
                                 P[(c + 1) & 7]);
    cols[c] = _mm256_xor_si256(cols[c], d);
  }
}

static inline __m256i mm256_gf28_mul_k(__m256i x, int k_idx) {
  __m256i mask = _mm256_set1_epi8(0x0F);
  __m256i lo = _mm256_and_si256(x, mask);
  __m256i hi = _mm256_and_si256(_mm256_srli_epi64(x, 4), mask);
  return _mm256_xor_si256(_mm256_shuffle_epi8(MDS_TBL_LO[k_idx], lo),
                          _mm256_shuffle_epi8(MDS_TBL_HI[k_idx], hi));
}

#define MDS_MUL_XOR(out_c, in_idx, tlo, thi)                                   \
  out_c = _mm256_xor_si256(                                                    \
      out_c, _mm256_xor_si256(_mm256_shuffle_epi8(tlo, lo[in_idx]),            \
                              _mm256_shuffle_epi8(thi, hi[in_idx])))

static inline __attribute__((always_inline)) void tentacle_mds_regs(__m256i cols[8]) {
  __m256i out[8], lo[8], hi[8];
  __m256i mask = _mm256_set1_epi8(0x0F);

  for (int c = 0; c < 8; c++) {
    lo[c] = _mm256_and_si256(cols[c], mask);
    hi[c] = _mm256_and_si256(_mm256_srli_epi64(cols[c], 4), mask);
    out[c] = _mm256_xor_si256(
        cols[c], _mm256_xor_si256(cols[(c + 1) & 7], cols[(c + 3) & 7]));
  }

  __m256i tlo2 = MDS_TBL_LO[2], thi2 = MDS_TBL_HI[2];
  __m256i tlo4 = MDS_TBL_LO[4], thi4 = MDS_TBL_HI[4];
  __m256i tlo5 = MDS_TBL_LO[5], thi5 = MDS_TBL_HI[5];
  __m256i tlo6 = MDS_TBL_LO[6], thi6 = MDS_TBL_HI[6];
  __m256i tlo7 = MDS_TBL_LO[7], thi7 = MDS_TBL_HI[7];

  for (int c = 0; c < 8; c++) {
    MDS_MUL_XOR(out[c], (c + 2) & 7, tlo2, thi2);
    MDS_MUL_XOR(out[c], (c + 4) & 7, tlo4, thi4);
    MDS_MUL_XOR(out[c], (c + 5) & 7, tlo5, thi5);
    MDS_MUL_XOR(out[c], (c + 6) & 7, tlo6, thi6);
    MDS_MUL_XOR(out[c], (c + 7) & 7, tlo7, thi7);
  }

  for (int c = 0; c < 8; c++)
    cols[c] = out[c];
}

static inline __attribute__((always_inline)) void rho_regs(__m256i cols[8]) {
  for (int c = 0; c < 8; c++) {
    cols[c] = _mm256_or_si256(_mm256_sllv_epi64(cols[c], RHO_VEC[c]),
                              _mm256_srlv_epi64(cols[c], RHO_INV_VEC[c]));
  }
}

static inline __attribute__((always_inline)) void pi_regs(__m256i cols[8]) {
  __m256i out[8];
  for (int c = 0; c < 8; c++) {
    out[c] = _mm256_blend_epi32(
        _mm256_blend_epi32(cols[c], cols[(c + 5) & 7], 0x0C),
        _mm256_blend_epi32(cols[(c + 2) & 7], cols[(c + 7) & 7], 0xC0), 0xF0);
  }
  for (int c = 0; c < 8; c++)
    cols[c] = out[c];
}

static inline __attribute__((always_inline)) void chi_regs(__m256i cols[8]) {
  for (int p = 0; p < 4; p++) {
    __m256i a = cols[p * 2];
    __m256i b = cols[p * 2 + 1];
    __m256i rb = MM256_ROT32_EPI64(b);
    __m256i ap = sbox8_abyssal256(_mm256_xor_si256(a, rb));
    __m256i ra = MM256_ROT32_EPI64(ap);
    __m256i bp = sbox8_abyssal256(_mm256_xor_si256(b, ra));
    cols[p * 2] = ap;
    cols[p * 2 + 1] = bp;
  }
}

#define PRESSURE_ROUND_VEC(a, b, c, d)                                         \
  do {                                                                         \
    a = _mm256_add_epi64(a, _mm256_xor_si256(c, _mm256_srli_epi64(c, 17)));    \
    b = _mm256_add_epi64(b, _mm256_xor_si256(d, _mm256_srli_epi64(d, 17)));    \
    c = _mm256_add_epi64(c, _mm256_xor_si256(a, _mm256_slli_epi64(a, 31)));    \
    d = _mm256_add_epi64(d, _mm256_xor_si256(b, _mm256_slli_epi64(b, 31)));    \
  } while (0)

static inline __attribute__((always_inline)) void pressure_arx_regs(__m256i cols[8]) {
  __m256i u0 = _mm256_unpacklo_epi64(cols[0], cols[1]);
  __m256i u1 = _mm256_unpackhi_epi64(cols[0], cols[1]);
  __m256i u2 = _mm256_unpacklo_epi64(cols[2], cols[3]);
  __m256i u3 = _mm256_unpackhi_epi64(cols[2], cols[3]);
  __m256i a = _mm256_permute2x128_si256(u0, u2, 0x20);
  __m256i b = _mm256_permute2x128_si256(u1, u3, 0x20);
  __m256i c = _mm256_permute2x128_si256(u0, u2, 0x31);
  __m256i d = _mm256_permute2x128_si256(u1, u3, 0x31);

  __m256i u4 = _mm256_unpacklo_epi64(cols[4], cols[5]);
  __m256i u5 = _mm256_unpackhi_epi64(cols[4], cols[5]);
  __m256i u6 = _mm256_unpacklo_epi64(cols[6], cols[7]);
  __m256i u7 = _mm256_unpackhi_epi64(cols[6], cols[7]);
  __m256i a2 = _mm256_permute2x128_si256(u4, u6, 0x20);
  __m256i b2 = _mm256_permute2x128_si256(u5, u7, 0x20);
  __m256i c2 = _mm256_permute2x128_si256(u4, u6, 0x31);
  __m256i d2 = _mm256_permute2x128_si256(u5, u7, 0x31);

  PRESSURE_ROUND_VEC(a, b, c, d);
  PRESSURE_ROUND_VEC(a2, b2, c2, d2);

  b = MM256_ROTL_EPI64_IMM(b, 7);
  d = MM256_ROTL_EPI64_IMM(d, 19);
  b2 = MM256_ROTL_EPI64_IMM(b2, 7);
  d2 = MM256_ROTL_EPI64_IMM(d2, 19);

  __m256i r0 = _mm256_unpacklo_epi64(a, b);
  __m256i r1 = _mm256_unpackhi_epi64(a, b);
  __m256i r2 = _mm256_unpacklo_epi64(c, d);
  __m256i r3 = _mm256_unpackhi_epi64(c, d);
  cols[0] = _mm256_permute2x128_si256(r0, r2, 0x20);
  cols[1] = _mm256_permute2x128_si256(r1, r3, 0x20);
  cols[2] = _mm256_permute2x128_si256(r0, r2, 0x31);
  cols[3] = _mm256_permute2x128_si256(r1, r3, 0x31);

  __m256i r4 = _mm256_unpacklo_epi64(a2, b2);
  __m256i r5 = _mm256_unpackhi_epi64(a2, b2);
  __m256i r6 = _mm256_unpacklo_epi64(c2, d2);
  __m256i r7 = _mm256_unpackhi_epi64(c2, d2);
  cols[4] = _mm256_permute2x128_si256(r4, r6, 0x20);
  cols[5] = _mm256_permute2x128_si256(r5, r7, 0x20);
  cols[6] = _mm256_permute2x128_si256(r4, r6, 0x31);
  cols[7] = _mm256_permute2x128_si256(r5, r7, 0x31);
}

static inline __attribute__((always_inline)) void beta_iota_regs(__m256i cols[8], int round) {
  for (int c = 0; c < 8; c++) {
    cols[c] = _mm256_xor_si256(cols[c], RC_VEC[round][c]);
  }
}

static inline __attribute__((always_inline)) void ink_cloud_regs(__m256i cols[8]) {
  for (int c = 0; c < 8; c++)
    cols[c] = MM256_ROTL_EPI64_IMM(cols[c], 11);

  __m256i t0 = cols[0], t1 = cols[1], t2 = cols[2], t3 = cols[3];
  __m256i t4 = cols[4], t5 = cols[5], t6 = cols[6], t7 = cols[7];

#define L0(v) _mm256_permute4x64_epi64(v, 0x00)
#define L1(v) _mm256_permute4x64_epi64(v, 0x55)
#define L2(v) _mm256_permute4x64_epi64(v, 0xAA)
#define L3(v) _mm256_permute4x64_epi64(v, 0xFF)

  cols[0] = _mm256_blend_epi32(L0(t0), L3(t5), 0x0C);
  cols[0] = _mm256_blend_epi32(cols[0], L2(t3), 0x30);
  cols[0] = _mm256_blend_epi32(cols[0], L1(t1), 0xC0);

  cols[1] = _mm256_blend_epi32(L0(t7), L3(t4), 0x0C);
  cols[1] = _mm256_blend_epi32(cols[1], L2(t2), 0x30);
  cols[1] = _mm256_blend_epi32(cols[1], L1(t0), 0xC0);

  cols[2] = _mm256_blend_epi32(L0(t6), L3(t3), 0x0C);
  cols[2] = _mm256_blend_epi32(cols[2], L2(t1), 0x30);
  cols[2] = _mm256_blend_epi32(cols[2], L1(t7), 0xC0);

  cols[3] = _mm256_blend_epi32(L0(t5), L3(t2), 0x0C);
  cols[3] = _mm256_blend_epi32(cols[3], L2(t0), 0x30);
  cols[3] = _mm256_blend_epi32(cols[3], L1(t6), 0xC0);

  cols[4] = _mm256_blend_epi32(L0(t4), L3(t1), 0x0C);
  cols[4] = _mm256_blend_epi32(cols[4], L2(t7), 0x30);
  cols[4] = _mm256_blend_epi32(cols[4], L1(t5), 0xC0);

  cols[5] = _mm256_blend_epi32(L0(t3), L3(t0), 0x0C);
  cols[5] = _mm256_blend_epi32(cols[5], L2(t6), 0x30);
  cols[5] = _mm256_blend_epi32(cols[5], L1(t4), 0xC0);

  cols[6] = _mm256_blend_epi32(L0(t2), L3(t7), 0x0C);
  cols[6] = _mm256_blend_epi32(cols[6], L2(t5), 0x30);
  cols[6] = _mm256_blend_epi32(cols[6], L1(t3), 0xC0);

  cols[7] = _mm256_blend_epi32(L0(t1), L3(t6), 0x0C);
  cols[7] = _mm256_blend_epi32(cols[7], L2(t4), 0x30);
  cols[7] = _mm256_blend_epi32(cols[7], L1(t2), 0xC0);
#undef L0
#undef L1
#undef L2
#undef L3
}

void krakken_permute_avx2_rounds(uint64_t state[32], int rounds) {
  init_rc_vectors_avx2();
  if (rounds <= 0)
    return;
  if (rounds > KRAKKEN_ROUNDS)
    rounds = KRAKKEN_ROUNDS;
  __m256i cols[8];
  for (int c = 0; c < 8; c++)
    cols[c] = _mm256_loadu_si256((const __m256i *)&state[c * 4]);
  for (int ir = 0; ir < rounds; ir++) {
    theta_regs(cols);
    tentacle_mds_regs(cols);
    rho_regs(cols);
    pi_regs(cols);
    chi_regs(cols);
    pressure_arx_regs(cols);
    beta_iota_regs(cols, ir);
    ink_cloud_regs(cols);
  }
  for (int c = 0; c < 8; c++)
    _mm256_storeu_si256((__m256i *)&state[c * 4], cols[c]);
}

void krakken_permute_avx2(uint64_t state[32]) {
  krakken_permute_avx2_rounds(state, KRAKKEN_ROUNDS);
}

static inline void absorb_rate_avx2(uint8_t state_b[256], const uint8_t *msg) {
  __m256i *sp = (__m256i *)state_b;
  for (int i = 0; i < 5; i++) {
    __m256i sv = _mm256_load_si256(sp + i);
    __m256i mv = _mm256_loadu_si256((const __m256i *)(msg + i * 32));
    _mm256_store_si256(sp + i, _mm256_xor_si256(sv, mv));
  }
}

void krakken_hash_avx2(uint8_t *out, size_t outlen, const uint8_t *in,
                       size_t inlen) {
  if (outlen == 0)
    return;
  init_rc_vectors_avx2();
  union {
    uint64_t w[32];
    uint8_t b[256];
  } state __attribute__((aligned(32)));
  memset(state.b, 0, 256);
  const uint8_t *msg = in;
  size_t rem = inlen;

  while (rem >= 160) {
    absorb_rate_avx2(state.b, msg);
    krakken_permute_avx2(state.w);
    msg += 160;
    rem -= 160;
  }

  uint8_t block[160] __attribute__((aligned(32)));
  memset(block, 0, 160);
  if (rem > 0)
    memcpy(block, msg, rem);
  uint8_t mask = (uint8_t)(-(rem < 159));
  block[rem]  = (uint8_t)((block[rem] & ~mask) | (0x06 & mask));
  block[159]  = (uint8_t)((mask & 0x80) | ((~mask) & 0x86));
  absorb_rate_avx2(state.b, block);
  krakken_permute_avx2(state.w);

  while (outlen > 0) {
    size_t take = outlen < 160 ? outlen : 160;
    memcpy(out, state.b, take);
    out += take;
    outlen -= take;
    if (outlen > 0)
      krakken_permute_avx2(state.w);
  }

  krakken_secure_zero(state.b, 256);
  krakken_secure_zero(block, 160);
}

typedef struct {
  uint8_t *out;
  size_t outlen;
  const uint8_t *in;
  size_t inlen;
} krakken_stream_t;
typedef struct {
  const krakken_stream_t *streams;
  int start;
  int end;
} krakken_worker_arg_t;

static void *krakken_parallel_worker(void *arg) {
  const krakken_worker_arg_t *w = (const krakken_worker_arg_t *)arg;
  for (int i = w->start; i < w->end; i++)
    krakken_hash_avx2(w->streams[i].out, w->streams[i].outlen, w->streams[i].in,
                      w->streams[i].inlen);
  return NULL;
}

int krakken_hash_avx2_parallel(const krakken_stream_t *streams, int n,
                               int n_threads) {
  if (n <= 0)
    return 0;
  if (n_threads < 1)
    n_threads = 1;
  if (n_threads > n)
    n_threads = n;
  init_rc_vectors_avx2();

  pthread_t *tids = malloc((size_t)n_threads * sizeof(pthread_t));
  krakken_worker_arg_t *args =
      malloc((size_t)n_threads * sizeof(krakken_worker_arg_t));

  if (!tids || !args) {
    free(tids);
    free(args);
    return -1;
  }

  // Initialize args array completely first
  int base = n / n_threads, extra = n % n_threads, cur = 0;
  for (int t = 0; t < n_threads; t++) {
    args[t].streams = streams;
    args[t].start = cur;
    args[t].end = cur + base + (t < extra ? 1 : 0);
    cur = args[t].end;
  }

  // Create threads safely
  int rc_ret = 0;
  for (int t = 0; t < n_threads; t++) {
    if (pthread_create(&tids[t], NULL, krakken_parallel_worker, &args[t]) != 0) {
      for (int j = t; j < n_threads; j++)
        krakken_parallel_worker(&args[j]);
      for (int j = 0; j < t; j++)
        pthread_join(tids[j], NULL);
      rc_ret = -1;
      goto done;
    }
  }
  for (int t = 0; t < n_threads; t++)
    pthread_join(tids[t], NULL);
done:
  free(tids);
  free(args);
  return rc_ret;
}

#ifdef KRAKKEN_MAIN
static double get_time(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + tv.tv_usec * 1e-6;
}
static void benchmark_single(void) {
  const size_t DATA = 16 * 1024 * 1024;
  const int ITER = 20;
  uint8_t *data = malloc(DATA), *hash = malloc(32);
  for (size_t i = 0; i < DATA; i++)
    data[i] = (uint8_t)(i ^ (i >> 8) ^ (i >> 16));
  printf(
      "Krakken-2048 Abyssal (10 rounds) AVX2 "
      "Single-thread\n----------------------------------------------------\n");
  krakken_hash_avx2(hash, 32, data, DATA);
  double t0 = get_time();
  for (int i = 0; i < ITER; i++)
    krakken_hash_avx2(hash, 32, data, DATA);
  double avg = (get_time() - t0) / ITER;
  double mbps = (DATA / (1024.0 * 1024.0)) / avg;
  printf("Throughput   : %.2f MB/s\n\n", mbps);
  free(data);
  free(hash);
}

static void benchmark_parallel(int n_threads) {
  const size_t DATA = 16 * 1024 * 1024;
  const int ITER = 20;
  uint8_t *all = malloc((size_t)n_threads * DATA);
  krakken_stream_t *streams =
      malloc((size_t)n_threads * sizeof(krakken_stream_t));
  uint8_t *hashes = malloc((size_t)n_threads * 32);

  for (int t = 0; t < n_threads; t++) {
    uint8_t *ptr = all + (size_t)t * DATA;
    for (size_t i = 0; i < DATA; i++)
      ptr[i] = (uint8_t)(i ^ t);
    streams[t].in = ptr;
    streams[t].inlen = DATA;
    streams[t].out = hashes + t * 32;
    streams[t].outlen = 32;
  }

  printf(
      "Parallel benchmark  (%d threads)\n----------------------------------\n",
      n_threads);
  double t0 = get_time();
  for (int i = 0; i < ITER; i++) {
    krakken_hash_avx2_parallel(streams, n_threads, n_threads);
  }
  double elapsed = get_time() - t0;
  double total_mb = ((double)DATA * ITER * n_threads) / (1024.0 * 1024.0);
  printf("Wall time        : %.3f s\n", elapsed);
  printf("Aggregate MB/s   : %.2f  (%.3f GB/s)\n\n", total_mb / elapsed,
         (total_mb / elapsed) / 1024.0);

  free(all);
  free(streams);
  free(hashes);
}

int main(void) {
  printf(
      "Krakken-2048 Abyssal (10 rounds) AVX2 + "
      "Multi-thread\n====================================================\n\n");
  init_rc_vectors_avx2();

  benchmark_single();
  benchmark_parallel(1);
  benchmark_parallel(4);
  benchmark_parallel(8);

  uint8_t empty[32];
  krakken_hash_avx2(empty, 32, (const uint8_t *)"", 0);
  printf("Empty hash   : ");
  for (int i = 0; i < 32; i++)
    printf("%02x", empty[i]);
  printf("\n");
  return 0;
}
#endif
