#include "internal.h"

#include <string.h>

typedef struct sha256_ctx {
  uint32_t h[8];
  uint64_t bits;
  uint8_t block[64];
  size_t used;
} sha256_ctx_t;

static uint32_t rotr(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32u - n));
}
static uint32_t load32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}
static void store32(uint8_t *p, uint32_t x) {
  p[0] = (uint8_t)(x >> 24);
  p[1] = (uint8_t)(x >> 16);
  p[2] = (uint8_t)(x >> 8);
  p[3] = (uint8_t)x;
}

static void transform(sha256_ctx_t *c, const uint8_t block[64]) {
  static const uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  uint32_t w[64];
  for (size_t i = 0; i < 16; ++i)
    w[i] = load32(block + 4u * i);
  for (size_t i = 16; i < 64; ++i) {
    uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = c->h[0], b = c->h[1], d = c->h[3], e = c->h[4], f = c->h[5],
           g = c->h[6], h = c->h[7], cc = c->h[2];
  for (size_t i = 0; i < 64; ++i) {
    uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25),
             ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + s1 + ch + k[i] + w[i],
             s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc), t2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = cc;
    cc = b;
    b = a;
    a = t1 + t2;
  }
  c->h[0] += a;
  c->h[1] += b;
  c->h[2] += cc;
  c->h[3] += d;
  c->h[4] += e;
  c->h[5] += f;
  c->h[6] += g;
  c->h[7] += h;
}

static void update(sha256_ctx_t *c, const uint8_t *data, size_t size) {
  c->bits += (uint64_t)size * 8u;
  while (size) {
    size_t take = 64u - c->used;
    if (take > size)
      take = size;
    memcpy(c->block + c->used, data, take);
    c->used += take;
    data += take;
    size -= take;
    if (c->used == 64u) {
      transform(c, c->block);
      c->used = 0;
    }
  }
}

void maelys_sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
  sha256_ctx_t c = {{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
                     0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
                    0,
                    {0},
                    0};
  update(&c, data, size);
  c.block[c.used++] = 0x80;
  if (c.used > 56u) {
    memset(c.block + c.used, 0, 64u - c.used);
    transform(&c, c.block);
    c.used = 0;
  }
  memset(c.block + c.used, 0, 56u - c.used);
  for (unsigned i = 0; i < 8; ++i)
    c.block[63u - i] = (uint8_t)(c.bits >> (8u * i));
  transform(&c, c.block);
  for (size_t i = 0; i < 8; ++i)
    store32(out + 4u * i, c.h[i]);
}

void maelys_digest_to_hex(const uint8_t digest[32],
                          char out[MAELYS_MIR_DIGEST_HEX_SIZE]) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < 32u; ++i) {
    out[2u * i] = hex[digest[i] >> 4];
    out[2u * i + 1u] = hex[digest[i] & 15u];
  }
  out[64] = '\0';
}

maelys_mir_result_t maelys_mir_artifact_digest_hex(
    const uint8_t *bytes, size_t size,
    char out[MAELYS_MIR_DIGEST_HEX_SIZE], char **err) {
  if ((!bytes && size != 0u) || !out) {
    maelys_set_error(err, "artifact bytes and digest output are required");
    return MAELYS_MIR_ERR_ARGUMENT;
  }
  uint8_t digest[32];
  maelys_sha256(bytes, size, digest);
  maelys_digest_to_hex(digest, out);
  return MAELYS_MIR_OK;
}
