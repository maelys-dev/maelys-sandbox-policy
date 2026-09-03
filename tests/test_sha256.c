#include "internal.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void digest_hex(const char *input, char out[65]) {
  static const char digits[] = "0123456789abcdef";
  uint8_t digest[32];
  maelys_sha256((const uint8_t *)input, strlen(input), digest);
  for (size_t i = 0; i < 32; ++i) {
    out[2u * i] = digits[digest[i] >> 4];
    out[2u * i + 1u] = digits[digest[i] & 15u];
  }
  out[64] = '\0';
}

static void check_vector(const char *input, const char *expected) {
  char actual[65];
  digest_hex(input, actual);
  if (strcmp(actual, expected) != 0) {
    fprintf(stderr, "SHA-256 vector mismatch:\nexpected %s\nactual   %s\n",
            expected, actual);
    ++failures;
  }
}

int main(void) {
  check_vector("", "e3b0c44298fc1c149afbf4c8996fb924"
                   "27ae41e4649b934ca495991b7852b855");
  check_vector("abc", "ba7816bf8f01cfea414140de5dae2223"
                      "b00361a396177a9cb410ff61f20015ad");
  return failures ? 1 : 0;
}
