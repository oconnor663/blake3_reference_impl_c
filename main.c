#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reference_impl.h"

#ifdef _WIN32
// Needed to switch stdin to binary mode.
#include <fcntl.h>
#include <io.h>
#endif

inline static uint8_t nibble_from_hex_char(char hex_char) {
  assert(('0' <= hex_char && hex_char <= '9') ||
         ('a' <= hex_char && hex_char <= 'f'));
  if ('0' <= hex_char && hex_char <= '9') {
    return (uint8_t)(hex_char - '0');
  } else {
    return (uint8_t)(hex_char - 'a') + 10;
  }
}

inline static void key_bytes_from_hex(const char *hex_key,
                                      uint8_t out[BLAKE3_KEY_LEN]) {
  assert(strlen(hex_key) == 2 * BLAKE3_KEY_LEN);
  for (size_t i = 0; i < BLAKE3_KEY_LEN; i++) {
    out[i] = nibble_from_hex_char(hex_key[2 * i]) * 16;
    out[i] += nibble_from_hex_char(hex_key[2 * i + 1]);
  }
}

int main(int argc, char **argv) {
#ifdef _WIN32
  // Windows defaults to text mode, which will mess with newlines in our input.
  // This switches to binary mode.
  _setmode(_fileno(stdin), _O_BINARY);
#endif

  uint8_t key[BLAKE3_KEY_LEN];
  bool has_key = false;
  const char *derive_key_context = NULL;
  size_t output_len = BLAKE3_OUT_LEN;

  // This is a toy main function, and we don't bother to check for invalid
  // inputs like negative lengths here.
  while (argc > 1) {
    if (strcmp(argv[1], "--help") == 0) {
      printf("Usage: blake3 [--len <BYTES>] [--key <HEX>] [--derive-key "
             "<CONTEXT>]\n");
      return 0;
    } else if (strcmp(argv[1], "--len") == 0) {
      output_len = (size_t)strtoll(argv[2], NULL, 10);
    } else if (strcmp(argv[1], "--key") == 0) {
      assert(derive_key_context == NULL);
      key_bytes_from_hex(argv[2], key);
      has_key = true;
    } else if (strcmp(argv[1], "--derive-key") == 0) {
      assert(!has_key);
      derive_key_context = argv[2];
    }
    argc -= 2;
    argv += 2;
  }

  // Initialize the hasher.
  blake3_hasher hasher;
  if (has_key) {
    blake3_hasher_init_keyed(&hasher, key);
  } else if (derive_key_context != NULL) {
    blake3_hasher_init_derive_key(&hasher, derive_key_context);
  } else {
    blake3_hasher_init(&hasher);
  }

  // Hash standard input until we reach EOF.
  unsigned char buf[65536];
  while (1) {
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0) {
      break; // EOF (or possibly an error)
    }
    blake3_hasher_update(&hasher, buf, n);
  }

  // Finalize the hash.
  uint8_t *output = malloc(output_len);
  assert(output != NULL);
  blake3_hasher_finalize(&hasher, output, output_len);

  // Print the hash as hexadecimal.
  for (size_t i = 0; i < output_len; i++) {
    printf("%02x", output[i]);
  }
  printf("\n");
  free(output);
  return 0;
}
