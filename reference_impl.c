#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define OUT_LEN 32
#define KEY_LEN 32
#define BLOCK_LEN 64
#define CHUNK_LEN 1024

#define CHUNK_START 1 << 0
#define CHUNK_END 1 << 1
#define PARENT 1 << 2
#define ROOT 1 << 3
#define KEYED_HASH 1 << 4
#define DERIVE_KEY_CONTEXT 1 << 5
#define DERIVE_KEY_MATERIAL 1 << 6

static uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

static size_t MSG_PERMUTATION[16] = {2, 6,  3,  10, 7, 0,  4,  13,
                                     1, 11, 12, 5,  9, 14, 15, 8};

static uint32_t rotate_right(uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}

// The mixing function, G, which mixes either a column or a diagonal.
static void g(uint32_t state[16], size_t a, size_t b, size_t c, size_t d,
              uint32_t mx, uint32_t my) {
  state[a] = state[a] + state[b] + mx;
  state[d] = rotate_right(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = rotate_right(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + my;
  state[d] = rotate_right(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = rotate_right(state[b] ^ state[c], 7);
}

static void round_function(uint32_t state[16], uint32_t m[16]) {
  // Mix the columns.
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  // Mix the diagonals.
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}

static void permute(uint32_t m[16]) {
  uint32_t permuted[16];
  for (size_t i = 0; i < 16; i++) {
    permuted[i] = m[MSG_PERMUTATION[i]];
  }
  memcpy(m, permuted, sizeof(permuted));
}

static void compress(const uint32_t chaining_value[8],
                     const uint32_t block_words[16], uint64_t counter,
                     uint32_t block_len, uint32_t flags, uint32_t out[16]) {
  uint32_t state[16] = {
      chaining_value[0],
      chaining_value[1],
      chaining_value[2],
      chaining_value[3],
      chaining_value[4],
      chaining_value[5],
      chaining_value[6],
      chaining_value[7],
      IV[0],
      IV[1],
      IV[2],
      IV[3],
      (uint32_t)counter,
      (uint32_t)(counter >> 32),
      block_len,
      flags,
  };
  uint32_t block[16];
  memcpy(block, block_words, sizeof(block));

  round_function(state, block); // round 1
  permute(block);
  round_function(state, block); // round 2
  permute(block);
  round_function(state, block); // round 3
  permute(block);
  round_function(state, block); // round 4
  permute(block);
  round_function(state, block); // round 5
  permute(block);
  round_function(state, block); // round 6
  permute(block);
  round_function(state, block); // round 7

  for (size_t i = 0; i < 8; i++) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= chaining_value[i];
  }

  memcpy(out, state, sizeof(state));
}

static void words_from_little_endian_bytes(const void *bytes, size_t bytes_len,
                                           uint32_t *out) {
  assert(bytes_len % 4 == 0);
  const uint8_t *u8_ptr = (const uint8_t *)bytes;
  for (size_t i = 0; i < (bytes_len / 4); i++) {
    out[i] = ((uint32_t)(*u8_ptr++));
    out[i] += ((uint32_t)(*u8_ptr++)) << 8;
    out[i] += ((uint32_t)(*u8_ptr++)) << 16;
    out[i] += ((uint32_t)(*u8_ptr++)) << 24;
  }
}

// Each chunk or parent node can produce either an 8-word chaining value or, by
// setting the ROOT flag, any number of final output bytes. The Output struct
// captures the state just prior to choosing between those two possibilities.
typedef struct output {
  uint32_t input_chaining_value[8];
  uint32_t block_words[16];
  uint64_t counter;
  uint32_t block_len;
  uint32_t flags;
} output;

static void output_chaining_value(const output *self, uint32_t out[8]) {
  uint32_t out16[16];
  compress(self->input_chaining_value, self->block_words, self->counter,
           self->block_len, self->flags, out16);
  memcpy(out, out16, 8 * 4);
}

static void output_root_bytes(const output *self, void *out, size_t out_len) {
  uint8_t *out_u8 = (uint8_t *)out;
  uint64_t output_block_counter = 0;
  while (out_len > 0) {
    uint32_t words[16];
    compress(self->input_chaining_value, self->block_words,
             output_block_counter, self->block_len, self->flags | ROOT, words);
    for (size_t word = 0; word < 16; word++) {
      for (int byte = 0; byte < 4; byte++) {
        if (out_len == 0) {
          return;
        }
        *out_u8 = (uint8_t)(words[word] >> (8 * byte));
        out_u8++;
        out_len--;
      }
    }
    output_block_counter++;
  }
}

typedef struct chunk_state {
  uint32_t chaining_value[8];
  uint64_t chunk_counter;
  uint8_t block[BLOCK_LEN];
  uint8_t block_len;
  uint8_t blocks_compressed;
  uint32_t flags;
} chunk_state;

static void chunk_state_init(chunk_state *self, const uint32_t key_words[8],
                             uint64_t chunk_counter, uint32_t flags) {
  memcpy(self->chaining_value, key_words, sizeof(self->chaining_value));
  self->chunk_counter = chunk_counter;
  memset(self->block, 0, sizeof(self->block));
  self->block_len = 0;
  self->blocks_compressed = 0;
  self->flags = flags;
}

static size_t chunk_state_len(const chunk_state *self) {
  return BLOCK_LEN * (size_t)self->blocks_compressed + (size_t)self->block_len;
}

static uint32_t chunk_state_start_flag(const chunk_state *self) {
  if (self->blocks_compressed == 0) {
    return CHUNK_START;
  } else {
    return 0;
  }
}

static void chunk_state_update(chunk_state *self, const void *input,
                               size_t input_len) {
  const uint8_t *input_u8 = (const uint8_t *)input;
  while (input_len > 0) {
    // If the block buffer is full, compress it and clear it. More input is
    // coming, so this compression is not CHUNK_END.
    if (self->block_len == BLOCK_LEN) {
      uint32_t block_words[16];
      words_from_little_endian_bytes(self->block, BLOCK_LEN, block_words);
      uint32_t out16[16];
      compress(self->chaining_value, block_words, self->chunk_counter,
               BLOCK_LEN, self->flags | chunk_state_start_flag(self), out16);
      memcpy(self->chaining_value, out16, sizeof(self->chaining_value));
      self->blocks_compressed++;
      memset(self->block, 0, sizeof(self->block));
      self->block_len = 0;
    }

    // Copy input bytes into the block buffer.
    size_t want = BLOCK_LEN - (size_t)self->block_len;
    size_t take = want;
    if (input_len < want) {
      take = input_len;
    }
    memcpy(&self->block[(size_t)self->block_len], input_u8, take);
    self->block_len += (uint8_t)take;
    input_u8 += take;
    input_len -= take;
  }
}

static output chunk_state_output(const chunk_state *self) {
  output ret;
  memcpy(ret.input_chaining_value, self->chaining_value,
         sizeof(ret.input_chaining_value));
  words_from_little_endian_bytes(self->block, sizeof(self->block),
                                 ret.block_words);
  ret.counter = self->chunk_counter;
  ret.block_len = (uint32_t)self->block_len;
  ret.flags = self->flags | chunk_state_start_flag(self) | CHUNK_END;
  return ret;
}

static output parent_output(const uint32_t left_child_cv[8],
                            const uint32_t right_child_cv[8],
                            const uint32_t key_words[8], uint32_t flags) {
  output ret;
  memcpy(ret.input_chaining_value, key_words, sizeof(ret.input_chaining_value));
  memcpy(&ret.block_words[0], left_child_cv, 8 * 4);
  memcpy(&ret.block_words[8], right_child_cv, 8 * 4);
  ret.counter = 0;           // Always 0 for parent nodes.
  ret.block_len = BLOCK_LEN; // Always BLOCK_LEN (64) for parent nodes.
  ret.flags = PARENT | flags;
  return ret;
}

static void parent_cv(const uint32_t left_child_cv[8],
                      const uint32_t right_child_cv[8],
                      const uint32_t key_words[8], uint32_t flags,
                      uint32_t out[8]) {
  output o = parent_output(left_child_cv, right_child_cv, key_words, flags);
  // We only write to `out` after we've read the inputs. That makes it safe for
  // `out` to alias an input, which we do below.
  output_chaining_value(&o, out);
}

/// An incremental hasher that can accept any number of writes.
typedef struct blake3_hasher {
  chunk_state chunk_state;
  uint32_t key_words[8];
  uint32_t cv_stack[8 * 54]; // Space for 54 subtree chaining values:
  uint8_t cv_stack_len;      // 2^54 * CHUNK_LEN = 2^64
  uint32_t flags;
} blake3_hasher;

static void hasher_init_internal(blake3_hasher *self,
                                 const uint32_t key_words[8], uint32_t flags) {
  chunk_state_init(&self->chunk_state, key_words, 0, flags);
  memcpy(self->key_words, key_words, sizeof(self->key_words));
  self->cv_stack_len = 0;
  self->flags = flags;
}

static void hasher_push_stack(blake3_hasher *self, const uint32_t cv[8]) {
  memcpy(&self->cv_stack[(size_t)self->cv_stack_len * 8], cv, 8 * 4);
  self->cv_stack_len++;
}

// Returns a pointer to the popped CV, which is valid until the next push.
static const uint32_t *hasher_pop_stack(blake3_hasher *self) {
  self->cv_stack_len--;
  return &self->cv_stack[(size_t)self->cv_stack_len * 8];
}

// Section 5.1.2 of the BLAKE3 spec explains this algorithm in more detail.
static void hasher_add_chunk_cv(blake3_hasher *self, uint32_t new_cv[8],
                                uint64_t total_chunks) {
  // This chunk might complete some subtrees. For each completed subtree, its
  // left child will be the current top entry in the CV stack, and its right
  // child will be the current value of `new_cv`. Pop each left child off the
  // stack, merge it with `new_cv`, and overwrite `new_cv` with the result.
  // After all these merges, push the final value of `new_cv` onto the stack.
  // The number of completed subtrees is given by the number of trailing 0-bits
  // in the new total number of chunks.
  while ((total_chunks & 1) == 0) {
    parent_cv(hasher_pop_stack(self), new_cv, self->key_words, self->flags,
              new_cv);
    total_chunks >>= 1;
  }
  hasher_push_stack(self, new_cv);
}

// Add input to the hash state. This can be called any number of times.
void blake3_hasher_update(blake3_hasher *self, const void *input,
                          size_t input_len) {
  const uint8_t *input_u8 = (const uint8_t *)input;
  while (input_len > 0) {
    // If the current chunk is complete, finalize it and reset the chunk state.
    // More input is coming, so this chunk is not ROOT.
    if (chunk_state_len(&self->chunk_state) == CHUNK_LEN) {
      output chunk_output = chunk_state_output(&self->chunk_state);
      uint32_t chunk_cv[8];
      output_chaining_value(&chunk_output, chunk_cv);
      uint64_t total_chunks = self->chunk_state.chunk_counter + 1;
      hasher_add_chunk_cv(self, chunk_cv, total_chunks);
      chunk_state_init(&self->chunk_state, self->key_words, total_chunks,
                       self->flags);
    }

    // Compress input bytes into the current chunk state.
    size_t want = CHUNK_LEN - chunk_state_len(&self->chunk_state);
    size_t take = want;
    if (input_len < want) {
      take = input_len;
    }
    chunk_state_update(&self->chunk_state, input_u8, take);
    input_u8 += take;
    input_len -= take;
  }
}

// Finalize the hash and write any number of output bytes.
void blake3_hasher_finalize(const blake3_hasher *self, void *out,
                            size_t out_len) {
  // Starting with the output from the current chunk, compute all the parent
  // chaining values along the right edge of the tree, until we have the root
  // output.
  output current_output = chunk_state_output(&self->chunk_state);
  size_t parent_nodes_remaining = (size_t)self->cv_stack_len;
  while (parent_nodes_remaining > 0) {
    parent_nodes_remaining--;
    uint32_t current_cv[8];
    output_chaining_value(&current_output, current_cv);
    current_output = parent_output(&self->cv_stack[parent_nodes_remaining * 8],
                                   current_cv, self->key_words, self->flags);
  }
  output_root_bytes(&current_output, out, out_len);
}

// Construct a new `Hasher` for the regular hash function.
void blake3_hasher_init(blake3_hasher *self) {
  hasher_init_internal(self, IV, 0);
}

/// Construct a new `Hasher` for the keyed hash function.
void blake3_hasher_init_keyed(blake3_hasher *self, const uint8_t key[KEY_LEN]) {
  uint32_t key_words[8];
  words_from_little_endian_bytes(key, KEY_LEN, key_words);
  hasher_init_internal(self, key_words, KEYED_HASH);
}

// Construct a new `Hasher` for the key derivation function. The context
// string should be hardcoded, globally unique, and application-specific.
void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context) {
  blake3_hasher context_hasher;
  hasher_init_internal(&context_hasher, IV, DERIVE_KEY_CONTEXT);
  blake3_hasher_update(&context_hasher, context, strlen(context));
  uint8_t context_key[KEY_LEN];
  blake3_hasher_finalize(&context_hasher, context_key, KEY_LEN);
  uint32_t context_key_words[8];
  words_from_little_endian_bytes(context_key, KEY_LEN, context_key_words);
  hasher_init_internal(self, context_key_words, DERIVE_KEY_MATERIAL);
}

static uint8_t nibble_from_hex_char(char hex_char) {
  assert(('0' <= hex_char && hex_char <= '9') ||
         ('a' <= hex_char && hex_char <= 'f'));
  if ('0' <= hex_char && hex_char <= '9') {
    return (uint8_t)(hex_char - '0');
  } else {
    return (uint8_t)(hex_char - 'a') + 10;
  }
}

static void key_bytes_from_hex(const char *hex_key, uint8_t out[KEY_LEN]) {
  assert(strlen(hex_key) == 2 * KEY_LEN);
  for (size_t i = 0; i < KEY_LEN; i++) {
    out[i] = nibble_from_hex_char(hex_key[2 * i]) * 16;
    out[i] += nibble_from_hex_char(hex_key[2 * i + 1]);
  }
}

int main(int argc, char **argv) {
  uint8_t key[KEY_LEN];
  bool has_key = false;
  const char *derive_key_context = NULL;
  size_t output_len = OUT_LEN;

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
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n > 0) {
      blake3_hasher_update(&hasher, buf, n);
    } else if (n == 0) {
      break; // EOF
    } else {
      fprintf(stderr, "read failed: %s\n", strerror(errno));
      exit(1);
    }
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
  return 0;
}
