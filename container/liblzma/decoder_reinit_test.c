// SPDX-License-Identifier: 0BSD
// Adapted from XZ Utils tests/test_alone_decoder.c by Lasse Collin:
// https://github.com/tukaani-project/xz/commit/ff834f25ae4f9b3e6270d41b4c843b8b1183346c
// Added: separate alone/auto invocations, bounded fixture reads, fault-injection
// accounting, output comparison, and final allocation/free balance checks.
// Run each mode in its own capped, isolated process:
//   decoder_reinit_test alone <good-unknown_size-with_eopm.lzma>
//   decoder_reinit_test auto  <good-unknown_size-with_eopm.lzma>
// A vulnerable baseline can crash during the final phase. Never run in-process
// with an agent/host application. Dynamic library selection is external.

#include <lzma.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEMLIMIT (UINT64_C(16) << 20)
#define REFUSE_SIZE ((size_t)1 << 20)
#define FIXTURE_LIMIT 4096
#define OUTPUT_LIMIT 256
#define LIVE_ALLOCATION_LIMIT 64

typedef struct {
    size_t allocations;
    size_t frees;
    size_t live;
    size_t rejected_large;
    bool unexpected_failure;
} allocation_state;

static void *
bounded_alloc(void *opaque, size_t nmemb, size_t size)
{
    allocation_state *state = opaque;
    // liblzma guarantees nmemb == 1 and size > 0. Reject anything else instead
    // of silently changing the injection boundary or overflowing arithmetic.
    if (nmemb != 1 || size == 0) {
        state->unexpected_failure = true;
        return NULL;
    }
    if (size >= REFUSE_SIZE) {
        ++state->rejected_large;
        return NULL;
    }
    if (state->live >= LIVE_ALLOCATION_LIMIT) {
        state->unexpected_failure = true;
        return NULL;
    }
    void *pointer = malloc(size);
    if (pointer == NULL) {
        state->unexpected_failure = true;
        return NULL;
    }
    ++state->allocations;
    ++state->live;
    return pointer;
}

static void
tracked_free(void *opaque, void *pointer)
{
    allocation_state *state = opaque;
    if (pointer == NULL)
        return;
    if (state->live == 0) {
        // This flags an ownership/accounting violation, not an expected error.
        state->unexpected_failure = true;
    } else {
        --state->live;
    }
    ++state->frees;
    free(pointer);
}

static bool
phase(lzma_stream *stream, bool automatic, const char *name,
      const uint8_t *input, size_t input_size, uint8_t *output,
      lzma_ret expected, size_t *written)
{
    fprintf(stderr, "%s: initialize\n", name);
    lzma_ret result = automatic
        ? lzma_auto_decoder(stream, MEMLIMIT, 0)
        : lzma_alone_decoder(stream, MEMLIMIT);
    if (result != LZMA_OK) {
        fprintf(stderr, "%s: unexpected init result %d\n", name, (int)result);
        return false;
    }
    memset(output, 0, OUTPUT_LIMIT);
    stream->next_in = input;
    stream->avail_in = input_size;
    stream->next_out = output;
    stream->avail_out = OUTPUT_LIMIT;
    fprintf(stderr, "%s: decode\n", name);
    result = lzma_code(stream, LZMA_FINISH);
    if (stream->avail_out > OUTPUT_LIMIT) {
        fprintf(stderr, "%s: invalid output cursor\n", name);
        return false;
    }
    *written = OUTPUT_LIMIT - stream->avail_out;
    fprintf(stderr, "%s: result=%d written=%zu\n", name, (int)result, *written);
    if (result != expected)
        return false;
    if (expected == LZMA_STREAM_END
            && (stream->avail_in != 0 || stream->total_out != *written))
        return false;
    return true;
}

int
main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[1], "alone") != 0
                  && strcmp(argv[1], "auto") != 0)) {
        fprintf(stderr, "Usage: decoder_reinit_test <alone|auto> <fixture>\n");
        return 2;
    }
    const bool automatic = strcmp(argv[1], "auto") == 0;
    // Read at most one byte beyond the cap, never an unbounded input allocation.
    uint8_t fixture[FIXTURE_LIMIT + 1];
    FILE *file = fopen(argv[2], "rb");
    if (file == NULL) {
        fprintf(stderr, "Cannot open fixture\n");
        return 2;
    }
    const size_t input_size = fread(fixture, 1, sizeof(fixture), file);
    const bool read_failed = ferror(file) != 0;
    const int close_result = fclose(file);
    if (read_failed || close_result != 0 || input_size < 13
            || input_size > FIXTURE_LIMIT) {
        fprintf(stderr, "Invalid fixture size or read failure\n");
        return 2;
    }
    const uint32_t dictionary = (uint32_t)fixture[1]
        | ((uint32_t)fixture[2] << 8) | ((uint32_t)fixture[3] << 16)
        | ((uint32_t)fixture[4] << 24);
    if (dictionary != 4096) {
        fprintf(stderr, "Fixture must declare a 4 KiB dictionary\n");
        return 2;
    }
    uint8_t large_dictionary[FIXTURE_LIMIT];
    memcpy(large_dictionary, fixture, input_size);
    large_dictionary[1] = 0x00;
    large_dictionary[2] = 0x00;
    large_dictionary[3] = 0x80;
    large_dictionary[4] = 0x00;

    allocation_state state = {0};
    const lzma_allocator allocator = {bounded_alloc, tracked_free, &state};
    lzma_stream stream = LZMA_STREAM_INIT;
    stream.allocator = &allocator;
    uint8_t first[OUTPUT_LIMIT], failed[OUTPUT_LIMIT], recovered[OUTPUT_LIMIT];
    size_t first_size = 0, failed_size = 0, recovered_size = 0;
    bool passed = false;

    fprintf(stderr, "mode=%s liblzma=%s\n", argv[1], lzma_version_string());
    if (!phase(&stream, automatic, "small-before", fixture, input_size,
               first, LZMA_STREAM_END, &first_size)
            || first_size == 0 || state.rejected_large != 0
            || state.unexpected_failure)
        goto cleanup;
    if (!phase(&stream, automatic, "large-rejected", large_dictionary,
               input_size, failed, LZMA_MEM_ERROR, &failed_size)
            || state.rejected_large == 0 || state.unexpected_failure)
        goto cleanup;
    const size_t injected_rejections = state.rejected_large;
    fprintf(stderr, "injected_rejections=%zu\n", injected_rejections);
    if (!phase(&stream, automatic, "small-after", fixture, input_size,
               recovered, LZMA_STREAM_END, &recovered_size)
            || state.rejected_large != injected_rejections
            || state.unexpected_failure || first_size != recovered_size
            || memcmp(first, recovered, first_size) != 0)
        goto cleanup;
    passed = true;

cleanup:
    // The stream borrows allocator/state; both remain alive through final free.
    lzma_end(&stream);
    if (state.live != 0 || state.allocations != state.frees
            || state.unexpected_failure)
        passed = false;
    fprintf(stderr, "allocations=%zu frees=%zu live=%zu result=%s\n",
            state.allocations, state.frees, state.live, passed ? "PASS" : "FAIL");
    return passed ? 0 : 1;
}
