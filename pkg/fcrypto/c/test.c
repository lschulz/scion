#include "crypto.h"
#include <immintrin.h>
#include <stdio.h>

static const int64_t TSC_FREQ = 3600ul * 1000ul * 1000ul;

int main(int argc, char* argv[])
{
    volatile uint64_t v = 0;

    const uint64_t N = 10000;
    int64_t t0 = __rdtsc();
    for (uint64_t i = 0; i < N; ++i) {
        v ^= RandUInt64();
    }
    int64_t t1 = __rdtsc();

    double delta = (double)(t1 - t0) / TSC_FREQ;
    printf("RandUInt64: %f ns (%ld ticks)\n", 1e9 * delta / N, (t1 - t0) / N);

    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t data[64] = {0xff};
    uint8_t mac[16] = {0};

    t0 = __rdtsc();
    for (uint64_t i = 0; i < N; ++i) {
        CBCMAC(key, data, sizeof(data), mac);
        v += mac[0];
    }
    t1 = __rdtsc();

    delta = (double)(t1 - t0) / TSC_FREQ;
    printf("CBCMAC(64 bytes): %f ns (%ld ticks)\n", 1e9 * delta / N, (t1 - t0) / N);

    uint8_t nonce[12] = {12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

    t0 = __rdtsc();
    for (uint64_t i = 0; i < N; ++i) {
        AESCTR(key, nonce, data, sizeof(data));
    }
    v += data[0];
    t1 = __rdtsc();

    delta = (double)(t1 - t0) / TSC_FREQ;
    printf("AESCTR(64 bytes): %f ns (%ld ticks)\n", 1e9 * delta / N, (t1 - t0) / N);

    return v;
}
