// Copyright 2024 OVGU Magdeburg
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "crypto.h"

#include <stdalign.h>
#include <stdbool.h>
#include <string.h>

#include <immintrin.h>
#include <emmintrin.h>


uint32_t RandUInt32(void)
{
    uint32_t val = 0;
    while (!_rdrand32_step(&val)) {
        _mm_pause();
    }
    return val;
}

uint64_t RandUInt64(void)
{
    unsigned long long val = 0;
    while (!_rdrand64_step(&val)) {
        _mm_pause();
    }
    return (uint64_t)val;
}


#define AESCTR_MAX_BYTES 64
#define KEY_SCHED_SIZE 10

#define AES_KEY_EXPANSION_ROUND(key, temp, rcon) \
    temp = _mm_aeskeygenassist_si128(key, rcon); \
    temp = _mm_shuffle_epi32(temp, 0xff); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, temp)

static void aes_key_expansion_128(__m128i key, __m128i keySchedule[KEY_SCHED_SIZE])
{
    __m128i temp;
    __m128i *dest = (__m128i*)keySchedule;
    AES_KEY_EXPANSION_ROUND(key, temp, 0x01);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x02);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x04);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x08);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x10);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x20);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x40);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x80);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x1b);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x36);
    _mm_store_si128(dest++, key);
}

static __m128i aes_encrypt_128(__m128i input, __m128i key, const __m128i keySchedule[KEY_SCHED_SIZE])
{
    // Initialization (round 0)
    __m128i state = input;
    state = _mm_xor_si128(state, key);

    // First 9 rounds
    for (size_t i = 0; i < 9; ++i)
        state = _mm_aesenc_si128(state, _mm_load_si128(keySchedule + i));

    // Last round
    state = _mm_aesenclast_si128(state, _mm_load_si128(&keySchedule[9]));

    return state;
}

void CBCMAC(const uint8_t* pKey, const uint8_t* pData, size_t len, uint8_t* mac)
{
    __m128i keySchedule[KEY_SCHED_SIZE];
    __m128i key = _mm_loadu_si128((const __m128i_u*)pKey);
    aes_key_expansion_128(key, keySchedule);

    __m128i data = _mm_setzero_si128();
    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; i++) {
        data = _mm_xor_si128(data, _mm_loadu_si128((const __m128i_u*)pData + i));
        data = aes_encrypt_128(data, key, keySchedule);
    }

    size_t rem = len % 16;
    if (rem > 0) {
        alignas(16) uint8_t buffer[16] = {0};
        memcpy(buffer, pData + len - rem, rem);
        data = _mm_xor_si128(data, _mm_load_si128((const __m128i*)buffer));
        data = aes_encrypt_128(data, key, keySchedule);
    }

    _mm_storeu_si128((__m128i_u*)mac, data);
}

bool AESCTR(const uint8_t* pKey, const uint8_t* pNonce, uint8_t* pData, size_t len)
{
    alignas(32) uint8_t data[AESCTR_MAX_BYTES] = {0};
    alignas(16) uint8_t nonce[16] = {0};

    if (len > AESCTR_MAX_BYTES) return false;
    memcpy(data, pData, len);
    memcpy(nonce, pNonce, 12);

    __m128i key = _mm_loadu_si128((const __m128i_u*)pKey);
    __m128i temp;

    // Initialization
    // Counter increment matches Go's cipher-Stream for <256 blocks.
    const __m128i inc = _mm_set_epi64x(1ll << 56, 0);
    __m128i state1 = _mm_load_si128((const __m128i*)nonce);
    __m128i state2 = _mm_add_epi8(state1, inc);
    __m128i state3 = _mm_add_epi8(state2, inc);
    __m128i state4 = _mm_add_epi8(state3, inc);

    state1 = _mm_xor_si128(state1, key);
    state2 = _mm_xor_si128(state2, key);
    state3 = _mm_xor_si128(state3, key);
    state4 = _mm_xor_si128(state4, key);

    // First 9 rounds
    AES_KEY_EXPANSION_ROUND(key, temp, 0x01);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x02);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x04);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x08);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x10);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x20);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x40);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x80);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x1b);
    state1 = _mm_aesenc_si128(state1, key);
    state2 = _mm_aesenc_si128(state2, key);
    state3 = _mm_aesenc_si128(state3, key);
    state4 = _mm_aesenc_si128(state4, key);

    // Last round
    AES_KEY_EXPANSION_ROUND(key, temp, 0x36);
    state1 = _mm_aesenclast_si128(state1, key);
    state2 = _mm_aesenclast_si128(state2, key);
    state3 = _mm_aesenclast_si128(state3, key);
    state4 = _mm_aesenclast_si128(state4, key);

    // XOR keystream with input data
    state1 = _mm_xor_si128(state1, _mm_load_si128((const __m128i*)(data + 0)));
    state2 = _mm_xor_si128(state2, _mm_load_si128((const __m128i*)(data + 16)));
    state3 = _mm_xor_si128(state3, _mm_load_si128((const __m128i*)(data + 32)));
    state4 = _mm_xor_si128(state4, _mm_load_si128((const __m128i*)(data + 48)));

    // Store result
    _mm_store_si128((__m128i*)(data + 0), state1);
    _mm_store_si128((__m128i*)(data + 16), state2);
    _mm_store_si128((__m128i*)(data + 32), state3);
    _mm_store_si128((__m128i*)(data + 48), state4);
    memcpy(pData, data, len);

    return true;
}
