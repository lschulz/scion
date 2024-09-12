#ifndef INCLUDE_GUARD_CRYPTO_H
#define INCLUDE_GUARD_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

uint32_t RandUInt32(void);
uint64_t RandUInt64(void);
void CBCMAC(const uint8_t* pKey, const uint8_t* pData, size_t len, uint8_t* mac);
bool AESCTR(const uint8_t* pKey, const uint8_t* pNonce, uint8_t* pData, size_t len);

#endif // INCLUDE_GUARD_CRYPTO_H
