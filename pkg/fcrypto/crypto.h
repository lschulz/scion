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
