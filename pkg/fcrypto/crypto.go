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

//go:build !amd64 || !cgo

package fcrypto

func CBCMAC(key *[16]byte, input []byte) [16]byte {
	return CBCMACslow(key, input)
}

// Data is encrypted in-place. Data must have a size of no more than 64 bytes.
func AESCTR(key *[16]byte, nonce *[12]byte, data []byte) {
	AESCTRslow(key, nonce, data)
}
