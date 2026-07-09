// Copyright 2026 OVGU Magdeburg
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

package fcrypto

import (
	"crypto/aes"
	"crypto/cipher"
)

func CBCMACslow(key *[16]byte, input []byte) [16]byte {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // NewCipher cannot fail
	}
	return cbcMac(block, input)
}

func AESCTRslow(key *[16]byte, nonce *[12]byte, data []byte) {
	if len(data) > 64 {
		panic("AESCTR input too long")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // NewCipher cannot fail
	}
	output := ctrMode(block, nonce, data)
	copy(data, output)
}

func cbcMac(block cipher.Block, input []byte) [16]byte {
	zeroBlock := [16]byte{}

	blockSize := block.BlockSize()
	blocks := len(input) / blockSize
	buffer := make([]byte, blocks*blockSize)
	copy(buffer, input)

	var mac [16]byte
	for i := range blocks {
		for j := 0; j < blockSize; j++ {
			mac[j] = mac[j] ^ input[i*blockSize+j]
		}
		cbc := cipher.NewCBCEncrypter(block, zeroBlock[:])
		cbc.CryptBlocks(mac[:], mac[:])
	}

	rem := len(input) % blockSize
	if rem > 0 {
		for j := 0; j < rem; j++ {
			mac[j] = mac[j] ^ input[blocks*blockSize+j]
		}
		cbc := cipher.NewCBCEncrypter(block, zeroBlock[:])
		cbc.CryptBlocks(mac[:], mac[:])
	}

	return mac
}

func ctrMode(block cipher.Block, nonce *[12]byte, input []byte) []byte {
	var iv [16]byte
	copy(iv[:], nonce[:])
	ctr := cipher.NewCTR(block, iv[:])
	output := make([]byte, len(input))
	ctr.XORKeyStream(output, input)
	return output
}
