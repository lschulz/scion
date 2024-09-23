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

//go:build amd64

package fcrypto_test

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/scionproto/scion/pkg/fcrypto"
	"github.com/stretchr/testify/assert"
)

func TestCBCMAC(t *testing.T) {

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	block, err := aes.NewCipher(key[:])
	assert.Nil(t, err)

	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(2*i - 1)
	}

	for size := 0; size <= 64; size++ {
		expected := cbcMac(block, input[:size])
		actual := fcrypto.CBCMAC(key, input[:size])
		assert.Equal(t, expected, actual)
	}
}

func cbcMac(block cipher.Block, input []byte) [16]byte {
	zeroBlock := [16]byte{}

	blockSize := block.BlockSize()
	blocks := len(input) / blockSize
	buffer := make([]byte, blocks*blockSize)
	copy(buffer, input)

	var mac [16]byte
	for i := 0; i < blocks; i++ {
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

func TestAESCTR(t *testing.T) {

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [12]byte{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	block, err := aes.NewCipher(key[:])
	assert.Nil(t, err)

	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(2*i - 1)
	}

	for size := 0; size <= 64; size++ {
		expected := ctrMode(block, nonce, input[:size])

		actual := make([]byte, size)
		copy(actual, input[:size])
		fcrypto.AESCTR(key, nonce, actual)

		assert.Equal(t, expected, actual)
	}
}

func ctrMode(block cipher.Block, nonce [12]byte, input []byte) []byte {
	var iv [16]byte
	copy(iv[:], nonce[:])
	ctr := cipher.NewCTR(block, iv[:])
	output := make([]byte, len(input))
	ctr.XORKeyStream(output, input)
	return output
}
