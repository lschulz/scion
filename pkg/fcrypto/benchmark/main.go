package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/fcrypto"
)

func main() {

	N := 10000
	t0 := time.Now()
	for i := 0; i < N; i++ {
		fcrypto.RandUInt64()
	}
	delta := time.Since(t0)
	fmt.Printf("RandUInt64: %v ns\n", float64(delta.Nanoseconds())/float64(N))

	t0 = time.Now()
	var v int
	buf := make([]byte, 8)
	for i := 0; i < N; i++ {
		n, _ := rand.Read(buf)
		v += n
	}
	delta = time.Since(t0)
	fmt.Printf("rand.Read: %v ns\n", float64(delta.Nanoseconds())/float64(N))

	key := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	nonce := [12]byte{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(2*i - 1)
	}

	t0 = time.Now()
	for i := 0; i < N; i++ {
		mac := fcrypto.CBCMAC(key, input)
		v += int(mac[0])
	}
	delta = time.Since(t0)
	fmt.Printf("CBCMAC(64 bytes): %v ns\n", float64(delta.Nanoseconds())/float64(N))

	t0 = time.Now()
	for i := 0; i < N; i++ {
		block, _ := aes.NewCipher(key[:])
		mac := cbcMac(block, input)
		v += int(mac[0])
	}
	delta = time.Since(t0)
	fmt.Printf("cbcMac(64 bytes): %v ns\n", float64(delta.Nanoseconds())/float64(N))

	t0 = time.Now()
	for i := 0; i < N; i++ {
		fcrypto.AESCTR(key, nonce, input)
		v += int(input[0])
	}
	delta = time.Since(t0)
	fmt.Printf("AESCTR(64 bytes): %v ns\n", float64(delta.Nanoseconds())/float64(N))

	t0 = time.Now()
	for i := 0; i < N; i++ {
		block, _ := aes.NewCipher(key[:])
		output := ctrMode(block, nonce, input)
		v += int(output[0])
	}
	delta = time.Since(t0)
	fmt.Printf("ctrMode(64 bytes): %v ns\n", float64(delta.Nanoseconds())/float64(N))
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

func ctrMode(block cipher.Block, nonce [12]byte, input []byte) []byte {
	var iv [16]byte
	copy(iv[:], nonce[:])
	ctr := cipher.NewCTR(block, iv[:])
	output := make([]byte, len(input))
	ctr.XORKeyStream(output, input)
	return output
}
