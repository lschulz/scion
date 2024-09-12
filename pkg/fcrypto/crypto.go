//go:build amd64

package fcrypto

// #cgo CFLAGS: -march=native
// #include "crypto.h"
import "C"
import (
	"unsafe"
)

func RandUInt32() uint32 {
	return uint32(C.RandUInt32())
}

func RandUInt64() uint64 {
	return uint64(C.RandUInt64())
}

func CBCMAC(key [16]byte, input []byte) [16]byte {
	var mac [16]byte
	if len(input) > 0 {
		C.CBCMAC(
			(*C.uchar)(unsafe.Pointer(&key)),
			(*C.uchar)(unsafe.Pointer(&input[0])),
			(C.size_t)(len(input)),
			(*C.uchar)(unsafe.Pointer(&mac)),
		)
	}
	return mac
}

// Data is encrypted in-place. Data must have a size of no more than 64 bytes.
func AESCTR(key [16]byte, nonce [12]byte, data []byte) {
	if len(data) > 0 {
		ok := C.AESCTR(
			(*C.uchar)(unsafe.Pointer(&key)),
			(*C.uchar)(unsafe.Pointer(&nonce)),
			(*C.uchar)(unsafe.Pointer(&data[0])),
			(C.size_t)(len(data)),
		)
		if !ok {
			panic("AESCTR failed")
		}
	}
}
