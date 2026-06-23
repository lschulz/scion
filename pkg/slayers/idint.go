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

package slayers

import (
	"encoding/binary"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/fcrypto"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/idint"
)

const (
	// ID-INT protocol version
	IdIntVersion = 0
	// ID-INT nonce length for encrypted telemetry in bytes
	IdIntNonceLen = 12
	// Maximum length of metadata values including padding
	IdIntMaxMdLen = 44
	// ID-INT telemetry MAC length in bytes
	IdIntMacLen = 4
	// Minimum length of the ID-INT main header including OptType and OptDataLen
	intMinHdrLen = 22
	// Length of an empty ID-INT stack entry including OptType and OptDataLen
	intEmptyEntryLen = 12
)

type IdIntKey [16]byte
type IdIntNonce [IdIntNonceLen]byte

// ID-INT hop-by-hop extension. ID-INT consists of two types of hop-by-hop
// options, exactly one main option (IdIntOpt), followed by one or more stack
// entries (IdIntStackEntryOpt). The stack entries are optionally followed a
// padding option that reserves space for additional stack entries.
type IdIntExt struct {
	Header   IdIntOpt           // ID-INT header
	TOS      IdIntStackEntryOpt // Top-of-Stack: The latest stack entry
	tosBegin int
	tosEnd   int
}

// Parses hop-by-hop options relating to ID-INT. Returns a subslice of opts
// that covers the parsed options.
func (ext *IdIntExt) Parse(opts []byte) ([]byte, error) {
	idintBegin, err := ext.parseMainHeader(opts)
	if err != nil {
		return nil, err
	}
	stackOffset := idintBegin + ext.Header.Length()
	if stackOffset < 0 {
		return nil, nil
	}

	tosBegin := stackOffset + 4*int(ext.Header.TOS)
	if tosBegin >= len(opts) {
		return nil, serrors.New("invalid ID-INT option")
	}
	tosLen, err := ext.TOS.Parse(opts[tosBegin:], true)
	if err != nil {
		return nil, err
	}
	ext.tosBegin = tosBegin - idintBegin
	ext.tosEnd = tosBegin + tosLen

	stackUsed := ext.tosEnd - stackOffset
	stackFree := 4*int(ext.Header.StackLen) - stackUsed
	if stackFree < 0 {
		return nil, serrors.New("invalid ID-INT option")
	}

	idintEnd := ext.tosEnd + stackFree
	if err = ext.parsePadding(opts[ext.tosEnd:idintEnd]); err != nil {
		return nil, err
	}
	return opts[idintBegin:idintEnd], nil
}

// parseMainHeader looks for and parses the ID-INT main header.
func (ext *IdIntExt) parseMainHeader(opts []byte) (int, error) {
	i := 0
	for i < len(opts) {
		optType := OptionType(opts[i])
		if optType == OptTypePad1 {
			i += 1
		} else {
			if (i + 1) >= len(opts) {
				return -1, serrors.New("invalid hop-by-hop option")
			}
			optLen := int(opts[i+1]) + 2
			if (i + optLen) >= len(opts) {
				return -1, serrors.New("invalid hop-by-hop option")
			}
			if optType == OptTypeIdInt {
				if err := ext.Header.Parse(opts[i:i+optLen], true); err != nil {
					return -1, err
				}
				return i, nil
			}
			i += optLen
		}
	}
	return -1, nil
}

// parsePadding checks whether there is sufficient padding after the end of the
// option stack.
func (ext *IdIntExt) parsePadding(opts []byte) error {
	i := 0
	for i < len(opts) {
		optType := OptionType(opts[i])
		if optType == OptTypePad1 {
			i += 1
		} else {
			if (i + 1) >= len(opts) {
				return serrors.New("invalid hop-by-hop option")
			}
			optLen := int(opts[i+1]) + 2
			if (i + optLen) > len(opts) {
				return serrors.New("invalid hop-by-hop option")
			}
			switch optType {
			case OptTypePadN:
			case OptTypeIdInt:
				return serrors.New("too many ID-INT headers")
			case OptTypeIdIntStackEntry:
				return serrors.New("invalid ID-INT telemetry stack")
			default:
				return serrors.New("unexpected end of hop-by-hop option header")
			}
			i += optLen
		}
	}
	return nil
}

// UpdateInPlace writes changes made to the main header and TOS back to the
// slice the ID-INT extension was parsed from. opts should be the slice returned
// by Parse(). If pushNewEntry is true, the current state of TOS is appended to
// the telemetry stack as a new entry, otherwise the current topmost entry is
// overwritten. Either way, UpdateInPlace adjusts the the padding options
// following the telemetry stack to fill the remaining free space.
// MACs are calculated in-situ to avoid copying buffers. If encryption is
// enabled nonce must no be nil. Key must never be nil.
func (ext *IdIntExt) UpdateInPlace(
	opts []byte, pushNewEntry bool, key *IdIntKey, nonce *IdIntNonce,
) error {

	// Update TOS
	stackOffset := ext.Header.Length()
	stackFree := len(opts) - ext.tosEnd
	var prevMac [IdIntMacLen]byte
	if pushNewEntry {
		if stackFree < ext.TOS.Length() {
			ext.Header.StackSpaceExhausted = true
		} else {
			copy(prevMac[:], opts[ext.tosEnd-4:ext.tosEnd])
			tosLen, err := ext.serializeTOS(opts[ext.tosEnd:], &prevMac, key, nonce)
			if err != nil {
				return err
			}
			ext.Header.TOS = byte((ext.tosEnd - stackOffset) / 4)
			ext.tosBegin = ext.tosEnd
			ext.tosEnd = ext.tosBegin + tosLen
		}
	} else {
		if stackFree < (ext.TOS.Length() - (ext.tosEnd - ext.tosBegin)) {
			ext.Header.StackSpaceExhausted = true
		} else {
			copy(prevMac[:], opts[ext.tosBegin-4:ext.tosBegin])
			tosLen, err := ext.serializeTOS(opts[ext.tosBegin:], &prevMac, key, nonce)
			if err != nil {
				return err
			}
			ext.Header.TOS = byte((ext.tosBegin - stackOffset) / 4)
			ext.tosEnd = ext.tosBegin + tosLen
		}
	}

	// Update main header
	_, err := ext.Header.SerializeToSlice(opts[:], true)
	if err != nil {
		return err
	}

	// Add padding to fill up the free space
	insertPadOpts(opts[ext.tosEnd:])
	return nil
}

func (ext *IdIntExt) serializeTOS(
	opt []byte, prevMac *[IdIntMacLen]byte, key *IdIntKey, nonce *IdIntNonce,
) (int, error) {
	if key == nil {
		return ext.TOS.SerializeToSlice(opt, true)
	} else if !ext.TOS.Encrypted {
		return ext.TOS.SerializeToSliceMac(opt, *prevMac, key)
	} else {
		return ext.TOS.SerializeToSliceEncrypt(opt, *prevMac, key, nonce)
	}
}

// insertPadOpts inserts padding options to completely fill up the given slice.
func insertPadOpts(opts []byte) {
	i := 0
	for i < len(opts) {
		remaining := len(opts) - i
		if remaining == 1 {
			opts[i] = byte(OptTypePad1)
			i += 1
		} else {
			n := min(remaining-2, 255)
			opts[i] = byte(OptTypePadN)
			opts[i+1] = byte(n)
			for j := range n {
				opts[j+2] = 0
			}
			i += n + 2
		}
	}
}

// ID-INT Main Option Header
type IdIntOpt struct {
	// Version of the header. Currently 0.
	Version uint8
	// Infrastructure mode. If set, the INT header is removed by the last border
	// router on the path.
	Infrastructure bool
	// Discard the packet (payload) at the last border router.
	Discard bool
	// Encrypt telemetry
	Encrypt bool
	// Some metadata omitted because maximum stack size was reached.
	StackSpaceExhausted bool
	// Aggregation mode (range 0-3)
	AggregationMode uint8
	// For whom the MAC/encrypt the telemetry (range 0-3 with 3 reserved)
	Verifier uint8
	// Type of third party verifier address.
	VerifierAddrType AddrType
	// Allocated space for the telemetry stack in multiples of 4 bytes
	StackLen uint8
	// Offset of the first byte of the last (most recently written) entry on the
	// telemetry stack in multiples of 4 bytes.
	TOS uint8
	// The number of AS-level hops (as counted by hop fields) to skip before the
	// first non-source telemetry stack entry is created.
	DelayHops uint8
	// Bitmap-encoded INT instructions (4 bit)
	InstructionBitmap uint8
	// Aggregation function for metadata 1-4
	AggregationFunc [4]uint8
	// Metadata instruction 1-4
	Instructions [4]uint8
	// INT source timestamp and egress port. Used as input to DRKey.
	SourceTsPort uint64
	// Verifier address
	VerifIA addr.IA
	// Host address of the verifier
	RawVerifAddr [16]byte
}

func (o *IdIntOpt) Length() int {
	return intMinHdrLen + o.VerifierAddrLen()
}

func (o *IdIntOpt) VerifierAddrLen() int {
	if o.Verifier == idint.VfThirdParty {
		return addr.IABytes + o.VerifierAddrType.Length()
	} else {
		return 0
	}
}

func (o *IdIntOpt) Parse(opt []byte, tlv bool) error {
	minLen := intMinHdrLen - 2
	offset := 0
	if tlv {
		minLen = intMinHdrLen
	}

	if len(opt) < minLen {
		return serrors.New("packet is shorter than the minimum header length",
			"min", minLen, "actual", len(opt))
	}

	// Type and Length
	if tlv {
		optType := OptionType(opt[0])
		optLen := int(opt[1]) + 2
		if optType != OptTypeIdInt {
			return serrors.New("unexpected option type",
				"expteced", OptTypeIdInt, "actual", optType)
		}
		if optLen != len(opt) || (optLen+2)%4 != 0 {
			return serrors.New("invalid ID-INT option length",
				"optLen", optLen, "actualLen", len(opt))
		}
		offset = 2
	}

	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | Ver |I|D|E|X|R|Mod|Vrf|VT |VL |   StackLen    |      TOS      |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	firstLine := binary.BigEndian.Uint32(opt[offset : offset+4])
	o.Version = uint8(firstLine >> 29)
	if o.Version != IdIntVersion {
		return serrors.New("unkonwn ID-INT header version",
			"expected", IdIntVersion, "version", o.Version)
	}
	o.Infrastructure = ((firstLine >> 28) & 0x1) != 0
	o.Discard = ((firstLine >> 27) & 0x1) != 0
	o.Encrypt = ((firstLine >> 26) & 0x1) != 0
	o.StackSpaceExhausted = ((firstLine >> 25) & 0x1) != 0
	o.AggregationMode = uint8((firstLine >> 22) & 0x3)
	o.Verifier = uint8((firstLine >> 20) & 0x3)
	o.VerifierAddrType = AddrType((firstLine >> 16) & 0xf)
	o.StackLen = uint8((firstLine >> 8) & 0xff)
	o.TOS = uint8(firstLine & 0xff)
	offset += 4

	//  0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// | DelayHops |      Reserved     | InstF | AF1 | AF2 | AF3 | AF4 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	secondLine := binary.BigEndian.Uint32(opt[offset : offset+4])
	o.DelayHops = uint8((secondLine >> 26) & 0x3f)
	o.InstructionBitmap = uint8((secondLine >> 12) & 0xf)
	o.AggregationFunc[0] = uint8((secondLine >> 9) & 0x7)
	o.AggregationFunc[1] = uint8((secondLine >> 6) & 0x7)
	o.AggregationFunc[2] = uint8((secondLine >> 3) & 0x7)
	o.AggregationFunc[3] = uint8(secondLine & 0x7)
	offset += 4

	// Instructions
	copy(o.Instructions[:], opt[offset:offset+4])
	offset += 4

	// Timestamp
	o.SourceTsPort = binary.BigEndian.Uint64(opt[offset : offset+8])
	offset += 8

	// Verifier address
	if o.Verifier == idint.VfThirdParty {
		if err := o.DecodeVerifierAddr(opt[offset:]); err != nil {
			return err
		}
	}
	return nil
}

func (o *IdIntOpt) SerializeToSlice(opt []byte, tlv bool) (int, error) {
	offset := 0
	if tlv {
		offset = 2
	}

	var firstLine uint32
	firstLine |= uint32(o.Version) << 29
	if o.Infrastructure {
		firstLine |= 1 << 28
	}
	if o.Discard {
		firstLine |= 1 << 27
	}
	if o.Encrypt {
		firstLine |= 1 << 26
	}
	if o.StackSpaceExhausted {
		firstLine |= 1 << 25
	}
	firstLine |= (uint32(o.AggregationMode) & 0x3) << 22
	firstLine |= (uint32(o.Verifier) & 0x3) << 20
	firstLine |= (uint32(o.VerifierAddrType) & 0xf) << 16
	firstLine |= (uint32(o.StackLen) & 0xff) << 8
	firstLine |= uint32(o.TOS) & 0xff
	binary.BigEndian.PutUint32(opt[offset:offset+4], firstLine)
	offset += 4

	var secondLine uint32
	secondLine |= (uint32(o.DelayHops) & 0x3f) << 26
	secondLine |= (uint32(o.InstructionBitmap) & 0xf) << 12
	secondLine |= (uint32(o.AggregationFunc[0]) & 0x7) << 9
	secondLine |= (uint32(o.AggregationFunc[1]) & 0x7) << 6
	secondLine |= (uint32(o.AggregationFunc[2]) & 0x7) << 3
	secondLine |= uint32(o.AggregationFunc[3]) & 0x7
	binary.BigEndian.PutUint32(opt[offset:offset+4], secondLine)
	offset += 4

	// Instructions
	copy(opt[offset:offset+4], o.Instructions[:])
	offset += 4

	// Timestamp
	binary.BigEndian.PutUint64(opt[offset:offset+8], o.SourceTsPort)
	offset += 8

	// Verifier address
	if o.Verifier == idint.VfThirdParty {
		if err := o.SerializeVerifierAddr(opt[offset:]); err != nil {
			return offset, err
		}
		offset += o.VerifierAddrLen()
	}

	if tlv {
		opt[0] = byte(OptTypeIdInt)
		opt[1] = byte(offset) - 2
	}
	return offset, nil
}

func (o *IdIntOpt) DecodeVerifierAddr(data []byte) error {
	addrLen := o.VerifierAddrLen()
	if len(data) < addrLen {
		return serrors.New("provided buffer is too small", "expected", addrLen, "actual", len(data))
	}
	o.VerifIA = addr.IA(binary.BigEndian.Uint64(data[0:8]))
	copy(o.RawVerifAddr[:], data[8:addrLen])
	return nil
}

func (o *IdIntOpt) SerializeVerifierAddr(data []byte) error {
	addrLen := o.VerifierAddrLen()
	if len(data) < addrLen {
		return serrors.New("provided buffer is too small", "expected", o.VerifierAddrLen(),
			"actual", len(data))
	}
	binary.BigEndian.PutUint64(data[0:8], uint64(o.VerifIA))
	copy(data[8:addrLen], o.RawVerifAddr[:])
	return nil
}

// IdIntStackEntryOpt contains the data of an ID-INT stack entry.
type IdIntStackEntryOpt struct {
	// Set if this is the source metadata entry at the bottom of the stack,
	// i.e., the first entry after the main header.
	SourceMetadata bool
	// From AS-ingress border router
	Ingress bool
	// From AS-egress border router
	Egress bool
	// Contains aggregated data
	Aggregated bool
	// Is encrypted
	Encrypted bool

	// Index of the corresponding hop field
	HopIndex uint8
	// Bitmap metadata presence mask (4 bit)
	MetadataMask uint8
	// Length of metadata stored in slot 1-4
	MetadataLength [4]uint8

	// Nonce for encrypted data, Considered valid iff Encrypted == true
	Nonce IdIntNonce
	// Encoded metadata with padding to a multiple of 4 bytes
	Metadata [IdIntMaxMdLen]byte
	// Length of the data in Metadata
	MetadataLen int
	// Metadata MAC
	Mac [IdIntMacLen]byte
}

func (m *IdIntStackEntryOpt) Length() int {
	length := 6
	if m.Encrypted {
		length += IdIntNonceLen
	}
	if m.MetadataMask&idint.NodeId != 0 {
		length += 4
	}
	if m.MetadataMask&idint.NodeCnt != 0 {
		length += 2
	}
	if m.MetadataMask&idint.IgPort != 0 {
		length += 2
	}
	if m.MetadataMask&idint.EgPort != 0 {
		length += 2
	}
	for _, x := range m.MetadataLength {
		length += int(x)
	}
	length += (length % 4) // padding
	return length + IdIntMacLen
}

func (o *IdIntStackEntryOpt) Parse(opt []byte, tlv bool) (int, error) {
	minLen := intEmptyEntryLen - 2
	offset := 0
	if tlv {
		minLen = intEmptyEntryLen
	}

	if len(opt) < minLen {
		return -1, serrors.New("ID-INT metadata header too short",
			"min", intEmptyEntryLen, "actual", len(opt))
	}

	// Type and Length
	if tlv {
		optType := OptionType(opt[0])
		optLen := int(opt[1]) + 2
		if optType != OptTypeIdIntStackEntry {
			return -1, serrors.New("unexpected option type",
				"expteced", OptTypeIdIntStackEntry, "actual", optType)
		}
		if optLen > len(opt) || optLen%4 != 0 {
			return -1, serrors.New("invalid ID-INT stack entry option length",
				"optLen", optLen, "actualLen", len(opt))
		}
		offset += 2
	}

	// 	0                   1                   2                   3
	//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// |S|I|E|A|C| Res |    Hop    |Res| Mask  | ML1 | ML2 | ML3 | ML4 |
	// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	firstLine := binary.BigEndian.Uint32(opt[offset : offset+4])
	o.SourceMetadata = ((firstLine >> 31) & 0x1) != 0
	o.Ingress = ((firstLine >> 30) & 0x1) != 0
	o.Egress = ((firstLine >> 29) & 0x1) != 0
	o.Aggregated = ((firstLine >> 28) & 0x1) != 0
	o.Encrypted = ((firstLine >> 27) & 0x1) != 0
	o.HopIndex = uint8((firstLine >> 18) & 0x3f)
	o.MetadataMask = uint8((firstLine >> 12) & 0xf)
	o.MetadataLength[0] = 2 * uint8((firstLine>>9)&0x7)
	o.MetadataLength[1] = 2 * uint8((firstLine>>6)&0x7)
	o.MetadataLength[2] = 2 * uint8((firstLine>>3)&0x7)
	o.MetadataLength[3] = 2 * uint8(firstLine&0x7)
	for _, length := range o.MetadataLength {
		if length > 8 {
			return -1, serrors.New("invalid metadata length", "length", length)
		}
	}
	offset += 4

	expectedLen := o.Length()
	if !tlv {
		expectedLen -= 2
	}
	if len(opt) < expectedLen {
		return -1, serrors.New("ID-INT metadata header too short",
			"expected", expectedLen, "actual", len(opt))
	}

	if o.Encrypted {
		copy(o.Nonce[:], opt[offset:offset+IdIntNonceLen])
		offset += IdIntNonceLen
	}

	metadata := opt[offset : expectedLen-IdIntMacLen]
	copy(o.Metadata[:], metadata)
	o.MetadataLen = len(metadata)
	copy(o.Mac[:], opt[expectedLen-IdIntMacLen:expectedLen])
	offset += o.MetadataLen + IdIntMacLen
	return offset, nil
}

func (o *IdIntStackEntryOpt) SerializeToSlice(opt []byte, tlv bool) (int, error) {
	expectedLen := o.Length() - 2
	offset := 0
	if tlv {
		expectedLen += 2
	}

	if len(opt) < expectedLen {
		return 0, serrors.New("buffer too short", "expected", expectedLen, "actual", len(opt))
	}

	// Type and Length
	if tlv {
		opt[0] = byte(OptTypeIdIntStackEntry)
		opt[1] = byte(expectedLen) - 2
		offset += 2
	}

	var firstLine uint32
	if o.SourceMetadata {
		firstLine |= 1 << 31
	}
	if o.Ingress {
		firstLine |= 1 << 30
	}
	if o.Egress {
		firstLine |= 1 << 29
	}
	if o.Aggregated {
		firstLine |= 1 << 28
	}
	if o.Encrypted {
		firstLine |= 1 << 27
	}
	firstLine |= (uint32(o.HopIndex) & 0x3f) << 18
	firstLine |= (uint32(o.MetadataMask) & 0xf) << 12
	firstLine |= (uint32(o.MetadataLength[0]/2) & 0x7) << 9
	firstLine |= (uint32(o.MetadataLength[1]/2) & 0x7) << 6
	firstLine |= (uint32(o.MetadataLength[2]/2) & 0x7) << 3
	firstLine |= uint32(o.MetadataLength[3]/2) & 0x7
	binary.BigEndian.PutUint32(opt[offset:offset+4], firstLine)
	offset += 4

	if o.Encrypted {
		copy(opt[offset:offset+IdIntNonceLen], o.Nonce[:])
		offset += IdIntNonceLen
	}

	offset += copy(opt[offset:], o.Metadata[:o.MetadataLen])
	offset += copy(opt[offset:], o.Mac[:])
	return offset, nil
}

func (o *IdIntStackEntryOpt) GetMetadata() (*IntMetadata, error) {
	md := &IntMetadata{}
	if err := md.DecodeFromBytes(o.Metadata, o); err != nil {
		return nil, err
	}
	return md, nil
}

func (o *IdIntStackEntryOpt) SetMetadata(md *IntMetadata) error {
	// Serialize metadata
	if mdLen, err := md.serializeToSlice(&o.Metadata); err != nil {
		return err
	} else {
		o.MetadataLen = mdLen
	}

	// Update metadata presence bitmap
	o.MetadataMask = 0
	if md.NodeIdValid {
		o.MetadataMask |= idint.NodeId
	}
	if md.NodeCntValid {
		o.MetadataMask |= idint.NodeCnt
	}
	if md.IgPortValid {
		o.MetadataMask |= idint.IgPort
	}
	if md.EgPortValid {
		o.MetadataMask |= idint.EgPort
	}

	// Update metadata slot length fields
	for i := range 4 {
		o.MetadataLength[i] = byte(md.InstrDataLen[i])
	}

	return nil
}

// SerializeToSliceMac serializes a stack entry and at the same time updates its
// MAC. This function calculates the MAC directly on the destination buffer
// avoiding a temporary buffer for calculating the MAC.
func (o *IdIntStackEntryOpt) SerializeToSliceMac(
	buf []byte,
	prevMac [IdIntMacLen]byte,
	key *IdIntKey,
) (int, error) {

	offset, err := o.SerializeToSlice(buf, true)
	if err != nil {
		return offset, err
	}
	buf = buf[:offset]

	// Overwrite MAC with MAC of the previous hop before calculating the new MAC
	copy(buf[offset-IdIntMacLen:], prevMac[:])
	mac := fcrypto.CBCMAC((*[16]byte)(key), buf)

	// Write the new MAC
	copy(buf[offset-IdIntMacLen:], mac[:])

	return offset, err
}

// SerializeToSliceEncrypt is like SerializeToSliceMac but also encrypts the
// serialized stack entry.
func (o *IdIntStackEntryOpt) SerializeToSliceEncrypt(
	buf []byte,
	prevMac [IdIntMacLen]byte,
	key *IdIntKey,
	nonce *IdIntNonce,
) (int, error) {

	copy(o.Nonce[:], nonce[:])
	offset, err := o.SerializeToSliceMac(buf, prevMac, key)
	if err != nil {
		return offset, err
	}

	// Encrypt
	const metadataOffset = 6 + IdIntNonceLen
	fcrypto.AESCTR((*[16]byte)(key), (*[12]byte)(nonce), buf[metadataOffset:offset])

	return offset, nil
}

// AuthSource updates the MAC of a source telemetry entry. header provides
// additional fields from the ID-INT main header for MACing.
func (o *IdIntStackEntryOpt) AuthSource(
	key *IdIntKey,
	header *IdIntOpt,
) ([IdIntMacLen]byte, error) {

	mac, err := o.calcSourceMac(key, header)
	if err != nil {
		return [IdIntMacLen]byte{}, err
	}
	copy(o.Mac[:], mac[:])

	return o.Mac, nil
}

// EncryptSource authenticates and encrypts a source telemetry entry. nonce is
// set as the entries nonce. headerOpt provides additional fields from the
// ID-INT main header for MACing.
func (o *IdIntStackEntryOpt) EncryptSource(
	key *IdIntKey,
	nonce *IdIntNonce,
	header *IdIntOpt,
) ([IdIntMacLen]byte, error) {

	o.Encrypted = true
	copy(o.Nonce[:], nonce[:])

	mac, err := o.calcSourceMac(key, header)
	if err != nil {
		return [IdIntMacLen]byte{}, err
	}
	copy(o.Mac[:], mac[:])
	o.encdecImpl(key)

	return o.Mac, nil
}

// DecryptSource decrypts the metadata and MAC of a source stack entry using the
// nonce from the header. Calculates and returns the expected MAC. Compare to
// the MAC in the header to validate telemetry integrity.
func (o *IdIntStackEntryOpt) DecryptSource(
	key *IdIntKey, header *IdIntOpt,
) ([IdIntMacLen]byte, error) {

	if o.Encrypted {
		o.encdecImpl(key)
	}
	// clear encrypted flag after calcSourceMac so nonce is included in MAC
	mac, err := o.calcSourceMac(key, header)
	o.Encrypted = false
	if err != nil {
		return [IdIntMacLen]byte{}, err
	}
	return mac, nil
}

// Decrypt decrypts the metadata and MAC of a non-source stack entry using the
// nonce from the header. Calculates and returns the expected MAC. Compare to
// the MAC in the header to validate telemetry integrity.
func (o *IdIntStackEntryOpt) Decrypt(
	key *IdIntKey, prevMac [IdIntMacLen]byte,
) ([IdIntMacLen]byte, error) {

	if o.Encrypted {
		o.encdecImpl(key)
	}
	// clear encrypted flag after calcSourceMac so nonce is included in MAC
	mac, err := o.calcMac(key, prevMac)
	o.Encrypted = false
	if err != nil {
		return [IdIntMacLen]byte{}, err
	}
	return mac, nil
}

func (o *IdIntStackEntryOpt) encdecImpl(key *IdIntKey) {
	// AES-CCM encrypts the MAC as well
	var data [IdIntMaxMdLen + len(o.Mac)]byte
	copy(data[:o.MetadataLen], o.Metadata[:o.MetadataLen])
	copy(data[o.MetadataLen:], o.Mac[:])

	fcrypto.AESCTR((*[16]byte)(key), (*[12]byte)(&o.Nonce), data[:])

	copy(o.Metadata[:o.MetadataLen], data[:o.MetadataLen])
	copy(o.Mac[:], data[o.MetadataLen:])
}

func (o *IdIntStackEntryOpt) calcMac(
	key *IdIntKey, prevMac [IdIntMacLen]byte,
) ([IdIntMacLen]byte, error) {

	var buf [64]byte

	length, err := o.SerializeToSlice(buf[:], true)
	if err != nil {
		return [IdIntMacLen]byte{}, err
	}
	copy(buf[length-IdIntMacLen:], prevMac[:IdIntMacLen])

	mac := fcrypto.CBCMAC((*[16]byte)(key), buf[:length])

	var truncMac [IdIntMacLen]byte
	copy(truncMac[:], mac[:IdIntMacLen])
	return truncMac, nil
}

func (o *IdIntStackEntryOpt) calcSourceMac(
	key *IdIntKey, header *IdIntOpt) ([IdIntMacLen]byte, error) {

	// Serialize main header and source stack entry
	buf := make([]byte, 128)
	offset, err := header.SerializeToSlice(buf, true)
	if err != nil {
		return [IdIntMacLen]byte{}, err
	}
	length, err := o.SerializeToSlice(buf[offset:], true)
	offset += length
	if err != nil {
		return [IdIntMacLen]byte{}, err
	}

	// Zero-out updatable fields
	buf[2] &= 0xfd // ignore telemetry stack space exhausted flag
	buf[5] = 0
	buf[6] = 0
	buf[7] = 0

	mac := fcrypto.CBCMAC((*[16]byte)(key), buf[:offset-IdIntMacLen])

	var truncMac [IdIntMacLen]byte
	copy(truncMac[:], mac[:IdIntMacLen])
	return truncMac, nil
}

// IntMetadata contains decoded metadata from an ID-INT stack entry.
type IntMetadata struct {
	// Bitmap metadata validity
	NodeIdValid  bool
	NodeCntValid bool
	IgPortValid  bool
	EgPortValid  bool

	// Unique AS-wide node ID
	NodeId uint32
	// Number of nodes aggregated into this entry
	NodeCnt uint16
	// Ingress device-level port identifier
	IgPort uint16
	// Egress device-level port identifier
	EgPort uint16

	// Length of metadata in InstrData in bytes
	InstrDataLen [4]int
	// Instruction byte controlled metadata
	InstrData [4]uint64
}

func (d *IntMetadata) Length() int {
	length := 0
	if d.NodeIdValid {
		length += 4
	}
	if d.NodeCntValid {
		length += 2
	}
	if d.IgPortValid {
		length += 2
	}
	if d.EgPortValid {
		length += 2
	}
	for _, len := range d.InstrDataLen {
		length += len
	}
	length += (length % 4) // padding
	return length
}

// Merges metadata from another object according to the given aggregation functions.
func (d *IntMetadata) Merge(aggrFuncs [4]uint8, other *IntMetadata) {
	updateNode := false
	for i := 0; i < 4; i++ {
		if d.InstrDataLen[i] != 0 && other.InstrDataLen[i] != 0 {
			switch aggrFuncs[i] {
			case idint.AfFirst:
				// keep old value
			case idint.AfLast:
				d.InstrDataLen[i] = other.InstrDataLen[i]
				d.InstrData[i] = other.InstrData[i]
				updateNode = true
			case idint.AfMin:
				if d.InstrData[i] > other.InstrData[i] {
					d.InstrData[i] = other.InstrData[i]
					updateNode = true
				}
			case idint.AfMax:
				if d.InstrData[i] < other.InstrData[i] {
					d.InstrData[i] = other.InstrData[i]
					updateNode = true
				}
			case idint.AfSum:
				d.InstrData[i] = d.InstrData[i] + other.InstrData[i]
				updateNode = true
			}
		} else if d.InstrDataLen[i] == 0 {
			// no existing data
			d.InstrDataLen[i] = other.InstrDataLen[i]
			d.InstrData[i] = other.InstrData[i]
			updateNode = true
		}
	}

	if other.NodeIdValid && (!d.NodeIdValid || updateNode) {
		d.NodeId = other.NodeId
	}
	if other.IgPortValid && (!d.IgPortValid || updateNode) {
		d.IgPort = other.IgPort
	}
	if other.EgPortValid && (!d.EgPortValid || updateNode) {
		d.EgPort = other.EgPort
	}

	if d.NodeCntValid {
		if other.NodeCntValid {
			d.NodeCnt += other.NodeCnt
		} else {
			d.NodeCnt += 1
		}
	}
}

// serializeToSlice serializes the metadata and pads the output to a length of
// 4n+2 for direct inclusion in a stack entry.
func (d *IntMetadata) serializeToSlice(buf *[IdIntMaxMdLen]byte) (int, error) {
	if len(buf) < d.Length() {
		return 0, serrors.New("buffer too short", "expected", d.Length(), "actual", len(buf))
	}
	offset := 0

	// Bitmap data
	if d.NodeIdValid {
		binary.BigEndian.PutUint32(buf[offset:], d.NodeId)
		offset += 4
	}
	if d.NodeCntValid {
		binary.BigEndian.PutUint16(buf[offset:], d.NodeCnt)
		offset += 2
	}
	if d.IgPortValid {
		binary.BigEndian.PutUint16(buf[offset:], d.IgPort)
		offset += 2
	}
	if d.EgPortValid {
		binary.BigEndian.PutUint16(buf[offset:], d.EgPort)
		offset += 2
	}
	// Instruction data
	for i := 0; i < 4; i++ {
		switch d.InstrDataLen[i] {
		case 0:
		case 2:
			binary.BigEndian.PutUint16(buf[offset:], uint16(d.InstrData[i]))
			offset += 2
		case 4:
			binary.BigEndian.PutUint32(buf[offset:], uint32(d.InstrData[i]))
			offset += 4
		case 6:
			var word [8]byte
			binary.BigEndian.PutUint64(word[:], d.InstrData[i])
			copy(buf[offset:offset+6], word[2:])
			offset += 6
		case 8:
			binary.BigEndian.PutUint64(buf[offset:], d.InstrData[i])
			offset += 8
		default:
			return offset, serrors.New("invalid metadata length", "length", d.InstrDataLen[i])
		}
	}
	// Padding
	padding := (offset + 2) % 4
	if padding > 0 {
		for i := 0; i < padding; i++ {
			buf[offset+i] = 0
		}
		offset += padding
	}
	return offset, nil
}

func (d *IntMetadata) DecodeFromBytes(data [IdIntMaxMdLen]byte, opt *IdIntStackEntryOpt) error {
	offset := 0

	if opt.MetadataMask&idint.NodeId != 0 {
		d.NodeId = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		d.NodeIdValid = true
	} else {
		d.NodeIdValid = false
	}

	if opt.MetadataMask&idint.NodeCnt != 0 {
		d.NodeCnt = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		d.NodeCntValid = true
	} else {
		d.NodeCntValid = false
	}

	if opt.MetadataMask&idint.IgPort != 0 {
		d.IgPort = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		d.IgPortValid = true
	} else {
		d.IgPortValid = false
	}

	if opt.MetadataMask&idint.EgPort != 0 {
		d.EgPort = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		d.EgPortValid = true
	} else {
		d.EgPortValid = false
	}

	for i := range 4 {
		d.InstrDataLen[i] = int(opt.MetadataLength[i])
		switch d.InstrDataLen[i] {
		case 0:
		case 2:
			d.InstrData[i] = uint64(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
		case 4:
			d.InstrData[i] = uint64(binary.BigEndian.Uint32(data[offset : offset+4]))
			offset += 4
		case 6:
			var word [8]byte
			copy(word[2:], data[offset:offset+6])
			d.InstrData[i] = binary.BigEndian.Uint64(word[:])
			offset += 6
		case 8:
			d.InstrData[i] = binary.BigEndian.Uint64(data[offset : offset+8])
			offset += 8
		default:
			return serrors.New("invalid metadata length", "length", d.InstrDataLen[i])
		}
	}
	return nil
}
