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

package slayers

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/fcrypto"
	"github.com/scionproto/scion/pkg/private/serrors"
)

// ID-INT verifier types
const (
	IdIntVerifOther = 0
	IdIntVerifDst   = 1
	IdIntVerifSrc   = 2
)

// ID-INT aggregation modes
const (
	IdIntAgrOff = 0
	IdIntAgrAS  = 1
	IdIntAgrBR  = 2
	IdIntAgrRtr = 3
)

// ID-INT aggregation functions
const (
	IdIntAFFirst = 0
	IdIntAFLast  = 1
	IdIntAFMin   = 2
	IdIntAFMax   = 3
	IdIntAFSum   = 4
)

// ID-INT instruction bitmap
const (
	IdIntNodeId  uint8 = 0x08
	IdIntNodeCnt uint8 = 0x04
	IdIntIgrIf   uint8 = 0x02
	IdIntEgrIf   uint8 = 0x01
)

// ID-INT instructions
const (
	IdIntIZero2           = 0x00
	IdIntIIsd             = 0x01
	IdIntIBrLinkType      = 0x02
	IdIntIDeviceTypeRole  = 0x03
	IdIntICpuMemUsage     = 0x04
	IdIntICpuTemp         = 0x05
	IdIntIAsicTemp        = 0x06
	IdIntIFanSpeed        = 0x07
	IdIntITotalPower      = 0x08
	IdIntIEnergyMix       = 0x09
	IdIntIZero4           = 0x40
	IdIntIDeviceVendor    = 0x41
	IdIntIDeviceModel     = 0x42
	IdIntISoftwareVersion = 0x43
	IdIntINodeIpv4Addr    = 0x44
	IdIntIIngressIfSpeed  = 0x45
	IdIntIEgressIfSpeed   = 0x46
	IdIntIGpsLat          = 0x47
	IdIntIGpsLong         = 0x48
	IdIntIUptime          = 0x49
	IdIntIFwdEnergy       = 0x4A
	IdIntICo2Emission     = 0x4B
	IdIntIIngressLinkRx   = 0x4C
	IdIntIEgressLinkTx    = 0x4D
	IdIntIQueueId         = 0x4E
	IdIntIInstQueueLen    = 0x4F
	IdIntIAvgQueueLen     = 0x50
	IdIntIBufferId        = 0x51
	IdIntIInstBufferOcc   = 0x52
	IdIntIAvgBufferOcc    = 0x53
	IdIntIZero6           = 0x80
	IdIntIAsn             = 0x81
	IdIntIIngressTstamp   = 0x82
	IdIntIEgressTstamp    = 0x83
	IdIntIIgScifPktCnt    = 0x84
	IdIntIEgScifPktCnt    = 0x85
	IdIntIIgScifPktDrop   = 0x86
	IdIntIEgScifPktDrop   = 0x87
	IdIntIIgScifBytes     = 0x88
	IdIntIEgScifBytes     = 0x89
	IdIntIIgPktCnt        = 0x8A
	IdIntIEgPktCnt        = 0x8B
	IdIntIIgPktDrop       = 0x8C
	IdIntIEgPktDrop       = 0x8D
	IdIntIIgBytes         = 0x8E
	IdIntIEgBytes         = 0x8F
	IdIntIZero8           = 0xC0
	IdIntINodeIpv6AddrH   = 0xC1
	IdIntINodeIpv6AddrL   = 0xC2
	IdIntINop             = 0xFF
)

const (
	// ID-INT protocol version
	IdIntVersion = 0
	// ID-INT telemetry MAC length in bytes
	IntMacLen = 4
	// ID-INT noce length for encrypted telemetry in bytes
	IntNonceLen = 12
	// Minimum length of the ID-INT main header
	intMinHdrLen = 20
	// Length of an empty ID-INT stack entry
	intEmptyEntryLen = 8
	// Abolute maximum length of the ID-INT stack
	intMaxStackLen = 255 * 4
)

// ID-INT main header
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Ver |I|D|E|X|R|Mod|Vrf|VT |VL |    Length     |    NextHdr    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | DelayHops |Res|  MaxStackLen  | InstF | AF1 | AF2 | AF3 | AF4 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Inst1     |     Inst2     |     Inst3     |     Inst4     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Source Timestamp                       |
// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
// |                               |          Source Port          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         VerifierISD           |                               | \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               | |
// |                          VerifierAS                           | | If Vrf == 0
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// |                       VerifierHostAddr (4-16 bytes)           | /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Telemetry Stack                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IDINT struct {
	BaseLayer

	// Version of the header. Currently 0.
	Version uint8
	// Infrastructure mode. If set, the INT header is removed by the last border
	// router on the path.
	Infrastructure bool
	// Discard the packet at the last border router.
	Discard bool
	// Encrypt telemetry
	Encrypt bool
	// Some metadata omitted because maximum stack size was reached.
	MaxLengthExceeded bool
	// Aggregation mode (range 0-3)
	AggregationMode uint8
	// For whom the MAC/encrypt the telemetry (range 0-3 with 3 reserved)
	Verifier uint8
	// Type of third party verifier address
	VerifierAddrType AddrType
	// Length of the telemetry stack in multiples of 4 bytes
	StackLength uint8
	// Next header following ID-INT
	NextHdr L4ProtocolType
	// Number of AS-level hops to skip before telemetry is inserted (max. 63)
	DelayHops uint8
	// Maximum length of the telemetry stack in multiples of 4 bytes
	MaxStackLen uint8
	// Bitmap-encoded INT instructions (4 bit)
	InstructionBitmap uint8
	// Aggregation function for meatdata 1-4
	AggregationFunc [4]uint8
	// Metadata instruction 1-4
	Instruction [4]uint8
	// INT source timestamp and egress port. Used as input to DRKey.
	SourceTsPort uint64
	// Verifier address
	VerifIA addr.IA
	// Host address of the verifier
	RawVerifAddr []byte
	// Telemetry stack. Length must be a multiple of 4.
	TelemetryStack []byte
}

func (i *IDINT) LayerType() gopacket.LayerType {
	return LayerTypeIDINT
}

func (i *IDINT) CanDecode() gopacket.LayerClass {
	return LayerClassIDINT
}

func (i *IDINT) NextLayerType() gopacket.LayerType {
	return scionNextLayerTypeAfterINT(i.NextHdr)
}

// Serialize the main header to a byte slice. Does not include the telemetry stack.
func (i *IDINT) SerializeToSlice(buf []byte) (int, error) {
	// First 4 bytes
	var firstLine uint32
	firstLine |= uint32(i.Version) << 29
	if i.Infrastructure {
		firstLine |= 1 << 28
	}
	if i.Discard {
		firstLine |= 1 << 27
	}
	if i.Encrypt {
		firstLine |= 1 << 26
	}
	if i.MaxLengthExceeded {
		firstLine |= 1 << 25
	}
	firstLine |= (uint32(i.AggregationMode) & 0x3) << 22
	firstLine |= (uint32(i.Verifier) & 0x3) << 20
	firstLine |= (uint32(i.VerifierAddrType) & 0xf) << 16
	firstLine |= (uint32(i.StackLength) & 0xff) << 8
	firstLine |= uint32(i.NextHdr) & 0xff
	binary.BigEndian.PutUint32(buf[:4], firstLine)

	// Second 4 bytes
	var secondLine uint32
	secondLine |= (uint32(i.DelayHops) & 0x3f) << 26
	secondLine |= (uint32(i.MaxStackLen) & 0xff) << 16
	secondLine |= (uint32(i.InstructionBitmap) & 0xf) << 12
	secondLine |= (uint32(i.AggregationFunc[0]) & 0x7) << 9
	secondLine |= (uint32(i.AggregationFunc[1]) & 0x7) << 6
	secondLine |= (uint32(i.AggregationFunc[2]) & 0x7) << 3
	secondLine |= uint32(i.AggregationFunc[3]) & 0x7
	binary.BigEndian.PutUint32(buf[4:8], secondLine)

	// Instructions
	buf[8] = i.Instruction[0]
	buf[9] = i.Instruction[1]
	buf[10] = i.Instruction[2]
	buf[11] = i.Instruction[3]

	// Timestamp
	binary.BigEndian.PutUint64(buf[12:20], i.SourceTsPort)

	// Verifier address
	offset := intMinHdrLen
	if i.Verifier == IdIntVerifOther {
		if err := i.SerializeVerifierAddr(buf[intMinHdrLen:]); err != nil {
			return offset, err
		}
		offset += i.VerifierAddrLen()
	}

	return offset, nil
}

func (i *IDINT) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	stackLen := i.TrueStackLength()
	if stackLen > intMaxStackLen {
		return serrors.New("header length exceeds maximum",
			"max", intMaxStackLen, "actual", stackLen)
	}
	if stackLen%4 != 0 {
		return serrors.New("header length is not a multiple of 4", "actual", stackLen)
	}
	buf, err := b.PrependBytes(i.Length())
	if err != nil {
		return err
	}

	if opts.FixLengths {
		i.StackLength = uint8(stackLen / 4)
	}

	var offset int
	if offset, err = i.SerializeToSlice(buf); err != nil {
		return err
	}

	// Telemetry stack
	copy(buf[offset:], i.TelemetryStack)

	return nil
}

func (i *IDINT) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < intMinHdrLen {
		df.SetTruncated()
		return serrors.New("packet is shorter than the minimum header length",
			"min", intMinHdrLen, "actual", len(data))
	}

	// First 4 bytes
	firstLine := binary.BigEndian.Uint32(data[:4])
	i.Version = uint8(firstLine >> 29)
	if i.Version != IdIntVersion {
		return serrors.New("unkonwn ID-INT header version",
			"expected", IdIntVersion, "version", i.Version)
	}
	i.Infrastructure = ((firstLine >> 28) & 0x1) != 0
	i.Discard = ((firstLine >> 27) & 0x1) != 0
	i.Encrypt = ((firstLine >> 26) & 0x1) != 0
	i.MaxLengthExceeded = ((firstLine >> 25) & 0x1) != 0
	i.AggregationMode = uint8((firstLine >> 22) & 0x3)
	i.Verifier = uint8((firstLine >> 20) & 0x3)
	i.VerifierAddrType = AddrType((firstLine >> 16) & 0xf)
	i.StackLength = uint8((firstLine >> 8) & 0xff)
	i.NextHdr = L4ProtocolType(firstLine & 0xff)

	// Second 4 bytes
	secondLine := binary.BigEndian.Uint32(data[4:8])
	i.DelayHops = uint8((secondLine >> 26) & 0x3f)
	i.MaxStackLen = uint8((secondLine >> 16) & 0xff)
	i.InstructionBitmap = uint8((secondLine >> 12) & 0xf)
	i.AggregationFunc[0] = uint8((secondLine >> 9) & 0x7)
	i.AggregationFunc[1] = uint8((secondLine >> 6) & 0x7)
	i.AggregationFunc[2] = uint8((secondLine >> 3) & 0x7)
	i.AggregationFunc[3] = uint8(secondLine & 0x7)

	// Instructions
	i.Instruction[0] = data[8]
	i.Instruction[1] = data[9]
	i.Instruction[2] = data[10]
	i.Instruction[3] = data[11]

	// Tiemstamp
	i.SourceTsPort = binary.BigEndian.Uint64(data[12:20])

	// Verifier address
	offset := intMinHdrLen
	if i.Verifier == IdIntVerifOther {
		if err := i.DecodeVerifierAddr(data[intMinHdrLen:]); err != nil {
			df.SetTruncated()
			return err
		}
		offset += i.VerifierAddrLen()
	}

	// Telemetry stack
	stackLen := 4 * int(i.StackLength)
	if (len(data) - offset) < stackLen {
		df.SetTruncated()
		return serrors.New("invalid ID-INT header, telemetry truncated",
			"stackLen", stackLen, "actual", len(data)-offset)
	}
	i.TelemetryStack = data[offset : offset+stackLen]
	offset += stackLen

	i.Contents = data[:offset]
	i.Payload = data[offset:]

	return nil
}

func (i *IDINT) Length() int {
	return intMinHdrLen + i.VerifierAddrLen() + i.TrueStackLength()
}

func (i *IDINT) VerifierAddrLen() int {
	if i.Verifier == IdIntVerifOther {
		return addr.IABytes + i.VerifierAddrType.Length()
	} else {
		return 0
	}
}

func (i *IDINT) TrueStackLength() int {
	return len(i.TelemetryStack)
}

func (i *IDINT) SerializeVerifierAddr(data []byte) error {
	if len(data) < i.VerifierAddrLen() {
		return serrors.New("provided buffer is too small", "expected", i.VerifierAddrLen(),
			"actual", len(data))
	}
	binary.BigEndian.PutUint64(data[0:8], uint64(i.VerifIA))
	copy(data[8:i.VerifierAddrType.Length()], i.RawVerifAddr)

	return nil
}

func (i *IDINT) DecodeVerifierAddr(data []byte) error {
	if len(data) < i.VerifierAddrLen() {
		return serrors.New("provided buffer is too small", "expected", i.VerifierAddrLen(),
			"actual", len(data))
	}
	i.VerifIA = addr.IA(binary.BigEndian.Uint64(data[0:8]))
	i.RawVerifAddr = data[8:i.VerifierAddrType.Length()]

	return nil
}

func decodeIDINT(data []byte, pb gopacket.PacketBuilder) error {
	idint := &IDINT{}
	err := idint.DecodeFromBytes(data, pb)
	if err != nil {
		return err
	}
	pb.AddLayer(idint)
	return pb.NextDecoder(scionNextLayerTypeAfterINT(idint.NextHdr))
}

// ID-INT metadata header. These are the entries on the metadata stack.
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |S|I|E|A|C| Res |    Hop    |Res| Mask  | ML1 | ML2 | ML3 | ML4 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               | \
// |                             Nonce                             | | If encrypted
// |                                                               | /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Metadata                            |
// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                               |  Padding to a multiple of 4B  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              MAC                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IntStackEntry struct {
	BaseLayer

	// Set if this is the source metadata entry at the bottom of the stack.
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
	Nonce [IntNonceLen]byte
	// Encoded metadata with padding to a multiple of 4 bytes
	Metadata []byte
	// Metadata MAC
	Mac [IntMacLen]byte
}

func (m *IntStackEntry) Length() int {
	length := intEmptyEntryLen
	if m.Encrypted {
		length += IntNonceLen
	}
	if m.MetadataMask&IdIntNodeId != 0 {
		length += 4
	}
	if m.MetadataMask&IdIntNodeCnt != 0 {
		length += 2
	}
	if m.MetadataMask&IdIntIgrIf != 0 {
		length += 2
	}
	if m.MetadataMask&IdIntEgrIf != 0 {
		length += 2
	}
	for _, x := range m.MetadataLength {
		length += decodeMdLen(x)
	}
	length += (length % 4) // padding
	return length
}

func (m *IntStackEntry) SerializeToSlice(buf []byte) (int, error) {
	if len(buf) < m.Length() {
		return 0, serrors.New("buffer too short", "expected", m.Length(), "actual", len(buf))
	}

	// First 4 bytes
	var firstLine uint32
	if m.SourceMetadata {
		firstLine |= 1 << 31
	}
	if m.Ingress {
		firstLine |= 1 << 30
	}
	if m.Egress {
		firstLine |= 1 << 29
	}
	if m.Aggregated {
		firstLine |= 1 << 28
	}
	if m.Encrypted {
		firstLine |= 1 << 27
	}
	firstLine |= (uint32(m.HopIndex) & 0x3f) << 18
	firstLine |= (uint32(m.MetadataMask) & 0xf) << 12
	firstLine |= (uint32(m.MetadataLength[0]) & 0x7) << 9
	firstLine |= (uint32(m.MetadataLength[1]) & 0x7) << 6
	firstLine |= (uint32(m.MetadataLength[2]) & 0x7) << 3
	firstLine |= uint32(m.MetadataLength[3]) & 0x7
	binary.BigEndian.PutUint32(buf[:4], firstLine)

	offset := 4
	if m.Encrypted {
		copy(buf[offset:offset+IntNonceLen], m.Nonce[:])
		offset += IntNonceLen
	}

	offset += copy(buf[offset:], m.Metadata)
	offset += copy(buf[offset:], m.Mac[:])

	return offset, nil
}

func (m *IntStackEntry) DecodeFromBytes(data []byte) error {
	if len(data) < intEmptyEntryLen {
		return serrors.New("metadata header too short",
			"min", intEmptyEntryLen, "actual", len(data))
	}

	// First 4 bytes
	firstLine := binary.BigEndian.Uint32(data[:4])
	m.SourceMetadata = ((firstLine >> 31) & 0x1) != 0
	m.Ingress = ((firstLine >> 30) & 0x1) != 0
	m.Egress = ((firstLine >> 29) & 0x1) != 0
	m.Aggregated = ((firstLine >> 28) & 0x1) != 0
	m.Encrypted = ((firstLine >> 27) & 0x1) != 0
	m.HopIndex = uint8((firstLine >> 18) & 0x3f)
	m.MetadataMask = uint8((firstLine >> 12) & 0xf)
	m.MetadataLength[0] = uint8((firstLine >> 9) & 0x7)
	m.MetadataLength[1] = uint8((firstLine >> 6) & 0x7)
	m.MetadataLength[2] = uint8((firstLine >> 3) & 0x7)
	m.MetadataLength[3] = uint8(firstLine & 0x7)

	expectedLen := m.Length()
	if len(data) < expectedLen {
		return serrors.New("metadata header too short",
			"expected", expectedLen, "actual", len(data))
	}

	offset := 4
	if m.Encrypted {
		copy(m.Nonce[:], data[offset:offset+IntNonceLen])
		offset += IntNonceLen
	}

	m.Metadata = data[offset : expectedLen-IntMacLen]
	copy(m.Mac[:], data[expectedLen-IntMacLen:expectedLen])
	offset += len(m.Metadata) + IntMacLen

	m.Contents = data[:offset]
	m.Payload = data[offset:]

	return nil
}

func (e *IntStackEntry) GetMetadata() (*IntMetadata, error) {
	md := &IntMetadata{}
	if err := md.DecodeFromBytes(e.Metadata, e); err != nil {
		return nil, err
	}
	return md, nil
}

func (e *IntStackEntry) SetMetadata(md *IntMetadata) error {
	// Serialize metadata
	e.Metadata = make([]byte, md.Length())
	if _, err := md.SerializeToSlice(e.Metadata); err != nil {
		return err
	}

	// Update metadata presence bitmap
	e.MetadataMask = 0
	if md.NodeIdValid {
		e.MetadataMask |= IdIntNodeId
	}
	if md.NodeCntValid {
		e.MetadataMask |= IdIntNodeCnt
	}
	if md.IgrIfValid {
		e.MetadataMask |= IdIntIgrIf
	}
	if md.EgrIfValid {
		e.MetadataMask |= IdIntEgrIf
	}

	// Update metadata slot length fields
	for i := 0; i < 4; i++ {
		e.MetadataLength[i] = encodeMdLen(md.InstrDataLen[i])
	}

	return nil
}

// Serialize to slice with a newly calculated MAC. The IntStackEntry instance
// itself is not changed. This function calculates the MAC directly on the
// destination buffer avoiding a temporary buffer for calculating the MAC.
func (m *IntStackEntry) SerializeToSliceMac(
	buf []byte,
	prevMac [IntMacLen]byte,
	key [16]byte,
) (int, error) {

	offset, err := m.SerializeToSlice(buf)
	if err != nil {
		return offset, err
	}

	// Overwrite MAC with MAC of the previous hop before calculating the new MAC
	copy(buf[offset-IntMacLen:], prevMac[:IntMacLen])
	mac := fcrypto.CBCMAC(key, buf)

	// Write the new MAC
	copy(buf[offset-IntMacLen:], mac[:IntMacLen])

	return offset, err
}

// Serialize to slice with a newly calculated MAC and encrypt the telemetry data
// in the buffer. The IntStackEntry instance itself is not changed. This
// function calculates the MAC directly on the destination buffer avoiding a
// temporary buffer for calculating the MAC.
func (m *IntStackEntry) SerializeToSliceEncrypt(
	buf []byte,
	prevMac [IntMacLen]byte,
	key [16]byte,
	nonce [12]byte,
) (int, error) {

	copy(m.Nonce[:], nonce[:])
	offset, err := m.SerializeToSliceMac(buf, prevMac, key)
	if err != nil {
		return offset, err
	}

	// Encrypt
	const metadataOffset = 4 + IntNonceLen
	fcrypto.AESCTR(key, m.Nonce, buf[metadataOffset:offset-IntMacLen])

	return offset, nil
}

// Update the MAC of a source telemetry entry.
// intLayer provides additional fields from the ID-INT main header for MACing.
func (m *IntStackEntry) AuthSource(
	key [16]byte,
	intLayer *IDINT,
) ([IntMacLen]byte, error) {

	mac, err := m.calcSourceMac(key, intLayer)
	if err != nil {
		return [IntMacLen]byte{}, err
	}
	copy(m.Mac[:], mac[:])

	return mac, nil
}

// Authenticate and encrypt a source telemetry entry.
// nonce is set as the entries nonce.
// intLayer provides additional fields from the ID-INT main header for MACing.
func (m *IntStackEntry) EncryptSource(
	key [16]byte,
	nonce [IntNonceLen]byte,
	intLayer *IDINT,
) ([IntMacLen]byte, error) {

	m.Encrypted = true
	copy(m.Nonce[:], nonce[:])

	mac, err := m.calcSourceMac(key, intLayer)
	if err != nil {
		return [IntMacLen]byte{}, err
	}
	copy(m.Mac[:], mac[:])
	m.encdecImpl(key)

	return mac, nil
}

// Decrypts the metadata and MAC of a source stack entry using the nonce from
// the header. Calculates and returns the expected nonce. Comapre to the nonce
// in the header to validate telemetry integrity.
func (m *IntStackEntry) DecryptSource(
	key [16]byte, intLayer *IDINT,
) ([IntMacLen]byte, error) {

	if m.Encrypted {
		m.encdecImpl(key)
	}
	// clear encrypted flag after calcSourceMac so nonce is included in MAC
	mac, err := m.calcSourceMac(key, intLayer)
	m.Encrypted = false
	if err != nil {
		return [IntMacLen]byte{}, err
	}
	return mac, nil
}

// Decrypts the metadata and MAC of this stack entry using the nonce from the
// header. Calculates and returns the expected nonce. Comapre to the nonce in
// the header to validate telemetry integrity.
func (m *IntStackEntry) Decrypt(
	key [16]byte, prevMac [IntMacLen]byte,
) ([IntMacLen]byte, error) {

	if m.Encrypted {
		m.encdecImpl(key)
	}
	// clear encrypted flag after calcSourceMac so nonce is included in MAC
	mac, err := m.calcMac(key, prevMac)
	m.Encrypted = false
	if err != nil {
		return [IntMacLen]byte{}, err
	}
	return mac, nil
}

func (m *IntStackEntry) encdecImpl(key [16]byte) {
	// AES-CCM requires encrypting the MAC as well
	data := append(m.Metadata, m.Mac[:]...)
	fcrypto.AESCTR(key, m.Nonce, data)
	m.Metadata = data[:len(m.Metadata)]
	copy(m.Mac[:], m.Metadata[len(data)-IntMacLen:])
}

// Calculate telemetry MAC.
// The MAC is computed over the following fields:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |S|I|E|A|C|  0  |    Hop    | 0 | Mask  | ML1 | ML2 | ML3 | ML4 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               | \
// |                             Nonce                             | | If encrypted
// |                                                               | /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Metadata                            |
// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                               |  Padding to a multiple of 4B  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    MAC of the previous hop                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (m *IntStackEntry) calcMac(key [16]byte, prevMac [IntMacLen]byte) ([IntMacLen]byte, error) {
	var buf [64]byte

	length, err := m.SerializeToSlice(buf[:])
	if err != nil {
		return [IntMacLen]byte{}, err
	}
	copy(buf[length-IntMacLen:], prevMac[:IntMacLen])

	mac := fcrypto.CBCMAC(key, buf[:length])

	var truncMac [IntMacLen]byte
	copy(truncMac[:], mac[:IntMacLen])
	return truncMac, nil
}

// Calculates and returns the MAC for the INT source entry on the telemetry stack.
// The Mac is calculated over to following fields:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Ver |I|D|E|0|0|Mod|Vrf|VT |VL |       0       |       0       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       0       |  MaxStackLen  | InstF | AF1 | AF2 | AF3 | AF4 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Inst1     |     Inst2     |     Inst3     |     Inst4     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Source Timestamp                       |
// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
// |                               |          Source Port          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         VerifierISD           |                               | \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               | |
// |                          VerifierAS                           | | Only if Vrf == 0
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
// |                       VerifierHostAddr (4-16 bytes)           | /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |1|I|E|0|C|  0  |    Hop    | 0 | Mask  | ML1 | ML2 | ML3 | ML4 |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               | \
// |                             Nonce                             | | If encrypted
// |                                                               | /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Metadata                            |
// |                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                               |  Padding to a multiple of 4B  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (m *IntStackEntry) calcSourceMac(key [16]byte, intLayer *IDINT) ([IntMacLen]byte, error) {
	// Serialize main header and source stack entry
	buf := make([]byte, 128)
	offset, err := intLayer.SerializeToSlice(buf)
	if err != nil {
		return [IntMacLen]byte{}, err
	}
	length, err := m.SerializeToSlice(buf[offset:])
	offset += length
	if err != nil {
		return [IntMacLen]byte{}, err
	}

	// Zero-out updateable fields
	buf[2] = 0
	buf[3] = 0
	buf[4] = 0

	mac := fcrypto.CBCMAC(key, buf[:offset-IntMacLen])

	var truncMac [IntMacLen]byte
	copy(truncMac[:], mac[:IntMacLen])
	return truncMac, nil
}

// Decoded metadata from an ID-INT stack entry
type IntMetadata struct {
	// Bitmap metadata validity
	NodeIdValid  bool
	NodeCntValid bool
	IgrIfValid   bool
	EgrIfValid   bool

	// AS-wide unique node ID
	NodeId uint32
	// Number of nodes aggregated into this entry
	NodeCnt uint16
	// Ingress device-level interface identifier
	IgrIf uint16
	// Egress device-level interface identifier
	EgrIf uint16

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
	if d.IgrIfValid {
		length += 2
	}
	if d.EgrIfValid {
		length += 2
	}
	for _, len := range d.InstrDataLen {
		length += len
	}
	length += (length % 4) // padding
	return length
}

// Merge metadata from another object according to the given aggregation functions.
func (d *IntMetadata) Merge(aggrFuncs [4]uint8, other *IntMetadata) error {
	updateNode := false
	for i := 0; i < 4; i++ {
		if d.InstrDataLen[i] != 0 && other.InstrDataLen[i] != 0 {
			switch aggrFuncs[i] {
			case IdIntAFFirst:
				// keep old value
			case IdIntAFLast:
				d.InstrDataLen[i] = other.InstrDataLen[i]
				d.InstrData[i] = other.InstrData[i]
				updateNode = true
			case IdIntAFMin:
				if d.InstrData[i] > other.InstrData[i] {
					d.InstrData[i] = other.InstrData[i]
					updateNode = true
				}
			case IdIntAFMax:
				if d.InstrData[i] < other.InstrData[i] {
					d.InstrData[i] = other.InstrData[i]
					updateNode = true
				}
			case IdIntAFSum:
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
	if other.IgrIfValid && (!d.IgrIfValid || updateNode) {
		d.IgrIf = other.IgrIf
	}
	if other.EgrIfValid && (!d.EgrIfValid || updateNode) {
		d.EgrIf = other.EgrIf
	}

	if d.NodeCntValid {
		if other.NodeCntValid {
			d.NodeCnt += other.NodeCnt
		} else {
			d.NodeCnt += 1
		}
	}

	return nil
}

func (d *IntMetadata) SerializeToSlice(buf []byte) (int, error) {
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
	if d.IgrIfValid {
		binary.BigEndian.PutUint16(buf[offset:], d.IgrIf)
		offset += 2
	}
	if d.EgrIfValid {
		binary.BigEndian.PutUint16(buf[offset:], d.EgrIf)
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
	padding := offset % 4
	if padding > 0 {
		for i := 0; i < padding; i++ {
			buf[offset+i] = 0
		}
		offset += padding
	}

	return offset, nil
}

func (d *IntMetadata) DecodeFromBytes(data []byte, entry *IntStackEntry) error {
	offset := 0

	if entry.MetadataMask&IdIntNodeId != 0 {
		d.NodeId = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		d.NodeIdValid = true
	} else {
		d.NodeIdValid = false
	}

	if entry.MetadataMask&IdIntNodeCnt != 0 {
		d.NodeCnt = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		d.NodeCntValid = true
	} else {
		d.NodeCntValid = false
	}

	if entry.MetadataMask&IdIntIgrIf != 0 {
		d.IgrIf = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		d.IgrIfValid = true
	} else {
		d.IgrIfValid = false
	}

	if entry.MetadataMask&IdIntEgrIf != 0 {
		d.EgrIf = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		d.EgrIfValid = true
	} else {
		d.EgrIfValid = false
	}

	for i := 0; i < 4; i++ {
		d.InstrDataLen[i] = decodeMdLen(entry.MetadataLength[i])
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

// Decode metadata length.
func decodeMdLen(ml uint8) int {
	// `0xxb` = 0 bytes
	// `100b` = 2 bytes
	// `101b` = 4 bytes
	// `110b` = 6 bytes
	// `111b` = 8 bytes
	if ml&0x4 != 0 {
		return 2*int(ml&0x3) + 2
	} else {
		return 0
	}
}

// Inverse of decodeMdLen.
func encodeMdLen(length int) uint8 {
	switch length {
	case 0:
		return 0x0
	case 2:
		return 0x4
	case 4:
		return 0x5
	case 6:
		return 0x6
	case 8:
		return 0x7
	default:
		panic(serrors.New("invalid metadata length", "length", length))
	}
}

// DecodingLayer for skipping ID-INT without fully decoding it.
type IdIntSkipper struct {
	BaseLayer

	// For whom the MAC/encrypt the telemetry (range 0-3 with 3 reserved)
	Verifier uint8
	// Type of third party verifier address
	VerifierAddrType AddrType
	// Length of the telemetry stack in multiples of 4 bytes
	StackLength uint8
	// Next header following ID-INT
	NextHdr L4ProtocolType
	// Total length of the header and telemetry data
	ActualLength int
}

func (s *IdIntSkipper) LayerType() gopacket.LayerType {
	return LayerTypeIDINT
}

func (s *IdIntSkipper) CanDecode() gopacket.LayerClass {
	return LayerClassIDINT
}

func (s *IdIntSkipper) NextLayerType() gopacket.LayerType {
	return scionNextLayerTypeAfterINT(s.NextHdr)
}

func (s *IdIntSkipper) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < intMinHdrLen {
		df.SetTruncated()
		return serrors.New("packet is shorter than the minimum header length",
			"min", intMinHdrLen, "actual", len(data))
	}

	s.Verifier = uint8((data[1] >> 4) & 0x3)
	s.VerifierAddrType = AddrType((data[1] & 0xf))
	s.StackLength = uint8(data[2])
	s.NextHdr = L4ProtocolType(data[3])
	s.ActualLength = intMinHdrLen + addr.IABytes + s.VerifierAddrType.Length()
	s.ActualLength += 4 * int(s.StackLength)

	return nil
}
