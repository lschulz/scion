package slayers

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
)

const (
	IntAggrUnlimited = 0
	IntAggrPerAS     = 1
	IntAggrPerBr     = 2
	IntAggrPerIntRtr = 3
)

const (
	IntVerifThirdParty = 0
	IntVerifDest       = 1
	IntVerifSrc        = 2
)

const (
	IntAggrFFirst = 0
	IntAggrFLast  = 1
	IntAggrFMin   = 2
	IntAggrFMax   = 3
	IntAggrFSum   = 4
)

const IntMacLen = 4
const intMaxStackLen = 255 * 4
const minIntHdrLen = 20
const minMetadataHdrLen = 8
const metadataNonceLen = 12

// ID-INT main header
//
// Format:
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Ver |I|D|E|X|F|Mod|Vrf|VT |VL |    Length     |    NextHdr    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | DelayHops |Res| RemHopCnt |Res| InstF | AF1 | AF2 | AF3 | AF4 |
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
// |                        Telemetry Stack                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type IDINT struct {
	BaseLayer

	// Version of the header. Currently 0.
	Version uint8
	// Infrastructure mode. If set, the INT header is removed by the last border router on the path.
	Infrastructure bool
	// Discard the packet at the last border router.
	Discard bool
	// Encrypt telemetry
	Encrypt bool
	// Some metadata omitted because maximum hop count was reached.
	MaxHopCntExceeded bool
	// Some metadata omitted because the MTU was reached.
	MtuExceeded bool
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
	// Remaining AS-level hops that can add telemetry to the stack (max. 63)
	RemHopCnt uint8
	// Bitmap-encoded INT instructions (4 bit)
	InstructionBitmap uint8
	// Aggregation function for meatdata 1-4
	AggregationFunc [4]uint8
	// Metadata instruction 1-4
	Instruction [4]uint8
	// INT source timestamp and egress port. Used as input to DRKey.
	SourceTsPort uint64
	// Verifier address if Verifier == IntVerifThirdParty
	VerifIA addr.IA
	// Host address of the verifier if Verifier == IntVerifThirdParty
	RawVerifAddr []byte

	// Whether to serialize TelemetryNew
	TelemetryNewValid bool
	// New telemetry stack entry to insert on top of TelemetryTos
	TelemetryNew IntMetadata
	// Top of telemetry stack
	TelemetryTos IntMetadata

	// Remaining telemetry stack. Length must be a multiple of 4.
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
	if i.MaxHopCntExceeded {
		firstLine |= 1 << 25
	}
	if i.MtuExceeded {
		firstLine |= 1 << 24
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
	secondLine |= (uint32(i.RemHopCnt) & 0x3f) << 18
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
	offset := CmnHdrLen
	if i.Verifier == IntVerifThirdParty {
		if err := i.SerializeVerifierAddr(buf[minIntHdrLen:]); err != nil {
			return err
		}
		offset += i.VerifierAddrLen()
	}

	// Telemetry stack
	if i.TelemetryNewValid {
		n, err := i.TelemetryNew.SerializeTo(buf[offset:])
		if err != nil {
			return err
		}
		offset += n
	}
	n, err := i.TelemetryTos.SerializeTo(buf[offset:])
	if err != nil {
		return err
	}
	offset += n
	copy(buf[offset:], i.TelemetryStack)

	return nil
}

func (i *IDINT) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < minIntHdrLen {
		df.SetTruncated()
		return serrors.New("packet is shorter than the minimum header length",
			"min", minIntHdrLen, "actual", len(data))
	}

	// First 4 bytes
	firstLine := binary.BigEndian.Uint32(data[:4])
	i.Version = uint8(firstLine >> 29)
	i.Infrastructure = ((firstLine >> 28) & 0x1) != 0
	i.Discard = ((firstLine >> 27) & 0x1) != 0
	i.Encrypt = ((firstLine >> 26) & 0x1) != 0
	i.MaxHopCntExceeded = ((firstLine >> 25) & 0x1) != 0
	i.MtuExceeded = ((firstLine >> 24) & 0x1) != 0
	i.AggregationMode = uint8((firstLine >> 22) & 0x3)
	i.Verifier = uint8((firstLine >> 20) & 0x3)
	i.VerifierAddrType = AddrType((firstLine >> 16) & 0xf)
	i.StackLength = uint8((firstLine >> 8) & 0xff)
	i.NextHdr = L4ProtocolType(firstLine & 0xff)

	// Second 4 bytes
	secondLine := binary.BigEndian.Uint32(data[4:8])
	i.DelayHops = uint8((secondLine >> 26) & 0x3f)
	i.RemHopCnt = uint8((secondLine >> 18) & 0x3f)
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
	offset := CmnHdrLen
	if i.Verifier == IntVerifThirdParty {
		if err := i.DecodeVerifierAddr(data[minIntHdrLen:]); err != nil {
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
	if err := i.TelemetryTos.DecodeFromBytes(data[offset:stackLen]); err != nil {
		df.SetTruncated()
		return err
	}
	offset += i.TelemetryTos.Length()
	i.TelemetryStack = data[offset:stackLen]

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

func (i *IDINT) Length() int {
	return minIntHdrLen + i.VerifierAddrLen() + i.TrueStackLength()
}

func (i *IDINT) VerifierAddrLen() int {
	return addr.IABytes + i.VerifierAddrType.Length()
}

func (i *IDINT) TrueStackLength() int {
	length := 0
	if i.TelemetryNewValid {
		length += i.TelemetryNew.Length()
	}
	length += i.TelemetryTos.Length()
	length += len(i.TelemetryStack)
	return length
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

// ID-INT metadata header. These are the entries on the metadata stack.
//
// Format:
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
type IntMetadata struct {
	BaseLayer

	// Set if this is tje source metadata entry, the bottom of the stack.
	SourceMetadata bool
	// Ingress border router
	Ingress bool
	// Egress border router
	Egress bool
	// Contains aggregated data
	Aggregated bool
	// Is encrypted
	Encrypted bool

	// Index of the corresponding hop field
	HopIndex uint8
	// Bitmap metadata presence mask (4 bit)
	MetadataMask uint8
	// Length of metadata stored in slot 1-4.
	MetadataLength [4]uint8

	// Nonce for encrypted data
	Nonce []byte
	// Encoded metadata with padding to a multiple of 4 bytes
	Metadata []byte
	// Metadata MAC
	Mac [IntMacLen]byte
}

func (m *IntMetadata) Length() int {
	length := minMetadataHdrLen
	if m.Encrypted {
		length += metadataNonceLen
	}
	for _, x := range m.MetadataLength {
		length += MetadataLength(x)
	}
	return length
}

func (m *IntMetadata) SerializeTo(buf []byte) (int, error) {
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
		copy(buf[offset:offset+metadataNonceLen], m.Nonce)
		offset += metadataNonceLen
	}

	offset = copy(buf[offset:], m.Metadata)
	offset = copy(buf[offset:], m.Mac[:])

	return offset, nil
}

func (m *IntMetadata) DecodeFromBytes(data []byte) error {
	if len(data) < minMetadataHdrLen {
		return serrors.New("metadata header too short",
			"min", minMetadataHdrLen, "actual", len(data))
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
		m.Nonce = data[offset : offset+metadataNonceLen]
		offset += metadataNonceLen
	}

	m.Metadata = data[offset : expectedLen-IntMacLen]
	copy(m.Mac[:], data[expectedLen-IntMacLen:expectedLen])

	return nil
}

func MetadataLength(ml uint8) int {
	if ml&0x4 == 1 {
		return 2 * int(ml&0x3)
	} else {
		return 0
	}
}

// DecodingLayer for skipping ID-INT without fully decoding it
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
	if len(data) < minIntHdrLen {
		df.SetTruncated()
		return serrors.New("packet is shorter than the minimum header length",
			"min", minIntHdrLen, "actual", len(data))
	}

	s.Verifier = uint8((data[1] >> 4) & 0x3)
	s.VerifierAddrType = AddrType((data[1] & 0xf))
	s.StackLength = uint8(data[2])
	s.NextHdr = L4ProtocolType(data[3])
	s.ActualLength = minIntHdrLen + addr.IABytes + s.VerifierAddrType.Length()
	s.ActualLength += 4 * int(s.StackLength)

	return nil
}
