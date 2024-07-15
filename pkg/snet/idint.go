package snet

import (
	"crypto/rand"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
	"github.com/scionproto/scion/pkg/slayers"
)

const IntDataMaxAgeNano = 60_0000_0000_0000

type InBandTelemetry interface {
	EncodeTo(intLayer *slayers.IDINT, nextLayer slayers.L4ProtocolType, sourcePort uint16) error
	DecodeFrom(intLayer *slayers.IDINT) error
}

type IntRequest struct {
	// Ask routers to encrypt telemetry data
	Encrypt bool
	// How many AS-level hop to skip before telemetry is requested
	SkipHops int
	// Maximum telemetry stack length
	MaxStackLen int
	// Get node ID
	ReqNodeId bool
	// Get node count for aggregated telemetry
	ReqNodeCount bool
	// Get ingress interfaces
	ReqIngressIf bool
	// Get egress interfaces
	ReqEgressIf bool
	// IntAggrF{First|Last|Min|Max|Sum}
	AggregationMode int
	// Aggregation function for slot 1-4
	AggregationFunc [4]uint8
	// Metadata instruction slot 1-4
	Instruction [4]uint8
	// IntVerif{ThirdParty|Dest|Src}
	Verifier int
	// Address of the verifier if not identical to packet source or destination
	VerifierAddr SCIONAddress
	// Metadata provided by the source
	SourceMetadata TelemetryHop
}

func (r *IntRequest) EncodeTo(intLayer *slayers.IDINT,
	nextLayer slayers.L4ProtocolType, sourcePort uint16) error {
	intLayer.Version = 0
	intLayer.Infrastructure = false
	intLayer.Discard = false
	intLayer.Encrypt = r.Encrypt
	intLayer.MaxLengthExceeded = false
	intLayer.AggregationMode = uint8(r.AggregationMode)

	intLayer.Verifier = uint8(r.Verifier)
	if r.Verifier == slayers.IntVerifThirdParty {
		intLayer.VerifIA = r.VerifierAddr.IA
		if r.VerifierAddr.Host.Type() == addr.HostTypeIP {
			if r.VerifierAddr.Host.IP().Is4() {
				intLayer.VerifierAddrType = slayers.T4Ip
			} else {
				intLayer.VerifierAddrType = slayers.T16Ip
			}
			intLayer.RawVerifAddr = r.VerifierAddr.Host.IP().AsSlice()
		} else {
			return serrors.New("address not valid as ID-INT verifier", "address", r.VerifierAddr)
		}
	}

	intLayer.NextHdr = nextLayer
	intLayer.DelayHops = uint8(r.SkipHops)
	intLayer.MaxStackLen = uint8(r.MaxStackLen / 4)

	intLayer.InstructionBitmap = 0
	if r.ReqNodeId {
		intLayer.InstructionBitmap |= slayers.IntBitNodeId
	}
	if r.ReqNodeCount {
		intLayer.InstructionBitmap |= slayers.IntBitNodeCnt
	}
	if r.ReqIngressIf {
		intLayer.InstructionBitmap |= slayers.IntBitIgrIf
	}
	if r.ReqEgressIf {
		intLayer.InstructionBitmap |= slayers.IntBitEgrIf
	}

	intLayer.AggregationFunc = r.AggregationFunc
	intLayer.Instruction = r.Instruction

	sourceData := slayers.IntMetadata{
		NodeIdValid:  r.SourceMetadata.HasNodeId(),
		NodeCntValid: r.SourceMetadata.HasNodeCount(),
		IgrIfValid:   r.SourceMetadata.HasIngressIf(),
		EgrIfValid:   r.SourceMetadata.HasEgressIf(),
		NodeId:       r.SourceMetadata.NodeId,
		NodeCnt:      r.SourceMetadata.NodeCount,
		IgrIf:        r.SourceMetadata.IngressIf,
		EgrIf:        r.SourceMetadata.EgressIf,
	}
	copy(sourceData.InstrDataLen[:], r.SourceMetadata.metadataLength[:])
	copy(sourceData.InstrData[:], r.SourceMetadata.DataSlots[:])
	source := slayers.IntStackEntry{
		SourceMetadata: true,
	}
	if err := source.SetMetadata(&sourceData); err != nil {
		return err
	}

	// TODO(lschulz): Derive key
	now := time.Now()
	var key drkey.HostHostKey

	if r.Encrypt {
		if _, err := rand.Read(source.Nonce[:]); err != nil {
			return err
		}
		if err := source.Encrypt(key.Key[:], source.Nonce[:]); err != nil {
			return err
		}
	}

	intLayer.SourceTsPort = (uint64(now.UnixNano()) << 16) | uint64(sourcePort)
	h, err := scrypto.InitMac(key.Key[:])
	if err != nil {
		return err
	}
	mac, err := source.CalcSourceMac(h, intLayer)
	if err != nil {
		return err
	}
	copy(source.Mac[:], mac[:slayers.IntMacLen])

	intLayer.TelemetryStack = make([]byte, source.Length())
	n, err := source.SerializeToSlice(intLayer.TelemetryStack)
	if err != nil {
		return err
	}
	intLayer.StackLength = uint8(n / 4)

	return nil
}

func (r *IntRequest) DecodeFrom(intLayer *slayers.IDINT) error {
	panic("not implemented")
}

type RawIntReport struct {
	header slayers.IDINT
	stack  []slayers.IntStackEntry
}

func (r *RawIntReport) SerializeToSlice(buf []byte) error {
	if len(buf) < r.header.Length() {
		return serrors.New("provided buffer is too small",
			"expected", r.header.Length(), "actual", len(buf))
	}

	offset, err := r.header.SerializeToSlice(buf)
	if err != nil {
		return err
	}

	for i := range r.stack {
		length, err := r.stack[i].SerializeToSlice(buf[offset:])
		if err != nil {
			return err
		}
		offset += length
	}

	return nil
}

func (r *RawIntReport) EncodeTo(intLayer *slayers.IDINT,
	nextLayer slayers.L4ProtocolType, sourcePort uint16) error {
	panic("not implemented")
}

func (r *RawIntReport) DecodeFrom(intLayer *slayers.IDINT) error {
	// Copy header so we can interpret telemetry data later.
	// Make sure our copy of the IDINT layer does not point into the original packet buffer anymore.
	r.header = *intLayer
	r.header.RawVerifAddr = make([]byte, len(intLayer.RawVerifAddr))
	copy(r.header.RawVerifAddr, intLayer.RawVerifAddr)
	r.header.TelemetryStack = nil

	// Parse telemetry stack
	r.stack = r.stack[:0]
	data := intLayer.TelemetryStack
	var entry slayers.IntStackEntry
	for len(data) > 0 {
		if err := entry.DecodeFromBytes(data); err != nil {
			return err
		}
		data = data[entry.Length():]
		r.stack = append(r.stack, entry)
	}
	return nil
}

// func (r *RawIntReport) Verifier() SCIONAddress {
// }

// Decode the telemetry report without verifying authenticity. Fails it the report
// contains encrypted data.
func (r *RawIntReport) DecodeUnverified(report *IntReport) error {
	report.MaxLengthExceeded = r.header.MaxLengthExceeded
	report.AggregationFunc = r.header.AggregationFunc
	report.Instruction = r.header.Instruction

	report.Data = report.Data[:0]
	for i := len(r.stack) - 1; i >= 0; i-- {
		entry := &r.stack[i]
		if entry.Encrypted {
			return serrors.New("no key for encrypted in-band telemetry")
		}
		if hop, err := decodeMetadata(entry); err != nil {
			return err
		} else {
			report.Data = append(report.Data, hop)
		}
	}
	return nil
}

func (r *RawIntReport) VerifyAndDecrypt(report *IntReport) error {
	report.MaxLengthExceeded = r.header.MaxLengthExceeded
	report.AggregationFunc = r.header.AggregationFunc
	report.Instruction = r.header.Instruction

	// Get source timestamp
	now := time.Now()
	elapsed := (uint64(now.UnixNano()&0xffff_ffff_ffff) - (r.header.SourceTsPort >> 16))
	elapsed &= 0xffff_ffff_ffff
	ts := now.UnixNano() - int64(elapsed)
	if elapsed > IntDataMaxAgeNano {
		return serrors.New("metadata timestamp too far in the past", "ts", ts)
	}

	// Verify metadata
	report.Data = report.Data[:0]
	var mac [slayers.IntMacLen]byte
	for i := len(r.stack) - 1; i >= 0; i-- {
		entry := &r.stack[i]
		var key [16]byte // TODO(lschulz): Get DRKey valid at source timestamp
		if err := r.verifyAndDecryptEntry(entry, key[:], &mac); err != nil {
			return err
		}
		if hop, err := decodeMetadata(entry); err != nil {
			return err
		} else {
			report.Data = append(report.Data, hop)
		}
	}
	return nil
}

func (r *RawIntReport) verifyAndDecryptEntry(entry *slayers.IntStackEntry,
	key []byte, prevMac *[slayers.IntMacLen]byte) error {
	h, err := scrypto.InitMac(key)
	if err != nil {
		return err
	}
	var mac []byte
	if entry.SourceMetadata {
		mac, err = entry.CalcSourceMac(h, &r.header)
		if err != nil {
			return err
		}
	} else {
		mac, err = entry.CalcMac(h, *prevMac)
		if err != nil {
			return err
		}
	}
	if !slayers.CompareMACs(entry.Mac[:], mac[:slayers.IntMacLen]) {
		return serrors.New("telemetry MAC verification failed",
			"expected", mac[:slayers.IntMacLen], "actual", entry.Mac[:])
	}
	copy(prevMac[:], mac[:slayers.IntMacLen])
	if entry.Encrypted {
		if err := entry.Decrypt(key); err != nil {
			return err
		}
	}
	return nil
}

func decodeMetadata(entry *slayers.IntStackEntry) (TelemetryHop, error) {
	hop := TelemetryHop{
		HopIndex:   entry.HopIndex,
		Source:     entry.SourceMetadata,
		Ingress:    entry.Ingress,
		Egress:     entry.Egress,
		Aggregated: entry.Aggregated,
	}
	md, err := entry.GetMetadata()
	if err != nil {
		return hop, err
	}
	if md.NodeIdValid {
		hop.SetNodeId(md.NodeId)
	}
	if md.NodeCntValid {
		hop.SetNodeCount(md.NodeCnt)
	}
	if md.IgrIfValid {
		hop.SetIngressIf(md.IgrIf)
	}
	if md.EgrIfValid {
		hop.SetEgressIf(md.EgrIf)
	}
	for i := 0; i < 4; i++ {
		hop.metadataLength[i] = md.InstrDataLen[i]
		hop.DataSlots[i] = md.InstrData[i]
	}
	return hop, nil
}

type IntReport struct {
	// Some metadata omitted because the maximum stack length was reached
	MaxLengthExceeded bool
	// IntAggrF{First|Last|Min|Max|Sum}
	AggregationMode int
	// Aggregation function for slot 1-4
	AggregationFunc [4]uint8
	// Metadata instruction slot 1-4
	Instruction [4]uint8
	// Telemetry data in path order (source to destination)
	Data []TelemetryHop
}

type TelemetryHop struct {
	// Which hop field to data relates to
	HopIndex uint8

	metadataMask   uint8
	metadataLength [4]int

	Source     bool
	Ingress    bool
	Egress     bool
	Aggregated bool

	NodeId    uint32
	NodeCount uint16
	IngressIf uint16
	EgressIf  uint16

	DataSlots [4]uint64
}

func (h *TelemetryHop) HasNodeId() bool {
	return (h.metadataMask & slayers.IntBitNodeId) != 0
}

func (h *TelemetryHop) SetNodeId(id uint32) {
	h.metadataMask |= slayers.IntBitNodeId
	h.NodeId = id
}

func (h *TelemetryHop) ClearNodeId() {
	h.metadataMask &= ^slayers.IntBitNodeId
}

func (h *TelemetryHop) HasNodeCount() bool {
	return (h.metadataMask & slayers.IntBitNodeCnt) != 0
}

func (h *TelemetryHop) SetNodeCount(count uint16) {
	h.metadataMask |= slayers.IntBitNodeCnt
	h.NodeCount = count
}

func (h *TelemetryHop) ClearNodeCount() {
	h.metadataMask &= ^slayers.IntBitNodeCnt
}

func (h *TelemetryHop) HasIngressIf() bool {
	return (h.metadataMask & slayers.IntBitIgrIf) != 0
}

func (h *TelemetryHop) SetIngressIf(igr uint16) {
	h.metadataMask |= slayers.IntBitIgrIf
	h.IngressIf = igr
}

func (h *TelemetryHop) ClearIngressIf() {
	h.metadataMask &= ^slayers.IntBitIgrIf
}

func (h *TelemetryHop) HasEgressIf() bool {
	return (h.metadataMask & slayers.IntBitEgrIf) != 0
}

func (h *TelemetryHop) SetEgressIf(egr uint16) {
	h.metadataMask |= slayers.IntBitEgrIf
	h.EgressIf = egr
}

func (h *TelemetryHop) ClearEgressIf() {
	h.metadataMask &= ^slayers.IntBitEgrIf
}

func (h *TelemetryHop) DataLength(slot int) int {
	return int(h.metadataLength[slot])
}

func (h *TelemetryHop) SetDataUint16(slot int, data uint16) {
	h.metadataLength[slot] = 2
	h.DataSlots[slot] = uint64(data)
}

func (h *TelemetryHop) SetDataUint32(slot int, data uint32) {
	h.metadataLength[slot] = 4
	h.DataSlots[slot] = uint64(data)
}

func (h *TelemetryHop) SetDataUint48(slot int, data uint64) {
	h.metadataLength[slot] = 6
	h.DataSlots[slot] = uint64(data)
}

func (h *TelemetryHop) SetDataUint64(slot int, data uint64) {
	h.metadataLength[slot] = 8
	h.DataSlots[slot] = data
}

func (h *TelemetryHop) ClearData(slot int) {
	h.metadataMask &= ^slayers.IntBitEgrIf
}
