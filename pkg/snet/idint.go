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

package snet

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"lukechampine.com/frand"
)

// How much an ID-INT timestamp is allowed to be in the past for the data to
// still be considered valid. In nanoseconds.
const idintMaxAge = 60_000_000_000

// IntRequest of RawIntReport for PacketInfo struct
type IdInt interface {
	DecodeFrom(intLayer *slayers.IDINT) error
}

// ID-INT request to be encoded in a packet.
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
	// Aggregate stack entries
	AggregationMode int
	// Aggregation function for slot 1-4
	AggregationFunc [4]uint8
	// Metadata instruction slot 1-4
	Instruction [4]uint8
	// Type of verifier
	Verifier int
	// Address of the verifier if not identical to packet source or destination
	VerifierAddr SCIONAddress
	// Metadata provided by the source
	SourceMetadata IntHop
	// Time at which SourceKey is valid
	SourceTS time.Time
	// Host->Host DRKey for MACing the source metadata
	SourceKey drkey.Key
}

func (r *IntRequest) EncodeTo(
	intLayer *slayers.IDINT,
	nextLayer slayers.L4ProtocolType,
	sourcePort uint16,
) error {
	intLayer.Version = 0
	intLayer.Infrastructure = false
	intLayer.Discard = false
	intLayer.Encrypt = r.Encrypt
	intLayer.MaxLengthExceeded = false
	intLayer.AggregationMode = uint8(r.AggregationMode)

	intLayer.Verifier = uint8(r.Verifier)
	if r.Verifier == slayers.IdIntVerifOther {
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
		intLayer.InstructionBitmap |= slayers.IdIntNodeId
	}
	if r.ReqNodeCount {
		intLayer.InstructionBitmap |= slayers.IdIntNodeCnt
	}
	if r.ReqIngressIf {
		intLayer.InstructionBitmap |= slayers.IdIntIgrIf
	}
	if r.ReqEgressIf {
		intLayer.InstructionBitmap |= slayers.IdIntEgrIf
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
	intLayer.SourceTsPort = (uint64(r.SourceTS.UnixNano()) << 16) | uint64(sourcePort)

	if !r.Encrypt {
		source.AuthSource(r.SourceKey, intLayer)
	} else {
		var nonce [slayers.IntNonceLen]byte
		frand.Read(nonce[:])
		source.EncryptSource(r.SourceKey, nonce, intLayer)
	}

	intLayer.TelemetryStack = make([]byte, source.Length())
	n, err := source.SerializeToSlice(intLayer.TelemetryStack)
	if err != nil {
		return err
	}
	intLayer.StackLength = uint8(n / 4)

	return nil
}

func (r *IntRequest) DecodeFrom(intLayer *slayers.IDINT) error {
	r.Encrypt = intLayer.Encrypt
	r.SkipHops = 0
	r.MaxStackLen = 4 * int(intLayer.MaxStackLen)
	r.ReqNodeId = (intLayer.InstructionBitmap & slayers.IdIntNodeId) != 0
	r.ReqNodeCount = (intLayer.InstructionBitmap & slayers.IdIntNodeCnt) != 0
	r.ReqIngressIf = (intLayer.InstructionBitmap & slayers.IdIntIgrIf) != 0
	r.ReqEgressIf = (intLayer.InstructionBitmap & slayers.IdIntEgrIf) != 0
	r.AggregationMode = int(intLayer.AggregationMode)
	r.AggregationFunc = intLayer.AggregationFunc
	r.Instruction = intLayer.Instruction

	r.Verifier = int(intLayer.Verifier)
	if r.Verifier == slayers.IdIntVerifOther {
		r.VerifierAddr.IA = intLayer.VerifIA
		if intLayer.VerifierAddrType != slayers.T4Ip && intLayer.VerifierAddrType == slayers.T16Ip {
			return serrors.New("address not valid as ID-INT verifier", "type", intLayer.VerifierAddrType)
		}
		if ip, ok := netip.AddrFromSlice(intLayer.RawVerifAddr); ok {
			r.VerifierAddr.Host = addr.HostIP(ip)
		}
	}

	r.SourceMetadata = IntHop{}
	r.SourceTS = time.Unix(0, int64(intLayer.SourceTsPort>>16))
	r.SourceKey = drkey.Key{}

	return nil
}

// Raw ID-INT headers as received from another host. Must be decoded/decrypted
// to an IntReport in order to be read.
type RawIntReport struct {
	header slayers.IDINT
	stack  []slayers.IntStackEntry
}

// Recover the original request strict from an ID-INT header. Does not include
// the source metadata or key.
func (r *RawIntReport) RecoverRequest(request *IntRequest) error {
	if err := request.DecodeFrom(&r.header); err != nil {
		return err
	}
	// Try to recover the original value of DelayHops from the first hop index
	// in the telemetry stack.
	for i := len(r.stack) - 1; i >= 0; i-- {
		if !r.stack[i].SourceMetadata {
			request.SkipHops = int(r.stack[i].HopIndex)
			break
		}
	}
	return nil
}

// Length of the raw report when serialized to a packet header.
func (r *RawIntReport) SerializedLength() int {
	length := r.header.Length()
	for i := range r.stack {
		length += r.stack[i].Length()
	}
	return length
}

// Serializes the ID-INT data in its packet header format.
func (r *RawIntReport) SerializeToSlice(buf []byte) (int, error) {
	if len(buf) < r.header.Length() {
		return 0, serrors.New("provided buffer is too small",
			"expected", r.header.Length(), "actual", len(buf))
	}

	offset, err := r.header.SerializeToSlice(buf)
	if err != nil {
		return offset, err
	}

	for i := range r.stack {
		length, err := r.stack[i].SerializeToSlice(buf[offset:])
		if err != nil {
			return offset, err
		}
		offset += length
	}

	return offset, nil
}

// Read ID-INT telemetry from raw header bytes.
func (r *RawIntReport) DecodeFromBytes(data []byte) error {
	var intLayer slayers.IDINT
	err := intLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}
	return r.DecodeFrom(&intLayer)
}

func (r *RawIntReport) DecodeFrom(intLayer *slayers.IDINT) error {
	// Copy header so we can interpret telemetry data later. Make sure our copy
	// of the IDINT layer does not point into the original packet buffer
	// anymore.
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

// Decode the telemetry report without verifying authenticity. Fails if the
// report contains encrypted data.
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

type HopToIA func(uint) (addr.IA, error)

// Decodes and verifies telemetry data. Fails if the data cannot be decrypted or
// verified.
// keyProv must provide DRKeys for hop verification.
// hopToIA maps hop indices to the ISD-ASN of the corresponding AS along the
// path.
func (r *RawIntReport) VerifyAndDecrypt(
	ctx context.Context,
	report *IntReport,
	source addr.Addr,
	keyProv KeyProvider,
	hopToIA HopToIA,
) error {
	report.MaxLengthExceeded = r.header.MaxLengthExceeded
	report.AggregationFunc = r.header.AggregationFunc
	report.Instruction = r.header.Instruction

	// Get source timestamp
	now := time.Now()
	elapsed := (uint64(now.UnixNano()&0xffff_ffff_ffff) - (r.header.SourceTsPort >> 16))
	elapsed &= 0xffff_ffff_ffff
	ts := now.UnixNano() - int64(elapsed)
	if elapsed > idintMaxAge {
		return serrors.New("metadata timestamp too far in the past", "ts", ts)
	}
	sourceTime := time.Unix(0, ts).UTC()

	// Verify metadata
	report.Data = report.Data[:0]
	var mac [slayers.IntMacLen]byte
	for i := len(r.stack) - 1; i >= 0; i-- {
		entry := &r.stack[i]
		ia, err := hopToIA(uint(entry.HopIndex))
		if err != nil {
			return err
		}
		var key drkey.Key
		if entry.SourceMetadata {
			key, err = keyProv.GetHostHostKey(ctx, sourceTime, source)
		} else {
			key, err = keyProv.GetASHostKey(ctx, sourceTime, ia)
		}
		if err != nil {
			return serrors.WithCtx(err, "source", entry.SourceMetadata, "hop", entry.HopIndex, "ia", ia)
		}
		wasEncrypted := entry.Encrypted
		if err := r.verifyAndDecryptEntry(entry, key, &mac); err != nil {
			return serrors.WithCtx(err, "source", entry.SourceMetadata, "hop", entry.HopIndex, "ia", ia)
		}
		if hop, err := decodeMetadata(entry); err != nil {
			return serrors.WithCtx(err, "source", entry.SourceMetadata, "hop", entry.HopIndex, "ia", ia)
		} else {
			hop.Encrypted = wasEncrypted
			report.Data = append(report.Data, hop)
		}
	}
	return nil
}

func (r *RawIntReport) verifyAndDecryptEntry(
	entry *slayers.IntStackEntry,
	key drkey.Key,
	prevMac *[slayers.IntMacLen]byte,
) error {
	var mac [slayers.IntMacLen]byte
	var err error

	if entry.SourceMetadata {
		mac, err = entry.DecryptSource(key, &r.header)
		if err != nil {
			return err
		}
	} else {
		mac, err = entry.Decrypt(key, *prevMac)
		if err != nil {
			return err
		}
	}
	if !compareMACs(entry.Mac[:], mac[:slayers.IntMacLen]) {
		return serrors.New("telemetry MAC verification failed",
			"expected", mac, "actual", entry.Mac[:])
	}
	copy(prevMac[:], mac[:])

	return nil
}

func decodeMetadata(entry *slayers.IntStackEntry) (IntHop, error) {
	hop := IntHop{
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

func compareMACs(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Decoded ID-INT header with metadata from remote routers.
type IntReport struct {
	// Whether metadata was omitted because the maximum stack length was reached
	MaxLengthExceeded bool
	// Requested metadata aggregation mode
	AggregationMode int
	// Aggregation function for slot 1-4
	AggregationFunc [4]uint8
	// Metadata instruction slot 1-4
	Instruction [4]uint8
	// Telemetry data in path order (source to destination)
	Data []IntHop
}

// ID-INT metadata from a single hop.
type IntHop struct {
	// Which hop field to data relates to
	HopIndex uint8

	metadataMask   uint8
	metadataLength [4]int

	Source     bool // Source entry flag
	Ingress    bool // AS-ingress BR flag
	Egress     bool // AS-egress BR flag
	Aggregated bool // Aggregated data flag
	Encrypted  bool // Original entry was encrypted

	NodeId    uint32 // ID of the originating node
	NodeCount uint16 // NUmber of aggregated notes in this entry
	IngressIf uint16 // Node ingress interface (not IfID)
	EgressIf  uint16 // Node egress interface (not IfID)

	// Instruction-requested metadata
	DataSlots [4]uint64
}

func (h *IntHop) HasNodeId() bool {
	return (h.metadataMask & slayers.IdIntNodeId) != 0
}

func (h *IntHop) SetNodeId(id uint32) {
	h.metadataMask |= slayers.IdIntNodeId
	h.NodeId = id
}

func (h *IntHop) ClearNodeId() {
	h.metadataMask &= ^slayers.IdIntNodeId
}

func (h *IntHop) HasNodeCount() bool {
	return (h.metadataMask & slayers.IdIntNodeCnt) != 0
}

func (h *IntHop) SetNodeCount(count uint16) {
	h.metadataMask |= slayers.IdIntNodeCnt
	h.NodeCount = count
}

func (h *IntHop) ClearNodeCount() {
	h.metadataMask &= ^slayers.IdIntNodeCnt
}

func (h *IntHop) HasIngressIf() bool {
	return (h.metadataMask & slayers.IdIntIgrIf) != 0
}

func (h *IntHop) SetIngressIf(igr uint16) {
	h.metadataMask |= slayers.IdIntIgrIf
	h.IngressIf = igr
}

func (h *IntHop) ClearIngressIf() {
	h.metadataMask &= ^slayers.IdIntIgrIf
}

func (h *IntHop) HasEgressIf() bool {
	return (h.metadataMask & slayers.IdIntEgrIf) != 0
}

func (h *IntHop) SetEgressIf(egr uint16) {
	h.metadataMask |= slayers.IdIntEgrIf
	h.EgressIf = egr
}

func (h *IntHop) ClearEgressIf() {
	h.metadataMask &= ^slayers.IdIntEgrIf
}

func (h *IntHop) DataLength(slot int) int {
	return int(h.metadataLength[slot])
}

func (h *IntHop) SetDataUint16(slot int, data uint16) {
	h.metadataLength[slot] = 2
	h.DataSlots[slot] = uint64(data)
}

func (h *IntHop) SetDataUint32(slot int, data uint32) {
	h.metadataLength[slot] = 4
	h.DataSlots[slot] = uint64(data)
}

func (h *IntHop) SetDataUint48(slot int, data uint64) {
	h.metadataLength[slot] = 6
	h.DataSlots[slot] = uint64(data)
}

func (h *IntHop) SetDataUint64(slot int, data uint64) {
	h.metadataLength[slot] = 8
	h.DataSlots[slot] = data
}

func (h *IntHop) ClearData(slot int) {
	h.metadataMask &= ^slayers.IdIntEgrIf
}
