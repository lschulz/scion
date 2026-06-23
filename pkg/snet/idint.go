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

package snet

import (
	"context"
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/idint"
	"lukechampine.com/frand"
)

// How much an ID-INT timestamp is allowed to be in the past for the data to
// still be considered valid. In nanoseconds.
const idintMaxAge = 60_000_000_000

// ID-INT request to be encoded in a packet.
type IntRequestEncoder interface {
	AppendTo(
		[]*slayers.HopByHopOption, slayers.L4ProtocolType, uint16,
	) ([]*slayers.HopByHopOption, error)
}

type IntRequest struct {
	// Ask routers to encrypt telemetry data
	Encrypt bool
	// How many AS-level hop to skip before telemetry is requested
	SkipHops int
	// Size of telemetry stack to allocate in bytes. Must be a multiple of 4
	// and provide sufficient space for at least the source entry.
	MaxStackLen int
	// Get node ID
	ReqNodeId bool
	// Get node count for aggregated telemetry
	ReqNodeCount bool
	// Get ingress interfaces
	ReqIgPort bool
	// Get egress interfaces
	ReqEgPort bool
	// Aggregate stack entries
	AggregationMode int
	// Aggregation function for slot 1-4
	AggregationFunc [4]uint8
	// Metadata instruction slot 1-4
	Instructions [4]uint8
	// Type of verifier
	Verifier int
	// Address of the verifier if not identical to packet source or destination
	VerifierAddr SCIONAddress
	// Metadata provided by the source
	SourceMetadata IntMetadata
	// Time at which SourceKey is valid
	SourceTS time.Time
	// Host->Host DRKey for MACing the source metadata
	SourceKey slayers.IdIntKey
}

func (r *IntRequest) AppendTo(
	opts []*slayers.HopByHopOption,
	nextLayer slayers.L4ProtocolType,
	sourcePort uint16,
) ([]*slayers.HopByHopOption, error) {
	hdr := new(slayers.IdIntOpt)
	hdr.Version = 0
	hdr.Infrastructure = false
	hdr.Discard = false
	hdr.Encrypt = r.Encrypt
	hdr.StackSpaceExhausted = false
	if r.AggregationMode > idint.AgRtr {
		return opts, serrors.New("invalid aggregation mode", "mode", r.AggregationMode)
	}
	hdr.AggregationMode = uint8(r.AggregationMode)

	hdr.Verifier = uint8(r.Verifier)
	if r.Verifier == idint.VfThirdParty {
		hdr.VerifIA = r.VerifierAddr.IA
		if r.VerifierAddr.Host.Type() == addr.HostTypeIP {
			if r.VerifierAddr.Host.IP().Is4() {
				hdr.VerifierAddrType = slayers.T4Ip
			} else {
				hdr.VerifierAddrType = slayers.T16Ip
			}
			copy(hdr.RawVerifAddr[:], r.VerifierAddr.Host.IP().AsSlice())
		} else {
			return nil, serrors.New("address not valid as ID-INT verifier",
				"address", r.VerifierAddr)
		}
	}

	if r.MaxStackLen%4 != 0 {
		return nil, serrors.New("telemetry stack length must be a multiple of 4",
			"requested", r.MaxStackLen)
	}
	hdr.StackLen = uint8(r.MaxStackLen / 4)
	hdr.TOS = 0
	hdr.DelayHops = uint8(min(max(r.SkipHops, 0), 63))

	hdr.InstructionBitmap = 0
	if r.ReqNodeId {
		hdr.InstructionBitmap |= idint.NodeId
	}
	if r.ReqNodeCount {
		hdr.InstructionBitmap |= idint.NodeCnt
	}
	if r.ReqIgPort {
		hdr.InstructionBitmap |= idint.IgPort
	}
	if r.ReqEgPort {
		hdr.InstructionBitmap |= idint.EgPort
	}

	hdr.AggregationFunc = r.AggregationFunc
	hdr.Instructions = r.Instructions

	sourceData := slayers.IntMetadata{
		NodeIdValid:  r.SourceMetadata.HasNodeId(),
		NodeCntValid: r.SourceMetadata.HasNodeCount(),
		IgPortValid:  r.SourceMetadata.HasIngressPort(),
		EgPortValid:  r.SourceMetadata.HasEgressPort(),
		NodeId:       r.SourceMetadata.NodeId,
		NodeCnt:      r.SourceMetadata.NodeCount,
		IgPort:       r.SourceMetadata.IngressPort,
		EgPort:       r.SourceMetadata.EgressPort,
	}
	copy(sourceData.InstrDataLen[:], r.SourceMetadata.metadataLength[:])
	copy(sourceData.InstrData[:], r.SourceMetadata.DataSlots[:])
	source := new(slayers.IdIntStackEntryOpt)
	source.SourceMetadata = true
	if err := source.SetMetadata(&sourceData); err != nil {
		return opts, err
	}
	hdr.SourceTsPort = (uint64(r.SourceTS.UnixNano()) << 16) | uint64(sourcePort)

	if !r.Encrypt {
		if _, err := source.AuthSource(&r.SourceKey, hdr); err != nil {
			return opts, err
		}
	} else {
		var nonce slayers.IdIntNonce
		frand.Read(nonce[:])
		source.EncryptSource(&r.SourceKey, &nonce, hdr)
	}

	sourceLen := source.Length()
	if r.MaxStackLen < sourceLen {
		return nil, serrors.New("requested stack too small",
			"requested", r.MaxStackLen, "required", sourceLen)
	}

	// Serialize ID-INT header option
	hdrOpt := new(slayers.HopByHopOption)
	hdrOpt.OptType = slayers.OptTypeIdInt
	hdrOpt.OptDataLen = byte(hdr.Length() - 2)
	hdrOpt.OptData = make([]byte, hdrOpt.OptDataLen)
	hdr.SerializeToSlice(hdrOpt.OptData, false)
	opts = append(opts, hdrOpt)

	// Serialize source stack entry
	srcOpt := new(slayers.HopByHopOption)
	srcOpt.OptType = slayers.OptTypeIdIntStackEntry
	srcOpt.OptDataLen = byte(source.Length() - 2)
	srcOpt.OptData = make([]byte, srcOpt.OptDataLen)
	source.SerializeToSlice(srcOpt.OptData, false)
	opts = append(opts, srcOpt)

	// Allocate space for telemetry stack
	opts = appendPadOpts(opts, r.MaxStackLen-sourceLen)
	return opts, nil
}

func (r *IntRequest) DecodeFrom(opt *slayers.IdIntOpt) error {
	r.Encrypt = opt.Encrypt
	r.MaxStackLen = 4 * int(opt.StackLen)
	r.ReqNodeId = (opt.InstructionBitmap & idint.NodeId) != 0
	r.ReqNodeCount = (opt.InstructionBitmap & idint.NodeCnt) != 0
	r.ReqIgPort = (opt.InstructionBitmap & idint.IgPort) != 0
	r.ReqEgPort = (opt.InstructionBitmap & idint.EgPort) != 0
	r.AggregationMode = int(opt.AggregationMode)
	r.AggregationFunc = opt.AggregationFunc
	r.Instructions = opt.Instructions

	r.Verifier = int(opt.Verifier)
	if r.Verifier == idint.VfThirdParty {
		r.VerifierAddr.IA = opt.VerifIA
		if opt.VerifierAddrType != slayers.T4Ip && opt.VerifierAddrType == slayers.T16Ip {
			return serrors.New("address not valid as ID-INT verifier", "type", opt.VerifierAddrType)
		}
		addrLen := 4
		if opt.VerifierAddrType == slayers.T16Ip {
			addrLen = 16
		}
		if ip, ok := netip.AddrFromSlice(opt.RawVerifAddr[:addrLen]); ok {
			r.VerifierAddr.Host = addr.HostIP(ip)
		}
	}

	r.SourceMetadata = IntMetadata{}
	r.SourceTS = time.Unix(0, int64(opt.SourceTsPort>>16))
	r.SourceKey = slayers.IdIntKey{}
	return nil
}

// appendPadOpts appends padding options to take up n bytes.
func appendPadOpts(opts []*slayers.HopByHopOption, n int) []*slayers.HopByHopOption {
	for n > 0 {
		if n == 1 {
			padding := new(slayers.HopByHopOption)
			padding.OptType = slayers.OptTypePad1
			opts = append(opts, padding)
			n -= 1
		} else {
			padLen := min(n-2, 255)
			padding := new(slayers.HopByHopOption)
			padding.OptType = slayers.OptTypePadN
			padding.OptDataLen = byte(padLen)
			padding.OptData = make([]byte, padLen)
			opts = append(opts, padding)
			n -= padLen + 2
		}
	}
	return opts
}

// Raw ID-INT headers as received from another host. Must be decoded/decrypted
// to an IntReport in order to be read.
type RawIntReport struct {
	Header slayers.IdIntOpt
	Stack  []slayers.IdIntStackEntryOpt
}

func (r *RawIntReport) Parse(opts []*slayers.HopByHopOption) error {
	if len(opts) < 2 {
		return serrors.New("too few options for ID-INT")
	}

	// Parse main header
	if err := r.Header.Parse(opts[0].OptData, false); err != nil {
		return err
	}

	// Parse telemetry stack
	for _, opt := range opts[1:] {
		if opt.OptType == slayers.OptTypeIdInt {
			return serrors.New("too many ID-INT headers")
		} else if opt.OptType == slayers.OptTypeIdIntStackEntry {
			entry := slayers.IdIntStackEntryOpt{}
			if _, err := entry.Parse(opt.OptData, false); err != nil {
				return err
			}
			r.Stack = append(r.Stack, entry)
		} else if opt.OptType == slayers.OptTypePadN || opt.OptType == slayers.OptTypePad1 {
			continue
		} else {
			break // remaining options do not belong to ID-INT
		}
	}

	return nil
}

// SerializeToSlice serializes an ID-INT report as a SCION hop-by-hop option
// header containing a sequence of TLV-encoded ID-INT and pad options.
// Returns the number of bytes written.
func (r *RawIntReport) SerializeToSlice(buf []byte) (int, error) {
	length := r.SerializeToSliceLength()
	if len(buf) < length {
		return 0, serrors.New("provided buffer is too small",
			"expected", length, "actual", len(buf))
	}

	offset := 2
	length, err := r.Header.SerializeToSlice(buf[offset:], true)
	if err != nil {
		return -1, err
	}
	offset += length
	for i := range r.Stack {
		length, err := r.Stack[i].SerializeToSlice(buf[offset:], true)
		if err != nil {
			return -1, err
		}
		offset += length
	}

	// Include hop-by-hop option header to help ParseFromSlice() and fix
	// alignment.
	buf[0] = 0                      // next header
	buf[1] = byte((offset / 4) - 1) // extension length

	return offset, nil
}

// SerializeToSliceLength returns the number of bytes that will be written by
// SerializeToSlice().
func (r *RawIntReport) SerializeToSliceLength() int {
	length := r.Header.Length()
	for i := range r.Stack {
		length += r.Stack[i].Length()
	}
	return 2 + length
}

// ParseFromSlice is the inverse of SerializeToSlice().
func (r *RawIntReport) ParseFromSlice(data []byte) error {
	var hbhExt slayers.HopByHopExtn
	if err := hbhExt.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}
	return r.Parse(hbhExt.Options)
}

// RecoverRequest recovers the original request from an ID-INT report. The
// generated requests does not contain the source metadata or key.
func (r *RawIntReport) RecoverRequest(request *IntRequest) error {
	if err := request.DecodeFrom(&r.Header); err != nil {
		return err
	}
	// Try to recover the original value of DelayHops from the first hop index
	// in the telemetry stack.
	for i := range r.Stack {
		if !r.Stack[i].SourceMetadata {
			request.SkipHops = int(r.Stack[i].HopIndex)
			break
		}
	}
	return nil
}

// DecodeUnverified decodes the telemetry report without verifying authenticity.
// Fails if the report contains encrypted data.
func (r *RawIntReport) DecodeUnverified(report *IntReport) error {
	report.MaxLengthExceeded = r.Header.StackSpaceExhausted
	report.SourceTS = r.Header.SourceTsPort >> 16
	report.AggregationFunc = r.Header.AggregationFunc
	report.Instructions = r.Header.Instructions

	report.Data = report.Data[:0]
	for i := range r.Stack {
		entry := &r.Stack[i]
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

// VerifyAndDecrypt decodes and verifies telemetry data. Fails if the data
// cannot be decrypted or verified. keyProv provides DRKeys for hop
// verification. hopToIA maps hop indices to the ISD-ASN of the corresponding AS
// along the path.
func (r *RawIntReport) VerifyAndDecrypt(
	ctx context.Context,
	report *IntReport,
	source addr.Addr,
	keyProv KeyProvider,
	hopToIA HopToIA,
) error {
	report.MaxLengthExceeded = r.Header.StackSpaceExhausted
	report.SourceTS = r.Header.SourceTsPort >> 16
	report.AggregationFunc = r.Header.AggregationFunc
	report.Instructions = r.Header.Instructions

	// Get source timestamp
	now := time.Now()
	elapsed := (uint64(now.UnixNano()&0xffff_ffff_ffff) - (r.Header.SourceTsPort >> 16))
	elapsed &= 0xffff_ffff_ffff
	ts := now.UnixNano() - int64(elapsed)
	if elapsed > idintMaxAge {
		return serrors.New("metadata timestamp too far in the past", "ts", ts)
	}
	sourceTime := time.Unix(0, ts).UTC()

	// Verify metadata
	report.Data = report.Data[:0]
	var mac [slayers.IdIntMacLen]byte
	for i := range r.Stack {
		entry := &r.Stack[i]
		ia, err := hopToIA(uint(entry.HopIndex))
		if err != nil {
			return err
		}
		var key drkey.Key
		if entry.SourceMetadata {
			key, err = keyProv.GetHostSelfKey(ctx, sourceTime, source)
		} else {
			key, err = keyProv.GetASHostKey(ctx, sourceTime, ia)
		}
		if err != nil {
			return serrors.Join(err, nil,
				"source", entry.SourceMetadata, "hop", entry.HopIndex, "ia", ia)
		}
		wasEncrypted := entry.Encrypted
		if err := r.verifyAndDecryptEntry(entry, (*slayers.IdIntKey)(&key), &mac); err != nil {
			return serrors.Join(err, nil,
				"source", entry.SourceMetadata, "hop", entry.HopIndex, "ia", ia)
		}
		if hop, err := decodeMetadata(entry); err != nil {
			return serrors.Join(err, nil,
				"source", entry.SourceMetadata, "hop", entry.HopIndex, "ia", ia)
		} else {
			hop.Encrypted = wasEncrypted
			report.Data = append(report.Data, hop)
		}
	}
	return nil
}

func (r *RawIntReport) verifyAndDecryptEntry(
	opt *slayers.IdIntStackEntryOpt,
	key *slayers.IdIntKey,
	prevMac *[slayers.IdIntMacLen]byte,
) error {
	var mac [slayers.IdIntMacLen]byte
	var err error

	encMac := opt.Mac // the encrypted MAC is used for chaining
	if opt.SourceMetadata {
		mac, err = opt.DecryptSource(key, &r.Header)
		if err != nil {
			return err
		}
	} else {
		mac, err = opt.Decrypt(key, *prevMac)
		if err != nil {
			return err
		}
	}
	if !compareMACs(opt.Mac[:], mac[:slayers.IdIntMacLen]) {
		return serrors.New("telemetry MAC verification failed",
			"expected", mac, "actual", opt.Mac[:])
	}
	copy(prevMac[:], encMac[:])

	return nil
}

func decodeMetadata(entry *slayers.IdIntStackEntryOpt) (IntMetadata, error) {
	hop := IntMetadata{
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
	if md.IgPortValid {
		hop.SetIngressPort(md.IgPort)
	}
	if md.EgPortValid {
		hop.SetEgressPort(md.EgPort)
	}
	for i := range 4 {
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
	// Source timestamp
	SourceTS uint64
	// Requested metadata aggregation mode
	AggregationMode int
	// Aggregation function for slot 1-4
	AggregationFunc [4]uint8
	// Metadata instruction slot 1-4
	Instructions [4]uint8
	// Telemetry data in path order (source to destination)
	Data []IntMetadata
}

// ID-INT metadata from a single hop.
type IntMetadata struct {
	// Which hop field to data relates to
	HopIndex uint8

	metadataMask   uint8
	metadataLength [4]int

	Source     bool // Source entry flag
	Ingress    bool // AS-ingress BR flag
	Egress     bool // AS-egress BR flag
	Aggregated bool // Aggregated data flag
	Encrypted  bool // Original entry was encrypted

	NodeId      uint32 // ID of the originating node
	NodeCount   uint16 // NUmber of aggregated notes in this entry
	IngressPort uint16 // Node ingress device port
	EgressPort  uint16 // Node egress device port

	// Instruction-requested metadata
	DataSlots [4]uint64
}

func (h *IntMetadata) HasNodeId() bool {
	return (h.metadataMask & idint.NodeId) != 0
}

func (h *IntMetadata) SetNodeId(id uint32) {
	h.metadataMask |= idint.NodeId
	h.NodeId = id
}

func (h *IntMetadata) ClearNodeId() {
	h.metadataMask &= ^idint.NodeId
}

func (h *IntMetadata) HasNodeCount() bool {
	return (h.metadataMask & idint.NodeCnt) != 0
}

func (h *IntMetadata) SetNodeCount(count uint16) {
	h.metadataMask |= idint.NodeCnt
	h.NodeCount = count
}

func (h *IntMetadata) ClearNodeCount() {
	h.metadataMask &= ^idint.NodeCnt
}

func (h *IntMetadata) HasIngressPort() bool {
	return (h.metadataMask & idint.IgPort) != 0
}

func (h *IntMetadata) SetIngressPort(igr uint16) {
	h.metadataMask |= idint.IgPort
	h.IngressPort = igr
}

func (h *IntMetadata) ClearIngressPort() {
	h.metadataMask &= ^idint.IgPort
}

func (h *IntMetadata) HasEgressPort() bool {
	return (h.metadataMask & idint.EgPort) != 0
}

func (h *IntMetadata) SetEgressPort(egr uint16) {
	h.metadataMask |= idint.EgPort
	h.EgressPort = egr
}

func (h *IntMetadata) ClearEgressPort() {
	h.metadataMask &= ^idint.EgPort
}

func (h *IntMetadata) DataLength(slot int) int {
	return int(h.metadataLength[slot])
}

func (h *IntMetadata) SetDataUint16(slot int, data uint16) {
	h.metadataLength[slot] = 2
	h.DataSlots[slot] = uint64(data)
}

func (h *IntMetadata) SetDataUint32(slot int, data uint32) {
	h.metadataLength[slot] = 4
	h.DataSlots[slot] = uint64(data)
}

func (h *IntMetadata) SetDataUint48(slot int, data uint64) {
	h.metadataLength[slot] = 6
	h.DataSlots[slot] = uint64(data)
}

func (h *IntMetadata) SetDataUint64(slot int, data uint64) {
	h.metadataLength[slot] = 8
	h.DataSlots[slot] = data
}

func (h *IntMetadata) ClearData(slot int) {
	h.metadataLength[slot] = 0
}
