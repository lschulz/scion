package snet

import (
	"context"
	"crypto/rand"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
)

const IntDataMaxAgeNano = 60_000_000_000

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

	if r.Encrypt {
		var nonce [slayers.IntNonceLen]byte
		_, err := rand.Read(nonce[:])
		if err != nil {
			return err
		}
		source.SetNonce(nonce)
	}

	intLayer.SourceTsPort = (uint64(r.SourceTS.UnixNano()) << 16) | uint64(sourcePort)
	mac, err := source.CalcSourceMac(r.SourceKey, intLayer)
	if err != nil {
		return err
	}
	copy(source.Mac[:], mac[:slayers.IntMacLen])

	if r.Encrypt {
		if err := source.Encrypt(r.SourceKey); err != nil {
			return err
		}
	}

	intLayer.TelemetryStack = make([]byte, source.Length())
	n, err := source.SerializeToSlice(intLayer.TelemetryStack)
	if err != nil {
		return err
	}
	intLayer.StackLength = uint8(n / 4)

	return nil
}

// Recover a request struct from an ID-INT header. Does not decode source
// or decrypt source metadata.
func (r *IntRequest) DecodeFrom(intLayer *slayers.IDINT) error {
	r.Encrypt = intLayer.Encrypt
	r.SkipHops = 0
	r.MaxStackLen = 4 * int(intLayer.MaxStackLen)
	r.ReqNodeId = (intLayer.InstructionBitmap & slayers.IntBitNodeId) != 0
	r.ReqNodeCount = (intLayer.InstructionBitmap & slayers.IntBitNodeCnt) != 0
	r.ReqIngressIf = (intLayer.InstructionBitmap & slayers.IntBitIgrIf) != 0
	r.ReqEgressIf = (intLayer.InstructionBitmap & slayers.IntBitEgrIf) != 0
	r.AggregationMode = int(intLayer.AggregationMode)
	r.AggregationFunc = intLayer.AggregationFunc
	r.Instruction = intLayer.Instruction

	r.Verifier = int(intLayer.Verifier)
	if r.Verifier == slayers.IntVerifThirdParty {
		r.VerifierAddr.IA = intLayer.VerifIA
		if intLayer.VerifierAddrType != slayers.T4Ip && intLayer.VerifierAddrType == slayers.T16Ip {
			return serrors.New("address not valid as ID-INT verifier", "type", intLayer.VerifierAddrType)
		}
		if ip, ok := netip.AddrFromSlice(intLayer.RawVerifAddr); ok {
			r.VerifierAddr.Host = addr.HostIP(ip)
		}
	}

	r.SourceMetadata = TelemetryHop{}
	r.SourceTS = time.Unix(0, int64(intLayer.SourceTsPort>>16))
	r.SourceKey = drkey.Key{}

	return nil
}

type RawIntReport struct {
	header slayers.IDINT
	stack  []slayers.IntStackEntry
}

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

func (r *RawIntReport) SerializedLength() int {
	length := r.header.Length()
	for i := range r.stack {
		length += r.stack[i].Length()
	}
	return length
}

// Serializes the ID-INT data in its standard wire format.
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

// Read ID-INT telemetry from raw bytes.
func (r *RawIntReport) DecodeFromBytes(data []byte) error {
	var intLayer slayers.IDINT
	err := intLayer.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}
	return r.DecodeFrom(&intLayer)
}

func (r *RawIntReport) EncodeTo(intLayer *slayers.IDINT,
	nextLayer slayers.L4ProtocolType, sourcePort uint16) error {
	panic("not implemented")
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

// Decode the telemetry report without verifying authenticity. Fails if the report
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

////////////////////////////////////////////////////////////////////////////////

// Provides level 2 DRKeys for validating messages from border routers.
// All methodes require external synchronization if used concurrently.
type KeyProvider interface {
	// Gets an AS-Host DRKey valid at the given point of time.
	GetASHostKey(ctx context.Context, validity time.Time, srcIA addr.IA) (drkey.Key, error)
	// Gets a Host-Host DRKey valid at the given point of time.
	GetHostHostKey(ctx context.Context, validity time.Time, srcAddr addr.Addr) (drkey.Key, error)
	// Refresh keys that will expire soon or already have expired assuming
	// a global epoch duration of 'keyDuration'.
	RefreshKeys(ctx context.Context, keyDuration time.Duration) []error
	// Deletes all keys expired since 'now'.
	DeleteExpiredKeys(now time.Time)
}

type DaemonConnector interface {
	// DRKeyGetASHostKey requests a AS-Host Key from the daemon.
	DRKeyGetASHostKey(ctx context.Context, meta drkey.ASHostMeta) (drkey.ASHostKey, error)
	// DRKeyGetHostHostKey requests a Host-Host Key from the daemon.
	DRKeyGetHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error)
}

type KeyCache struct {
	Sciond    DaemonConnector
	DstIA     addr.IA
	DstHost   netip.Addr
	cache     map[addr.IA][]drkey.ASHostKey
	hostCache map[addr.Addr][]drkey.HostHostKey
}

func (c *KeyCache) GetASHostKey(
	ctx context.Context,
	validity time.Time,
	srcIA addr.IA,
) (drkey.Key, error) {
	if c.cache == nil {
		c.cache = make(map[addr.IA][]drkey.ASHostKey)
	}

	keys, ok := c.cache[srcIA]
	if ok {
		for i := len(keys) - 1; i >= 0; i-- {
			if keys[i].Epoch.Contains(validity) {
				return keys[i].Key, nil
			}
		}
	}

	key, err := c.fetchASHostKey(ctx, validity, srcIA)
	if err != nil {
		return drkey.Key{}, err
	}
	if ok {
		c.cache[srcIA] = append(c.cache[srcIA], key)
	} else {
		c.cache[srcIA] = []drkey.ASHostKey{key}
	}
	return key.Key, nil
}

func (c *KeyCache) GetHostHostKey(
	ctx context.Context,
	validity time.Time,
	srcAddr addr.Addr,
) (drkey.Key, error) {
	if c.hostCache == nil {
		c.hostCache = make(map[addr.Addr][]drkey.HostHostKey)
	}

	keys, ok := c.hostCache[srcAddr]
	if ok {
		for i := len(keys) - 1; i >= 0; i-- {
			if keys[i].Epoch.Contains(validity) {
				return keys[i].Key, nil
			}
		}
	}

	key, err := c.fetchHostHostKey(ctx, validity, srcAddr)
	if err != nil {
		return drkey.Key{}, err
	}
	if ok {
		c.hostCache[srcAddr] = append(c.hostCache[srcAddr], key)
	} else {
		c.hostCache[srcAddr] = []drkey.HostHostKey{key}
	}
	return key.Key, nil
}

func (c *KeyCache) RefreshKeys(ctx context.Context, keyDuration time.Duration) []error {

	errors := make([]error, 0)
	t := time.Now().Add(keyDuration / 2)

	if c.cache != nil {
		for srcIA, keys := range c.cache {
			if len(keys) == 0 || keys[len(keys)-1].Epoch.NotAfter.After(t) {
				key, err := c.fetchASHostKey(ctx, t, srcIA)
				if err != nil {
					errors = append(errors, err)
					continue
				}
				if len(keys) > 0 && keys[len(keys)-1].Epoch.Covers(key.Epoch.Validity) {
					continue
				}
				c.cache[srcIA] = append(c.cache[srcIA], key)
			}
		}
	}

	if c.hostCache != nil {
		for srcAddr, keys := range c.hostCache {
			if len(keys) == 0 || keys[len(keys)-1].Epoch.NotAfter.After(t) {
				key, err := c.fetchHostHostKey(ctx, t, srcAddr)
				if err != nil {
					errors = append(errors, err)
					continue
				}
				if len(keys) > 0 && keys[len(keys)-1].Epoch.Covers(key.Epoch.Validity) {
					continue
				}
				c.hostCache[srcAddr] = append(c.hostCache[srcAddr], key)
			}
		}
	}

	return errors
}

func (c *KeyCache) DeleteExpiredKeys(now time.Time) {
	if c.cache != nil {
		for srcIA, keys := range c.cache {
			for i, key := range keys {
				if key.Epoch.NotAfter.After(now) {
					c.cache[srcIA] = c.cache[srcIA][i:]
					break
				}
			}
		}
	}
	if c.hostCache != nil {
		for srcAddr, keys := range c.hostCache {
			for i, key := range keys {
				if key.Epoch.NotAfter.After(now) {
					c.hostCache[srcAddr] = c.hostCache[srcAddr][i:]
					break
				}
			}
		}
	}
}

// Gets an AS-Host key from Daemon.
func (c *KeyCache) fetchASHostKey(
	ctx context.Context,
	validity time.Time,
	srcIA addr.IA,
) (drkey.ASHostKey, error) {
	meta := drkey.ASHostMeta{
		ProtoId:  drkey.IDINT,
		Validity: validity,
		SrcIA:    srcIA,
		DstIA:    c.DstIA,
		DstHost:  c.DstHost.String(),
	}
	key, err := c.Sciond.DRKeyGetASHostKey(ctx, meta)
	if err != nil {
		return drkey.ASHostKey{}, err
	}
	return key, nil
}

// Gets a Host-Host key from Daemon.
func (c *KeyCache) fetchHostHostKey(
	ctx context.Context,
	validity time.Time,
	srcAddr addr.Addr,
) (drkey.HostHostKey, error) {
	meta := drkey.HostHostMeta{
		ProtoId:  drkey.IDINT,
		Validity: validity,
		SrcIA:    srcAddr.IA,
		DstIA:    c.DstIA,
		SrcHost:  srcAddr.Host.String(),
		DstHost:  c.DstHost.String(),
	}
	key, err := c.Sciond.DRKeyGetHostHostKey(ctx, meta)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	return key, nil
}

type HopToIA func(uint) (addr.IA, error)

////////////////////////////////////////////////////////////////////////////////

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
	if elapsed > IntDataMaxAgeNano {
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
	var mac [16]byte
	var err error

	if entry.Encrypted {
		if err := entry.Decrypt(key); err != nil {
			return err
		}
		defer entry.RemoveNonce()
	}

	if entry.SourceMetadata {
		mac, err = entry.CalcSourceMac(key, &r.header)
		if err != nil {
			return err
		}
	} else {
		mac, err = entry.CalcMac(key, *prevMac)
		if err != nil {
			return err
		}
	}
	if !slayers.CompareMACs(entry.Mac[:], mac[:slayers.IntMacLen]) {
		return serrors.New("telemetry MAC verification failed",
			"expected", mac[:slayers.IntMacLen], "actual", entry.Mac[:])
	}
	copy(prevMac[:], mac[:slayers.IntMacLen])

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
	Encrypted  bool

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
