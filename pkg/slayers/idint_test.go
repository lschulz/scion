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

package slayers_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/idint"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	idintPktFilename = "scion-idint.bin"
)

func TestDecodeIdIntExt(t *testing.T) {
	raw := xtest.MustReadFromFile(t, idintPktFilename)
	packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	assert.Nil(t, packet.ErrorLayer(), "Packet parsing should not error")
	// Check that there are exactly 4 layers (SCION, HBH, SCION/UDP, Payload)
	assert.Equal(t, 4, len(packet.Layers()), "Packet must have 4 layers")

	scnL := packet.Layer(slayers.LayerTypeSCION)
	require.NotNil(t, scnL, "SCION layer should exist")
	s := scnL.(*slayers.SCION) // Guaranteed to work
	// Check SCION Header
	assert.Equal(t, uint8(32), s.HdrLen, "HdrLen")
	assert.Equal(t, uint16(1200), s.PayloadLen, "PayloadLen")
	assert.Equal(t, slayers.HopByHopClass, s.NextHdr, "scion.NextHdr")

	// Check H2H Extn
	hbhL := packet.Layer(slayers.LayerTypeHopByHopExtn)
	require.NotNil(t, hbhL, "HBH layer should exist")
	hbh := hbhL.(*slayers.HopByHopExtn) // Guaranteed to work
	assert.Equal(t, slayers.L4UDP, hbh.NextHdr, "NextHeader")
	assert.Equal(t, uint8(41), hbh.ExtLen, "HBH ExtLen")
	assert.Equal(t, 5, len(hbh.Options), "len(hbh.Options)")
	assert.Equal(t, 4*(41+1), hbh.ActualLen, "ActualLength")

	// Check ID-INT
	var ext slayers.IdIntExt
	_, err := ext.Parse(hbhL.LayerContents()[2:])
	require.NoError(t, err)
	assert.Equal(t, uint8(0), ext.Header.Version)
	assert.Equal(t, false, ext.Header.Infrastructure)
	assert.Equal(t, true, ext.Header.Encrypt)
	assert.Equal(t, false, ext.Header.StackSpaceExhausted)
	assert.Equal(t, uint8(idint.AgBR), ext.Header.AggregationMode)
	assert.Equal(t, uint8(0), ext.Header.Verifier)
	assert.Equal(t, slayers.T16Ip, ext.Header.VerifierAddrType)
	assert.Equal(t, uint8(30), ext.Header.StackLen)
	assert.Equal(t, uint8(14), ext.Header.TOS)
	assert.Equal(t, uint8(0), ext.Header.DelayHops)
	assert.Equal(t, uint8(idint.NodeId), ext.Header.InstructionBitmap)
	for _, f := range ext.Header.AggregationFunc {
		assert.Equal(t, uint8(idint.AfLast), f)
	}
	assert.Equal(t, uint8(idint.InIngressTstamp), ext.Header.Instructions[0])
	assert.Equal(t, uint8(idint.InDeviceTypeRole), ext.Header.Instructions[1])
	assert.Equal(t, uint8(idint.InNop), ext.Header.Instructions[2])
	assert.Equal(t, uint8(idint.InNop), ext.Header.Instructions[3])
	assert.Equal(t, uint64((1000<<16)|10), ext.Header.SourceTsPort)
	assert.Equal(t, addr.IA(0x1ff0000000001), ext.Header.VerifIA)
	assert.Equal(t,
		[16]byte{0xfd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
		ext.Header.RawVerifAddr)

	assert.Equal(t, false, ext.TOS.SourceMetadata)
	assert.Equal(t, true, ext.TOS.Ingress)
	assert.Equal(t, false, ext.TOS.Egress)
	assert.Equal(t, false, ext.TOS.Aggregated)
	assert.Equal(t, true, ext.TOS.Encrypted)
	assert.Equal(t, uint8(2), ext.TOS.HopIndex)
	assert.Equal(t, uint8(idint.NodeId), ext.TOS.MetadataMask)
	assert.Equal(t, uint8(4), ext.TOS.MetadataLength[0])
	assert.Equal(t, uint8(2), ext.TOS.MetadataLength[1])
	assert.Equal(t, uint8(0), ext.TOS.MetadataLength[2])
	assert.Equal(t, uint8(0), ext.TOS.MetadataLength[3])
	assert.Equal(t,
		slayers.IdIntNonce{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3},
		ext.TOS.Nonce)
	assert.Equal(t, 10, ext.TOS.MetadataLen)
	assert.Equal(t,
		[4]byte{0xff, 0xff, 0xff, 0xff},
		ext.TOS.Mac)

	// Check SCION/UDP Header
	udpL := packet.Layer(slayers.LayerTypeSCIONUDP)
	require.NotNil(t, udpL, "SCION/UDP layer should exist")
	udpHdr := udpL.(*slayers.UDP) // Guaranteed to work
	assert.Equal(t, uint16(43000), udpHdr.SrcPort, "UDP.SrcPort")
	assert.Equal(t, uint16(1200), udpHdr.DstPort, "UDP.DstPort")
	assert.Equal(t, uint16(1032), udpHdr.Length, "UDP.Len")
	assert.Equal(t, uint16(0x452b), udpHdr.Checksum, "UDP.Checksum")

	// Check Payload
	appLayer := packet.ApplicationLayer()
	require.NotNil(t, appLayer, "Application Layer should exist")
	assert.Equal(t, mkPayload(1024), appLayer.Payload(), "Payload")
}

func TestUpdateIdIntExt(t *testing.T) {
	key := slayers.IdIntKey{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	nonce := slayers.IdIntNonce{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	testCases := map[string]struct {
		rawFile string
		update  func(t *testing.T, ext *slayers.IdIntExt, buf []byte)
	}{
		"update": {
			rawFile: filepath.Join(goldenDir, "scion-idint-update.bin"),
			update: func(t *testing.T, ext *slayers.IdIntExt, buf []byte) {
				md, err := ext.TOS.GetMetadata()
				require.NoError(t, err)
				new_md := slayers.IntMetadata{
					NodeIdValid:  true,
					NodeId:       2,
					InstrDataLen: [4]int{4, 2, 0, 0},
					InstrData:    [4]uint64{10, 11, 0, 0},
				}
				md.Merge(ext.Header.AggregationFunc, &new_md)
				err = ext.TOS.SetMetadata(md)
				require.NoError(t, err)
				err = ext.UpdateInPlace(buf, false, &key, &nonce)
				require.NoError(t, err)
			},
		},
		"append": {
			rawFile: filepath.Join(goldenDir, "scion-idint-append.bin"),
			update: func(t *testing.T, ext *slayers.IdIntExt, buf []byte) {
				ext.TOS = slayers.IdIntStackEntryOpt{
					Egress:    true,
					Encrypted: true,
					HopIndex:  3,
				}
				ext.TOS.SetMetadata(&slayers.IntMetadata{
					NodeIdValid:  true,
					NodeId:       3,
					InstrDataLen: [4]int{4, 2, 0, 0},
					InstrData:    [4]uint64{20, 21, 0, 0},
				})
				err := ext.UpdateInPlace(buf, true, &key, &nonce)
				require.NoError(t, err)
			},
		},
		"stack_full": {
			rawFile: filepath.Join(goldenDir, "scion-idint-stack-full.bin"),
			update: func(t *testing.T, ext *slayers.IdIntExt, buf []byte) {
				ext.TOS = slayers.IdIntStackEntryOpt{
					Egress:    true,
					Encrypted: true,
					HopIndex:  3,
				}
				ext.TOS.SetMetadata(&slayers.IntMetadata{
					NodeIdValid:  true,
					NodeId:       3,
					InstrDataLen: [4]int{4, 2, 2, 0},
					InstrData:    [4]uint64{20, 21, 22, 0},
				})
				err := ext.UpdateInPlace(buf, true, &key, &nonce)
				require.NoError(t, err)
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Load packet that will be updated
			raw := xtest.MustReadFromFile(t, idintPktFilename)
			packet := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
			assert.Nil(t, packet.ErrorLayer(), "Packet parsing should not error")
			scnL := packet.Layer(slayers.LayerTypeSCION)
			s := scnL.(*slayers.SCION) // Guaranteed to work
			require.NotNil(t, scnL, "SCION layer should exist")
			hbhL := packet.Layer(slayers.LayerTypeHopByHopExtn)
			require.NotNil(t, hbhL, "HBH layer should exist")
			var ext slayers.IdIntExt
			buf, err := ext.Parse(hbhL.LayerContents()[2:])
			require.NoError(t, err)
			udpL := packet.Layer(slayers.LayerTypeSCIONUDP)
			require.NotNil(t, udpL, "SCION/UDP layer should exist")
			udpHdr := udpL.(*slayers.UDP) // Guaranteed to work
			appLayer := packet.ApplicationLayer()
			require.NotNil(t, appLayer, "Application Layer should exist")
			appHdr := appLayer.(*gopacket.Payload) // Guaranteed to work

			tc.update(t, &ext, buf)
			hbh := hbhL.(*slayers.HopByHopExtn) // Guaranteed to work
			buf = append(hbhL.LayerContents()[:2], buf...)
			err = hbh.DecodeFromBytes(buf, gopacket.NilDecodeFeedback)
			require.NoError(t, err)

			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			got := gopacket.NewSerializeBuffer()
			udpHdr.SetNetworkLayerForChecksum(s)
			err = gopacket.SerializeLayers(got, opts, s, hbh, udpHdr, appHdr)
			require.NoError(t, err)
			raw, err = os.ReadFile(tc.rawFile)
			require.NoError(t, err)
			assert.Equal(t, raw, got.Bytes())
		})
	}
}
