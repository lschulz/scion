// Copyright 2020 Anapaya Systems
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

package snet_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/idint"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/onehop"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
)

func TestPacketSerializeDecodeLoop(t *testing.T) {
	scionP := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]uint8{2, 0, 0},
			},
			NumINF:  1,
			NumHops: 2,
		},
		InfoFields: []path.InfoField{{ConsDir: true}},
		HopFields:  []path.HopField{{ConsEgress: 4}, {ConsIngress: 1}},
	}
	rawSP := func() []byte {
		raw := make([]byte, scionP.Len())
		require.NoError(t, scionP.SerializeTo(raw))
		return raw
	}

	testCases := map[string]snet.Packet{
		"UDP OHP packet": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.OneHop{},
				Payload: snet.UDPPayload{
					SrcPort: 25,
					DstPort: 1925,
					Payload: []byte("hello packet"),
				},
			},
		},
		"UDP packet": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Payload: snet.UDPPayload{
					SrcPort: 25,
					DstPort: 1925,
					Payload: []byte("hello packet"),
				},
			},
		},
		"SCMP EchoRequest": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Payload: snet.SCMPEchoRequest{
					Identifier: 4,
					SeqNumber:  3310,
					Payload:    []byte("echo request"),
				},
			},
		},
		"SCMP EchoReply": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Payload: snet.SCMPEchoReply{
					Identifier: 5,
					SeqNumber:  3410,
					Payload:    []byte("echo reply"),
				},
			},
		},
		"SCMP ExternalInterfaceDown": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Payload: snet.SCMPExternalInterfaceDown{
					IA:        addr.MustParseIA("1-ff00:0:111"),
					Interface: 13,
					Payload:   []byte("scmp quote"),
				},
			},
		},
		"SCMP InternalConnectivityDown": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Payload: snet.SCMPInternalConnectivityDown{
					IA:      addr.MustParseIA("1-ff00:0:111"),
					Ingress: 14,
					Egress:  25,
					Payload: []byte("scmp quote"),
				},
			},
		},
		"SCMP ParameterProblem": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Payload: snet.SCMPParameterProblemWithCode(
					snet.SCMPParameterProblem{
						Pointer: 16,
						Payload: []byte("scmp quote"),
					},
					slayers.SCMPCodePathExpired,
				),
			},
		},
		"SCMP PacketTooBig": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Payload: snet.SCMPPacketTooBig{
					MTU:     1503,
					Payload: []byte("scmp quote"),
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, tc.Serialize())
			actual := snet.Packet{Bytes: tc.Bytes}
			assert.NoError(t, actual.Decode())

			r, ok := actual.Path.(snet.RawPath)
			require.True(t, ok)
			rp, err := convertRawPath(r)
			require.NoError(t, err)
			actual.Path = rp

			assert.Equal(t, tc.PacketInfo, actual.PacketInfo)
			assert.Equal(t, tc.PacketInfo.Payload, actual.PacketInfo.Payload)
			actual.Bytes = nil
			assert.NoError(t, actual.Serialize())
			assert.Equal(t, tc.Bytes, actual.Bytes)
		})
	}
}

func TestIdIntSerializeDecode(t *testing.T) {
	scionP := scion.Decoded{
		Base: scion.Base{
			PathMeta: scion.MetaHdr{
				SegLen: [3]uint8{2, 0, 0},
			},
			NumINF:  1,
			NumHops: 2,
		},
		InfoFields: []path.InfoField{{ConsDir: true}},
		HopFields:  []path.HopField{{ConsEgress: 4}, {ConsIngress: 1}},
	}
	rawSP := func() []byte {
		raw := make([]byte, scionP.Len())
		require.NoError(t, scionP.SerializeTo(raw))
		return raw
	}
	source := snet.IntMetadata{Source: true}
	source.SetNodeId(1)
	source.SetDataUint48(0, 0xcccc_cccc_cccc)
	source.SetDataUint48(1, 0xffff_ffff_ffff)
	request := &snet.IntRequest{
		MaxStackLen:    128,
		ReqNodeId:      true,
		Instructions:   [4]uint8{idint.InIngressTstamp, idint.InEgressTstamp},
		VerifierAddr:   addr.MustParseAddr("1-ff00:0:111,127.0.0.1"),
		SourceMetadata: source,
		SourceTS:       time.Now(),
		SourceKey:      slayers.IdIntKey{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	}

	testCases := map[string]snet.Packet{
		"UDP packet": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Telemetry: snet.IdIntInfo{
					Request: request,
				},
				Payload: snet.UDPPayload{
					SrcPort: 25,
					DstPort: 1925,
					Payload: []byte("hello packet"),
				},
			},
		},
		"SCMP EchoRequest": {
			PacketInfo: snet.PacketInfo{
				Destination: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:110"),
					Host: addr.HostSVC(addr.SvcCS),
				},
				Source: snet.SCIONAddress{
					IA:   addr.MustParseIA("1-ff00:0:112"),
					Host: addr.MustParseHost("127.0.0.1"),
				},
				Path: snetpath.SCION{
					Raw: rawSP(),
				},
				Telemetry: snet.IdIntInfo{
					Request: request,
				},
				Payload: snet.SCMPEchoRequest{
					Identifier: 4,
					SeqNumber:  3310,
					Payload:    []byte("echo request"),
				},
			},
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.NoError(t, tc.Serialize())
			actual := snet.Packet{Bytes: tc.Bytes}
			assert.NoError(t, actual.Decode())

			r, ok := actual.Path.(snet.RawPath)
			require.True(t, ok)
			rp, err := convertRawPath(r)
			require.NoError(t, err)
			actual.Path = rp

			assert.Nil(t, actual.Telemetry.Request)
			require.NotNil(t, actual.Telemetry.Report)
			recovered := new(snet.IntRequest)

			actual.Telemetry.Report.RecoverRequest(recovered)
			recovered.SourceMetadata = request.SourceMetadata
			recovered.SourceKey = request.SourceKey
			assert.Equal(t, tc.Telemetry.Request, request)

			unverified := new(snet.IntReport)
			err = actual.Telemetry.Report.DecodeUnverified(unverified)
			require.NoError(t, err)
			assert.Equal(t, unverified.Data[0], source)

			keys := snet.MockKeyProvider{Key: drkey.Key(request.SourceKey)}
			hopToIA := func(uint) (addr.IA, error) {
				return addr.MustParseIA("1-ff00:0:112"), nil
			}
			verified := new(snet.IntReport)
			ctx := context.Background()
			err = actual.Telemetry.Report.VerifyAndDecrypt(
				ctx, verified, actual.PacketInfo.Source, &keys, hopToIA)
			require.NoError(t, err)
			assert.Equal(t, verified.Data[0], source)
		})
	}
}

func convertRawPath(r snet.RawPath) (snet.DataplanePath, error) {
	switch r.PathType {
	case scion.PathType:
		return snetpath.SCION{Raw: r.Raw}, nil
	case onehop.PathType:
		p := onehop.Path{}
		if err := p.DecodeFromBytes(r.Raw); err != nil {
			return nil, serrors.Wrap("decoding ohp", err)
		}
		return snetpath.OneHop{
			Info:      p.Info,
			FirstHop:  p.FirstHop,
			SecondHop: p.SecondHop,
		}, nil
	default:
		return nil, serrors.New("unexpected path type", "type", r.PathType)
	}
}

func TestPacketSerialize(t *testing.T) {
	decodedOHP := onehop.Path{}
	rawOHP := make([]byte, decodedOHP.Len())
	require.NoError(t, decodedOHP.SerializeTo(rawOHP))

	testCases := map[string]struct {
		input     snet.Packet
		assertErr assert.ErrorAssertionFunc
	}{
		"valid UDP OHP": {
			input: snet.Packet{
				PacketInfo: snet.PacketInfo{
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:110"),
						Host: addr.HostSVC(addr.SvcCS),
					},
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:112"),
						Host: addr.MustParseHost("127.0.0.1"),
					},
					Path: snetpath.OneHop{},
					Payload: snet.UDPPayload{
						SrcPort: 25,
						DstPort: 1925,
						Payload: []byte("hello packet"),
					},
				},
			},
			assertErr: assert.NoError,
		},
		"valid empty path": {
			input: snet.Packet{
				PacketInfo: snet.PacketInfo{
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:110"),
						Host: addr.HostSVC(addr.SvcCS),
					},
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:112"),
						Host: addr.MustParseHost("127.0.0.1"),
					},
					Payload: snet.UDPPayload{
						SrcPort: 25,
						DstPort: 1925,
						Payload: []byte("hello packet"),
					},
					Path: snetpath.Empty{},
				},
			},
			assertErr: assert.NoError,
		},
		"empty packet": {
			assertErr: assert.Error,
		},
		"missing payload": {
			input: snet.Packet{
				PacketInfo: snet.PacketInfo{
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:110"),
						Host: addr.HostSVC(addr.SvcCS),
					},
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:112"),
						Host: addr.MustParseHost("127.0.0.1"),
					},
					Path: snetpath.OneHop{},
				},
			},
			assertErr: assert.Error,
		},
		"ID-INT request": {
			input: snet.Packet{
				PacketInfo: snet.PacketInfo{
					Destination: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:110"),
						Host: addr.HostSVC(addr.SvcCS),
					},
					Source: snet.SCIONAddress{
						IA:   addr.MustParseIA("1-ff00:0:112"),
						Host: addr.MustParseHost("127.0.0.1"),
					},
					Payload: snet.UDPPayload{
						SrcPort: 25,
						DstPort: 1925,
						Payload: []byte("hello packet"),
					},
					Telemetry: snet.IdIntInfo{
						Request: &snet.IntRequest{
							Encrypt:      true,
							MaxStackLen:  128,
							ReqNodeId:    true,
							VerifierAddr: addr.MustParseAddr("1-ff00:0:111,127.0.0.1"),
							SourceMetadata: snet.IntMetadata{
								Source: true,
							},
							SourceTS:  time.Now(),
							SourceKey: slayers.IdIntKey{},
						},
					},
					Path: snetpath.Empty{},
				},
			},
			assertErr: assert.NoError,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			tc.assertErr(t, tc.input.Serialize())
		})
	}
}
