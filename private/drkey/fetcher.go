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

package drkey

import (
	"context"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	libgrpc "github.com/scionproto/scion/pkg/grpc"
	"github.com/scionproto/scion/pkg/private/serrors"
	cppb "github.com/scionproto/scion/pkg/proto/control_plane"
	dkpb "github.com/scionproto/scion/pkg/proto/drkey"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/pkg/snet"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GrpcFetcher obtains Level1 DRKeys from a local CS.
type GrpcFetcher struct {
	Dialer libgrpc.TCPDialer
	conn   *grpc.ClientConn
}

func (f *GrpcFetcher) Dial(ctx context.Context, localIA addr.IA) error {
	remote := &snet.SVCAddr{
		IA:  localIA,
		SVC: addr.SvcCS,
	}
	var err error
	f.conn, err = f.Dialer.Dial(ctx, remote)
	if err != nil {
		return serrors.WrapStr("dialing", err)
	}
	return nil
}

// Close the connection to the CS.
func (f *GrpcFetcher) Close() {
	if f.conn != nil {
		f.conn.Close()
		f.conn = nil
	}
}

// Level1 queries a CS for a level 1 key.
func (f *GrpcFetcher) Level1(
	ctx context.Context,
	meta drkey.Level1Meta,
) (drkey.Level1Key, error) {

	if f.conn == nil {
		return drkey.Level1Key{}, serrors.New("not connected to CS")
	}

	req := level1MetaToProtoRequest(meta)

	client := cppb.NewDRKeyIntraServiceClient(f.conn)
	rep, err := client.DRKeyIntraLevel1(ctx, req)
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("requesting level 1 key", err)
	} else {
		lvl1Key, err := getLevel1KeyFromReply(meta, rep)
		if err != nil {
			return drkey.Level1Key{}, serrors.WrapStr("obtaining level 1 key from reply", err)
		}
		return lvl1Key, nil
	}
}

func level1MetaToProtoRequest(meta drkey.Level1Meta) *cppb.DRKeyIntraLevel1Request {
	return &cppb.DRKeyIntraLevel1Request{
		ValTime:    timestamppb.New(meta.Validity),
		ProtocolId: dkpb.Protocol(meta.ProtoId),
		SrcIa:      uint64(meta.SrcIA),
		DstIa:      uint64(meta.DstIA),
	}
}

func getLevel1KeyFromReply(
	meta drkey.Level1Meta,
	rep *cppb.DRKeyIntraLevel1Response,
) (drkey.Level1Key, error) {

	err := rep.EpochBegin.CheckValid()
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("invalid EpochBegin from response", err)
	}
	err = rep.EpochEnd.CheckValid()
	if err != nil {
		return drkey.Level1Key{}, serrors.WrapStr("invalid EpochEnd from response", err)
	}
	epoch := drkey.Epoch{
		Validity: cppki.Validity{
			NotBefore: rep.EpochBegin.AsTime(),
			NotAfter:  rep.EpochEnd.AsTime(),
		},
	}
	returningKey := drkey.Level1Key{
		SrcIA:   meta.SrcIA,
		DstIA:   meta.DstIA,
		Epoch:   epoch,
		ProtoId: meta.ProtoId,
	}
	if len(rep.Key) != 16 {
		return drkey.Level1Key{}, serrors.New("key size in reply is not 16 bytes",
			"len", len(rep.Key))
	}
	copy(returningKey.Key[:], rep.Key)
	return returningKey, nil
}
