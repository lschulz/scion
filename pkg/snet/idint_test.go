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

package snet_test

import (
	"testing"

	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawIdIntReportSerializationLoop(t *testing.T) {
	report := &snet.RawIntReport{
		Header: slayers.IdIntOpt{
			Encrypt: true,
		},
		Stack: make([]slayers.IdIntStackEntryOpt, 3),
	}
	report.Stack[0].SourceMetadata = true
	report.Stack[0].SetMetadata(&slayers.IntMetadata{
		NodeIdValid:  true,
		NodeId:       1,
		InstrDataLen: [4]int{6, 2},
		InstrData:    [4]uint64{0xcccc_cccc_cccc, 0x0101},
	})
	report.Stack[1].SetMetadata(&slayers.IntMetadata{
		NodeIdValid:  true,
		NodeId:       2,
		InstrDataLen: [4]int{6, 2},
		InstrData:    [4]uint64{0xddd_dddd_dddd, 0x0201},
	})
	report.Stack[2].SetMetadata(&slayers.IntMetadata{
		NodeIdValid:  true,
		NodeId:       3,
		InstrDataLen: [4]int{6, 2},
		InstrData:    [4]uint64{0xeee_eeee_eeee, 0x0201},
	})

	length := report.SerializeToSliceLength()
	assert.Equal(t, 108, length)

	buf := make([]byte, length)
	n, err := report.SerializeToSlice(buf)
	require.NoError(t, err)
	assert.Equal(t, length, n)

	actual := &snet.RawIntReport{}
	err = actual.ParseFromSlice(buf)
	require.NoError(t, err)
	assert.Equal(t, report, actual)
}
