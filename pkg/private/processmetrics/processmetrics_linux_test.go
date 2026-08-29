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

//go:build linux

package processmetrics

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserHz(t *testing.T) {
	hz, err := userHz()
	require.NoError(t, err)
	assert.Positive(t, hz)
}

func TestReadHostCpuTime(t *testing.T) {
	cpu, err := ReadHostCpuTime()
	require.NoError(t, err)

	upfile, err := os.ReadFile("/proc/uptime")
	require.NoError(t, err)
	uptime, err := strconv.ParseFloat(strings.Fields(string(upfile))[0], 64)
	require.NoError(t, err)

	notIdle := cpu.User + cpu.Sys + cpu.SoftIrq + cpu.Steal
	assert.LessOrEqual(t, notIdle, cpu.Total)

	// Total CPU time since boot is number of cores times uptime.
	numCores := float64(runtime.GOMAXPROCS(0))
	assert.InEpsilon(t, numCores*uptime, cpu.Total.Seconds(), 0.01)
}
