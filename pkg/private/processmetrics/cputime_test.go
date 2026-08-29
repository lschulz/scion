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

package processmetrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHostCPUTime(t *testing.T) {
	cases := map[string]struct {
		stat     string
		expected HostCpuTime
	}{
		// user nice system idle iowait irq softirq steal guest guest_nice
		"full": {
			stat: "cpu 100 200 300 400 500 600 700 800 900 1000\ncpu0\n",
			expected: HostCpuTime{
				User:    3000 * time.Millisecond,
				Sys:     9000 * time.Millisecond,
				SoftIrq: 7000 * time.Millisecond,
				Steal:   8000 * time.Millisecond,
				Total:   36000 * time.Millisecond,
			},
		},
		"truncated": {
			stat: "cpu 100 200 300 400 500 600 700",
			expected: HostCpuTime{
				User:    3000 * time.Millisecond,
				Sys:     9000 * time.Millisecond,
				SoftIrq: 7000 * time.Millisecond,
				Steal:   0 * time.Millisecond,
				Total:   28000 * time.Millisecond,
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			actual, err := parseHostCPUTime([]byte(tc.stat), 100)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestParseHostCPUTimeError(t *testing.T) {
	cases := map[string]string{
		"empty":             "\n",
		"truncated":         "cpu 100 200 300 400 500 600",
		"aggregate missing": "cpu0 100 200 300 400 500 600 700 800 900 1000\ncpu1\n",
		"mangled":           "cpu 100 x y z",
	}
	for name, stat := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseHostCPUTime([]byte(stat), 100)
			assert.Error(t, err)
		})
	}
}
