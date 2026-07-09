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

package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVersion(t *testing.T) {
	cases := map[string]struct {
		raw             string
		maj, min, patch uint32
	}{
		"simple": {
			raw: "0.15.1",
			maj: 0, min: 15, patch: 1,
		},
		"dirty": {
			raw: "0.15.1-xyz-dirty",
			maj: 0, min: 15, patch: 1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			maj, min, patch := parseVersion(tc.raw)
			assert.Equal(t, maj, tc.maj)
			assert.Equal(t, min, tc.min)
			assert.Equal(t, patch, tc.patch)
		})
	}
}
