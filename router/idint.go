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
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/private/env"
)

// parseVersion parses major and minor version, and patch level from a
// git-describe version string.
func parseVersion(raw string) (major, minor, patch uint32) {
	before, _, _ := strings.Cut(raw, "-")
	parts := strings.SplitN(before, ".", 3)
	if len(parts) != 3 {
		return 0, 0, 0
	}
	v := [3]*uint32{&major, &minor, &patch}
	for i, part := range parts {
		a, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return 0, 0, 0
		}
		*v[i] = uint32(a)
	}
	return
}

// idintEncodeVersion extracts the major.minor.patch version from a git-describe
// version string and encodes them for use with the ID_INT SOFTWARE_VERSION
// instruction.
func idintEncodeVersion(raw string) uint32 {
	major, minor, patch := parseVersion(raw)
	major = min(major, 1023)
	minor = min(minor, 1023)
	patch = min(patch, 4095)
	return (major << 22) | (minor << 12) | patch
}

var (
	// Router version in the format of the ID-INT SOFTWARE_VERSION instruction.
	idintStartupVersion = idintEncodeVersion(env.StartupVersion)
	// Unix time the router was started at in nanoseconds.
	idintStartupTime = uint64(time.Now().UnixNano())
)
