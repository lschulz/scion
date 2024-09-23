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

package router

import (
	"math"
	"sync/atomic"
	"time"
)

const linkMeterPeriod = 0.1

// Meter for estimating link utilization.
type linkMeter struct {
	bucket      float64 // bit
	elapsed     float64 // seconds
	linkSpeed   float64 // bit/s
	lastCount   time.Time
	utilization atomic.Uint32
}

func newLinkMeter(linkSpeedBps uint64) *linkMeter {
	return &linkMeter{
		linkSpeed: float64(linkSpeedBps),
	}
}

// cannot be called concurrently without external synchronization
func (m *linkMeter) count(bits int, now time.Time) {

	m.bucket += float64(bits)
	m.elapsed += 1e-9 * float64(now.Sub(m.lastCount).Nanoseconds())
	m.lastCount = now

	if m.elapsed >= linkMeterPeriod {
		util := math.Min(m.bucket/(m.elapsed*m.linkSpeed), 1.0)
		m.utilization.Store(uint32(util * float64(^uint32(0))))
		m.bucket = .0
		m.elapsed = .0
	}
}
