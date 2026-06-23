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
)

const linkMeterPeriod = 0.1

// Meter for estimating link utilization.
type LinkMeter struct {
	bucket      float64 // bits
	elapsed     float64 // seconds
	linkSpeed   float64 // bits/s
	lastCount   uint64  // nanoseconds, arbitrary epoch
	utilization atomic.Uint32
}

func newLinkMeter(linkSpeedBps uint64) LinkMeter {
	return LinkMeter{
		linkSpeed: float64(linkSpeedBps),
	}
}

// Update updates the meter. Update must not be called concurrently without
// external synchronization. size is the packet size in bytes. now is the
// current time in nanoseconds since some common epoch.
func (m *LinkMeter) Update(size int, now uint64) {

	m.bucket += float64(8 * size)
	m.elapsed += 1e-9 * float64(now-m.lastCount)
	m.lastCount = now

	if m.elapsed >= linkMeterPeriod {
		util := math.Min(m.bucket/(m.elapsed*m.linkSpeed), 1.0)
		m.utilization.Store(uint32(util * float64(^uint32(0))))
		m.bucket = .0
		m.elapsed = .0
	}
}

type DpCounters struct {
	BytesTotal     atomic.Uint64
	PacketsTotal   atomic.Uint64
	PacketsDropped atomic.Uint64
}

type DpMetrics struct {
	InputCounters  DpCounters
	OutputCounters DpCounters
	InputMeter     LinkMeter
	OutputMeter    LinkMeter
}

func newDpMetrics(linkSpeedBps uint64) *DpMetrics {
	return &DpMetrics{
		InputCounters:  DpCounters{},
		OutputCounters: DpCounters{},
		InputMeter:     newLinkMeter(linkSpeedBps),
		OutputMeter:    newLinkMeter(linkSpeedBps),
	}
}
