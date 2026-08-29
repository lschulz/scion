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
	"context"
	"math"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/processmetrics"
)

const (
	// CPU meter sampling period.
	cpuMeterPeriod = 200 * time.Millisecond
	// Host CPU statistics update modifier. The host CPU usage is update in an
	// interval of cpuMeterPeriod * cpuMeterHostCpuDiv.
	cpuMeterHostCpuDiv = 5
	// Scheduler statistics update rate modifier. The scheduler statistics are
	// updated in an interval of cpuMeterPeriod * cpuMeterSchedDiv.
	cpuMeterSchedDiv = 5
	// Time constants for load averages. These are the same values as used in
	// computing the values exposed in /proc/loadavg.
	cpuMeter1MinTau = 60.0
	cpuMeter5MinTau = 300.0
)

type hostCpuCategory int

const (
	hostCpuNotIdle hostCpuCategory = iota
	hostCpuUser
	hostCpuSys
	hostCpuSoftIrq
	hostCpuNumCategories
)

// CPUMeter estimates how much CPU capacity is consumed by the router and how
// much capacity the system has left.
// The published values may be read concurrently from the dataplane for
// exporting to end hosts via ID-INT.
type CPUMeter struct {
	// Published CPU load statistics
	userNow         atomic.Uint32
	userAvg1Min     atomic.Uint32
	userAvg5Min     atomic.Uint32
	sysNow          atomic.Uint32
	sysAvg1Min      atomic.Uint32
	sysAvg5Min      atomic.Uint32
	runnableNow     atomic.Uint32
	runnableAvg1Min atomic.Uint32
	runnableAvg5Min atomic.Uint32
	hostNow         [hostCpuNumCategories]atomic.Uint32
	host1Min        [hostCpuNumCategories]atomic.Uint32
	host5Min        [hostCpuNumCategories]atomic.Uint32

	// Internal state for moving averages
	avgUser1Min     float64
	avgUser5Min     float64
	avgSys1Min      float64
	avgSys5Min      float64
	avgRunnable1Min float64
	avgRunnable5Min float64
	avgHostNow      [hostCpuNumCategories]float64
	avgHost1Min     [hostCpuNumCategories]float64
	avgHost5Min     [hostCpuNumCategories]float64

	// Total number of samples taken so far
	samples uint64

	// Last process CPU timestamp
	prevProcCpuTS time.Time
	// Last process CPU sample
	prevProcCpu processmetrics.ProcCpuTime

	// Whether scheduler statistics are available
	schedAvail bool
	// Last scheduler sample timestamp
	prevSchedTS time.Time
	// Last scheduler sample
	prevSchedRunnable time.Duration

	// Whether system-wide CPU statistics are available
	hostCpuAvail bool
	// Last host CPU sample timestamp
	prevHostCpuTS time.Time
	// Last host CPU sample
	prevHostCpu processmetrics.HostCpuTime
}

// run samples the CPU time counters until ctx is cancelled. This must be
// invoked at most once per meter instance.
func (m *CPUMeter) run(ctx context.Context) {
	now := time.Now()

	if cpu, err := processmetrics.ReadProcCpuTime(); err == nil {
		m.prevProcCpuTS = now
		m.prevProcCpu = cpu
	} else {
		log.Info("ID-INT CPU meter not available", "err", err)
		return
	}

	if sched, err := processmetrics.ReadSchedTime(); err == nil {
		m.schedAvail = true
		m.prevSchedTS = now
		m.prevSchedRunnable = sched.Runnable
	} else {
		log.Info("ID-INT scheduler meter not available", "err", err)
	}

	if host, err := processmetrics.ReadHostCpuTime(); err == nil {
		m.hostCpuAvail = true
		m.prevHostCpuTS = now
		m.prevHostCpu = host
	} else {
		log.Info("ID-INT system wide CPU meter not available", "err", err)
	}

	ticker := time.NewTicker(cpuMeterPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			m.sample(now)
		}
	}
}

// sample updates the published CPU load statistics.
func (m *CPUMeter) sample(now time.Time) error {
	cpu, err := processmetrics.ReadProcCpuTime()
	if err != nil {
		return err
	}

	numCores := float64(runtime.GOMAXPROCS(0))
	if dt := now.Sub(m.prevProcCpuTS).Seconds(); dt > 0 {
		user := (cpu.User - m.prevProcCpu.User).Seconds() / (numCores * dt)
		m.avgUser1Min = cpuTimeEwma(m.avgUser1Min, user, dt, cpuMeter1MinTau)
		m.avgUser5Min = cpuTimeEwma(m.avgUser5Min, user, dt, cpuMeter1MinTau)
		m.userNow.Store(scaleCpuUsage(user))
		m.userAvg1Min.Store(scaleCpuUsage(m.avgUser1Min))
		m.userAvg5Min.Store(scaleCpuUsage(m.avgUser5Min))

		sys := (cpu.Sys - m.prevProcCpu.Sys).Seconds() / (numCores * dt)
		m.avgSys1Min = cpuTimeEwma(m.avgSys1Min, sys, dt, cpuMeter5MinTau)
		m.avgSys5Min = cpuTimeEwma(m.avgSys5Min, sys, dt, cpuMeter5MinTau)
		m.sysNow.Store(scaleCpuUsage(sys))
		m.sysAvg1Min.Store(scaleCpuUsage(m.avgSys1Min))
		m.sysAvg5Min.Store(scaleCpuUsage(m.avgSys5Min))
	}
	m.prevProcCpuTS = now
	m.prevProcCpu = cpu

	if m.schedAvail && m.samples%cpuMeterSchedDiv == 0 {
		m.sampleSched(now, numCores)
	}
	if m.hostCpuAvail && m.samples%cpuMeterHostCpuDiv == 0 {
		m.sampleSysProc(now)
	}
	m.samples++

	return nil
}

func (m *CPUMeter) sampleSched(now time.Time, numCores float64) {
	sched, err := processmetrics.ReadSchedTime()
	if err != nil {
		m.schedAvail = false
		return
	}
	if dt := now.Sub(m.prevSchedTS).Seconds(); dt > 0 {
		runnable := (sched.Runnable - m.prevSchedRunnable).Seconds() / (numCores * dt)
		m.avgRunnable1Min = cpuTimeEwma(m.avgRunnable1Min, runnable, dt, cpuMeter1MinTau)
		m.avgRunnable5Min = cpuTimeEwma(m.avgRunnable5Min, runnable, dt, cpuMeter5MinTau)
		m.runnableNow.Store(scaleCpuUsage(runnable))
		m.runnableAvg1Min.Store(scaleCpuUsage(m.avgRunnable1Min))
		m.runnableAvg5Min.Store(scaleCpuUsage(m.avgRunnable5Min))
		m.prevSchedTS = now
		m.prevSchedRunnable = sched.Runnable
	}
}

func (m *CPUMeter) sampleSysProc(now time.Time) {
	host, err := processmetrics.ReadHostCpuTime()
	if err != nil {
		m.hostCpuAvail = false
		return
	}
	dt := now.Sub(m.prevHostCpuTS).Seconds()
	total := (host.Total - m.prevHostCpu.Total).Seconds()
	if dt > 0 && total > 0 {
		notIdle := host.User + host.Sys + host.SoftIrq + host.Steal
		prevNotIdle := m.prevHostCpu.User + m.prevHostCpu.Sys + m.prevHostCpu.SoftIrq + m.prevHostCpu.Steal
		fractions := [hostCpuNumCategories]float64{
			hostCpuNotIdle: (notIdle - prevNotIdle).Seconds() / total,
			hostCpuUser:    (host.User - m.prevHostCpu.User).Seconds() / total,
			hostCpuSys:     (host.Sys - m.prevHostCpu.Sys).Seconds() / total,
			hostCpuSoftIrq: (host.SoftIrq - m.prevHostCpu.SoftIrq).Seconds() / total,
		}
		for i, frac := range fractions {
			m.avgHost1Min[i] = cpuTimeEwma(m.avgHost1Min[i], frac, dt, cpuMeter1MinTau)
			m.avgHost5Min[i] = cpuTimeEwma(m.avgHost5Min[i], frac, dt, cpuMeter5MinTau)
			m.hostNow[i].Store(scaleCpuUsage(frac))
			m.host1Min[i].Store(scaleCpuUsage(m.avgHost1Min[i]))
			m.host5Min[i].Store(scaleCpuUsage(m.avgHost5Min[i]))
		}
	}
	m.prevHostCpuTS = now
	m.prevHostCpu = host
}

// cpuTimeEwma Adds a new sample after dt seconds to an exponentially weighted
// moving average with time constant tau.
func cpuTimeEwma(avg, sample, dt, tau float64) float64 {
	alpha := math.Exp(-dt / tau)
	return alpha*avg + (1-alpha)*sample
}

// scaleCpuUsage clamps fraction to [0, 1] and scales to the full range of a uint16.
func scaleCpuUsage(fraction float64) uint32 {
	if !(fraction > 0) { // catch <= 0 and NaN
		return 0
	}
	return uint32(math.Min(fraction, 1.0) * float64(^uint16(0)))
}
