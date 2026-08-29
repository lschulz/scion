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
	"bytes"
	"strconv"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// ProcCpuTime is the total CPU time consumed by all threads of a process since
// it was started.
type ProcCpuTime struct {
	// User is the time spend in user mode.
	User time.Duration
	// Sys is the time spend in kernel mode.
	Sys time.Duration
}

// HostCpuTime is the CPU time consumed by all processes on the system since it
// was booted. User, Sys, SoftIrq, and Steal are disjoint categories, adding
// them up gives the total time the system was not idle. Divide by Total to get
// the fraction of CPU time spent in any category.
type HostCpuTime struct {
	// Time spend in user mode (user + nice).
	User time.Duration
	// Time spend in kernel mode excluding softirq (system + irq).
	Sys time.Duration
	// Time spend servicing software interrupts. XDP processing happens in this
	// context.
	SoftIrq time.Duration
	// CPU time denied to the process by the hypervisor when running in a VM.
	// Steal is zero when not running in a virtual machine.
	Steal time.Duration
	// Sum of other categories (User, Sys, SoftIrq, and Steal), idle and iowait
	// time. This is the total available CPU time since boot.
	Total time.Duration
}

// SchedTime is CPU time recorded by the OS scheduler for all threads of a
// process since it was started.
type SchedTime struct {
	// Running is the total CPU time threads spend executing. Equal to the sum
	// of ProcCpuTime.User and ProcCpuTime.Sys, but measured independently.
	Running time.Duration
	// Runnable is the total time threads were ready to run, but were waiting
	// for a CPU. Since Go creates no more than one thread per CPU, this is the
	// total available CPU time that the process was denied.
	Runnable time.Duration
}

// Fields of the summary line in /proc/stat in order of appearance, excluding
// the label "cpu".
const (
	statUser = iota
	statNice
	statSystem
	statIdle
	statIowait
	statIrq
	statSoftIrq
	statSteal
	// guest and guest_nice are already included in user and user_nice
	statNumFields
)

// parseHostCPUTime parses the first line of /proc/stat. Fields beyond softriq
// my be missing and will be assumed as zero. The input may be truncated to just
// the first line. userHz is the system's USER_HZ.
func parseHostCPUTime(stat []byte, userHz int64) (HostCpuTime, error) {
	line, _, _ := bytes.Cut(stat, []byte{'\n'})
	label, values, ok := bytes.Cut(line, []byte{' '})
	if !ok || string(label) != "cpu" {
		return HostCpuTime{}, serrors.New("no cpu line in /proc/stat")
	}

	var ticks [statNumFields]int64
	for i := range statNumFields {
		values = bytes.TrimLeft(values, " ")
		if len(values) == 0 {
			// Truncated input must contain counters at least up to softirq,
			// the rest is optional.
			if i < statSteal {
				return HostCpuTime{}, serrors.New("input truncated")
			}
			break
		}
		field, rem, _ := bytes.Cut(values, []byte{' '})
		value, err := strconv.ParseInt(string(field), 10, 64)
		if err != nil {
			return HostCpuTime{}, serrors.Wrap("unexpected value in /proc/stat", err,
				"field", i, "value", string(field))
		}
		ticks[i], values = value, rem
	}

	toDuration := func(t int64) time.Duration {
		return time.Duration(t) * time.Second / time.Duration(userHz)
	}
	var total int64
	for _, t := range ticks {
		total += t
	}
	return HostCpuTime{
		User:    toDuration(ticks[statUser] + ticks[statNice]),
		Sys:     toDuration(ticks[statSystem] + ticks[statIrq]),
		SoftIrq: toDuration(ticks[statSoftIrq]),
		Steal:   toDuration(ticks[statSteal]),
		Total:   toDuration(total),
	}, nil
}
