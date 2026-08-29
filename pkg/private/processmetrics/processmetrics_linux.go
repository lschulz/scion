// Copyright 2023 SCION Association
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

// Package processmetrics provides a custom collector to export process-level metrics beyond what
// prometheus.ProcesssCollector offers.  This implementation is restricted to Linux. The generic
// implementation does nothing.
//
// The metrics we add serve to estimate the available cpu time; that is, the amount of CPU that the
// scheduler granted to the process, independently of whether it ran with it or slept on it. The
// goal is to measure what the overall performance of the process would be if it was never
// preempted. For example, this could be expressed as some_output/available_cpu_time.
//
// At a given time, a given thread is either running, runnable, or sleeping. When running it
// consumes exactly one core. When runnable, it is being deprived of exactly one core (because Go
// does not create more runnable threads than there are cores, there is no other thread of that
// process that is receiving it.). So, for our accounting purposes, the total time that all the
// process's threads spend "runnable" is the total core*time that the process did not receive. The
// complement of that: the available_cpu_time is: num_cores * real_time - total_runnable_time.
//
// We expose only running and runnable times. Available time can be inferred more conveniently in
// prometheus queries depending on the desired unit. For example:
// * available_cpu_seconds_per_seconds = num_cores - rate(process_runnable_seconds_total)
// * available_machine_seconds_per_seconds = 1 - rate(process_runnable_seconds_total)/num_cores
//
// Example of a query for processed_pkts per available cpu seconds:
//
//	rate(router_processed_pkts_total[1m])
//	  / on (instance, job) group_left ()
//	(num_cores - rate(process_runnable_seconds_total[1m]))
//
// Example of a query that only looks at on-cpu efficiency;
//
//	rate(router_processed_pkts_total[1m])
//	  / on (instance, job) group_left ()
//	(rate(process_running_seconds_total[1m]))
//
// The effective number of cores is best obtained from the go runtime. However, no prometheus
// collector seems to expose it yet, so we surface it here for convenience and simplicity
// under the name go_maxprocs_threads.

//go:build linux

package processmetrics

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"github.com/scionproto/scion/pkg/private/serrors"
)

var (
	runningTime = prometheus.NewDesc(
		"process_running_seconds_total",
		"CPU time the process used (running state) since it started (all threads summed).",
		nil, nil,
	)
	runnableTime = prometheus.NewDesc(
		"process_runnable_seconds_total",
		"CPU time the process was denied (runnable state) since it started (all threads summed).",
		nil, nil,
	)
	goCores = prometheus.NewDesc(
		"go_sched_maxprocs_threads",
		"The current runtime.GOMAXPROCS setting. The number of cores Go code uses simultaneously",
		nil, nil,
	)

	// This metric is introspective. It's trying to gauge if we're successful in collecting the
	// other two at a reasonable cost.
	tasklistUpdates = prometheus.NewDesc(
		"process_metrics_tasklist_updates_total",
		"The number of time the processmetrics collector recreated its list of tasks.",
		nil, nil,
	)
)

// userHz returns the kernel's USER_HZ. This is almost always 100. If determining
// USER_HZ from the system fails, 100 is returned together with an error.
var userHz = sync.OnceValues(func() (int64, error) {
	const defaultUserHz = 100
	// Linux passes USER_HZ to processes through the ELF auxiliary vector
	auxv, err := unix.Auxv()
	if err != nil {
		return defaultUserHz, serrors.Wrap("ELF auxiliary vector not accessible", err)
	}
	for _, entry := range auxv {
		if entry[0] == 17 { // AT_CLKTCK
			if entry[1] == 0 {
				return defaultUserHz, serrors.Wrap("AT_CLKTCK is zero", err)
			}
			return int64(entry[1]), nil
		}
	}
	return defaultUserHz, serrors.New("AT_CLKTCK not found in ELF auxiliary vector")
})

var (
	// collectorMtx guards access to the collector. The collector is shared
	// between prometheus and ReadSchedTime.
	collectorMtx sync.Mutex
	// Collector created by Init().
	collector *procStatCollector
)

// procStatCollector is a custom collector for some process-wide statistics
// that are not available in default collectors.
type procStatCollector struct {
	myPid           int
	myProcs         procfs.Procs
	myTasks         *os.File
	lastTaskCount   uint64
	taskListUpdates int64
	totalRunning    uint64
	totalRunnable   uint64
}

// UpdateStat fetches the raw per-thread scheduling metrics from /proc.
// That is: from /proc/<pid>task/*/schedstat.
// This raw data is cached for Collect to pick-up and reshape
// when prometheus scrapes.
func (c *procStatCollector) updateStat() error {

	// procfs.AllThreads is expensive (lots of garbage in its wake) and often idempotent.
	// To reduce the cost, we skip doing it when we know that the threads line-up is
	// unchanged. Since Go never terminates the threads it creates, if the lineup has
	// changed, the count has changed. We can only get that from the syscall API.
	// As soon as we get the bareFd the IOs with that file become blocking. So, the thread
	// collector thread could theoretically block on the IO (not sure stating /proc results
	// in any IO wait, though).

	var taskStat syscall.Stat_t
	err := syscall.Fstat(int(c.myTasks.Fd()), &taskStat)
	if err != nil {
		return err
	}
	//nolint:unconvert // this is required for arm64 support
	newCount := uint64(taskStat.Nlink - 2)
	if newCount != c.lastTaskCount {
		c.taskListUpdates++
		c.myProcs, err = procfs.AllThreads(c.myPid)
		if err != nil {
			return err
		}
		c.lastTaskCount = newCount
	}

	// Sum the times of all threads.
	totalRunning := uint64(0)
	totalRunnable := uint64(0)
	for _, p := range c.myProcs {
		// The procfs API gives us no choice. For each thread, it builds an object with a
		// set of stats, which we throw on the garbage pile after picking what we need.
		schedStat, oneErr := p.Schedstat()
		if oneErr != nil {
			err = oneErr
			// The only reason would be that this thread has disappeared, which doesn't
			// invalidate the values from the others. So, continuing makes more sense.
			continue
		}
		totalRunning += schedStat.RunningNanoseconds
		totalRunnable += schedStat.WaitingNanoseconds
	}

	c.totalRunning = totalRunning
	c.totalRunnable = totalRunnable
	return err
}

// Describe tells prometheus all the metrics that this collector
// collects.
func (c *procStatCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

// Collect picks the necessary raw metrics from lastSchedstat
// and derives the metrics to be returned. This is invoked whenever
// prometheus scrapes. The derivation consists mostly in unit conversions.
// Because raw metrics are very few and not expensive to get, Collect
// currently calls updateStat() every time to get the latest.
func (c *procStatCollector) Collect(ch chan<- prometheus.Metric) {
	collectorMtx.Lock()
	_ = c.updateStat()
	totalRunning, totalRunnable := c.totalRunning, c.totalRunnable
	taskListUpdates := c.taskListUpdates
	collectorMtx.Unlock()

	ch <- prometheus.MustNewConstMetric(
		runningTime,
		prometheus.CounterValue,
		float64(totalRunning)/1000000000, // Report duration in SI
	)
	ch <- prometheus.MustNewConstMetric(
		runnableTime,
		prometheus.CounterValue,
		float64(totalRunnable)/1000000000, // Report duration in SI
	)
	ch <- prometheus.MustNewConstMetric(
		goCores,
		prometheus.GaugeValue,
		float64(runtime.GOMAXPROCS(-1)),
	)
	ch <- prometheus.MustNewConstMetric(
		tasklistUpdates,
		prometheus.CounterValue,
		float64(taskListUpdates),
	)
}

// ReadProcCpuTime returns the CPU time consumed by all threads of this process.
func ReadProcCpuTime() (ProcCpuTime, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return ProcCpuTime{}, serrors.Wrap("getrusage failed", err)
	}
	return ProcCpuTime{
		User: time.Duration(usage.Utime.Nano()),
		Sys:  time.Duration(usage.Stime.Nano()),
	}, nil
}

// ReadHostCpuTime returns the CPU time consumed by all processes on the system.
// The counters read by this function have a resolution that is limited by the
// clock tick, usually 10 ms. ReadHostCpuTime parses /proc/stat and is more
// expensive than ReadProcCpuTime.
func ReadHostCpuTime() (HostCpuTime, error) {
	f, err := os.Open(filepath.Join(procfs.DefaultMountPoint, "stat"))
	if err != nil {
		return HostCpuTime{}, serrors.Wrap("opening /proc/stat failed", err)
	}
	defer f.Close()
	var buf [256]byte
	n, err := f.Read(buf[:])
	if err != nil {
		return HostCpuTime{}, serrors.Wrap("reading from /proc/stat failed", err)
	}
	hz, _ := userHz()
	return parseHostCPUTime(buf[:n], hz)
}

// ReadSchedTime returns the scheduler statistics of all threads of this
// process. Init must have been called successfully before this function,
// otherwise an error is returned. This function is much more expensive then
// ReadProcCpuTime.
func ReadSchedTime() (SchedTime, error) {
	collectorMtx.Lock()
	defer collectorMtx.Unlock()
	if collector == nil {
		return SchedTime{}, serrors.New("process metrics have not been initialized")
	}
	if err := collector.updateStat(); err != nil {
		return SchedTime{}, err
	}
	return SchedTime{
		Running:  time.Duration(collector.totalRunning),
		Runnable: time.Duration(collector.totalRunnable),
	}, nil
}

// Init creates a new collector for process statistics.
// The collector exposes those statistics to prometheus and responds
// to scraping requests. Call this only once per process or get an error.
// It is safe to ignore errors from this but prometheus may lack some
// metrics.
func Init() error {
	me := os.Getpid()
	taskPath := filepath.Join(procfs.DefaultMountPoint, strconv.Itoa(me), "task")
	taskDir, err := os.Open(taskPath)
	if err != nil {
		return serrors.Wrap("Opening /proc/pid/task/ failed", err,
			"pid", me)

	}

	c := &procStatCollector{
		myPid:   me,
		myTasks: taskDir,
	}

	err = c.updateStat()
	if err != nil {
		// Ditch the broken collector. It won't do anything useful.
		return serrors.Wrap("First update failed", err)
	}

	// It works. Make it available to ReadSchedTime and register it so
	// prometheus milks it.
	collectorMtx.Lock()
	collector = c
	collectorMtx.Unlock()
	err = prometheus.Register(c)
	if err != nil {
		return serrors.Wrap("Registration failed", err)
	}

	// Cache USER_HZ now. If determining USER_HZ fails, report the error and
	// assume the new universal default of 100 Hz.
	if _, err := userHz(); err != nil {
		return serrors.Wrap("Could not determine USER_HZ, assuming 100 Hz", err)
	}
	return nil
}
