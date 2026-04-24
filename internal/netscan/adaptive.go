package netscan

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/metrics"
	"sync/atomic"
	"time"
)

const (
	defaultAdjustInterval = 1200 * time.Millisecond
	defaultPollInterval   = 80 * time.Millisecond
	defaultCPUHigh        = 0.88
	defaultCPULow         = 0.58
)

var (
	metricCPUTotal   = "/cpu/classes/total:cpu-seconds"
	metricMemTotal   = "/memory/classes/total:bytes"
	errNoPendingWork = errors.New("no pending work")
)

type adaptiveTuner struct {
	maxWorkers int
	maxPPS     int
	minWorkers int
	minPPS     int

	workerCap atomic.Int32
	ppsCap    atomic.Int32

	adjustInterval time.Duration
	pollInterval   time.Duration
	cpuHigh        float64
	cpuLow         float64
	memHighBytes   uint64
	memLowBytes    uint64

	sampler *runtimeSampler
}

type runtimeStats struct {
	cpuUtilization float64
	cpuValid       bool
	memoryBytes    uint64
}

type runtimeSampler struct {
	samples []metrics.Sample
	prevCPU float64
	prevAt  time.Time
	hasPrev bool
}

func newAdaptiveTuner(maxWorkers, maxPPS int) *adaptiveTuner {
	if maxWorkers <= 0 {
		maxWorkers = 1
	}
	if maxPPS <= 0 {
		maxPPS = 1
	}

	initialWorkers := maxWorkers
	if initialWorkers > 32 {
		initialWorkers = 32
	}
	if initialWorkers < 1 {
		initialWorkers = 1
	}
	initialPPS := maxPPS
	if initialPPS > 1000 {
		initialPPS = 1000
	}
	if initialPPS < 10 {
		initialPPS = maxPPS
	}
	if initialPPS < 1 {
		initialPPS = 1
	}

	memHigh := mibToBytes(1536)
	memLow := mibToBytes(1024)

	return &adaptiveTuner{
		maxWorkers:     maxWorkers,
		maxPPS:         maxPPS,
		minWorkers:     1,
		minPPS:         5,
		adjustInterval: defaultAdjustInterval,
		pollInterval:   defaultPollInterval,
		cpuHigh:        defaultCPUHigh,
		cpuLow:         defaultCPULow,
		memHighBytes:   memHigh,
		memLowBytes:    memLow,
		sampler: &runtimeSampler{
			samples: []metrics.Sample{
				{Name: metricCPUTotal},
				{Name: metricMemTotal},
			},
		},
	}
}

func (t *adaptiveTuner) initialize() {
	initialWorkers := t.maxWorkers
	if initialWorkers > 32 {
		initialWorkers = 32
	}
	if initialWorkers < t.minWorkers {
		initialWorkers = t.minWorkers
	}
	initialPPS := t.maxPPS
	if initialPPS > 1000 {
		initialPPS = 1000
	}
	if initialPPS < t.minPPS {
		initialPPS = t.minPPS
	}
	t.workerCap.Store(int32(initialWorkers))
	t.ppsCap.Store(int32(initialPPS))
}

func (t *adaptiveTuner) effectiveWorkers() int {
	value := int(t.workerCap.Load())
	if value < t.minWorkers {
		return t.minWorkers
	}
	if value > t.maxWorkers {
		return t.maxWorkers
	}
	return value
}

func (t *adaptiveTuner) effectivePPS() int {
	value := int(t.ppsCap.Load())
	if value < t.minPPS {
		return t.minPPS
	}
	if value > t.maxPPS {
		return t.maxPPS
	}
	return value
}

func (t *adaptiveTuner) waitForWorkerSlot(ctx context.Context, workerID int, done *atomic.Int64, total int) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if done != nil && total > 0 && int(done.Load()) >= total {
			return errNoPendingWork
		}
		if workerID < t.effectiveWorkers() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(t.pollInterval):
		}
	}
}

func (t *adaptiveTuner) start(ctx context.Context, total int, done *atomic.Int64, progress ProgressFunc) {
	if total <= 0 {
		return
	}
	t.initialize()

	ticker := time.NewTicker(t.adjustInterval)
	defer ticker.Stop()

	prevDone := int(done.Load())
	prevRate := 0.0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			backlog := total - int(done.Load())
			if backlog <= 0 {
				return
			}

			stats := t.sampler.sample()
			currentWorkers := t.effectiveWorkers()
			currentPPS := t.effectivePPS()

			nextWorkers := currentWorkers
			nextPPS := currentPPS

			switch {
			case stats.memoryBytes >= t.memHighBytes:
				nextWorkers--
				nextPPS = int(float64(nextPPS) * 0.70)
			case stats.cpuValid && stats.cpuUtilization >= t.cpuHigh:
				nextWorkers--
				nextPPS = int(float64(nextPPS) * 0.75)
			case backlog > currentWorkers*2 && stats.memoryBytes <= t.memLowBytes && (!stats.cpuValid || stats.cpuUtilization <= t.cpuLow):
				nextWorkers++
				nextPPS = int(float64(nextPPS) * 1.20)
			case backlog < currentWorkers:
				nextWorkers--
				nextPPS = int(float64(nextPPS) * 0.90)
			}

			intervalSec := t.adjustInterval.Seconds()
			if intervalSec <= 0 {
				intervalSec = 1
			}
			doneNow := int(done.Load())
			deltaDone := doneNow - prevDone
			if deltaDone < 0 {
				deltaDone = 0
			}
			rate := float64(deltaDone) / intervalSec
			if prevRate > 0 && rate > 0 {
				if rate < prevRate*0.85 && nextWorkers > t.minWorkers {
					nextWorkers--
				} else if rate > prevRate*1.10 && backlog > currentWorkers*2 && nextWorkers < t.maxWorkers {
					nextWorkers++
				}
			}
			prevDone = doneNow
			if rate > 0 {
				if prevRate <= 0 {
					prevRate = rate
				} else {
					prevRate = (prevRate * 0.7) + (rate * 0.3)
				}
			}

			if nextWorkers < t.minWorkers {
				nextWorkers = t.minWorkers
			}
			if nextWorkers > t.maxWorkers {
				nextWorkers = t.maxWorkers
			}
			if backlog > 0 && nextWorkers > backlog {
				nextWorkers = maxInt(t.minWorkers, backlog)
			}
			if nextPPS < t.minPPS {
				nextPPS = t.minPPS
			}
			if nextPPS > t.maxPPS {
				nextPPS = t.maxPPS
			}

			changed := nextWorkers != currentWorkers || nextPPS != currentPPS
			if !changed {
				continue
			}
			t.workerCap.Store(int32(nextWorkers))
			t.ppsCap.Store(int32(nextPPS))

			if progress != nil {
				stage := fmt.Sprintf(
					"adaptive workers=%d pps=%d cpu=%.2f mem_mb=%d backlog=%d",
					nextWorkers,
					nextPPS,
					stats.cpuUtilization,
					stats.memoryBytes/(1024*1024),
					backlog,
				)
				progress(int(done.Load()), total, stage)
			}
		}
	}
}

func (s *runtimeSampler) sample() runtimeStats {
	now := time.Now()
	metrics.Read(s.samples)

	stats := runtimeStats{}
	if len(s.samples) >= 2 && s.samples[1].Value.Kind() == metrics.KindUint64 {
		stats.memoryBytes = s.samples[1].Value.Uint64()
	}

	var cpuTotal float64
	if len(s.samples) >= 1 && s.samples[0].Value.Kind() == metrics.KindFloat64 {
		cpuTotal = s.samples[0].Value.Float64()
	}
	if s.hasPrev && cpuTotal >= s.prevCPU {
		wall := now.Sub(s.prevAt).Seconds()
		if wall > 0 {
			procs := float64(runtime.GOMAXPROCS(0))
			if procs <= 0 {
				procs = 1
			}
			util := (cpuTotal - s.prevCPU) / (wall * procs)
			if util < 0 {
				util = 0
			}
			if util > 2 {
				util = 2
			}
			stats.cpuUtilization = util
			stats.cpuValid = true
		}
	}

	s.prevCPU = cpuTotal
	s.prevAt = now
	s.hasPrev = true
	return stats
}

func mibToBytes(mib int) uint64 {
	if mib <= 0 {
		return 0
	}
	return uint64(mib) * 1024 * 1024
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
