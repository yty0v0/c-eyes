package filescan

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultPipelineAdjustInterval = 1200 * time.Millisecond
	defaultPipelinePollInterval   = 80 * time.Millisecond
	defaultPipelineCPUHigh        = 0.90
	defaultPipelineCPULow         = 0.60
)

var (
	pipelineMetricCPUTotal = "/cpu/classes/total:cpu-seconds"
	pipelineMetricMemTotal = "/memory/classes/total:bytes"
)

// PipelineExecutionOptions controls execution-level behavior for the scan pipeline.
type PipelineExecutionOptions struct {
	// Workers forces a fixed worker count when > 0.
	Workers int
	// Mode hints scenario-specific defaults for adaptive worker selection.
	Mode ScanMode
	// OnTaskError reports task-scoped failures while allowing the pipeline to continue.
	OnTaskError TaskErrorFunc
}

type pipelineJob struct {
	index int
	task  ScanTask
}

type pipelineWorkerProfile struct {
	min            int
	initial        int
	max            int
	adaptive       bool
	pollInterval   time.Duration
	adjustInterval time.Duration
	cpuHigh        float64
	cpuLow         float64
	memHighBytes   uint64
	memLowBytes    uint64
	debugAdaptive  bool
}

type runtimeAdaptiveStats struct {
	cpuUtilization float64
	cpuValid       bool
	memoryBytes    uint64
}

type runtimeAdaptiveSampler struct {
	samples []metrics.Sample
	prevCPU float64
	prevAt  time.Time
	hasPrev bool
}

// RunPipeline executes filter -> deep scan -> report in order.
func RunPipeline(ctx context.Context, tasks []ScanTask, filter FilterEngine, deep DeepScanner, reporter ResultReporter) ([]FileScanResult, error) {
	return RunPipelineWithProgressAndOptions(ctx, tasks, filter, deep, reporter, nil, PipelineExecutionOptions{})
}

// RunPipelineWithProgress executes filter -> deep scan -> report and emits progress.
func RunPipelineWithProgress(ctx context.Context, tasks []ScanTask, filter FilterEngine, deep DeepScanner, reporter ResultReporter, progress ProgressFunc) ([]FileScanResult, error) {
	return RunPipelineWithProgressAndOptions(ctx, tasks, filter, deep, reporter, progress, PipelineExecutionOptions{})
}

// RunPipelineWithProgressAndOptions executes filter -> deep scan -> report with adaptive workers.
func RunPipelineWithProgressAndOptions(
	ctx context.Context,
	tasks []ScanTask,
	filter FilterEngine,
	deep DeepScanner,
	reporter ResultReporter,
	progress ProgressFunc,
	options PipelineExecutionOptions,
) ([]FileScanResult, error) {
	total := len(tasks)
	if total == 0 {
		return nil, nil
	}

	profile := resolvePipelineWorkerProfile(total, options)
	results := make([]FileScanResult, 0, total)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		progressMu sync.Mutex
		resultsMu  sync.Mutex
		doneCount  atomic.Int64
		workerCap  atomic.Int32
		wg         sync.WaitGroup
	)
	workerCap.Store(int32(profile.initial))

	emit := func(done int, stage string) {
		if progress == nil || total <= 0 {
			return
		}
		progressMu.Lock()
		progress(done, total, stage)
		progressMu.Unlock()
	}

	bufferSize := pipelineMaxInt(64, profile.max*4)
	if total < bufferSize {
		bufferSize = total
	}
	jobs := make(chan pipelineJob, bufferSize)

	for id := 0; id < profile.max; id++ {
		workerID := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				if doneCount.Load() >= int64(total) {
					return
				}
				if profile.adaptive && workerID >= int(workerCap.Load()) {
					select {
					case <-ctx.Done():
						return
					case <-time.After(profile.pollInterval):
						continue
					}
				}

				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}

					reported, stage, err := runPipelineTask(ctx, job.task, filter, deep, reporter)
					if err != nil {
						if options.OnTaskError != nil {
							options.OnTaskError(job.task, stage, err)
						}
						doneNow := int(doneCount.Add(1))
						emit(doneNow, "failed_"+stage)
						continue
					}

					resultsMu.Lock()
					results = append(results, reported)
					resultsMu.Unlock()
					doneNow := int(doneCount.Add(1))
					emit(doneNow, stage)
				}
			}
		}()
	}

	if profile.adaptive && profile.max > profile.min {
		go tunePipelineWorkers(ctx, total, &doneCount, &workerCap, profile, emit)
	}

enqueue:
	for i, task := range tasks {
		select {
		case <-ctx.Done():
			break enqueue
		case jobs <- pipelineJob{index: i, task: task}:
		}
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil && doneCount.Load() < int64(total) {
		return nil, ctx.Err()
	}

	emit(total, "complete")
	return results, nil
}

func runPipelineTask(
	ctx context.Context,
	task ScanTask,
	filter FilterEngine,
	deep DeepScanner,
	reporter ResultReporter,
) (FileScanResult, string, error) {
	decision, err := filter.Filter(ctx, task)
	if err != nil {
		return FileScanResult{}, "filter", err
	}
	if decision.Final {
		reported, err := reporter.Report(ctx, decision.Result)
		if err != nil {
			return FileScanResult{}, "report_filter", err
		}
		return reported, "filter", nil
	}

	base := decision.Result
	deepResult, err := deep.Scan(ctx, task)
	if err != nil {
		return FileScanResult{}, "deep_scan", err
	}
	base.ScanResult = scanResultPtr(deepResult.Result)
	reported, err := reporter.Report(ctx, base)
	if err != nil {
		return FileScanResult{}, "report_deep_scan", err
	}
	return reported, "deep_scan", nil
}

func tunePipelineWorkers(
	ctx context.Context,
	total int,
	done *atomic.Int64,
	workerCap *atomic.Int32,
	profile pipelineWorkerProfile,
	emit func(done int, stage string),
) {
	if total <= 0 {
		return
	}
	sampler := newRuntimeAdaptiveSampler()
	ticker := time.NewTicker(profile.adjustInterval)
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

			current := int(workerCap.Load())
			stats := sampler.sample()
			next := decideNextWorkerLimit(current, backlog, stats, profile)

			intervalSec := profile.adjustInterval.Seconds()
			if intervalSec <= 0 {
				intervalSec = defaultPipelineAdjustInterval.Seconds()
			}
			doneNow := int(done.Load())
			deltaDone := doneNow - prevDone
			if deltaDone < 0 {
				deltaDone = 0
			}
			rate := float64(deltaDone) / intervalSec
			if prevRate > 0 && rate > 0 {
				if rate < prevRate*0.85 && current > profile.min {
					next = pipelineMinInt(next, current-1)
				} else if rate > prevRate*1.10 && backlog > current*2 && current < profile.max {
					next = pipelineMaxInt(next, current+1)
				}
			}
			prevDone = doneNow
			if rate > 0 {
				if prevRate <= 0 {
					prevRate = rate
				} else {
					// Smooth jitter with a lightweight EMA.
					prevRate = (prevRate * 0.7) + (rate * 0.3)
				}
			}

			if next == current {
				continue
			}

			workerCap.Store(int32(next))
			if profile.debugAdaptive {
				stage := fmt.Sprintf(
					"adaptive workers=%d cpu=%.2f mem_mb=%d backlog=%d",
					next,
					stats.cpuUtilization,
					stats.memoryBytes/(1024*1024),
					backlog,
				)
				emit(int(done.Load()), stage)
			}
		}
	}
}

func decideNextWorkerLimit(current, backlog int, stats runtimeAdaptiveStats, profile pipelineWorkerProfile) int {
	if current < profile.min {
		current = profile.min
	}
	if current > profile.max {
		current = profile.max
	}

	next := current
	if stats.memoryBytes >= profile.memHighBytes {
		next--
	} else {
		if stats.cpuValid && stats.cpuUtilization >= profile.cpuHigh {
			next--
		} else if backlog > current*2 && stats.memoryBytes <= profile.memLowBytes && (!stats.cpuValid || stats.cpuUtilization <= profile.cpuLow) {
			next++
		} else if backlog < current && current > profile.min {
			next--
		}
	}

	if backlog > 0 && next > backlog {
		next = pipelineMaxInt(profile.min, backlog)
	}
	if next < profile.min {
		next = profile.min
	}
	if next > profile.max {
		next = profile.max
	}
	return next
}

func resolvePipelineWorkerProfile(total int, options PipelineExecutionOptions) pipelineWorkerProfile {
	procs := runtime.GOMAXPROCS(0)
	if procs <= 0 {
		procs = runtime.NumCPU()
	}
	if procs <= 0 {
		procs = 1
	}

	fixed := options.Workers
	if fixed <= 0 {
		fixed = lookupPipelineIntEnv("C_EYES_FILESCAN_WORKERS", 0)
	}
	if fixed > 0 {
		fixed = clampPipelineInt(fixed, 1, pipelineMaxInt(1, total))
		return pipelineWorkerProfile{
			min:            fixed,
			initial:        fixed,
			max:            fixed,
			adaptive:       false,
			pollInterval:   defaultPipelinePollInterval,
			adjustInterval: defaultPipelineAdjustInterval,
			cpuHigh:        defaultPipelineCPUHigh,
			cpuLow:         defaultPipelineCPULow,
			memHighBytes:   mibToBytes(1536),
			memLowBytes:    mibToBytes(1024),
			debugAdaptive:  false,
		}
	}

	mode := normalizePipelineMode(options.Mode)
	initial, maxW, memHighDefault, memLowDefault := resolvePipelineAutoWorkers(total, procs, mode)
	cpuHigh, cpuLow := resolvePipelineCPUThresholds(mode)

	if memBytes, ok := readPipelineRuntimeMemoryTotal(); ok {
		switch {
		case memBytes >= mibToBytes(3072) && maxW > 4:
			maxW = 4
		case memBytes >= mibToBytes(2048) && maxW > 6:
			maxW = 6
		}
		if initial > maxW {
			initial = maxW
		}
	}

	if total < maxW {
		maxW = total
	}
	if maxW <= 0 {
		maxW = 1
	}
	if initial > maxW {
		initial = maxW
	}
	if initial <= 0 {
		initial = 1
	}

	minW := 1
	if envMin := lookupPipelineIntEnv("C_EYES_FILESCAN_WORKERS_MIN", 0); envMin > 0 {
		minW = envMin
	}
	if envMax := lookupPipelineIntEnv("C_EYES_FILESCAN_WORKERS_MAX", 0); envMax > 0 {
		maxW = envMax
	}
	if maxW < 1 {
		maxW = 1
	}
	if maxW > total {
		maxW = total
	}
	if minW > maxW {
		minW = maxW
	}
	if initial < minW {
		initial = minW
	}
	if initial > maxW {
		initial = maxW
	}

	memHighMiB := lookupPipelineIntEnv("C_EYES_FILESCAN_MEM_HIGH_MIB", memHighDefault)
	if memHighMiB < 512 {
		memHighMiB = 512
	}
	memLowMiB := lookupPipelineIntEnv("C_EYES_FILESCAN_MEM_LOW_MIB", memLowDefault)
	if memLowMiB < 256 {
		memLowMiB = 256
	}
	if memLowMiB > memHighMiB {
		memLowMiB = memHighMiB
	}

	adjustIntervalMs := lookupPipelineIntEnv("C_EYES_FILESCAN_ADAPTIVE_INTERVAL_MS", int(defaultPipelineAdjustInterval/time.Millisecond))
	if adjustIntervalMs < 500 {
		adjustIntervalMs = 500
	}

	pollIntervalMs := lookupPipelineIntEnv("C_EYES_FILESCAN_WORKER_POLL_MS", int(defaultPipelinePollInterval/time.Millisecond))
	if pollIntervalMs < 20 {
		pollIntervalMs = 20
	}

	return pipelineWorkerProfile{
		min:            minW,
		initial:        initial,
		max:            maxW,
		adaptive:       !lookupPipelineBoolEnv("C_EYES_FILESCAN_DISABLE_ADAPTIVE", false),
		pollInterval:   time.Duration(pollIntervalMs) * time.Millisecond,
		adjustInterval: time.Duration(adjustIntervalMs) * time.Millisecond,
		cpuHigh:        cpuHigh,
		cpuLow:         cpuLow,
		memHighBytes:   mibToBytes(memHighMiB),
		memLowBytes:    mibToBytes(memLowMiB),
		debugAdaptive:  lookupPipelineBoolEnv("C_EYES_FILESCAN_DEBUG_ADAPTIVE", false),
	}
}

func resolvePipelineAutoWorkers(total, procs int, mode ScanMode) (initial, maxW, memHighMiB, memLowMiB int) {
	if total <= 0 {
		total = 1
	}
	if procs <= 0 {
		procs = 1
	}

	if mode == ScanModePath || mode == ScanModeFull {
		maxCap := pipelineMinInt(total, pipelineMaxInt(2, pipelineMinInt(procs*2, 10)))
		initialCap := pipelineMinInt(maxCap, pipelineMaxInt(1, pipelineMinInt(procs, 6)))

		switch {
		case total <= 300:
			maxW = pipelineMinInt(maxCap, 4)
			initial = pipelineMinInt(initialCap, 3)
		case total <= 2000:
			maxW = pipelineMinInt(maxCap, 6)
			initial = pipelineMinInt(initialCap, 4)
		default:
			maxW = pipelineMinInt(maxCap, 8)
			initial = pipelineMinInt(initialCap, 5)
		}

		if total >= 512 && procs >= 4 && initial < 3 {
			initial = 3
		}
		memHighMiB = 1024 + (maxW * 192)
	} else {
		maxCap := pipelineMinInt(total, pipelineMaxInt(2, pipelineMinInt(procs, 6)))
		initialCap := pipelineMinInt(maxCap, pipelineMaxInt(1, pipelineMinInt(procs, 4)))

		switch {
		case total <= 300:
			maxW = pipelineMinInt(maxCap, 4)
			initial = pipelineMinInt(initialCap, 3)
		case total <= 2000:
			maxW = pipelineMinInt(maxCap, 5)
			initial = pipelineMinInt(initialCap, 3)
		default:
			maxW = pipelineMinInt(maxCap, 6)
			initial = pipelineMinInt(initialCap, 2)
		}

		if total >= 512 && procs >= 4 && initial < 2 {
			initial = 2
		}
		memHighMiB = 768 + (maxW * 128)
	}

	if total < 64 && initial > 3 {
		initial = 3
	}
	if total < 16 && initial > 2 {
		initial = 2
	}
	if maxW < 1 {
		maxW = 1
	}
	if initial < 1 {
		initial = 1
	}
	if initial > maxW {
		initial = maxW
	}

	memLowMiB = int(float64(memHighMiB) * 0.70)
	if memLowMiB < 384 {
		memLowMiB = 384
	}
	if memLowMiB > memHighMiB {
		memLowMiB = memHighMiB
	}
	return initial, maxW, memHighMiB, memLowMiB
}

func resolvePipelineCPUThresholds(mode ScanMode) (high, low float64) {
	if mode == ScanModePath || mode == ScanModeFull {
		return 0.95, 0.68
	}
	return defaultPipelineCPUHigh, defaultPipelineCPULow
}

func normalizePipelineMode(mode ScanMode) ScanMode {
	switch mode {
	case ScanModeFull, ScanModePath, ScanModeSmart:
		return mode
	default:
		return ScanModeSmart
	}
}

func newRuntimeAdaptiveSampler() *runtimeAdaptiveSampler {
	return &runtimeAdaptiveSampler{
		samples: []metrics.Sample{
			{Name: pipelineMetricCPUTotal},
			{Name: pipelineMetricMemTotal},
		},
	}
}

func (s *runtimeAdaptiveSampler) sample() runtimeAdaptiveStats {
	now := time.Now()
	metrics.Read(s.samples)

	stats := runtimeAdaptiveStats{}

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

func readPipelineRuntimeMemoryTotal() (uint64, bool) {
	samples := []metrics.Sample{{Name: pipelineMetricMemTotal}}
	metrics.Read(samples)
	if len(samples) == 0 || samples[0].Value.Kind() != metrics.KindUint64 {
		return 0, false
	}
	return samples[0].Value.Uint64(), true
}

func lookupPipelineIntEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return val
}

func lookupPipelineBoolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func clampPipelineInt(val, lo, hi int) int {
	if val < lo {
		return lo
	}
	if val > hi {
		return hi
	}
	return val
}

func pipelineMinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func pipelineMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func mibToBytes(val int) uint64 {
	if val <= 0 {
		return 0
	}
	return uint64(val) * 1024 * 1024
}
