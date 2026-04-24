package netscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scan performs internal host discovery and returns normalized asset rows.
func Scan(ctx context.Context, input Params) (ScanResult, error) {
	params, err := normalizeParams(input)
	if err != nil {
		return ScanResult{}, err
	}

	targets, targetWarnings, err := resolveTargets(params)
	if err != nil {
		return ScanResult{}, err
	}
	warnings := append([]string{}, targetWarnings...)
	reachableMetrics := []ReachableSegmentMetric{}

	if params.ReachableSegments {
		if params.Progress != nil {
			params.Progress(0, maxInt(1, len(targets)), "discover_reachable_segments")
		}
		discoveredMetrics, verifiedTargets, reachableWarnings := discoverAndVerifyReachableSegments(ctx, params)
		reachableMetrics = discoveredMetrics
		warnings = append(warnings, reachableWarnings...)
		var reachableMergeWarnings []string
		targets, reachableMergeWarnings = mergeVerifiedTargets(targets, verifiedTargets, params.MaxTargets)
		warnings = append(warnings, reachableMergeWarnings...)
	}

	if len(targets) == 0 {
		return ScanResult{
			Total: 0,
			Rows:  []AssetRow{},
			Metrics: RuntimeMetrics{
				WorkerCeiling:              params.Workers,
				EffectiveWorkers:           0,
				PPSCeiling:                 params.PPS,
				EffectivePPS:               0,
				SkippedModes:               []string{},
				ReachableCandidateSegments: len(reachableMetrics),
				ReachableVerifiedSegments:  countVerifiedReachableSegments(reachableMetrics),
				ReachableSegments:          reachableMetrics,
			},
			Warnings: uniqueStrings(warnings),
		}, nil
	}

	hasIPv6Targets := false
	for _, target := range targets {
		if net.ParseIP(target).To4() == nil {
			hasIPv6Targets = true
			break
		}
	}

	selection := selectModes(params.ScanModes, hasIPv6Targets)
	warnings = append(warnings, selection.Warnings...)
	if len(selection.Executable) == 0 {
		allErrors := append([]string{}, selection.Permissions...)
		allErrors = append(allErrors, selection.Skipped...)
		if len(allErrors) == 0 {
			allErrors = append(allErrors, "no executable scan modes remain after capability checks")
		}
		return ScanResult{}, fmt.Errorf("invalid argument: %s", strings.Join(allErrors, "; "))
	}

	if hasIPv6Targets {
		for _, mode := range selection.Executable {
			capability := modeCapabilities[mode]
			if !capability.SupportsIPv6 {
				warnings = append(warnings, fmt.Sprintf("%s mode is skipped for IPv6 targets", mode))
			}
		}
	}

	matcher, err := loadManagedMatcher(params.ManagedSource)
	if err != nil {
		return ScanResult{}, err
	}
	portPolicy := resolvePortFieldPolicy(params.ScanModes)

	store, err := openAssetStore(defaultStorePath())
	if err != nil {
		return ScanResult{}, fmt.Errorf("netscan persistence initialization failed: %w", err)
	}
	defer func() { _ = store.close() }()

	tuner := newAdaptiveTuner(params.Workers, params.PPS)
	limiter := newRateLimiter(tuner, params.Jitter)

	var (
		doneCount atomic.Int64
		wg        sync.WaitGroup
		resultMu  sync.Mutex
		observed  = make([]probeObservation, 0, len(targets))
		obsWarns  = make([]string, 0, len(targets))
	)

	workerCount := params.Workers
	if workerCount < 1 {
		workerCount = 1
	}
	jobs := make(chan string, minInt(len(targets), maxInt(64, workerCount*4)))
	go tuner.start(ctx, len(targets), &doneCount, params.Progress)

	for workerID := 0; workerID < workerCount; workerID++ {
		id := workerID
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				if err := tuner.waitForWorkerSlot(ctx, id, &doneCount, len(targets)); err != nil {
					if errors.Is(err, errNoPendingWork) {
						return
					}
					return
				}

				select {
				case <-ctx.Done():
					return
				case target, ok := <-jobs:
					if !ok {
						return
					}

					modes := modesForTarget(target, selection.Executable)
					if len(modes) == 0 {
						nowDone := int(doneCount.Add(1))
						if params.Progress != nil {
							params.Progress(nowDone, len(targets), "target_skipped")
						}
						continue
					}

					observation := probeHost(ctx, target, params, modes, limiter)
					resultMu.Lock()
					recordObservation(observation, &observed, &obsWarns)
					resultMu.Unlock()

					nowDone := int(doneCount.Add(1))
					if params.Progress != nil {
						params.Progress(nowDone, len(targets), "probe_target")
					}
				}
			}
		}()
	}

	for _, target := range targets {
		select {
		case <-ctx.Done():
			break
		case jobs <- target:
		}
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil {
		return ScanResult{}, ctx.Err()
	}
	warnings = append(warnings, obsWarns...)

	rows := make([]AssetRow, 0, len(observed))
	nowMs := time.Now().UnixMilli()
	for _, obs := range observed {
		host := strings.TrimSpace(obs.Hostname)
		if host == "" {
			host = resolveHostname(obs.IP, params.Timeout/2)
		}

		normalizedIP, ok := normalizeIP(obs.IP)
		if !ok {
			continue
		}
		normalizedMAC, hasMAC := normalizeMAC(obs.MAC)
		if !hasMAC {
			normalizedMAC = ""
		}

		osFamily, deviceType, confidence := inferProfile(obs)
		assetStatus := matcher.classify(normalizedIP, normalizedMAC)

		row := AssetRow{
			AssetID:     deterministicAssetID(normalizedIP, normalizedMAC),
			IPAddress:   normalizedIP,
			IPVersion:   ipVersion(normalizedIP),
			MACAddress:  optionalString(normalizedMAC),
			MACVendor:   optionalString(obs.MACVendor),
			Hostname:    optionalString(host),
			OSFamily:    osFamily,
			DeviceType:  deviceType,
			AssetStatus: assetStatus,
			Alive:       true,
			Confidence:  confidence,
			ScanModes:   uniqueStrings(obs.ScanModes),
			Sources:     uniqueStrings(obs.Sources),
		}
		if portPolicy.IncludeTCP {
			row.OpenTCPPorts = uniqueInts(obs.OpenTCPPorts)
		}
		if portPolicy.IncludeUDP {
			row.OpenUDPPorts = uniqueInts(obs.OpenUDPPorts)
		}
		if portPolicy.IncludeTCP || portPolicy.IncludeUDP {
			row.PortScanModes = uniqueStrings(obs.PortScanModes)
			row.OpenPorts = uniqueInts(append(append([]int{}, row.OpenTCPPorts...), row.OpenUDPPorts...))
		}

		firstSeen, lastSeen, err := store.upsert(ctx, row, nowMs)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("persistence warning for %s: %v", normalizedIP, err))
			row.FirstSeen = nowMs
			row.LastSeen = nowMs
		} else {
			row.FirstSeen = firstSeen
			row.LastSeen = lastSeen
		}

		rows = append(rows, row)
	}

	rows = applyFilters(rows, params.AssetStatus, params.Keyword)
	sortRows(rows, params.SortBy, params.SortOrder)

	if params.Progress != nil {
		params.Progress(len(targets), len(targets), "complete")
	}

	return ScanResult{
		Total: len(rows),
		Rows:  rows,
		Metrics: RuntimeMetrics{
			WorkerCeiling:              params.Workers,
			EffectiveWorkers:           tuner.effectiveWorkers(),
			PPSCeiling:                 params.PPS,
			EffectivePPS:               tuner.effectivePPS(),
			SkippedModes:               uniqueStrings(selection.Skipped),
			PermissionFailures:         uniqueStrings(selection.Permissions),
			ReachableCandidateSegments: len(reachableMetrics),
			ReachableVerifiedSegments:  countVerifiedReachableSegments(reachableMetrics),
			ReachableSegments:          reachableMetrics,
		},
		Warnings: uniqueStrings(warnings),
	}, nil
}

func countVerifiedReachableSegments(items []ReachableSegmentMetric) int {
	count := 0
	for _, item := range items {
		if item.Verified {
			count++
		}
	}
	return count
}

func recordObservation(observation probeObservation, observed *[]probeObservation, warnings *[]string) {
	if len(observation.Warnings) > 0 {
		*warnings = append(*warnings, observation.Warnings...)
	}
	if observation.Alive {
		*observed = append(*observed, observation)
	}
}

func modesForTarget(target string, modes []ScanMode) []ScanMode {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		return nil
	}
	isV4 := ip.To4() != nil
	out := make([]ScanMode, 0, len(modes))
	for _, mode := range modes {
		capability := modeCapabilities[mode]
		if isV4 && !capability.SupportsIPv4 {
			continue
		}
		if !isV4 && !capability.SupportsIPv6 {
			continue
		}
		out = append(out, mode)
	}
	return out
}

type portFieldPolicy struct {
	IncludeTCP bool
	IncludeUDP bool
}

func resolvePortFieldPolicy(modes []ScanMode) portFieldPolicy {
	policy := portFieldPolicy{}
	for _, mode := range modes {
		switch mode {
		case ModeTCPConnect, ModeTCPSYN, ModeOXID:
			policy.IncludeTCP = true
		case ModeUDP:
			policy.IncludeUDP = true
		}
	}
	return policy
}

func applyFilters(rows []AssetRow, status, keyword string) []AssetRow {
	status = strings.ToLower(strings.TrimSpace(status))
	keyword = strings.ToLower(strings.TrimSpace(keyword))
	if status == "" && keyword == "" {
		return rows
	}

	out := make([]AssetRow, 0, len(rows))
	for _, row := range rows {
		if status != "" && strings.ToLower(strings.TrimSpace(row.AssetStatus)) != status {
			continue
		}
		if keyword != "" {
			content := []string{
				strings.ToLower(row.IPAddress),
				strings.ToLower(ptrString(row.MACAddress)),
				strings.ToLower(ptrString(row.Hostname)),
			}
			if !strings.Contains(strings.Join(content, " "), keyword) {
				continue
			}
		}
		out = append(out, row)
	}
	return out
}

func sortRows(rows []AssetRow, sortBy, sortOrder string) {
	desc := strings.EqualFold(sortOrder, "desc")
	sort.SliceStable(rows, func(i, j int) bool {
		a := rows[i]
		b := rows[j]
		cmp := 0
		switch strings.ToLower(strings.TrimSpace(sortBy)) {
		case "firstseen":
			cmp = compareInt64(a.FirstSeen, b.FirstSeen)
		case "ipaddress":
			cmp = compareIPStrings(a.IPAddress, b.IPAddress)
		case "assetstatus":
			cmp = strings.Compare(strings.ToLower(a.AssetStatus), strings.ToLower(b.AssetStatus))
		default:
			cmp = compareInt64(a.LastSeen, b.LastSeen)
		}
		if cmp == 0 {
			cmp = strings.Compare(a.AssetID, b.AssetID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func compareInt64(a, b int64) int {
	switch {
	case a > b:
		return 1
	case a < b:
		return -1
	default:
		return 0
	}
}

func ptrString(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func stringifyIntSlice(values []int) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strconv.Itoa(value))
	}
	return out
}
