package netscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseModesCSV(t *testing.T) {
	t.Parallel()

	modes, err := ParseModesCSV("ICP,TS,U,ICP")
	if err != nil {
		t.Fatalf("ParseModesCSV error: %v", err)
	}
	if len(modes) != 3 {
		t.Fatalf("expected 3 unique modes, got %d", len(modes))
	}
	if modes[0] != ModeICMPEcho || modes[1] != ModeTCPSYN || modes[2] != ModeUDP {
		t.Fatalf("unexpected mode sequence: %#v", modes)
	}
}

func TestParsePortsCSVValidation(t *testing.T) {
	t.Parallel()

	ports, err := ParsePortsCSV("22,80,443,80", "tcpPorts")
	if err != nil {
		t.Fatalf("ParsePortsCSV error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected deduplicated ports, got %v", ports)
	}

	if _, err := ParsePortsCSV("0,22", "tcpPorts"); err == nil {
		t.Fatal("expected invalid port range error")
	}
}

func TestNormalizeParamsReachableSegmentsDefaultFalse(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(Params{})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}
	if params.ReachableSegments {
		t.Fatal("expected reachableSegments=false by default")
	}
}

func TestRuntimeMetricsReachableSegmentsJSON(t *testing.T) {
	t.Parallel()

	metrics := RuntimeMetrics{
		WorkerCeiling:              24,
		EffectiveWorkers:           8,
		PPSCeiling:                 80,
		EffectivePPS:               40,
		SkippedModes:               []string{},
		PermissionFailures:         []string{},
		ReachableCandidateSegments: 3,
		ReachableVerifiedSegments:  2,
		ReachableSegments: []ReachableSegmentMetric{
			{
				CIDR:             "10.50.1.0/24",
				DiscoverySources: []string{"route_table", "active_connections"},
				Verified:         true,
			},
		},
	}
	b, err := json.Marshal(metrics)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	raw := string(b)
	if !strings.Contains(raw, "reachableCandidateSegments") {
		t.Fatalf("expected reachableCandidateSegments in JSON: %s", raw)
	}
	if !strings.Contains(raw, "reachableVerifiedSegments") {
		t.Fatalf("expected reachableVerifiedSegments in JSON: %s", raw)
	}
	if !strings.Contains(raw, "reachableSegments") {
		t.Fatalf("expected reachableSegments in JSON: %s", raw)
	}
}

func TestResolveTargetsWithExclude(t *testing.T) {
	t.Parallel()

	params := normalizedParams{
		Params: Params{
			Target:     "192.168.1.1-3,192.168.1.4",
			Exclude:    "192.168.1.2,192.168.1.4",
			MaxTargets: 32,
		},
	}
	targets, warnings, err := resolveTargets(params)
	if err != nil {
		t.Fatalf("resolveTargets error: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got: %v", warnings)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d (%v)", len(targets), targets)
	}
	if targets[0] != "192.168.1.1" || targets[1] != "192.168.1.3" {
		t.Fatalf("unexpected target order/content: %v", targets)
	}
}

func TestManagedMatcherPrecedence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "managed.csv")
	content := strings.Join([]string{
		"ipAddress,macAddress",
		"10.0.0.5,AA-BB-CC-11-22-33",
		"10.0.0.9,",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	matcher, err := loadManagedMatcher(path)
	if err != nil {
		t.Fatalf("loadManagedMatcher error: %v", err)
	}

	if got := matcher.classify("10.0.0.5", "AA:BB:CC:11:22:33"); got != "managed" {
		t.Fatalf("expected ip+mac managed match, got %s", got)
	}
	if got := matcher.classify("10.0.0.9", ""); got != "managed" {
		t.Fatalf("expected ip fallback managed match, got %s", got)
	}
	if got := matcher.classify("10.0.0.9", "FF:EE:DD:11:22:33"); got != "managed" {
		t.Fatalf("expected ip fallback managed match with unmatched mac, got %s", got)
	}
	if got := matcher.classify("10.0.0.50", ""); got != "unmanaged" {
		t.Fatalf("expected unmanaged match, got %s", got)
	}
}

func TestDeterministicAssetIDStability(t *testing.T) {
	t.Parallel()

	id1 := deterministicAssetID("192.168.1.10", "AA:BB:CC:11:22:33")
	id2 := deterministicAssetID("192.168.1.20", "AA:BB:CC:11:22:33")
	id3 := deterministicAssetID("192.168.1.10", "")

	if id1 != id2 {
		t.Fatalf("expected mac-based IDs to stay stable across IP changes, got %s vs %s", id1, id2)
	}
	if id1 == id3 {
		t.Fatalf("expected mac-aware ID to differ from ip-only ID")
	}
}

func TestAssetStoreFirstSeenLastSeen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "netscan.db")
	store, err := openAssetStore(path)
	if err != nil {
		t.Fatalf("openAssetStore error: %v", err)
	}
	defer func() { _ = store.close() }()

	row := AssetRow{
		AssetID:     deterministicAssetID("192.168.1.10", ""),
		IPAddress:   "192.168.1.10",
		OSFamily:    "unknown",
		DeviceType:  "pc",
		AssetStatus: "unmanaged",
	}

	firstNow := time.Now().UnixMilli()
	firstSeen, lastSeen, err := store.upsert(context.Background(), row, firstNow)
	if err != nil {
		t.Fatalf("first upsert error: %v", err)
	}
	if firstSeen != firstNow || lastSeen != firstNow {
		t.Fatalf("unexpected first/last timestamps: %d/%d", firstSeen, lastSeen)
	}

	secondNow := firstNow + 5000
	firstSeen2, lastSeen2, err := store.upsert(context.Background(), row, secondNow)
	if err != nil {
		t.Fatalf("second upsert error: %v", err)
	}
	if firstSeen2 != firstNow {
		t.Fatalf("expected firstSeen unchanged, got %d", firstSeen2)
	}
	if lastSeen2 != secondNow {
		t.Fatalf("expected lastSeen updated, got %d", lastSeen2)
	}
}

func TestAssetStoreUpgradesRecentIPOnlyIdentityToMACIdentity(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "netscan.db")
	store, err := openAssetStore(path)
	if err != nil {
		t.Fatalf("openAssetStore error: %v", err)
	}
	defer func() { _ = store.close() }()

	weakRow := AssetRow{
		AssetID:     deterministicAssetID("192.168.1.10", ""),
		IPAddress:   "192.168.1.10",
		OSFamily:    "unknown",
		DeviceType:  "pc",
		AssetStatus: "unmanaged",
	}
	firstNow := time.Now().UnixMilli()
	firstSeen, lastSeen, err := store.upsert(context.Background(), weakRow, firstNow)
	if err != nil {
		t.Fatalf("weak upsert error: %v", err)
	}
	if firstSeen != firstNow || lastSeen != firstNow {
		t.Fatalf("unexpected weak first/last timestamps: %d/%d", firstSeen, lastSeen)
	}

	strongRow := AssetRow{
		AssetID:     deterministicAssetID("192.168.1.10", "AA:BB:CC:11:22:33"),
		IPAddress:   "192.168.1.10",
		MACAddress:  optionalString("AA:BB:CC:11:22:33"),
		OSFamily:    "unknown",
		DeviceType:  "pc",
		AssetStatus: "managed",
	}
	secondNow := firstNow + 5000
	firstSeen2, lastSeen2, err := store.upsert(context.Background(), strongRow, secondNow)
	if err != nil {
		t.Fatalf("strong upsert error: %v", err)
	}
	if firstSeen2 != firstNow {
		t.Fatalf("expected upgraded firstSeen preserved, got %d", firstSeen2)
	}
	if lastSeen2 != secondNow {
		t.Fatalf("expected upgraded lastSeen updated, got %d", lastSeen2)
	}
}

func TestAssetStoreDoesNotUpgradeWeakIdentityWhenEvidenceConflicts(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "netscan.db")
	store, err := openAssetStore(path)
	if err != nil {
		t.Fatalf("openAssetStore error: %v", err)
	}
	defer func() { _ = store.close() }()

	weakRow := AssetRow{
		AssetID:     deterministicAssetID("192.168.1.10", ""),
		IPAddress:   "192.168.1.10",
		Hostname:    optionalString("old-host"),
		OSFamily:    "windows",
		DeviceType:  "pc",
		AssetStatus: "unmanaged",
	}
	firstNow := time.Now().UnixMilli()
	if _, _, err := store.upsert(context.Background(), weakRow, firstNow); err != nil {
		t.Fatalf("weak upsert error: %v", err)
	}

	strongRow := AssetRow{
		AssetID:     deterministicAssetID("192.168.1.10", "AA:BB:CC:11:22:33"),
		IPAddress:   "192.168.1.10",
		MACAddress:  optionalString("AA:BB:CC:11:22:33"),
		Hostname:    optionalString("new-host"),
		OSFamily:    "linux",
		DeviceType:  "pc",
		AssetStatus: "managed",
	}
	secondNow := firstNow + 5000
	firstSeen2, lastSeen2, err := store.upsert(context.Background(), strongRow, secondNow)
	if err != nil {
		t.Fatalf("strong upsert error: %v", err)
	}
	if firstSeen2 != secondNow {
		t.Fatalf("expected conflicting weak identity not reused, got firstSeen=%d want %d", firstSeen2, secondNow)
	}
	if lastSeen2 != secondNow {
		t.Fatalf("expected fresh lastSeen updated, got %d", lastSeen2)
	}
}

func TestApplyFiltersAndSort(t *testing.T) {
	t.Parallel()

	rows := []AssetRow{
		{
			AssetID:     "a",
			IPAddress:   "10.0.0.2",
			AssetStatus: "managed",
			LastSeen:    20,
		},
		{
			AssetID:     "b",
			IPAddress:   "10.0.0.1",
			AssetStatus: "unmanaged",
			LastSeen:    30,
			Hostname:    optionalString("db-prod"),
		},
	}

	filtered := applyFilters(rows, "unmanaged", "db")
	if len(filtered) != 1 || filtered[0].AssetID != "b" {
		t.Fatalf("unexpected filtered rows: %#v", filtered)
	}

	sortRows(rows, "ipAddress", "asc")
	if rows[0].IPAddress != "10.0.0.1" {
		t.Fatalf("expected ip sort asc, got %v", rows)
	}
}

func TestResolvePortFieldPolicy(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		modes   []ScanMode
		wantTCP bool
		wantUDP bool
	}{
		{name: "arp only", modes: []ScanMode{ModeARP}, wantTCP: false, wantUDP: false},
		{name: "tcp connect", modes: []ScanMode{ModeTCPConnect}, wantTCP: true, wantUDP: false},
		{name: "tcp syn", modes: []ScanMode{ModeTCPSYN}, wantTCP: true, wantUDP: false},
		{name: "oxid", modes: []ScanMode{ModeOXID}, wantTCP: true, wantUDP: false},
		{name: "udp", modes: []ScanMode{ModeUDP}, wantTCP: false, wantUDP: true},
		{name: "mixed", modes: []ScanMode{ModeARP, ModeUDP, ModeTCPConnect}, wantTCP: true, wantUDP: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := resolvePortFieldPolicy(tc.modes)
			if got.IncludeTCP != tc.wantTCP || got.IncludeUDP != tc.wantUDP {
				t.Fatalf("resolvePortFieldPolicy(%v) = %+v, want tcp=%v udp=%v", tc.modes, got, tc.wantTCP, tc.wantUDP)
			}
		})
	}
}

func TestRecordObservationKeepsWarningsForNonAliveTarget(t *testing.T) {
	t.Parallel()

	observed := []probeObservation{}
	warnings := []string{}

	recordObservation(probeObservation{
		IP:       "192.0.2.1",
		Alive:    false,
		Warnings: []string{"A mode uses local-subnet ARP-compatible fallback probing in this build."},
	}, &observed, &warnings)

	if len(observed) != 0 {
		t.Fatalf("expected non-alive observation not to be persisted, got %d item(s)", len(observed))
	}
	if len(warnings) != 1 {
		t.Fatalf("expected warning to be preserved, got %v", warnings)
	}
}

func TestScanReachableSegmentsDisabledSkipsCollectors(t *testing.T) {
	originalRouteCollector := reachabilityRouteCollector
	originalConnectionCollector := reachabilityConnectionCollector
	defer func() {
		reachabilityRouteCollector = originalRouteCollector
		reachabilityConnectionCollector = originalConnectionCollector
	}()

	called := false
	reachabilityRouteCollector = func() ([]reachabilitySignal, []string) {
		called = true
		return nil, nil
	}
	reachabilityConnectionCollector = func() ([]reachabilitySignal, []string) {
		called = true
		return nil, nil
	}

	result, err := Scan(context.Background(), Params{
		Target:     "10.255.255.1",
		ScanModes:  []ScanMode{ModeTCPConnect},
		TCPPorts:   []int{65535},
		TimeoutMs:  50,
		Workers:    1,
		MaxTargets: 8,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if called {
		t.Fatal("expected reachable collectors not to run when reachableSegments=false")
	}
	if result.Metrics.ReachableCandidateSegments != 0 || result.Metrics.ReachableVerifiedSegments != 0 {
		t.Fatalf("expected reachable metrics to remain zero, got %+v", result.Metrics)
	}
}

func TestScanReachableSegmentsEnabledAddsMetricsAndWarnings(t *testing.T) {
	originalRouteCollector := reachabilityRouteCollector
	originalConnectionCollector := reachabilityConnectionCollector
	originalICMP := reachabilityICMPProbe
	originalTCP := reachabilityTCPPortProbe
	defer func() {
		reachabilityRouteCollector = originalRouteCollector
		reachabilityConnectionCollector = originalConnectionCollector
		reachabilityICMPProbe = originalICMP
		reachabilityTCPPortProbe = originalTCP
	}()

	reachabilityRouteCollector = func() ([]reachabilitySignal, []string) {
		return []reachabilitySignal{
			{CIDR: "10.50.1.0/24", NextHop: "10.50.1.1", Source: "route_table"},
		}, nil
	}
	reachabilityConnectionCollector = func() ([]reachabilitySignal, []string) {
		return nil, nil
	}
	reachabilityICMPProbe = func(target string, mode ScanMode, timeout time.Duration) (bool, error) {
		return false, nil
	}
	reachabilityTCPPortProbe = func(ctx context.Context, target string, port int, timeout time.Duration) bool {
		return target == "10.50.1.1" && port == 445
	}

	result, err := Scan(context.Background(), Params{
		Target:            "10.255.255.1",
		ReachableSegments: true,
		ScanModes:         []ScanMode{ModeTCPConnect},
		TCPPorts:          []int{65535},
		TimeoutMs:         50,
		Workers:           1,
		MaxTargets:        1,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if result.Metrics.ReachableCandidateSegments != 1 {
		t.Fatalf("expected reachable candidate count=1, got %+v", result.Metrics)
	}
	if result.Metrics.ReachableVerifiedSegments != 1 {
		t.Fatalf("expected reachable verified count=1, got %+v", result.Metrics)
	}
	if len(result.Metrics.ReachableSegments) != 1 || !result.Metrics.ReachableSegments[0].Verified {
		t.Fatalf("expected verified reachable segment evidence, got %+v", result.Metrics.ReachableSegments)
	}
	if !strings.Contains(strings.ToLower(strings.Join(result.Warnings, " ")), "maxtargets") {
		t.Fatalf("expected maxTargets warning in reachable mode, got %v", result.Warnings)
	}
}

func TestScanReachableSegmentsPartialCollectorWarningAndContinuation(t *testing.T) {
	originalRouteCollector := reachabilityRouteCollector
	originalConnectionCollector := reachabilityConnectionCollector
	originalICMP := reachabilityICMPProbe
	originalTCP := reachabilityTCPPortProbe
	defer func() {
		reachabilityRouteCollector = originalRouteCollector
		reachabilityConnectionCollector = originalConnectionCollector
		reachabilityICMPProbe = originalICMP
		reachabilityTCPPortProbe = originalTCP
	}()

	reachabilityRouteCollector = func() ([]reachabilitySignal, []string) {
		return nil, []string{"reachableSegments: route collector unavailable on test: denied"}
	}
	reachabilityConnectionCollector = func() ([]reachabilitySignal, []string) {
		return []reachabilitySignal{
			{CIDR: "10.60.1.0/24", Source: "active_connections"},
		}, nil
	}
	reachabilityICMPProbe = func(target string, mode ScanMode, timeout time.Duration) (bool, error) {
		return false, nil
	}
	reachabilityTCPPortProbe = func(ctx context.Context, target string, port int, timeout time.Duration) bool {
		return target == "10.60.1.1" && port == 445
	}

	result, err := Scan(context.Background(), Params{
		Target:            "10.255.255.1",
		ReachableSegments: true,
		ScanModes:         []ScanMode{ModeTCPConnect},
		TCPPorts:          []int{65535},
		TimeoutMs:         50,
		Workers:           1,
		MaxTargets:        8,
	})
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if result.Metrics.ReachableCandidateSegments != 1 {
		t.Fatalf("expected reachable candidate count=1 with remaining collector, got %+v", result.Metrics)
	}
	if result.Metrics.ReachableVerifiedSegments != 1 {
		t.Fatalf("expected reachable verified count=1 with remaining collector, got %+v", result.Metrics)
	}
	if !strings.Contains(strings.ToLower(strings.Join(result.Warnings, " ")), "route collector unavailable") {
		t.Fatalf("expected route collector unavailable warning, got %v", result.Warnings)
	}
}

func TestWorkerLoopExitsWhenJobsClosedUnderThrottle(t *testing.T) {
	t.Parallel()

	tuner := newAdaptiveTuner(8, 100)
	tuner.initialize()
	tuner.workerCap.Store(1)

	const total = 6
	jobs := make(chan string, total)
	for i := 0; i < total; i++ {
		jobs <- fmt.Sprintf("192.168.1.%d", i+1)
	}
	close(jobs)

	var (
		wg   sync.WaitGroup
		done atomic.Int64
	)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for workerID := 0; workerID < 8; workerID++ {
		id := workerID
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if err := tuner.waitForWorkerSlot(ctx, id, &done, total); err != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case _, ok := <-jobs:
					if !ok {
						return
					}
					done.Add(1)
				}
			}
		}()
	}

	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
	case <-ctx.Done():
		t.Fatal("worker loop did not exit after jobs channel closed")
	}

	if got := int(done.Load()); got != total {
		t.Fatalf("expected %d processed jobs, got %d", total, got)
	}
}
