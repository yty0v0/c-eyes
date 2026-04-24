package filescan

import (
	"context"
	"time"
)

// TargetCollector collects scan candidates for smart scan.
type TargetCollector interface {
	Collect(ctx context.Context, params FileScanParams) ([]ScanTask, error)
}

// FilterDecision is the output of the filter engine.
type FilterDecision struct {
	Result FileScanResult
	Final  bool
}

// FilterEngine performs cache/signature/reputation checks.
type FilterEngine interface {
	Filter(ctx context.Context, task ScanTask) (FilterDecision, error)
}

// DeepScanResult is the output of deep scanning.
type DeepScanResult struct {
	Result ScanResult
}

// DeepScanner performs deep content inspection.
type DeepScanner interface {
	Scan(ctx context.Context, task ScanTask) (DeepScanResult, error)
}

// ResultReporter persists cache updates and returns final output.
type ResultReporter interface {
	Report(ctx context.Context, result FileScanResult) (FileScanResult, error)
}

// CacheEntry represents a cache row.
type CacheEntry struct {
	Path         string
	Hash         string
	LastModified time.Time
	ScanResult   ScanResult
	LastScanTime time.Time
}

// CacheStore provides local cache lookups.
type CacheStore interface {
	Get(ctx context.Context, path string, modTime time.Time) (*CacheEntry, bool, error)
	Put(ctx context.Context, entry CacheEntry) error
	Close() error
}

// ReputationVerdict indicates cloud reputation.
type ReputationVerdict int

const (
	ReputationUnknown ReputationVerdict = iota
	ReputationSafe
	ReputationMalicious
)

// ReputationRequest is the query input to reputation checks.
type ReputationRequest struct {
	Path    string
	HashMd5 string
	HashSha string
}

// ReputationClient queries cloud reputation.
type ReputationClient interface {
	Lookup(ctx context.Context, req ReputationRequest) (ReputationVerdict, error)
}

// SignatureVerifier validates trusted signatures.
type SignatureVerifier interface {
	IsTrusted(ctx context.Context, path string) (bool, error)
}
