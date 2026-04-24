package filescan

import (
	"context"
	"os"
	"testing"
	"time"
)

type memCache struct {
	entry *CacheEntry
	calls int
}

func (m *memCache) Get(ctx context.Context, path string, modTime time.Time) (*CacheEntry, bool, error) {
	m.calls++
	if m.entry == nil {
		return nil, false, nil
	}
	if m.entry.Path == path && m.entry.LastModified.Equal(modTime) {
		return m.entry, true, nil
	}
	return nil, false, nil
}

func (m *memCache) Put(ctx context.Context, entry CacheEntry) error {
	m.entry = &entry
	return nil
}

func (m *memCache) Close() error { return nil }

type countingSignature struct {
	calls   int
	trusted bool
}

func (c *countingSignature) IsTrusted(ctx context.Context, path string) (bool, error) {
	c.calls++
	return c.trusted, nil
}

type countingReputation struct {
	calls   int
	verdict ReputationVerdict
}

func (c *countingReputation) Lookup(ctx context.Context, req ReputationRequest) (ReputationVerdict, error) {
	c.calls++
	return c.verdict, nil
}

func TestFilter_CacheHitShortCircuit(t *testing.T) {
	tmp := t.TempDir()
	file := tmp + "/sample.txt"
	if err := os.WriteFile(file, []byte("data"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	meta, err := fileMeta(file)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	cache := &memCache{
		entry: &CacheEntry{
			Path:         file,
			Hash:         "hash",
			LastModified: meta.ModifiedTime,
			ScanResult:   ScanResultSafe,
			LastScanTime: time.Now().UTC(),
		},
	}
	signature := &countingSignature{}
	reputation := &countingReputation{}

	engine := &DefaultFilterEngine{
		Cache:      cache,
		Signature:  signature,
		Reputation: reputation,
	}

	decision, err := engine.Filter(context.Background(), ScanTask{Path: file, Source: SourcePath, Mode: ScanModePath})
	if err != nil {
		t.Fatalf("filter error: %v", err)
	}
	if !decision.Final {
		t.Fatalf("expected final decision")
	}
	if signature.calls != 0 || reputation.calls != 0 {
		t.Fatalf("expected cache short-circuit, got signature=%d reputation=%d", signature.calls, reputation.calls)
	}
}

func TestFilter_SignatureShortCircuit(t *testing.T) {
	tmp := t.TempDir()
	file := tmp + "/sample.txt"
	if err := os.WriteFile(file, []byte("data"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cache := &memCache{}
	signature := &countingSignature{trusted: true}
	reputation := &countingReputation{}

	engine := &DefaultFilterEngine{
		Cache:      cache,
		Signature:  signature,
		Reputation: reputation,
	}

	decision, err := engine.Filter(context.Background(), ScanTask{Path: file, Source: SourcePath, Mode: ScanModePath})
	if err != nil {
		t.Fatalf("filter error: %v", err)
	}
	if !decision.Final {
		t.Fatalf("expected final decision")
	}
	if reputation.calls != 0 {
		t.Fatalf("expected reputation not called")
	}
}
