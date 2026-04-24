package filescan

import "context"

// StubDeepScanner is a placeholder deep scanner.
type StubDeepScanner struct{}

func (StubDeepScanner) Scan(ctx context.Context, task ScanTask) (DeepScanResult, error) {
	_ = ctx
	_ = task
	return DeepScanResult{
		Result: ScanResultUnknown,
	}, nil
}

// ThrottledDeepScanner applies resource throttling before scanning.
type ThrottledDeepScanner struct {
	Inner DeepScanner
}

func (t ThrottledDeepScanner) Scan(ctx context.Context, task ScanTask) (DeepScanResult, error) {
	applyThrottling()
	if t.Inner == nil {
		return StubDeepScanner{}.Scan(ctx, task)
	}
	return t.Inner.Scan(ctx, task)
}
