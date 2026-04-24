//go:build windows

package startupscan

import (
	"context"
	"testing"
)

type mockWindowsStartupCollector struct{}

func (m *mockWindowsStartupCollector) Collect(ctx context.Context) ([]windowsServiceRecord, error) {
	_ = ctx
	return []windowsServiceRecord{
		{
			Name:      "Spooler",
			Display:   "Print Spooler",
			User:      "LocalSystem",
			State:     4,
			StartType: 2,
		},
	}, nil
}

func TestCollectStartupItemsWithMockWindowsProvider(t *testing.T) {
	origCollector := windowsServiceCollectorProvider
	origPublisher := resolvePublisherFn
	windowsServiceCollectorProvider = func() windowsServiceCollector { return &mockWindowsStartupCollector{} }
	resolvePublisherFn = func(path string) string {
		_ = path
		return "Microsoft Corporation"
	}
	defer func() {
		windowsServiceCollectorProvider = origCollector
		resolvePublisherFn = origPublisher
	}()

	got, err := collectStartupItems(context.Background())
	if err != nil {
		t.Fatalf("collectStartupItems error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].ShowName == nil || *got[0].ShowName != "Print Spooler" {
		t.Fatalf("unexpected showName: %+v", got[0].ShowName)
	}
	if got[0].Publisher == nil || *got[0].Publisher != "Microsoft Corporation" {
		t.Fatalf("unexpected publisher: %+v", got[0].Publisher)
	}
}
