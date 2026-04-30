package benchmark

import "testing"

func TestBenchmarkRangedProgress(t *testing.T) {
	t.Parallel()

	if got := benchmarkRangedProgress(22, 86, 0, 68); got != 22 {
		t.Fatalf("expected zero progress to stay at range start, got %d", got)
	}
	if got := benchmarkRangedProgress(22, 86, 68, 68); got != 86 {
		t.Fatalf("expected completed progress to reach range end, got %d", got)
	}
	got := benchmarkRangedProgress(22, 86, 34, 68)
	if got <= 22 || got >= 86 {
		t.Fatalf("expected midpoint progress inside range, got %d", got)
	}
}
