package filescan

import (
	"context"
	"testing"
	"time"
)

func TestSchedulerPauseResume(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	processed := make(chan ScanTask, 1)
	scheduler := NewScheduler(func(ctx context.Context, task ScanTask) error {
		processed <- task
		return nil
	}, 1)
	scheduler.Start(ctx)

	scheduler.Pause()
	_ = scheduler.Enqueue(ScanTask{Path: "/tmp/a", Source: SourceEvent, Mode: ScanModeSmart})

	select {
	case <-processed:
		t.Fatalf("task should not be processed while paused")
	case <-time.After(50 * time.Millisecond):
	}

	scheduler.Resume()

	select {
	case <-processed:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("task not processed after resume")
	}
}
