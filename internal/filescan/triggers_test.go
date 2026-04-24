package filescan

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type fakeIdleDetector struct {
	value atomic.Value
}

func newFakeIdleDetector(initial time.Duration) *fakeIdleDetector {
	d := &fakeIdleDetector{}
	d.value.Store(initial)
	return d
}

func (f *fakeIdleDetector) IdleFor() (time.Duration, error) {
	return f.value.Load().(time.Duration), nil
}

func (f *fakeIdleDetector) set(val time.Duration) {
	f.value.Store(val)
}

func TestIdleTriggerTransitions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	detector := newFakeIdleDetector(0)
	idleCh := make(chan struct{}, 1)
	activeCh := make(chan struct{}, 1)

	trigger := &IdleTrigger{
		Detector:     detector,
		Threshold:    50 * time.Millisecond,
		PollInterval: 10 * time.Millisecond,
		OnIdle:       func() { idleCh <- struct{}{} },
		OnActive:     func() { activeCh <- struct{}{} },
	}
	trigger.Start(ctx)

	detector.set(80 * time.Millisecond)
	select {
	case <-idleCh:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected idle transition")
	}

	detector.set(0)
	select {
	case <-activeCh:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected active transition")
	}
}
