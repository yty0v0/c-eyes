package filescan

import (
	"context"
	"time"
)

// IdleDetector reports how long the system has been idle.
type IdleDetector interface {
	IdleFor() (time.Duration, error)
}

// IdleTrigger pauses/resumes scanning based on user activity.
type IdleTrigger struct {
	Detector     IdleDetector
	Threshold    time.Duration
	PollInterval time.Duration
	OnIdle       func()
	OnActive     func()
}

func (t *IdleTrigger) Start(ctx context.Context) {
	go t.loop(ctx)
}

func (t *IdleTrigger) loop(ctx context.Context) {
	if t.Detector == nil {
		return
	}
	threshold := t.Threshold
	if threshold <= 0 {
		threshold = 5 * time.Minute
	}
	interval := t.PollInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	idle := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			duration, err := t.Detector.IdleFor()
			if err != nil {
				continue
			}
			if duration >= threshold {
				if !idle {
					idle = true
					if t.OnIdle != nil {
						t.OnIdle()
					}
				}
			} else if idle {
				idle = false
				if t.OnActive != nil {
					t.OnActive()
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// EventTrigger forwards driver-pushed tasks.
type EventTrigger struct {
	handler func(ScanTask)
}

func NewEventTrigger(handler func(ScanTask)) *EventTrigger {
	return &EventTrigger{handler: handler}
}

func (t *EventTrigger) Push(task ScanTask) {
	if t == nil || t.handler == nil {
		return
	}
	t.handler(task)
}
