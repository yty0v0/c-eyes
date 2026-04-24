package filescan

import (
	"context"
	"errors"
	"sync/atomic"
)

// Scheduler processes scan tasks with pause/resume support.
type Scheduler struct {
	queue    chan ScanTask
	paused   atomic.Bool
	resumeCh chan struct{}
	worker   func(context.Context, ScanTask) error
}

func NewScheduler(worker func(context.Context, ScanTask) error, buffer int) *Scheduler {
	if buffer <= 0 {
		buffer = 32
	}
	return &Scheduler{
		queue:    make(chan ScanTask, buffer),
		resumeCh: make(chan struct{}, 1),
		worker:   worker,
	}
}

func (s *Scheduler) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *Scheduler) Enqueue(task ScanTask) error {
	if s == nil {
		return errors.New("scheduler is nil")
	}
	s.queue <- task
	return nil
}

func (s *Scheduler) Pause() {
	if s == nil {
		return
	}
	s.paused.Store(true)
}

func (s *Scheduler) Resume() {
	if s == nil {
		return
	}
	if s.paused.Swap(false) {
		select {
		case s.resumeCh <- struct{}{}:
		default:
		}
	}
}

func (s *Scheduler) loop(ctx context.Context) {
	for {
		if s.paused.Load() {
			select {
			case <-s.resumeCh:
			case <-ctx.Done():
				return
			}
			continue
		}

		select {
		case task := <-s.queue:
			if s.worker != nil {
				_ = s.worker(ctx, task)
			}
		case <-ctx.Done():
			return
		case <-s.resumeCh:
		}
	}
}
