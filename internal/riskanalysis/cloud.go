package riskanalysis

import (
	"context"
	"time"
)

// CloudClient queries threat intel services.
type CloudClient interface {
	Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error)
}

// CloudUploadRequest defines parameters for cloud sample upload.
type CloudUploadRequest struct {
	FilePath      string
	Hashes        Hashes
	SubmitTimeout time.Duration
	WaitTimeout   time.Duration
	PollInterval  time.Duration
	Concurrency   int
}

// CloudUploadTask captures upload execution details for one provider.
type CloudUploadTask struct {
	Provider string  `json:"provider"`
	TaskID   string  `json:"task_id,omitempty"`
	Status   string  `json:"status"`
	Score    float64 `json:"score,omitempty"`
	Link     string  `json:"link,omitempty"`
	Error    string  `json:"error,omitempty"`
}

const (
	CloudUploadStatusCompleted = "completed"
	CloudUploadStatusPending   = "pending"
	CloudUploadStatusSkipped   = "skipped"
	CloudUploadStatusFailed    = "failed"
)

// CloudUploadClient can submit files to cloud providers.
// CloudClient implementations may optionally implement this interface.
type CloudUploadClient interface {
	Upload(ctx context.Context, req CloudUploadRequest) ([]CloudUploadTask, error)
}

type providerUploadClient interface {
	UploadSample(ctx context.Context, req CloudUploadRequest) (CloudUploadTask, error)
}
