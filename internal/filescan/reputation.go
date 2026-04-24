package filescan

import "context"

// NoopReputationClient always returns unknown.
type NoopReputationClient struct{}

func (NoopReputationClient) Lookup(ctx context.Context, req ReputationRequest) (ReputationVerdict, error) {
	_ = ctx
	_ = req
	return ReputationUnknown, nil
}
