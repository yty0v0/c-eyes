package riskanalysis

import (
	"context"
	"errors"
	"testing"
)

type stubCloudProvider struct {
	calls    *int
	analysis CloudAnalysis
	score    float64
	err      error
}

func (s stubCloudProvider) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	if s.calls != nil {
		*s.calls++
	}
	return s.analysis, s.score, s.err
}

func TestShouldDisableProviderAfterError(t *testing.T) {
	t.Parallel()

	if !shouldDisableProviderAfterError(errors.New("cloud api key is required")) {
		t.Fatal("expected missing-key error to disable provider")
	}
	if !shouldDisableProviderAfterError(errors.New("cloud query failed: 401 Unauthorized")) {
		t.Fatal("expected unauthorized error to disable provider")
	}
	if shouldDisableProviderAfterError(errors.New("context deadline exceeded")) {
		t.Fatal("did not expect timeout error to disable provider")
	}
}

func TestSelectProvidersSkipsDisabled(t *testing.T) {
	t.Parallel()

	client := &MultiCloudClient{
		Providers: []CloudProviderClient{
			{Name: "otx"},
			{Name: "virustotal"},
		},
	}
	client.disableProvider("otx", "unauthorized")

	chosen := client.selectProviders([]string{"otx", "virustotal"})
	if len(chosen) != 1 {
		t.Fatalf("expected 1 provider after disable, got %d", len(chosen))
	}
	if NormalizeProvider(chosen[0].Name) != "virustotal" {
		t.Fatalf("expected virustotal, got %s", chosen[0].Name)
	}
}

func TestQueryWithProvidersDisablesAuthFailureProvider(t *testing.T) {
	t.Parallel()

	otxCalls := 0
	vtCalls := 0
	client := &MultiCloudClient{
		Providers: []CloudProviderClient{
			{
				Name: "otx",
				Client: stubCloudProvider{
					calls: &otxCalls,
					err:   errors.New("cloud api key is required"),
				},
			},
			{
				Name: "virustotal",
				Client: stubCloudProvider{
					calls: &vtCalls,
					analysis: CloudAnalysis{
						CloudQueried: true,
					},
					score: 30,
				},
			},
		},
	}

	_, _, err := client.queryWithProviders(context.Background(), Hashes{Sha256: "abc"}, []string{"otx", "virustotal"})
	if err != nil {
		t.Fatalf("queryWithProviders returned error: %v", err)
	}
	if otxCalls != 1 || vtCalls != 1 {
		t.Fatalf("expected first call to hit both providers, otx=%d vt=%d", otxCalls, vtCalls)
	}

	_, _, err = client.queryWithProviders(context.Background(), Hashes{Sha256: "def"}, []string{"otx", "virustotal"})
	if err != nil {
		t.Fatalf("queryWithProviders returned error: %v", err)
	}
	if otxCalls != 1 {
		t.Fatalf("expected disabled otx not called again, got %d calls", otxCalls)
	}
	if vtCalls != 2 {
		t.Fatalf("expected virustotal called twice, got %d", vtCalls)
	}
}
