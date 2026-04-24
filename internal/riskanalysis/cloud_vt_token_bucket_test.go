package riskanalysis

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVirusTotalTokenBucketExhaustionNoBlock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {
				"attributes": {
					"last_analysis_stats": {
						"malicious": 0,
						"suspicious": 0,
						"harmless": 1,
						"undetected": 9,
						"timeout": 0,
						"failure": 0,
						"type-unsupported": 0,
						"confirmed-timeout": 0
					}
				}
			}
		}`))
	}))
	defer server.Close()

	client, err := NewVirusTotalClient(VirusTotalConfig{
		APIKey:              "test-key",
		BaseURL:             server.URL,
		Timeout:             2 * time.Second,
		TokenBucketCapacity: 1,
		TokenBucketWindow:   time.Hour,
	})
	if err != nil {
		t.Fatalf("NewVirusTotalClient error: %v", err)
	}

	_, _, err = client.Query(context.Background(), Hashes{
		Sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatalf("first query should succeed, got %v", err)
	}

	start := time.Now()
	_, _, err = client.Query(context.Background(), Hashes{
		Sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected ErrRateLimited, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("expected token bucket reject without blocking, elapsed=%v", elapsed)
	}
}
