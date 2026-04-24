package riskanalysis

import (
	"net/http"
	"testing"
	"time"
)

func TestNewCloudHTTPClientWithProxy(t *testing.T) {
	client, err := newCloudHTTPClient(3*time.Second, "http://127.0.0.1:7890")
	if err != nil {
		t.Fatalf("newCloudHTTPClient error: %v", err)
	}
	if client.Timeout != 3*time.Second {
		t.Fatalf("unexpected timeout: %v", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatalf("new request error: %v", err)
	}
	proxy, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("transport proxy error: %v", err)
	}
	if proxy == nil || proxy.String() != "http://127.0.0.1:7890" {
		t.Fatalf("unexpected proxy url: %v", proxy)
	}
}

func TestNewCloudHTTPClientWithoutProxy(t *testing.T) {
	client, err := newCloudHTTPClient(time.Second, "")
	if err != nil {
		t.Fatalf("newCloudHTTPClient error: %v", err)
	}
	if client.Timeout != time.Second {
		t.Fatalf("unexpected timeout: %v", client.Timeout)
	}
	if client.Transport != nil {
		t.Fatalf("expected nil transport when proxy is empty, got %T", client.Transport)
	}
}

func TestNewCloudHTTPClientInvalidProxy(t *testing.T) {
	if _, err := newCloudHTTPClient(time.Second, "127.0.0.1:7890"); err == nil {
		t.Fatalf("expected invalid proxy error")
	}
}
