package riskanalysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func pickHash(hashes Hashes) (string, string) {
	if hashes.Sha256 != "" {
		return hashes.Sha256, "sha256"
	}
	if hashes.Sha1 != "" {
		return hashes.Sha1, "sha1"
	}
	if hashes.Md5 != "" {
		return hashes.Md5, "md5"
	}
	return "", ""
}

func appendUnique(dst []string, values ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[strings.ToLower(v)] = struct{}{}
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		key := strings.ToLower(v)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, v)
	}
	return dst
}

func appendUniqueSlice(dst []string, values []string) []string {
	return appendUnique(dst, values...)
}

func scoreAsRatio(score float64) (int, int, string) {
	score = ClampScore(score)
	malicious := int(math.Round(score))
	total := 100
	return malicious, total, fmt.Sprintf("%d/%d", malicious, total)
}

func stringFromAny(val any) (string, bool) {
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v), v != ""
	case json.Number:
		return v.String(), true
	case float64:
		return fmt.Sprintf("%.0f", v), true
	case fmt.Stringer:
		return v.String(), true
	default:
		return "", false
	}
}

func floatFromAny(val any) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f, true
		}
	case string:
		if f, err := json.Number(strings.TrimSpace(v)).Float64(); err == nil {
			return f, true
		}
	}
	return 0, false
}

func intFromAny(val any) (int, bool) {
	if f, ok := floatFromAny(val); ok {
		return int(f), true
	}
	return 0, false
}

func mapString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if s, ok := stringFromAny(val); ok {
				return s
			}
		}
	}
	return ""
}

func mapFloat(m map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if f, ok := floatFromAny(val); ok {
				return f, true
			}
		}
	}
	return 0, false
}

func mapStringSlice(m map[string]any, keys ...string) []string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if list := stringSliceFromAny(val); len(list) > 0 {
				return list
			}
		}
	}
	return nil
}

func stringSliceFromAny(val any) []string {
	switch v := val.(type) {
	case []string:
		return append([]string{}, v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := stringFromAny(item); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func mapFromAny(val any) (map[string]any, bool) {
	if m, ok := val.(map[string]any); ok {
		return m, true
	}
	return nil, false
}

func newCloudHTTPClient(timeout time.Duration, proxyURL string) (*http.Client, error) {
	client := &http.Client{
		Timeout: timeout,
	}
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return client, nil
	}
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy_url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid proxy_url: scheme and host are required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(parsed)
	client.Transport = transport
	return client, nil
}

func createMultipartFileBody(fieldName, filePath string, extra map[string]string) (*bytes.Buffer, string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = file.Close() }()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile(fieldName, filepath.Base(filePath))
	if err != nil {
		return nil, "", err
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, "", err
	}
	for key, val := range extra {
		if strings.TrimSpace(key) == "" {
			continue
		}
		_ = writer.WriteField(key, val)
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return body, writer.FormDataContentType(), nil
}
