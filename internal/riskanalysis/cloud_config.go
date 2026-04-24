package riskanalysis

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CloudConfigFile defines cloud provider credentials loaded from disk.
// The config file is optional and intended to live next to the executable.
type CloudConfigFile struct {
	Provider  string                         `json:"provider"`
	APIKey    string                         `json:"api_key,omitempty"`
	BaseURL   string                         `json:"base_url,omitempty"`
	ProxyURL  string                         `json:"proxy_url,omitempty"`
	RateLimit string                         `json:"rate_limit,omitempty"`
	Timeout   string                         `json:"timeout,omitempty"`
	CacheTTL  string                         `json:"cache_ttl,omitempty"`
	Providers map[string]CloudProviderConfig `json:"providers,omitempty"`
}

// CloudProviderConfig holds per-provider API settings.
type CloudProviderConfig struct {
	APIKey          string `json:"api_key,omitempty"`
	BaseURL         string `json:"base_url,omitempty"`
	ProxyURL        string `json:"proxy_url,omitempty"`
	RateLimit       string `json:"rate_limit,omitempty"`
	Timeout         string `json:"timeout,omitempty"`
	CacheTTL        string `json:"cache_ttl,omitempty"`
	UploadEnabled   *bool  `json:"upload_enabled,omitempty"`
	UploadRateLimit string `json:"upload_rate_limit,omitempty"`
}

// LoadCloudConfig loads cloud config from disk if present.
// Search order:
// 1) C_EYES_CLOUD_CONFIG
// 2) <exe-dir>/c-eyes-cloud.json
// 3) ./c-eyes-cloud.json
// 4) ~/.c-eyes/cloud.json
func LoadCloudConfig() (*CloudConfigFile, string, error) {
	path := cloudConfigPath()
	if path == "" {
		return nil, "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}
	data = bytesTrimBOM(data)
	var cfg CloudConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, path, fmt.Errorf("cloud config parse failed: %w", err)
	}
	return &cfg, path, nil
}

// SelectedProvider returns the provider name and resolved config.
func (cfg *CloudConfigFile) SelectedProvider() (string, CloudProviderConfig) {
	if cfg == nil {
		return "", CloudProviderConfig{}
	}
	provider := normalizeProvider(cfg.Provider)
	if provider == "" {
		// If user didn't specify and there's only one provider, use it.
		if len(cfg.Providers) == 1 {
			for key := range cfg.Providers {
				provider = normalizeProvider(key)
			}
		}
	}
	if provider == "" {
		provider = "virustotal"
	}

	if len(cfg.Providers) > 0 {
		for key, val := range cfg.Providers {
			if normalizeProvider(key) == provider {
				return provider, val
			}
		}
	}

	return provider, CloudProviderConfig{
		APIKey:    cfg.APIKey,
		BaseURL:   cfg.BaseURL,
		ProxyURL:  cfg.ProxyURL,
		RateLimit: cfg.RateLimit,
		Timeout:   cfg.Timeout,
		CacheTTL:  cfg.CacheTTL,
	}
}

// ResolveProvider returns the provider name and config for a specific provider override.
func (cfg *CloudConfigFile) ResolveProvider(name string) (string, CloudProviderConfig) {
	if cfg == nil {
		return normalizeProvider(name), CloudProviderConfig{}
	}
	provider := normalizeProvider(name)
	if provider == "" {
		return cfg.SelectedProvider()
	}
	if len(cfg.Providers) > 0 {
		for key, val := range cfg.Providers {
			if normalizeProvider(key) == provider {
				return provider, val
			}
		}
	}
	return provider, CloudProviderConfig{
		APIKey:    cfg.APIKey,
		BaseURL:   cfg.BaseURL,
		ProxyURL:  cfg.ProxyURL,
		RateLimit: cfg.RateLimit,
		Timeout:   cfg.Timeout,
		CacheTTL:  cfg.CacheTTL,
	}
}

// NormalizeProvider normalizes a cloud provider name.
func NormalizeProvider(name string) string {
	return normalizeProvider(name)
}

func (cfg CloudProviderConfig) RateLimitDuration() (time.Duration, error) {
	return parseDurationField(cfg.RateLimit)
}

func (cfg CloudProviderConfig) TimeoutDuration() (time.Duration, error) {
	return parseDurationField(cfg.Timeout)
}

func (cfg CloudProviderConfig) CacheTTLDuration() (time.Duration, error) {
	return parseDurationField(cfg.CacheTTL)
}

func (cfg CloudProviderConfig) UploadRateLimitDuration() (time.Duration, error) {
	return parseDurationField(cfg.UploadRateLimit)
}

// UploadEnabledOrDefault resolves provider upload policy.
// Defaults:
// - virustotal/triage/hybrid_analysis: enabled
// - malwarebazaar/otx and others: disabled
func (cfg CloudProviderConfig) UploadEnabledOrDefault(provider string) bool {
	if cfg.UploadEnabled != nil {
		return *cfg.UploadEnabled
	}
	switch NormalizeProvider(provider) {
	case "virustotal", "triage", "hybrid_analysis":
		return true
	default:
		return false
	}
}

func parseDurationField(val string) (time.Duration, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0, nil
	}
	parsed, err := time.ParseDuration(val)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func cloudConfigPath() string {
	if path := strings.TrimSpace(os.Getenv("C_EYES_CLOUD_CONFIG")); path != "" {
		if fileExists(path) {
			return path
		}
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidate := filepath.Join(exeDir, "c-eyes-cloud.json")
		if fileExists(candidate) {
			return candidate
		}
	}

	if fileExists("c-eyes-cloud.json") {
		return "c-eyes-cloud.json"
	}

	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, ".c-eyes", "cloud.json")
		if fileExists(candidate) {
			return candidate
		}
	}

	return ""
}

func normalizeProvider(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "vt", "virustotal", "virus-total":
		return "virustotal"
	case "otx", "alienvault", "alienvault-otx":
		return "otx"
	case "malwarebazaar", "malware-bazaar", "bazaar":
		return "malwarebazaar"
	case "hybridanalysis", "hybrid-analysis", "falcon-sandbox":
		return "hybrid_analysis"
	case "anyrun", "any-run":
		return "anyrun"
	case "triage", "hatching", "hatching-triage":
		return "triage"
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func bytesTrimBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}

var ErrUnsupportedProvider = errors.New("cloud provider not supported")
