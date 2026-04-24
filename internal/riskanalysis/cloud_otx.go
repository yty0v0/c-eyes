package riskanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OTXConfig defines API settings.
type OTXConfig struct {
	APIKey    string
	BaseURL   string
	ProxyURL  string
	Timeout   time.Duration
	RateLimit time.Duration
	CacheTTL  time.Duration
}

// OTXClient queries the AlienVault OTX API for file hashes.
type OTXClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	limiter    *rateLimiter
	cache      *cloudCache
}

// NewOTXClient creates an OTX client with caching and rate limiting.
func NewOTXClient(cfg OTXConfig) (*OTXClient, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://otx.alienvault.com"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	httpClient, err := newCloudHTTPClient(timeout, cfg.ProxyURL)
	if err != nil {
		return nil, err
	}

	return &OTXClient{
		apiKey:     cfg.APIKey,
		baseURL:    cfg.BaseURL,
		httpClient: httpClient,
		limiter:    newRateLimiter(cfg.RateLimit),
		cache:      newCloudCache(cfg.CacheTTL),
	}, nil
}

// Query performs a threat intel lookup for a hash.
func (c *OTXClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	if c == nil {
		return CloudAnalysis{CloudQueried: false}, 0, fmt.Errorf("cloud client is nil")
	}
	hash, kind := pickHash(hashes)
	if hash == "" {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}
	if c.apiKey == "" {
		return CloudAnalysis{CloudQueried: false}, 0, fmt.Errorf("cloud api key is required")
	}

	cacheKey := fmt.Sprintf("%s:%s", kind, hash)
	if analysis, score, ok := c.cache.Get(cacheKey); ok {
		return analysis, score, nil
	}

	if err := c.limiter.Wait(ctx); err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}

	endpoint := fmt.Sprintf("%s/api/v1/indicators/file/%s/general", c.baseURL, url.PathEscape(hash))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	request.Header.Set("X-OTX-API-KEY", c.apiKey)
	request.Header.Set("accept", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return CloudAnalysis{CloudQueried: false}, 0, fmt.Errorf("cloud query failed: %s", response.Status)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}

	analysis, score := parseOTX(body, hash)
	analysis.CloudQueried = true
	analysis.CloudProvider = "otx"
	c.cache.Set(cacheKey, analysis, score)
	return analysis, score, nil
}

type otxResponse struct {
	PulseInfo struct {
		Count  int        `json:"count"`
		Pulses []otxPulse `json:"pulses"`
	} `json:"pulse_info"`
}

type otxPulse struct {
	Name       string   `json:"name"`
	Tags       []string `json:"tags"`
	AuthorName string   `json:"author_name"`
	Author     string   `json:"author"`
}

func parseOTX(body []byte, hash string) (CloudAnalysis, float64) {
	var payload otxResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return CloudAnalysis{}, 0
	}
	score := otxPulseScore(payload.PulseInfo.Count, payload.PulseInfo.Pulses)
	malicious, total, ratio := scoreAsRatio(score)

	labels := []string{}
	for _, pulse := range payload.PulseInfo.Pulses {
		labels = appendUnique(labels, pulse.Name)
		labels = appendUniqueSlice(labels, pulse.Tags)
	}

	return CloudAnalysis{
		Malicious:     malicious,
		TotalEngines:  total,
		DetectionRate: ratio,
		ThreatLabels:  labels,
		CloudLink:     otxLink(hash),
	}, score
}

func otxPulseScore(count int, pulses []otxPulse) float64 {
	if count <= 0 {
		return 0
	}
	var score float64
	switch {
	case count == 1:
		score = 20
	case count == 2:
		score = 30
	case count <= 4:
		score = 40
	case count <= 8:
		score = 50
	default:
		score = 60
	}
	if otxHasTrustedAuthor(pulses) {
		score += 15
	}
	if score > 80 {
		score = 80
	}
	return score
}

func otxHasTrustedAuthor(pulses []otxPulse) bool {
	for _, pulse := range pulses {
		author := strings.ToLower(strings.TrimSpace(pulse.AuthorName))
		if author == "" {
			author = strings.ToLower(strings.TrimSpace(pulse.Author))
		}
		if author == "" {
			continue
		}
		if strings.Contains(author, "alien labs") || strings.Contains(author, "alienvault") || strings.Contains(author, "alien vault") {
			return true
		}
	}
	return false
}

func otxLink(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return ""
	}
	return fmt.Sprintf("https://otx.alienvault.com/indicator/file/%s", hash)
}
