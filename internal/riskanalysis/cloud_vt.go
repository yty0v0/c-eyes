package riskanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VirusTotalConfig defines API settings.
type VirusTotalConfig struct {
	APIKey              string
	BaseURL             string
	ProxyURL            string
	Timeout             time.Duration
	RateLimit           time.Duration
	CacheTTL            time.Duration
	TokenBucketCapacity int
	TokenBucketWindow   time.Duration
}

// VirusTotalClient queries the VirusTotal API for file hashes.
type VirusTotalClient struct {
	apiKey      string
	baseURL     string
	httpClient  *http.Client
	limiter     *rateLimiter
	tokenBucket *tokenBucketLimiter
	cache       *cloudCache
}

// NewVirusTotalClient creates a VirusTotal client with caching and rate limiting.
func NewVirusTotalClient(cfg VirusTotalConfig) (*VirusTotalClient, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://www.virustotal.com"
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
	capacity := cfg.TokenBucketCapacity
	if capacity <= 0 {
		capacity = 4
	}
	window := cfg.TokenBucketWindow
	if window <= 0 {
		window = time.Minute
	}

	return &VirusTotalClient{
		apiKey:      cfg.APIKey,
		baseURL:     cfg.BaseURL,
		httpClient:  httpClient,
		limiter:     newRateLimiter(cfg.RateLimit),
		tokenBucket: newTokenBucketLimiter(capacity, window),
		cache:       newCloudCache(cfg.CacheTTL),
	}, nil
}

// Query performs a threat intel lookup for a hash.
func (c *VirusTotalClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	if c == nil {
		return CloudAnalysis{CloudQueried: false}, 0, fmt.Errorf("cloud client is nil")
	}
	if hashes.Sha256 == "" {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}
	if c.apiKey == "" {
		return CloudAnalysis{CloudQueried: false}, 0, fmt.Errorf("cloud api key is required")
	}

	if analysis, score, ok := c.cache.Get(hashes.Sha256); ok {
		return analysis, score, nil
	}

	if err := c.limiter.Wait(ctx); err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	if !c.tokenBucket.TryTake() {
		return CloudAnalysis{CloudQueried: false}, 0, ErrRateLimited
	}

	url := fmt.Sprintf("%s/api/v3/files/%s", c.baseURL, hashes.Sha256)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	request.Header.Set("x-apikey", c.apiKey)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return CloudAnalysis{CloudQueried: false}, 0, fmt.Errorf("cloud query failed: %s", response.Status)
	}

	var payload vtResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}

	analysis, score := payload.toAnalysisAndScore(hashes.Sha256, c.baseURL)
	analysis.CloudProvider = "virustotal"
	c.cache.Set(hashes.Sha256, analysis, score)
	return analysis, score, nil
}

// UploadSample submits a file to VirusTotal and polls for analysis.
func (c *VirusTotalClient) UploadSample(ctx context.Context, req CloudUploadRequest) (CloudUploadTask, error) {
	task := CloudUploadTask{
		Provider: "virustotal",
		Status:   CloudUploadStatusPending,
	}
	if c == nil {
		task.Status = CloudUploadStatusFailed
		task.Error = "cloud client is nil"
		return task, fmt.Errorf("%s", task.Error)
	}
	if c.apiKey == "" {
		task.Status = CloudUploadStatusSkipped
		task.Error = "cloud api key is required"
		return task, nil
	}
	if strings.TrimSpace(req.FilePath) == "" {
		task.Status = CloudUploadStatusSkipped
		task.Error = "empty file path"
		return task, nil
	}

	if err := c.limiter.Wait(ctx); err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}

	submitCtx := ctx
	if req.SubmitTimeout > 0 {
		var cancel context.CancelFunc
		submitCtx, cancel = context.WithTimeout(ctx, req.SubmitTimeout)
		defer cancel()
	}

	body, contentType, err := createMultipartFileBody("file", req.FilePath, nil)
	if err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	uploadURL := fmt.Sprintf("%s/api/v3/files", c.baseURL)
	request, err := http.NewRequestWithContext(submitCtx, http.MethodPost, uploadURL, body)
	if err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	request.Header.Set("x-apikey", c.apiKey)
	request.Header.Set("Content-Type", contentType)

	response, err := c.httpClient.Do(request)
	if err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := fmt.Errorf("upload failed: %s", response.Status)
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}

	var payload vtUploadResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	taskID := strings.TrimSpace(payload.Data.ID)
	task.TaskID = taskID
	if taskID == "" {
		task.Status = CloudUploadStatusFailed
		task.Error = "missing upload task id"
		return task, fmt.Errorf("%s", task.Error)
	}
	if req.WaitTimeout <= 0 {
		return task, nil
	}

	waitCtx, cancelWait := context.WithTimeout(ctx, req.WaitTimeout)
	defer cancelWait()
	pollEvery := req.PollInterval
	if pollEvery <= 0 {
		pollEvery = 5 * time.Second
	}
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	for {
		pollReq, err := http.NewRequestWithContext(waitCtx, http.MethodGet, fmt.Sprintf("%s/api/v3/analyses/%s", c.baseURL, url.PathEscape(taskID)), nil)
		if err != nil {
			task.Status = CloudUploadStatusFailed
			task.Error = err.Error()
			return task, err
		}
		pollReq.Header.Set("x-apikey", c.apiKey)
		pollResp, err := c.httpClient.Do(pollReq)
		if err != nil {
			if waitCtx.Err() != nil {
				task.Status = CloudUploadStatusPending
				task.Error = waitCtx.Err().Error()
				return task, nil
			}
			task.Status = CloudUploadStatusFailed
			task.Error = err.Error()
			return task, err
		}

		var analysisPayload vtUploadAnalysisResponse
		decodeErr := json.NewDecoder(pollResp.Body).Decode(&analysisPayload)
		_ = pollResp.Body.Close()
		if decodeErr != nil {
			task.Status = CloudUploadStatusFailed
			task.Error = decodeErr.Error()
			return task, decodeErr
		}
		if pollResp.StatusCode < 200 || pollResp.StatusCode >= 300 {
			err := fmt.Errorf("upload poll failed: %s", pollResp.Status)
			task.Status = CloudUploadStatusFailed
			task.Error = err.Error()
			return task, err
		}

		status := strings.ToLower(strings.TrimSpace(analysisPayload.Data.Attributes.Status))
		if status == "completed" {
			task.Status = CloudUploadStatusCompleted
			stats := analysisPayload.Data.Attributes.Stats
			total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected
			if total > 0 {
				task.Score = ClampScore((float64(stats.Malicious)/float64(total))*100 + math.Min(float64(stats.Suspicious)*2, 10))
			}
			if req.Hashes.Sha256 != "" {
				task.Link = fmt.Sprintf("%s/gui/file/%s/detection", strings.TrimRight(c.baseURL, "/"), req.Hashes.Sha256)
			}
			return task, nil
		}

		select {
		case <-waitCtx.Done():
			task.Status = CloudUploadStatusPending
			task.Error = waitCtx.Err().Error()
			return task, nil
		case <-ticker.C:
		}
	}
}

type vtResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious        int `json:"malicious"`
				Suspicious       int `json:"suspicious"`
				Harmless         int `json:"harmless"`
				Undetected       int `json:"undetected"`
				Timeout          int `json:"timeout"`
				Failure          int `json:"failure"`
				TypeUnsupported  int `json:"type-unsupported"`
				ConfirmedTimeout int `json:"confirmed-timeout"`
			} `json:"last_analysis_stats"`
			LastAnalysisResults         map[string]vtEngineResult `json:"last_analysis_results"`
			PopularThreatClassification struct {
				SuggestedThreatLabel string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`
			Tags []string `json:"tags"`
		} `json:"attributes"`
	} `json:"data"`
}

type vtUploadResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

type vtUploadAnalysisResponse struct {
	Data struct {
		Attributes struct {
			Status string `json:"status"`
			Stats  struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"stats"`
		} `json:"attributes"`
	} `json:"data"`
}

type vtEngineResult struct {
	Category string `json:"category"`
	Result   string `json:"result"`
}

func (r vtResponse) toAnalysisAndScore(sha256, baseURL string) (CloudAnalysis, float64) {
	stats := r.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected + stats.Timeout + stats.Failure + stats.TypeUnsupported + stats.ConfirmedTimeout
	linkBase := strings.TrimRight(baseURL, "/")
	analysis := CloudAnalysis{
		CloudQueried:  true,
		Malicious:     stats.Malicious,
		TotalEngines:  total,
		DetectionRate: fmt.Sprintf("%d/%d", stats.Malicious, total),
		ThreatLabels:  []string{},
		CloudLink:     fmt.Sprintf("%s/gui/file/%s/detection", linkBase, sha256),
	}
	label := strings.TrimSpace(r.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel)
	if label != "" {
		analysis.ThreatLabels = append(analysis.ThreatLabels, label)
	}
	if len(r.Data.Attributes.Tags) > 0 {
		analysis.ThreatLabels = append(analysis.ThreatLabels, r.Data.Attributes.Tags...)
	}
	baseScore := CloudScoreFromAnalysis(analysis)
	suspiciousBonus := math.Min(12, float64(stats.Suspicious)*2)
	score := ClampScore(baseScore + suspiciousBonus + vtMajorEngineBonus(r.Data.Attributes.LastAnalysisResults))
	return analysis, score
}

func vtMajorEngineBonus(results map[string]vtEngineResult) float64 {
	if len(results) == 0 {
		return 0
	}
	majorEngines := []string{
		"microsoft",
		"kaspersky",
		"bitdefender",
		"eset",
		"sophos",
		"trendmicro",
		"symantec",
		"avast",
		"crowdstrike",
	}
	hits := 0
	for engine, res := range results {
		if !isVTMaliciousCategory(res.Category) {
			continue
		}
		engineLower := strings.ToLower(strings.TrimSpace(engine))
		for _, major := range majorEngines {
			if strings.Contains(engineLower, major) {
				hits++
				break
			}
		}
	}
	// Reward detections from major vendors, but keep the bonus bounded.
	return math.Min(float64(hits)*4, 16)
}

func isVTMaliciousCategory(category string) bool {
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "malicious", "suspicious":
		return true
	default:
		return false
	}
}
