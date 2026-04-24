package riskanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HybridAnalysisConfig defines API settings.
type HybridAnalysisConfig struct {
	APIKey    string
	BaseURL   string
	ProxyURL  string
	Timeout   time.Duration
	RateLimit time.Duration
	CacheTTL  time.Duration
	UserAgent string
}

// HybridAnalysisClient queries the Hybrid Analysis API for file hashes.
type HybridAnalysisClient struct {
	apiKey     string
	baseURL    string
	userAgent  string
	httpClient *http.Client
	limiter    *rateLimiter
	cache      *cloudCache
}

// NewHybridAnalysisClient creates a Hybrid Analysis client with caching and rate limiting.
func NewHybridAnalysisClient(cfg HybridAnalysisConfig) (*HybridAnalysisClient, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://hybrid-analysis.com/api/v2"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Falcon"
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	httpClient, err := newCloudHTTPClient(timeout, cfg.ProxyURL)
	if err != nil {
		return nil, err
	}

	return &HybridAnalysisClient{
		apiKey:     cfg.APIKey,
		baseURL:    cfg.BaseURL,
		userAgent:  cfg.UserAgent,
		httpClient: httpClient,
		limiter:    newRateLimiter(cfg.RateLimit),
		cache:      newCloudCache(cfg.CacheTTL),
	}, nil
}

// Query performs a threat intel lookup for a hash.
func (c *HybridAnalysisClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
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

	endpoint := fmt.Sprintf("%s/search/hash?hash=%s", c.baseURL, url.QueryEscape(hash))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	request.Header.Set("api-key", c.apiKey)
	request.Header.Set("user-agent", c.userAgent)
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

	analysis, score := parseHybridSearch(body, hash)
	analysis.CloudQueried = true
	analysis.CloudProvider = "hybrid_analysis"
	c.cache.Set(cacheKey, analysis, score)
	return analysis, score, nil
}

// UploadSample submits a file to Hybrid Analysis and polls for verdict.
func (c *HybridAnalysisClient) UploadSample(ctx context.Context, req CloudUploadRequest) (CloudUploadTask, error) {
	task := CloudUploadTask{
		Provider: "hybrid_analysis",
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

	body, contentType, err := createMultipartFileBody("file", req.FilePath, map[string]string{
		"environment_id": "100",
	})
	if err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	uploadURL := fmt.Sprintf("%s/submit/file", c.baseURL)
	uploadReq, err := http.NewRequestWithContext(submitCtx, http.MethodPost, uploadURL, body)
	if err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	uploadReq.Header.Set("api-key", c.apiKey)
	uploadReq.Header.Set("user-agent", c.userAgent)
	uploadReq.Header.Set("Content-Type", contentType)
	uploadReq.Header.Set("accept", "application/json")

	uploadResp, err := c.httpClient.Do(uploadReq)
	if err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	defer func() { _ = uploadResp.Body.Close() }()

	if uploadResp.StatusCode < 200 || uploadResp.StatusCode >= 300 {
		err := fmt.Errorf("upload failed: %s", uploadResp.Status)
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	bodyBytes, err := io.ReadAll(uploadResp.Body)
	if err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}

	submit := hybridUploadResponse{}
	_ = json.Unmarshal(bodyBytes, &submit)
	taskID := strings.TrimSpace(submit.JobID)
	if taskID == "" {
		taskID = strings.TrimSpace(submit.ID)
	}
	if taskID == "" {
		taskID = strings.TrimSpace(submit.SHA256)
	}
	task.TaskID = taskID
	if taskID == "" {
		task.Status = CloudUploadStatusFailed
		task.Error = "missing upload task id"
		return task, fmt.Errorf("%s", task.Error)
	}
	if submit.SHA256 != "" {
		task.Link = hybridSampleLink(submit.SHA256)
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
		if err := c.limiter.Wait(waitCtx); err != nil {
			task.Status = CloudUploadStatusPending
			task.Error = err.Error()
			return task, nil
		}
		// Prefer polling by task id.
		reportURL := fmt.Sprintf("%s/report/%s/summary", c.baseURL, url.PathEscape(taskID))
		reportReq, err := http.NewRequestWithContext(waitCtx, http.MethodGet, reportURL, nil)
		if err != nil {
			task.Status = CloudUploadStatusFailed
			task.Error = err.Error()
			return task, err
		}
		reportReq.Header.Set("api-key", c.apiKey)
		reportReq.Header.Set("user-agent", c.userAgent)
		reportReq.Header.Set("accept", "application/json")

		reportResp, err := c.httpClient.Do(reportReq)
		if err == nil && reportResp != nil {
			reportBody, readErr := io.ReadAll(reportResp.Body)
			_ = reportResp.Body.Close()
			if readErr != nil {
				task.Status = CloudUploadStatusFailed
				task.Error = readErr.Error()
				return task, readErr
			}
			if reportResp.StatusCode >= 200 && reportResp.StatusCode < 300 {
				analysis, score := parseHybridSearch(reportBody, req.Hashes.Sha256)
				if score > 0 || len(analysis.ThreatLabels) > 0 {
					task.Status = CloudUploadStatusCompleted
					task.Score = score
					if task.Link == "" {
						task.Link = analysis.CloudLink
					}
					return task, nil
				}
			}
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

type hybridSearchResponse struct {
	SHA256s []string         `json:"sha256s"`
	Reports []hybridHAReport `json:"reports"`
}

type hybridHAReport struct {
	Verdict string `json:"verdict"`
	ID      string `json:"id"`
}

func parseHybridSearch(body []byte, fallbackHash string) (CloudAnalysis, float64) {
	var response hybridSearchResponse
	if err := json.Unmarshal(body, &response); err == nil && (len(response.Reports) > 0 || len(response.SHA256s) > 0) {
		hash := fallbackHash
		if len(response.SHA256s) > 0 {
			hash = response.SHA256s[0]
		}
		verdict := ""
		if len(response.Reports) > 0 {
			verdict = strings.TrimSpace(response.Reports[0].Verdict)
		}
		score := hybridVerdictScore(verdict)
		malicious, total, ratio := scoreAsRatio(score)
		labels := appendUnique(nil, verdict)
		return CloudAnalysis{
			Malicious:     malicious,
			TotalEngines:  total,
			DetectionRate: ratio,
			ThreatLabels:  labels,
			CloudLink:     hybridSampleLink(hash),
		}, score
	}

	var list []map[string]any
	if err := json.Unmarshal(body, &list); err == nil && len(list) > 0 {
		item := list[0]
		score := 0.0
		if val, ok := mapFloat(item, "threat_score", "score"); ok {
			score = val
		} else {
			score = hybridVerdictScore(mapString(item, "verdict"))
		}
		labels := appendUnique(nil, mapString(item, "verdict"))
		labels = appendUniqueSlice(labels, mapStringSlice(item, "classification_tags"))
		labels = appendUniqueSlice(labels, mapStringSlice(item, "tags"))
		hash := mapString(item, "sha256", "sha256_hash")
		if hash == "" {
			hash = fallbackHash
		}
		malicious, total, ratio := scoreAsRatio(score)
		return CloudAnalysis{
			Malicious:     malicious,
			TotalEngines:  total,
			DetectionRate: ratio,
			ThreatLabels:  labels,
			CloudLink:     hybridSampleLink(hash),
		}, score
	}

	return CloudAnalysis{}, 0
}

func hybridVerdictScore(verdict string) float64 {
	v := strings.ToLower(strings.TrimSpace(verdict))
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		switch n {
		case 5:
			return 90
		case 4:
			return 70
		case 3:
			return 20
		case 2:
			return 10
		default:
			return 0
		}
	}
	switch v {
	case "malicious":
		return 90
	case "suspicious":
		return 70
	case "no specific threat", "no-specific-threat", "no_specific_threat":
		return 20
	case "clean", "whitelisted", "no verdict", "no_verdict":
		return 0
	default:
		return 0
	}
}

func hybridSampleLink(hash string) string {
	hash = strings.TrimSpace(hash)
	if hash == "" {
		return ""
	}
	return fmt.Sprintf("https://www.hybrid-analysis.com/sample/%s", hash)
}

type hybridUploadResponse struct {
	ID     string `json:"id"`
	JobID  string `json:"job_id"`
	SHA256 string `json:"sha256"`
}
