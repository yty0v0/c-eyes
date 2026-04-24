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

// TriageConfig defines API settings.
type TriageConfig struct {
	APIKey    string
	BaseURL   string
	ProxyURL  string
	Timeout   time.Duration
	RateLimit time.Duration
	CacheTTL  time.Duration
}

// TriageClient queries the Hatching Triage API for file hashes.
type TriageClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	limiter    *rateLimiter
	cache      *cloudCache
}

// NewTriageClient creates a Triage client with caching and rate limiting.
func NewTriageClient(cfg TriageConfig) (*TriageClient, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://tria.ge/api/v0"
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

	return &TriageClient{
		apiKey:     cfg.APIKey,
		baseURL:    cfg.BaseURL,
		httpClient: httpClient,
		limiter:    newRateLimiter(cfg.RateLimit),
		cache:      newCloudCache(cfg.CacheTTL),
	}, nil
}

// Query performs a threat intel lookup for a hash.
func (c *TriageClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
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

	query := fmt.Sprintf("%s:%s", kind, hash)
	searchURL := fmt.Sprintf("%s/search?query=%s", c.baseURL, url.QueryEscape(query))

	if err := c.limiter.Wait(ctx); err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	searchReq, err := http.NewRequestWithContext(ctx, http.MethodGet, searchURL, nil)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	searchReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	searchReq.Header.Set("accept", "application/json")

	searchResp, err := c.httpClient.Do(searchReq)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	defer func() { _ = searchResp.Body.Close() }()

	if searchResp.StatusCode < 200 || searchResp.StatusCode >= 300 {
		return CloudAnalysis{CloudQueried: false}, 0, fmt.Errorf("cloud query failed: %s", searchResp.Status)
	}

	searchBody, err := io.ReadAll(searchResp.Body)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}

	var searchPayload triageSearchResponse
	if err := json.Unmarshal(searchBody, &searchPayload); err != nil || len(searchPayload.Data) == 0 {
		analysis := CloudAnalysis{CloudQueried: true, CloudProvider: "triage"}
		c.cache.Set(cacheKey, analysis, 0)
		return analysis, 0, nil
	}

	id := strings.TrimSpace(searchPayload.Data[0].ID)
	if id == "" {
		analysis := CloudAnalysis{CloudQueried: true, CloudProvider: "triage"}
		c.cache.Set(cacheKey, analysis, 0)
		return analysis, 0, nil
	}

	summaryURL := fmt.Sprintf("%s/samples/%s/summary", c.baseURL, url.PathEscape(id))
	if err := c.limiter.Wait(ctx); err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	summaryReq, err := http.NewRequestWithContext(ctx, http.MethodGet, summaryURL, nil)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	summaryReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	summaryReq.Header.Set("accept", "application/json")

	summaryResp, err := c.httpClient.Do(summaryReq)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}
	defer func() { _ = summaryResp.Body.Close() }()

	if summaryResp.StatusCode < 200 || summaryResp.StatusCode >= 300 {
		return CloudAnalysis{CloudQueried: false}, 0, fmt.Errorf("cloud query failed: %s", summaryResp.Status)
	}

	summaryBody, err := io.ReadAll(summaryResp.Body)
	if err != nil {
		return CloudAnalysis{CloudQueried: false}, 0, err
	}

	analysis, score := parseTriageSummary(summaryBody)
	analysis.CloudQueried = true
	analysis.CloudProvider = "triage"
	analysis.CloudLink = triageLink(triageWebBase(c.baseURL), id)
	c.cache.Set(cacheKey, analysis, score)
	return analysis, score, nil
}

// UploadSample submits a sample to Triage and polls for summary.
func (c *TriageClient) UploadSample(ctx context.Context, req CloudUploadRequest) (CloudUploadTask, error) {
	task := CloudUploadTask{
		Provider: "triage",
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
	uploadURL := fmt.Sprintf("%s/samples", c.baseURL)
	uploadReq, err := http.NewRequestWithContext(submitCtx, http.MethodPost, uploadURL, body)
	if err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	uploadReq.Header.Set("Authorization", "Bearer "+c.apiKey)
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
	var submit triageUploadResponse
	if err := json.NewDecoder(uploadResp.Body).Decode(&submit); err != nil {
		task.Status = CloudUploadStatusFailed
		task.Error = err.Error()
		return task, err
	}
	taskID := strings.TrimSpace(submit.ID)
	task.TaskID = taskID
	if taskID == "" {
		task.Status = CloudUploadStatusFailed
		task.Error = "missing upload task id"
		return task, fmt.Errorf("%s", task.Error)
	}
	task.Link = triageLink(triageWebBase(c.baseURL), taskID)
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

	summaryURL := fmt.Sprintf("%s/samples/%s/summary", c.baseURL, url.PathEscape(taskID))
	for {
		if err := c.limiter.Wait(waitCtx); err != nil {
			task.Status = CloudUploadStatusPending
			task.Error = err.Error()
			return task, nil
		}
		summaryReq, err := http.NewRequestWithContext(waitCtx, http.MethodGet, summaryURL, nil)
		if err != nil {
			task.Status = CloudUploadStatusFailed
			task.Error = err.Error()
			return task, err
		}
		summaryReq.Header.Set("Authorization", "Bearer "+c.apiKey)
		summaryReq.Header.Set("accept", "application/json")

		summaryResp, err := c.httpClient.Do(summaryReq)
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
		summaryBody, readErr := io.ReadAll(summaryResp.Body)
		_ = summaryResp.Body.Close()
		if readErr != nil {
			task.Status = CloudUploadStatusFailed
			task.Error = readErr.Error()
			return task, readErr
		}

		if summaryResp.StatusCode >= 200 && summaryResp.StatusCode < 300 {
			analysis, score := parseTriageSummary(summaryBody)
			if analysis.TotalEngines > 0 || score > 0 {
				task.Status = CloudUploadStatusCompleted
				task.Score = score
				return task, nil
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

type triageSearchResponse struct {
	Data []triageSearchItem `json:"data"`
}

type triageSearchItem struct {
	ID string `json:"id"`
}

type triageUploadResponse struct {
	ID string `json:"id"`
}

type triageSummary struct {
	Score  float64 `json:"score"`
	SHA256 string  `json:"sha256"`
}

func parseTriageSummary(body []byte) (CloudAnalysis, float64) {
	var summary triageSummary
	if err := json.Unmarshal(body, &summary); err != nil {
		return CloudAnalysis{}, 0
	}
	score := triageScoreToRisk(summary.Score)
	malicious, total, ratio := scoreAsRatio(score)
	return CloudAnalysis{
		Malicious:     malicious,
		TotalEngines:  total,
		DetectionRate: ratio,
	}, score
}

func triageScoreToRisk(raw float64) float64 {
	score10 := raw
	if score10 > 0 && score10 <= 1 {
		// Some integrations use a 0-1 normalized score.
		score10 = score10 * 10
	}
	if score10 <= 0 {
		return 0
	}
	if score10 >= 8 {
		// Keep >=8 in high-risk range.
		return ClampScore(90 + (score10-8)*5)
	}
	return ClampScore(score10 * 10)
}

func triageWebBase(apiBase string) string {
	apiBase = strings.TrimRight(apiBase, "/")
	if strings.HasSuffix(apiBase, "/api/v0") {
		return strings.TrimSuffix(apiBase, "/api/v0")
	}
	return apiBase
}

func triageLink(base, id string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if base == "" {
		base = "https://tria.ge"
	}
	return fmt.Sprintf("%s/%s", base, id)
}
