package riskanalysis

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// CloudProviderClient bundles a provider name with its client.
type CloudProviderClient struct {
	Name   string
	Client CloudClient
}

// MultiCloudClient queries multiple cloud providers in parallel and aggregates results.
type MultiCloudClient struct {
	Providers    []CloudProviderClient
	UploadPolicy map[string]bool
	disabledMu   sync.RWMutex
	disabled     map[string]string
}

type providerResult struct {
	name     string
	analysis CloudAnalysis
	score    float64
	err      error
}

// Query performs parallel lookups against all configured providers and aggregates the results.
func (m *MultiCloudClient) Query(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	return m.queryWithProviders(ctx, hashes, nil)
}

// QueryFast performs stage-1 fast lookup with high-confidence cloud providers.
func (m *MultiCloudClient) QueryFast(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	// Stage 1: MalwareBazaar + VirusTotal.
	return m.queryWithProviders(ctx, hashes, []string{"malwarebazaar", "virustotal"})
}

// QuerySmart performs stage-2 contextual lookup and routes by local hints.
func (m *MultiCloudClient) QuerySmart(ctx context.Context, hashes Hashes, hints AnalysisHints) (CloudAnalysis, float64, error) {
	tags := strings.ToLower(strings.Join(hints.LocalTags, ","))
	rules := strings.ToLower(strings.Join(hints.LocalRuleNames, ","))
	blob := tags + "," + rules
	switch {
	case containsAny(blob, "macro", "powershell", "vba", "script"):
		return m.queryWithProviders(ctx, hashes, []string{"hybrid_analysis"})
	case containsAny(blob, "apt", "rat", "c2", "ttp", "backdoor"):
		return m.queryWithProviders(ctx, hashes, []string{"otx"})
	case containsAny(blob, "upx", "packed", "packer", "pe"):
		return m.queryWithProviders(ctx, hashes, []string{"virustotal"})
	default:
		// Default contextual blend favors OTX+VT.
		return m.queryWithProviders(ctx, hashes, []string{"otx", "virustotal"})
	}
}

// QueryDeep performs stage-3 deep dynamic lookup.
func (m *MultiCloudClient) QueryDeep(ctx context.Context, hashes Hashes, hints AnalysisHints) (CloudAnalysis, float64, error) {
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(hints.TargetPath)))
	switch ext {
	case ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptx", ".ps1", ".vbs", ".js":
		return m.queryWithProviders(ctx, hashes, []string{"hybrid_analysis"})
	default:
		return m.queryWithProviders(ctx, hashes, []string{"triage", "hybrid_analysis"})
	}
}

// Upload submits file samples to upload-capable providers with bounded concurrency.
func (m *MultiCloudClient) Upload(ctx context.Context, req CloudUploadRequest) ([]CloudUploadTask, error) {
	if m == nil || len(m.Providers) == 0 {
		return nil, nil
	}
	if strings.TrimSpace(req.FilePath) == "" {
		return nil, nil
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 2
	}

	candidates := make([]CloudProviderClient, 0, len(m.Providers))
	tasks := make([]CloudUploadTask, 0, len(m.Providers))
	for _, provider := range m.Providers {
		name := NormalizeProvider(provider.Name)
		if name == "" {
			name = provider.Name
		}
		uploadClient, ok := provider.Client.(providerUploadClient)
		allowed := m.providerUploadAllowed(name)
		if !ok || !allowed {
			if name == "malwarebazaar" || name == "otx" {
				tasks = append(tasks, CloudUploadTask{
					Provider: name,
					Status:   CloudUploadStatusSkipped,
					Error:    "hash-only provider",
				})
				continue
			}
			if ok {
				tasks = append(tasks, CloudUploadTask{
					Provider: name,
					Status:   CloudUploadStatusSkipped,
					Error:    "upload disabled by policy",
				})
			}
			_ = uploadClient
			continue
		}
		candidates = append(candidates, CloudProviderClient{
			Name:   name,
			Client: provider.Client,
		})
	}
	if len(candidates) == 0 {
		return tasks, nil
	}

	type uploadResult struct {
		task CloudUploadTask
		err  error
	}
	resultCh := make(chan uploadResult, len(candidates))
	sem := make(chan struct{}, req.Concurrency)
	var wg sync.WaitGroup

	for _, provider := range candidates {
		uploadClient := provider.Client.(providerUploadClient)
		wg.Add(1)
		go func(name string, client providerUploadClient) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				resultCh <- uploadResult{
					task: CloudUploadTask{
						Provider: name,
						Status:   CloudUploadStatusFailed,
						Error:    ctx.Err().Error(),
					},
					err: ctx.Err(),
				}
				return
			}
			defer func() { <-sem }()

			task, err := client.UploadSample(ctx, req)
			if task.Provider == "" {
				task.Provider = name
			}
			if task.Status == "" {
				if err != nil {
					task.Status = CloudUploadStatusFailed
				} else {
					task.Status = CloudUploadStatusCompleted
				}
			}
			if err != nil && task.Error == "" {
				task.Error = err.Error()
			}
			resultCh <- uploadResult{task: task, err: err}
		}(provider.Name, uploadClient)
	}

	wg.Wait()
	close(resultCh)

	for res := range resultCh {
		tasks = append(tasks, res.task)
	}
	return tasks, nil
}

func (m *MultiCloudClient) queryWithProviders(ctx context.Context, hashes Hashes, selected []string) (CloudAnalysis, float64, error) {
	if m == nil || len(m.Providers) == 0 {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}
	if hash, _ := pickHash(hashes); hash == "" {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}

	chosen := m.selectProviders(selected)
	if len(chosen) == 0 {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}

	results := make(chan providerResult, len(chosen))
	var wg sync.WaitGroup
	launched := 0
	for _, provider := range chosen {
		if provider.Client == nil {
			continue
		}
		launched++
		wg.Add(1)
		go func(p CloudProviderClient) {
			defer wg.Done()
			analysis, score, err := p.Client.Query(ctx, hashes)
			results <- providerResult{name: p.Name, analysis: analysis, score: score, err: err}
		}(provider)
	}
	wg.Wait()
	close(results)

	if launched == 0 {
		return CloudAnalysis{
			CloudQueried:       false,
			CloudProvider:      "multi",
			ProviderTotalCount: len(chosen),
		}, 0, nil
	}

	var (
		providers         []string
		labels            []string
		link              string
		maxProviderScore  float64
		maxScore          float64
		effectiveTotal    float64
		effectiveCount    int
		successCount      int
		noResultCount     int
		failedCount       int
		timeoutCount      int
		pendingCount      int
		providerScores    = make(map[string]float64)
		outcomeCard       = make(map[string]string)
		errorCard         = make(map[string]string)
		labelOverride     bool
		detectionOverride bool
	)

	for result := range results {
		name := result.name
		if result.analysis.CloudProvider != "" {
			name = result.analysis.CloudProvider
		}
		normalized := NormalizeProvider(name)
		if normalized != "" {
			name = normalized
		}

		outcome := classifyProviderOutcome(result.analysis, result.err)
		outcomeCard[name] = outcome
		if result.err != nil {
			errorCard[name] = result.err.Error()
			if shouldDisableProviderAfterError(result.err) {
				m.disableProvider(name, result.err.Error())
			}
		}

		switch outcome {
		case cloudOutcomeSuccess:
			successCount++
		case cloudOutcomeTimeout:
			timeoutCount++
			continue
		case cloudOutcomePending:
			pendingCount++
			continue
		case cloudOutcomeFailed:
			failedCount++
			continue
		default:
			noResultCount++
			continue
		}

		providers = appendUnique(providers, name)
		labels = appendUniqueSlice(labels, result.analysis.ThreatLabels)
		if link == "" && result.analysis.CloudLink != "" {
			link = result.analysis.CloudLink
		}

		score := ClampScore(result.score)
		providerScores[name] = score
		if score > maxProviderScore {
			maxProviderScore = score
		}

		if !providerHasEffectiveVerdict(name, result.analysis, score) {
			noResultCount++
			outcomeCard[name] = cloudOutcomeNoResult
			continue
		}

		effectiveCount++
		effectiveTotal += score
		if score > maxScore {
			maxScore = score
		}
		if hasMaliciousThreatLabel(result.analysis.ThreatLabels) {
			labelOverride = true
		}
		if providerHitsDetectionThreshold(result.analysis) {
			detectionOverride = true
		}
	}

	if labelOverride && maxScore < 95 {
		maxScore = 95
	}
	maxScore = ClampScore(maxScore)

	effectiveAverage := 0.0
	if effectiveCount > 0 {
		effectiveAverage = ClampScore(effectiveTotal / float64(effectiveCount))
	}

	unresolvedCount := failedCount + timeoutCount + pendingCount
	failSafeTriggered := len(chosen) >= 5 && unresolvedCount >= 3
	failSafeReason := ""
	if failSafeTriggered {
		switch {
		case pendingCount > 0:
			failSafeReason = "cloud providers still pending"
		case timeoutCount > 0:
			failSafeReason = "cloud providers timed out"
		default:
			failSafeReason = "cloud providers failed"
		}
	}

	malicious, totalEngines, ratio := scoreAsRatio(maxScore)
	analysis := CloudAnalysis{
		CloudQueried:               successCount > 0,
		CloudProvider:              "multi",
		CloudProviders:             providers,
		Malicious:                  malicious,
		TotalEngines:               totalEngines,
		DetectionRate:              ratio,
		ThreatLabels:               labels,
		CloudLink:                  link,
		MaxProviderScore:           maxProviderScore,
		EffectiveAverageScore:      effectiveAverage,
		ProviderScoreCard:          providerScores,
		ProviderOutcomeCard:        outcomeCard,
		ProviderErrorCard:          errorCard,
		EffectiveProviderCount:     effectiveCount,
		ProviderSuccessCount:       successCount,
		ProviderNoResultCount:      noResultCount,
		ProviderFailedCount:        failedCount,
		ProviderTimeoutCount:       timeoutCount,
		ProviderPendingCount:       pendingCount,
		ProviderTotalCount:         len(chosen),
		LabelOverrideTriggered:     labelOverride,
		DetectionOverrideTriggered: detectionOverride,
		FailSafeTriggered:          failSafeTriggered,
		FailSafeReason:             failSafeReason,
	}
	return analysis, maxScore, nil
}

func (m *MultiCloudClient) selectProviders(selected []string) []CloudProviderClient {
	if len(selected) == 0 {
		return append([]CloudProviderClient{}, m.Providers...)
	}
	need := make(map[string]struct{}, len(selected))
	for _, name := range selected {
		if normalized := NormalizeProvider(name); normalized != "" {
			need[normalized] = struct{}{}
		}
	}
	chosen := make([]CloudProviderClient, 0, len(need))
	for _, provider := range m.Providers {
		name := NormalizeProvider(provider.Name)
		if name == "" && provider.Client != nil {
			name = NormalizeProvider(provider.Name)
		}
		if m.isProviderDisabled(name) {
			continue
		}
		if _, ok := need[name]; ok {
			chosen = append(chosen, provider)
		}
	}
	return chosen
}

func (m *MultiCloudClient) disableProvider(name string, reason string) {
	if m == nil {
		return
	}
	name = NormalizeProvider(name)
	if name == "" {
		return
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "disabled by cloud client policy"
	}
	m.disabledMu.Lock()
	defer m.disabledMu.Unlock()
	if m.disabled == nil {
		m.disabled = map[string]string{}
	}
	m.disabled[name] = reason
}

func (m *MultiCloudClient) isProviderDisabled(name string) bool {
	if m == nil {
		return false
	}
	name = NormalizeProvider(name)
	if name == "" {
		return false
	}
	m.disabledMu.RLock()
	defer m.disabledMu.RUnlock()
	_, ok := m.disabled[name]
	return ok
}

func shouldDisableProviderAfterError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(msg, "api key is required"),
		strings.Contains(msg, "missing api key"),
		strings.Contains(msg, "invalid api key"),
		strings.Contains(msg, "unauthorized"),
		strings.Contains(msg, "forbidden"),
		strings.Contains(msg, "401"),
		strings.Contains(msg, "403"):
		return true
	default:
		return false
	}
}

func containsAny(value string, tokens ...string) bool {
	for _, token := range tokens {
		token = strings.TrimSpace(strings.ToLower(token))
		if token == "" {
			continue
		}
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

const (
	cloudOutcomeSuccess  = "success"
	cloudOutcomeNoResult = "no_result"
	cloudOutcomeFailed   = "failed"
	cloudOutcomeTimeout  = "timeout"
	cloudOutcomePending  = "pending"
)

func classifyProviderOutcome(analysis CloudAnalysis, err error) string {
	if err == nil {
		if analysis.CloudQueried {
			return cloudOutcomeSuccess
		}
		return cloudOutcomeNoResult
	}
	if errors.Is(err, ErrRateLimited) {
		return cloudOutcomePending
	}
	if isTimeoutErr(err) {
		return cloudOutcomeTimeout
	}
	errText := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(errText, "timeout"), strings.Contains(errText, "timed out"), strings.Contains(errText, "deadline"):
		return cloudOutcomeTimeout
	case strings.Contains(errText, "pending"), strings.Contains(errText, "processing"):
		return cloudOutcomePending
	default:
		return cloudOutcomeFailed
	}
}

func providerHasEffectiveVerdict(provider string, analysis CloudAnalysis, score float64) bool {
	score = ClampScore(score)
	if score > 0 {
		return true
	}
	if analysis.Malicious > 0 {
		return true
	}
	if len(analysis.ThreatLabels) > 0 {
		return true
	}
	if NormalizeProvider(provider) == "virustotal" && analysis.TotalEngines > 0 {
		return true
	}
	if detected, total, ok := parseDetectionRatio(analysis.DetectionRate); ok {
		if detected > 0 || (NormalizeProvider(provider) == "virustotal" && total > 0) {
			return true
		}
	}
	return false
}

func hasMaliciousThreatLabel(labels []string) bool {
	if len(labels) == 0 {
		return false
	}
	keywords := []string{
		"webshell",
		"trojan",
		"backdoor",
		"ransom",
		"malware",
		"worm",
		"spyware",
		"rootkit",
		"botnet",
		"rat",
		"dropper",
		"loader",
		"exploit",
		"c2",
	}
	for _, label := range labels {
		label = strings.ToLower(strings.TrimSpace(label))
		if label == "" {
			continue
		}
		for _, keyword := range keywords {
			if strings.Contains(label, keyword) {
				return true
			}
		}
	}
	return false
}

func providerHitsDetectionThreshold(analysis CloudAnalysis) bool {
	malicious := analysis.Malicious
	total := analysis.TotalEngines
	if total <= 0 {
		if detected, parsedTotal, ok := parseDetectionRatio(analysis.DetectionRate); ok {
			malicious = detected
			total = parsedTotal
		}
	}
	if total <= 0 {
		return false
	}
	if malicious >= 3 {
		return true
	}
	return float64(malicious)/float64(total) > 0.05
}

func parseDetectionRatio(value string) (int, int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, 0, false
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 {
		return 0, 0, false
	}
	detected, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, false
	}
	total, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || total <= 0 {
		return 0, 0, false
	}
	if detected < 0 {
		detected = 0
	}
	return detected, total, true
}

func providerSupportsUpload(name string) bool {
	switch NormalizeProvider(name) {
	case "virustotal", "triage", "hybrid_analysis":
		return true
	default:
		return false
	}
}

func (m *MultiCloudClient) providerUploadAllowed(name string) bool {
	name = NormalizeProvider(name)
	if name == "" {
		return false
	}
	if m != nil && len(m.UploadPolicy) > 0 {
		if enabled, ok := m.UploadPolicy[name]; ok {
			return enabled
		}
	}
	return providerSupportsUpload(name)
}
