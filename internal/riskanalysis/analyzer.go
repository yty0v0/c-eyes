package riskanalysis

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/metrics"
	"strings"
	"time"
)

const (
	defaultFastTimeout  = 2 * time.Second
	defaultSmartTimeout = 10 * time.Second
	defaultDeepTimeout  = 15 * time.Minute
	defaultLocalFastTTL = 500 * time.Millisecond
	defaultLocalScanTTL = 3 * time.Second
)

const (
	stageLocalOnly        = "local_only"
	stageCloudOnly        = "cloud_only"
	stageFastLookup       = "fast_lookup"
	stageFastWhitelist    = "fast_whitelist"
	stageLocalPreScan     = "local_pre_scan"
	stageSmartWhitelist   = "smart_whitelist"
	stageSmartCloud       = "smart_cloud"
	stageDeepWhitelist    = "deep_whitelist"
	stageDeepDynamic      = "deep_dynamic"
	stageFastFallbackYara = "fast_fallback_yara"
	stageSmartFallback    = "smart_fallback_yara"
	stageDeepFallback     = "deep_fallback_memory"
	stageUploadFinalGate  = "upload_final_gate"
	stageUploadWaiting    = "upload_waiting_result"
	stageHighRiskShort    = "high_risk_short_circuit"
)

// ProgressEvent reports staged progress for risk analysis.
type ProgressEvent struct {
	Index   int    `json:"index"`
	Total   int    `json:"total"`
	ScanID  string `json:"scan_id"`
	Stage   string `json:"stage"`
	Percent int    `json:"percent"`
}

type fastCloudClient interface {
	QueryFast(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error)
}

type smartCloudClient interface {
	QuerySmart(ctx context.Context, hashes Hashes, hints AnalysisHints) (CloudAnalysis, float64, error)
}

type deepCloudClient interface {
	QueryDeep(ctx context.Context, hashes Hashes, hints AnalysisHints) (CloudAnalysis, float64, error)
}

// Analyzer coordinates local and cloud analysis.
type Analyzer struct {
	Local       LocalMatcher
	Cloud       CloudClient
	Whitelist   WhitelistEngine
	LocalWeight float64
	CloudWeight float64
	Now         func() time.Time

	FastTimeout  time.Duration
	SmartTimeout time.Duration
	DeepTimeout  time.Duration

	CloudUploadEnabled       bool
	CloudUploadConcurrency   int
	CloudUploadWait          time.Duration
	CloudUploadSubmitTimeout time.Duration
	CloudUploadPollInterval  time.Duration
	CloudUploadMaxSize       int64
	AnalysisMaxDuration      time.Duration
	OnDiagnostic             func(string)

	OnProgress func(ProgressEvent)
	OnResult   func(AnalysisResult)
}

// Analyze executes risk analysis for the provided scan records.
func (a *Analyzer) Analyze(ctx context.Context, records []ScanRecord, mode AnalysisMode) ([]AnalysisResult, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no scan records provided")
	}

	mode = normalizeMode(mode)
	localRequired, cloudRequired, err := resolveMode(mode)
	if err != nil {
		return nil, err
	}
	if localRequired && a.Local == nil {
		return nil, fmt.Errorf("local analysis requested but no matcher configured")
	}
	if cloudRequired && a.Cloud == nil {
		return nil, fmt.Errorf("cloud analysis requested but no client configured")
	}

	nowFn := a.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	uploadConcurrency := a.uploadConcurrency(mode, len(records))
	uploadTuner := newUploadConcurrencyTuner(a.CloudUploadConcurrency <= 0)
	uploadWait := a.uploadWait(mode)
	uploadSubmit := a.uploadSubmitTimeout()
	uploadPoll := a.uploadPollInterval()

	effectiveMaxDuration := a.AnalysisMaxDuration
	if effectiveMaxDuration <= 0 {
		estimatedUploads := 0
		if a.CloudUploadEnabled {
			estimatedUploads = len(records)
		}
		effectiveMaxDuration = a.computeAutoBudget(mode, len(records), estimatedUploads, uploadConcurrency, uploadSubmit, uploadWait, uploadPoll)
		a.emitDiagnostic(fmt.Sprintf("auto budget estimated: mode=%s N=%d U=%d C=%d total=%s", mode, len(records), estimatedUploads, uploadConcurrency, effectiveMaxDuration))
	} else {
		a.emitDiagnostic(fmt.Sprintf("using user max duration override: %s", effectiveMaxDuration))
	}
	if effectiveMaxDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, effectiveMaxDuration)
		defer cancel()
	}

	results := make([]AnalysisResult, 0, len(records))
	uploadAttempts := 0
	for i, record := range records {
		meta := NormalizeTarget(record, nowFn())
		result := AnalysisResult{
			ScanID:            meta.ScanID,
			Timestamp:         meta.Timestamp,
			TargetType:        meta.TargetType,
			TargetPath:        meta.TargetPath,
			PID:               meta.PID,
			FileSize:          meta.FileSize,
			Hashes:            meta.Hashes,
			CloudUploadStatus: CloudUploadStatusSkipped,
		}

		var (
			localAnalysis *LocalAnalysis
			cloudAnalysis *CloudAnalysis
			whitelist     *WhitelistAnalysis
			localScore    float64
			cloudScore    float64
			stage         string
		)

		switch mode {
		case ModeLocalOnly:
			a.emitProgress(i+1, len(records), meta.ScanID, stageLocalOnly)
			analysis, score, err := a.matchLocal(ctx, meta, record, 0)
			if err != nil {
				analysis = LocalAnalysis{
					LocalMatched:        false,
					LocalFallback:       true,
					LocalFallbackReason: err.Error(),
				}
				score = 0
			}
			localAnalysis = &analysis
			localScore = score
			stage = stageLocalOnly

		case ModeCloudOnly:
			a.emitProgress(i+1, len(records), meta.ScanID, stageCloudOnly)
			analysis, score, _ := a.queryCloud(ctx, meta.Hashes)
			cloudAnalysis = &analysis
			cloudScore = score
			stage = stageCloudOnly

		case ModeFast:
			localAnalysis, localScore, cloudAnalysis, cloudScore, whitelist, stage = a.executeFast(ctx, meta, record, i+1, len(records))

		case ModeSmart:
			localAnalysis, localScore, cloudAnalysis, cloudScore, whitelist, stage = a.executeSmart(ctx, meta, record, i+1, len(records))

		case ModeDeep:
			localAnalysis, localScore, cloudAnalysis, cloudScore, whitelist, stage = a.executeDeep(ctx, meta, record, i+1, len(records))

		default:
			return nil, fmt.Errorf("invalid analysis mode: %s", mode)
		}

		result.LocalAnalysis = localAnalysis
		result.CloudAnalysis = cloudAnalysis
		result.Whitelist = whitelist

		if a.CloudUploadEnabled {
			result.CloudUploadEnabled = true
			if mode == ModeLocalOnly {
				result.CloudUploadStatus = CloudUploadStatusSkipped
				result.CloudUploadReason = "mode local_only"
			} else if blocked, reason := a.shouldBlockUpload(localAnalysis, localScore, cloudAnalysis, cloudScore, whitelist); blocked {
				result.CloudUploadStatus = CloudUploadStatusSkipped
				result.CloudUploadReason = reason
			} else if uploadable, reason := a.targetUploadable(meta); !uploadable {
				result.CloudUploadStatus = CloudUploadStatusSkipped
				result.CloudUploadReason = reason
			} else if uploader, ok := a.Cloud.(CloudUploadClient); ok {
				if tuned, changed := uploadTuner.Next(uploadConcurrency, len(records)-(i+1)); changed {
					a.emitDiagnostic(fmt.Sprintf("adaptive cloud-upload-concurrency: %d -> %d", uploadConcurrency, tuned))
					uploadConcurrency = tuned
				}
				uploadAttempts++
				a.emitProgress(i+1, len(records), meta.ScanID, stageUploadFinalGate)
				uploadStart := time.Now()
				waitProgressBase := effectiveMaxDuration
				if waitProgressBase <= 0 {
					waitProgressBase = uploadWait
				}
				waitProgressTotal := durationProgressSeconds(waitProgressBase)
				a.emitProgress(0, waitProgressTotal, meta.ScanID, stageUploadWaiting)

				type uploadOutcome struct {
					tasks []CloudUploadTask
					err   error
				}
				uploadCh := make(chan uploadOutcome, 1)
				go func() {
					tasks, err := uploader.Upload(ctx, CloudUploadRequest{
						FilePath:      meta.TargetPath,
						Hashes:        meta.Hashes,
						SubmitTimeout: uploadSubmit,
						WaitTimeout:   uploadWait,
						PollInterval:  uploadPoll,
						Concurrency:   uploadConcurrency,
					})
					uploadCh <- uploadOutcome{tasks: tasks, err: err}
				}()

				ticker := time.NewTicker(time.Second)
				var (
					tasks []CloudUploadTask
					err   error
				)
			waitLoop:
				for {
					select {
					case outcome := <-uploadCh:
						tasks = outcome.tasks
						err = outcome.err
						break waitLoop
					case <-ticker.C:
						elapsed := durationProgressDone(time.Since(uploadStart), waitProgressTotal)
						a.emitProgress(elapsed, waitProgressTotal, meta.ScanID, stageUploadWaiting)
					}
				}
				ticker.Stop()
				a.emitProgress(durationProgressDone(time.Since(uploadStart), waitProgressTotal), waitProgressTotal, meta.ScanID, stageUploadWaiting)
				result.CloudUploadAttempted = true
				result.CloudUploadDurationMS = time.Since(uploadStart).Milliseconds()
				result.CloudUploadTasks = tasks
				result.CloudUploadProviders = providersFromUploadTasks(tasks)
				if err != nil {
					result.CloudUploadStatus = CloudUploadStatusFailed
					result.CloudUploadReason = err.Error()
				} else {
					result.CloudUploadStatus, result.CloudUploadReason = summarizeUploadTasks(tasks)
					cloudAnalysis, cloudScore = mergeUploadEvidence(cloudAnalysis, cloudScore, tasks)
					result.CloudAnalysis = cloudAnalysis
				}
			} else {
				result.CloudUploadStatus = CloudUploadStatusSkipped
				result.CloudUploadReason = "cloud client does not support upload"
			}
		}

		stageForScore := stage
		weighted := 0.0
		if score, terminal := whitelistTerminalScore(whitelist); terminal {
			weighted = score
		} else if score, short := a.highRiskShortCircuit(localAnalysis, localScore, cloudAnalysis, cloudScore); short {
			weighted = score
			stageForScore = stageHighRiskShort
		} else {
			weighted = a.finalScore(mode, localAnalysis, localScore, cloudAnalysis, cloudScore, whitelist, meta)
		}
		riskScore, riskLevel := applyCloudRiskOverrides(weighted, cloudAnalysis)
		result.RiskAssessment = RiskAssessment{
			AnalysisMode: mode,
			RiskScore:    riskScore,
			RiskLevel:    riskLevel,
			Stage:        stageForScore,
		}
		results = append(results, result)
		if a.OnResult != nil {
			a.OnResult(result)
		}
	}

	if a.CloudUploadEnabled && a.AnalysisMaxDuration <= 0 {
		actualBudget := a.computeAutoBudget(mode, len(records), uploadAttempts, uploadConcurrency, uploadSubmit, uploadWait, uploadPoll)
		a.emitDiagnostic(fmt.Sprintf("auto budget finalized: mode=%s N=%d U=%d C=%d total=%s", mode, len(records), uploadAttempts, uploadConcurrency, actualBudget))
	}
	return results, nil
}

func (a *Analyzer) executeFast(ctx context.Context, meta TargetMetadata, record ScanRecord, index, total int) (*LocalAnalysis, float64, *CloudAnalysis, float64, *WhitelistAnalysis, string) {
	whitelist := a.evaluateWhitelist(ctx, meta, record, whitelistStageFast)
	if whitelist != nil && whitelist.Checked {
		a.emitProgress(index, total, meta.ScanID, stageFastWhitelist)
		switch whitelist.Decision {
		case WhitelistDecisionAllow:
			return nil, 0, nil, 0, whitelist, stageFastWhitelist
		case WhitelistDecisionDeny:
			return nil, 0, nil, 0, whitelist, stageFastWhitelist
		}
	}

	a.emitProgress(index, total, meta.ScanID, stageFastLookup)
	cloudCtx, cancel := context.WithTimeout(ctx, a.fastTimeout())
	defer cancel()

	cloudAnalysis, cloudScore, cloudErr := a.queryCloudFast(cloudCtx, meta.Hashes)
	cloudPtr := &cloudAnalysis
	if cloudErr != nil {
		cloudPtr = &CloudAnalysis{CloudQueried: false}
	}
	if cloudErr == nil && cloudScore >= 80 {
		return nil, 0, cloudPtr, cloudScore, whitelist, stageFastLookup
	}

	if a.Local == nil {
		return nil, 0, cloudPtr, cloudScore, whitelist, stageFastLookup
	}

	a.emitProgress(index, total, meta.ScanID, stageFastFallbackYara)
	localCtx, cancelLocal := context.WithTimeout(ctx, defaultLocalFastTTL)
	defer cancelLocal()
	localAnalysis, localScore, err := a.matchLocal(localCtx, meta, record, 0)
	if err != nil {
		localAnalysis = LocalAnalysis{
			LocalMatched:        false,
			LocalFallback:       true,
			LocalFallbackReason: err.Error(),
		}
		localScore = 0
	}
	localPtr := &localAnalysis
	return localPtr, localScore, cloudPtr, cloudScore, whitelist, stageFastFallbackYara
}

func (a *Analyzer) executeSmart(ctx context.Context, meta TargetMetadata, record ScanRecord, index, total int) (*LocalAnalysis, float64, *CloudAnalysis, float64, *WhitelistAnalysis, string) {
	whitelist := a.evaluateWhitelist(ctx, meta, record, whitelistStageSmart)
	if whitelist != nil && whitelist.Checked {
		a.emitProgress(index, total, meta.ScanID, stageSmartWhitelist)
		switch whitelist.Decision {
		case WhitelistDecisionAllow:
			return nil, 0, nil, 0, whitelist, stageSmartWhitelist
		case WhitelistDecisionDeny:
			return nil, 0, nil, 0, whitelist, stageSmartWhitelist
		}
	}

	var (
		localPtr *LocalAnalysis
		local    LocalAnalysis
		localErr error
	)

	if a.Local != nil {
		a.emitProgress(index, total, meta.ScanID, stageLocalPreScan)
		localCtx, cancelLocal := context.WithTimeout(ctx, defaultLocalScanTTL)
		defer cancelLocal()
		local, _, localErr = a.matchLocal(localCtx, meta, record, 0)
		if localErr != nil {
			local = LocalAnalysis{
				LocalMatched:        false,
				LocalFallback:       true,
				LocalFallbackReason: localErr.Error(),
			}
		}
		localPtr = &local
	}

	localScore := smartLocalScore(local)
	hints := buildHints(meta, localPtr, localScore)
	if hints.HighConfidence {
		return localPtr, localScore, nil, 0, whitelist, stageLocalPreScan
	}

	a.emitProgress(index, total, meta.ScanID, stageSmartCloud)
	cloudCtx, cancelCloud := context.WithTimeout(ctx, a.smartTimeout())
	defer cancelCloud()
	cloud, cloudScore, cloudErr := a.queryCloudSmart(cloudCtx, meta.Hashes, hints)
	if cloudErr != nil {
		cloud = CloudAnalysis{CloudQueried: false}
	}
	cloudPtr := &cloud

	if cloudErr != nil && localPtr != nil {
		return localPtr, localScore, cloudPtr, cloudScore, whitelist, stageSmartFallback
	}
	return localPtr, localScore, cloudPtr, cloudScore, whitelist, stageSmartCloud
}

func (a *Analyzer) executeDeep(ctx context.Context, meta TargetMetadata, record ScanRecord, index, total int) (*LocalAnalysis, float64, *CloudAnalysis, float64, *WhitelistAnalysis, string) {
	whitelist := a.evaluateWhitelist(ctx, meta, record, whitelistStageDeep)
	if whitelist != nil && whitelist.Checked {
		a.emitProgress(index, total, meta.ScanID, stageDeepWhitelist)
		switch whitelist.Decision {
		case WhitelistDecisionAllow:
			return nil, 0, nil, 0, whitelist, stageDeepWhitelist
		case WhitelistDecisionDeny:
			return nil, 0, nil, 0, whitelist, stageDeepWhitelist
		}
	}

	localPtr, localScore, cloudPtr, cloudScore, smartWhitelist, stage := a.executeSmart(ctx, meta, record, index, total)
	if whitelist == nil || !whitelist.Checked {
		whitelist = smartWhitelist
	}
	if stage == stageSmartWhitelist || (stage == stageLocalPreScan && cloudPtr == nil) {
		return localPtr, localScore, cloudPtr, cloudScore, whitelist, stage
	}
	smartScore := a.finalScore(ModeSmart, localPtr, localScore, cloudPtr, cloudScore, whitelist, meta)
	if smartScore >= 80 {
		return localPtr, localScore, cloudPtr, cloudScore, whitelist, stage
	}

	hints := buildHints(meta, localPtr, localScore)
	a.emitProgress(index, total, meta.ScanID, stageDeepDynamic)
	deepCtx, cancelDeep := context.WithTimeout(ctx, a.deepTimeout())
	defer cancelDeep()
	deepAnalysis, deepScore, deepErr := a.queryCloudDeep(deepCtx, meta.Hashes, hints)
	if deepErr != nil {
		// Deep-stage timeout/failure falls back to local evidence (memory path is engine-specific).
		if localPtr != nil {
			return localPtr, localScore, cloudPtr, cloudScore, whitelist, stageDeepFallback
		}
		return nil, 0, cloudPtr, cloudScore, whitelist, stageDeepFallback
	}

	// Favor deeper dynamic verdict when available.
	if cloudPtr == nil || deepScore > cloudScore {
		cloudPtr = &deepAnalysis
		cloudScore = deepScore
	}
	return localPtr, localScore, cloudPtr, cloudScore, whitelist, stageDeepDynamic
}

func (a *Analyzer) matchLocal(ctx context.Context, meta TargetMetadata, record ScanRecord, timeout time.Duration) (LocalAnalysis, float64, error) {
	if a.Local == nil {
		return LocalAnalysis{LocalMatched: false}, 0, nil
	}
	if timeout <= 0 {
		return a.Local.Match(ctx, meta, record)
	}
	localCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return a.Local.Match(localCtx, meta, record)
}

func (a *Analyzer) queryCloud(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	if a.Cloud == nil {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}
	return a.Cloud.Query(ctx, hashes)
}

func (a *Analyzer) queryCloudFast(ctx context.Context, hashes Hashes) (CloudAnalysis, float64, error) {
	if a.Cloud == nil {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}
	if staged, ok := a.Cloud.(fastCloudClient); ok {
		return staged.QueryFast(ctx, hashes)
	}
	return a.Cloud.Query(ctx, hashes)
}

func (a *Analyzer) queryCloudSmart(ctx context.Context, hashes Hashes, hints AnalysisHints) (CloudAnalysis, float64, error) {
	if a.Cloud == nil {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}
	if staged, ok := a.Cloud.(smartCloudClient); ok {
		return staged.QuerySmart(ctx, hashes, hints)
	}
	return a.Cloud.Query(ctx, hashes)
}

func (a *Analyzer) queryCloudDeep(ctx context.Context, hashes Hashes, hints AnalysisHints) (CloudAnalysis, float64, error) {
	if a.Cloud == nil {
		return CloudAnalysis{CloudQueried: false}, 0, nil
	}
	if staged, ok := a.Cloud.(deepCloudClient); ok {
		return staged.QueryDeep(ctx, hashes, hints)
	}
	return a.Cloud.Query(ctx, hashes)
}

func (a *Analyzer) finalScore(mode AnalysisMode, local *LocalAnalysis, localScore float64, cloud *CloudAnalysis, cloudScore float64, whitelist *WhitelistAnalysis, meta TargetMetadata) float64 {
	mode = normalizeMode(mode)
	localEnabled := local != nil
	cloudEnabled := cloud != nil

	if whitelist != nil && whitelist.Checked {
		switch whitelist.Decision {
		case WhitelistDecisionAllow:
			return 0
		case WhitelistDecisionDeny:
			return 100
		}
	}

	switch mode {
	case ModeSmart, ModeDeep:
		score := crossValidationScore(local, localScore, cloud, cloudScore)
		if score > 0 {
			return score
		}
	}

	return WeightedScore(localScore, cloudScore, a.LocalWeight, a.CloudWeight, localEnabled, cloudEnabled)
}

func (a *Analyzer) fastTimeout() time.Duration {
	if a.FastTimeout <= 0 {
		return defaultFastTimeout
	}
	return a.FastTimeout
}

func (a *Analyzer) smartTimeout() time.Duration {
	if a.SmartTimeout <= 0 {
		return defaultSmartTimeout
	}
	return a.SmartTimeout
}

func (a *Analyzer) deepTimeout() time.Duration {
	if a.DeepTimeout <= 0 {
		return defaultDeepTimeout
	}
	return a.DeepTimeout
}

func (a *Analyzer) emitProgress(index, total int, scanID, stage string) {
	if a == nil || a.OnProgress == nil || total <= 0 {
		return
	}
	percent := int(float64(index) / float64(total) * 100)
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	a.OnProgress(ProgressEvent{
		Index:   index,
		Total:   total,
		ScanID:  scanID,
		Stage:   stage,
		Percent: percent,
	})
}

func (a *Analyzer) evaluateWhitelist(ctx context.Context, meta TargetMetadata, record ScanRecord, stage string) *WhitelistAnalysis {
	if a == nil || a.Whitelist == nil {
		return nil
	}
	analysis, err := a.Whitelist.Evaluate(ctx, meta, record, stage)
	if err != nil {
		return &WhitelistAnalysis{
			Checked:  true,
			Decision: WhitelistDecisionContinue,
			Source:   "whitelist_funnel",
			Reason:   err.Error(),
		}
	}
	return &analysis
}

func resolveMode(mode AnalysisMode) (bool, bool, error) {
	switch normalizeMode(mode) {
	case ModeLocalOnly:
		return true, false, nil
	case ModeCloudOnly:
		return false, true, nil
	case ModeFast:
		return false, true, nil
	case ModeSmart:
		return false, true, nil
	case ModeDeep:
		return false, true, nil
	default:
		return false, false, fmt.Errorf("invalid analysis mode: %s", mode)
	}
}

func normalizeMode(mode AnalysisMode) AnalysisMode {
	switch mode {
	case ModeHybrid:
		return ModeSmart
	default:
		return mode
	}
}

func buildHints(meta TargetMetadata, local *LocalAnalysis, localScore float64) AnalysisHints {
	hints := AnalysisHints{
		TargetType: meta.TargetType,
		TargetPath: meta.TargetPath,
	}
	if local == nil {
		return hints
	}

	tagSet := make([]string, 0)
	ruleNames := make([]string, 0)
	suspiciousLabels := 0
	for _, m := range local.YaraResults {
		rule := strings.ToLower(strings.TrimSpace(m.RuleName))
		if rule != "" {
			ruleNames = appendUnique(ruleNames, rule)
			tagSet = appendUnique(tagSet, rule)
		}
		for _, tag := range m.Tags {
			t := strings.ToLower(strings.TrimSpace(tag))
			if t == "" {
				continue
			}
			tagSet = appendUnique(tagSet, t)
			if tagHasAny(t, "obfus", "upx", "packed", "macro", "powershell", "apt", "rat", "c2", "inject", "credential", "anti_debug", "anti-sandbox", "sandbox") {
				suspiciousLabels++
			}
		}
	}

	rawScore := localScore
	if matchScore := LocalScoreFromMatches(local.YaraResults); matchScore > rawScore {
		rawScore = matchScore
	}
	highConfidence := rawScore >= 90 || hasTag(tagSet, "high_confidence", "high-confidence", "known_malware", "ransomware", "cobaltstrike", "cobalt_strike")
	localSuspicious := localScore >= 50 || suspiciousLabels > 0

	hints.LocalTags = tagSet
	hints.LocalRuleNames = ruleNames
	hints.LocalSuspicious = localSuspicious
	hints.HighConfidence = highConfidence
	hints.SuspiciousLabels = suspiciousLabels
	return hints
}

func smartLocalScore(local LocalAnalysis) float64 {
	if len(local.YaraResults) == 0 {
		return 0
	}

	hints := buildHints(TargetMetadata{}, &local, LocalScoreFromMatches(local.YaraResults))
	if hints.HighConfidence {
		return 40
	}

	score := 0.0
	if hasTag(hints.LocalTags, "upx", "packed", "packer", "encrypt", "obfus", "obfuscated") {
		score += 10
	}
	if hasTag(hints.LocalTags, "anti_debug", "antidebug", "anti-sandbox", "sandbox", "vm", "anti_vm") {
		score += 20
	}
	if hasTag(hints.LocalTags, "apt", "rat", "c2", "toolkit", "inject", "credential", "t1055", "t1003") {
		score += 30
	}
	if score == 0 {
		score = ClampScore(LocalScoreFromMatches(local.YaraResults) * 0.4)
	}
	if score > 40 {
		score = 40
	}
	return score
}

func crossValidationScore(local *LocalAnalysis, localScore float64, cloud *CloudAnalysis, cloudScore float64) float64 {
	localPart := 0.0
	if local != nil {
		localPart = smartLocalScore(*local)
	}

	cloudPart := 0.0
	if cloud != nil && cloud.CloudQueried {
		if cloudHasProvider(cloud, "otx") && (cloud.Malicious > 0 || hasTag(cloud.ThreatLabels, "ip", "c2", "rat", "apt")) {
			cloudPart += 20
		}
		if cloudHasProvider(cloud, "virustotal") {
			switch {
			case cloud.Malicious >= 1 && cloud.Malicious <= 5:
				cloudPart += 15
			case cloud.Malicious >= 10:
				cloudPart += 30
			}
		}
		if cloudHasProvider(cloud, "hybrid_analysis") || cloudHasProvider(cloud, "triage") {
			cloudPart += min(30, ClampScore(cloudScore)*0.3)
		}
		if cloudPart == 0 && cloudScore > 0 {
			cloudPart = min(60, ClampScore(cloudScore)*0.6)
		}
	}

	if cloudPart > 60 {
		cloudPart = 60
	}

	score := localPart + cloudPart
	if local != nil && cloud != nil && score > 0 {
		if localCloudAlignment(*local, *cloud) {
			score = score * 1.2
		}
	}
	if score == 0 {
		return 0
	}
	return ClampScore(score)
}

func localCloudAlignment(local LocalAnalysis, cloud CloudAnalysis) bool {
	if len(local.YaraResults) == 0 || len(cloud.ThreatLabels) == 0 {
		return false
	}
	localTokens := make([]string, 0, len(local.YaraResults)*4)
	for _, m := range local.YaraResults {
		localTokens = appendUnique(localTokens, strings.ToLower(strings.TrimSpace(m.RuleName)))
		for _, tag := range m.Tags {
			localTokens = appendUnique(localTokens, strings.ToLower(strings.TrimSpace(tag)))
		}
	}
	for _, label := range cloud.ThreatLabels {
		labelLower := strings.ToLower(strings.TrimSpace(label))
		for _, token := range localTokens {
			if token == "" {
				continue
			}
			if strings.Contains(labelLower, token) || strings.Contains(token, labelLower) {
				return true
			}
		}
	}
	return false
}

func cloudHasProvider(analysis *CloudAnalysis, provider string) bool {
	if analysis == nil {
		return false
	}
	provider = NormalizeProvider(provider)
	if provider == "" {
		return false
	}
	if NormalizeProvider(analysis.CloudProvider) == provider {
		return true
	}
	for _, p := range analysis.CloudProviders {
		if NormalizeProvider(p) == provider {
			return true
		}
	}
	return false
}

func (a *Analyzer) uploadConcurrency(mode AnalysisMode, totalRecords int) int {
	if a.CloudUploadConcurrency > 0 {
		return a.CloudUploadConcurrency
	}

	procs := runtime.GOMAXPROCS(0)
	if procs <= 0 {
		procs = runtime.NumCPU()
	}
	if procs <= 0 {
		procs = 1
	}

	concurrency := 2
	switch normalizeMode(mode) {
	case ModeDeep:
		concurrency = 3
	case ModeCloudOnly:
		concurrency = 3
	}
	if totalRecords >= 128 {
		concurrency++
	}
	if totalRecords >= 512 {
		concurrency++
	}
	if procs >= 12 && totalRecords >= 512 {
		concurrency++
	}
	if procs <= 2 && concurrency > 2 {
		concurrency = 2
	}

	if memBytes, ok := readGoRuntimeMemoryTotal(); ok {
		if memBytes >= uint64(2)*1024*1024*1024 && concurrency > 2 {
			concurrency--
		}
	}

	if concurrency < 2 {
		concurrency = 2
	}
	if concurrency > 8 {
		concurrency = 8
	}
	return concurrency
}

func (a *Analyzer) uploadSubmitTimeout() time.Duration {
	if a.CloudUploadSubmitTimeout > 0 {
		return a.CloudUploadSubmitTimeout
	}
	return 20 * time.Second
}

func (a *Analyzer) uploadPollInterval() time.Duration {
	if a.CloudUploadPollInterval > 0 {
		return a.CloudUploadPollInterval
	}
	return 5 * time.Second
}

func (a *Analyzer) uploadWait(mode AnalysisMode) time.Duration {
	if a.CloudUploadWait > 0 {
		return a.CloudUploadWait
	}
	switch normalizeMode(mode) {
	case ModeFast:
		return 10 * time.Second
	case ModeSmart:
		return 3 * time.Minute
	case ModeCloudOnly:
		return 4 * time.Minute
	case ModeDeep:
		return 6 * time.Minute
	default:
		return 30 * time.Second
	}
}

type uploadConcurrencyTuner struct {
	enabled bool
	samples []metrics.Sample
	prevCPU float64
	prevAt  time.Time
	hasPrev bool
}

func newUploadConcurrencyTuner(enabled bool) *uploadConcurrencyTuner {
	if !enabled {
		return &uploadConcurrencyTuner{enabled: false}
	}
	return &uploadConcurrencyTuner{
		enabled: true,
		samples: []metrics.Sample{
			{Name: "/cpu/classes/total:cpu-seconds"},
			{Name: "/memory/classes/total:bytes"},
		},
	}
}

func (t *uploadConcurrencyTuner) Next(current, remaining int) (int, bool) {
	if t == nil || !t.enabled {
		return current, false
	}
	stats := t.sample()
	next := current

	if stats.memBytes >= uint64(2)*1024*1024*1024 {
		next--
	} else if remaining > current*2 && stats.memBytes <= uint64(1536)*1024*1024 {
		if !stats.cpuValid || stats.cpuUtil <= 0.70 {
			next++
		}
	} else if remaining < current && current > 2 {
		next--
	}

	if stats.cpuValid && stats.cpuUtil >= 0.90 {
		next--
	}

	if next < 2 {
		next = 2
	}
	if next > 8 {
		next = 8
	}
	return next, next != current
}

type uploadRuntimeStats struct {
	cpuUtil  float64
	cpuValid bool
	memBytes uint64
}

func (t *uploadConcurrencyTuner) sample() uploadRuntimeStats {
	if t == nil || !t.enabled {
		return uploadRuntimeStats{}
	}
	now := time.Now()
	metrics.Read(t.samples)

	stats := uploadRuntimeStats{}
	if len(t.samples) >= 2 && t.samples[1].Value.Kind() == metrics.KindUint64 {
		stats.memBytes = t.samples[1].Value.Uint64()
	}
	var cpuTotal float64
	if len(t.samples) >= 1 && t.samples[0].Value.Kind() == metrics.KindFloat64 {
		cpuTotal = t.samples[0].Value.Float64()
	}

	if t.hasPrev && cpuTotal >= t.prevCPU {
		wall := now.Sub(t.prevAt).Seconds()
		if wall > 0 {
			procs := float64(runtime.GOMAXPROCS(0))
			if procs <= 0 {
				procs = 1
			}
			util := (cpuTotal - t.prevCPU) / (wall * procs)
			if util < 0 {
				util = 0
			}
			if util > 2 {
				util = 2
			}
			stats.cpuUtil = util
			stats.cpuValid = true
		}
	}

	t.prevCPU = cpuTotal
	t.prevAt = now
	t.hasPrev = true
	return stats
}

func readGoRuntimeMemoryTotal() (uint64, bool) {
	samples := []metrics.Sample{{Name: "/memory/classes/total:bytes"}}
	metrics.Read(samples)
	if len(samples) == 0 || samples[0].Value.Kind() != metrics.KindUint64 {
		return 0, false
	}
	return samples[0].Value.Uint64(), true
}

func (a *Analyzer) emitDiagnostic(message string) {
	if a == nil || a.OnDiagnostic == nil || strings.TrimSpace(message) == "" {
		return
	}
	a.OnDiagnostic(message)
}

func (a *Analyzer) computeAutoBudget(mode AnalysisMode, totalRecords, uploadRecords, concurrency int, submitTimeout, waitTimeout, pollInterval time.Duration) time.Duration {
	if totalRecords < 0 {
		totalRecords = 0
	}
	if uploadRecords < 0 {
		uploadRecords = 0
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	base := time.Minute
	capLimit := 60 * time.Minute
	switch normalizeMode(mode) {
	case ModeFast:
		base = clampDuration(15*time.Second+time.Duration(totalRecords)*2*time.Second, 30*time.Second, 30*time.Minute)
		capLimit = 30 * time.Minute
	case ModeSmart:
		base = clampDuration(40*time.Second+time.Duration(totalRecords)*6*time.Second, 3*time.Minute, 90*time.Minute)
		capLimit = 90 * time.Minute
	case ModeCloudOnly:
		base = clampDuration(30*time.Second+time.Duration(totalRecords)*4*time.Second, 2*time.Minute, 60*time.Minute)
		capLimit = 60 * time.Minute
	case ModeDeep:
		base = clampDuration(2*time.Minute+time.Duration(totalRecords)*20*time.Second, 20*time.Minute, 240*time.Minute)
		capLimit = 240 * time.Minute
	default:
		base = clampDuration(30*time.Second+time.Duration(totalRecords)*3*time.Second, 30*time.Second, 60*time.Minute)
		capLimit = 60 * time.Minute
	}

	if !a.CloudUploadEnabled || uploadRecords <= 0 {
		return base
	}

	if submitTimeout <= 0 {
		submitTimeout = 20 * time.Second
	}
	if waitTimeout <= 0 {
		waitTimeout = a.uploadWait(mode)
	}
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}

	batches := (uploadRecords + concurrency - 1) / concurrency
	perBatch := submitTimeout + waitTimeout + 2*pollInterval
	uploadBudget := time.Duration(float64(time.Duration(batches)*perBatch) * 1.2)

	total := base + uploadBudget
	if total > capLimit {
		total = capLimit
	}
	return total
}

func clampDuration(value, minDur, maxDur time.Duration) time.Duration {
	if value < minDur {
		return minDur
	}
	if value > maxDur {
		return maxDur
	}
	return value
}

func durationProgressSeconds(value time.Duration) int {
	if value <= 0 {
		return 1
	}
	seconds := int(math.Ceil(value.Seconds()))
	if seconds <= 0 {
		return 1
	}
	return seconds
}

func durationProgressDone(elapsed time.Duration, total int) int {
	if total <= 0 {
		return 0
	}
	done := int(math.Ceil(elapsed.Seconds()))
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	return done
}

func (a *Analyzer) shouldBlockUpload(local *LocalAnalysis, localScore float64, cloud *CloudAnalysis, cloudScore float64, whitelist *WhitelistAnalysis) (bool, string) {
	if whitelist != nil && whitelist.Checked {
		switch whitelist.Decision {
		case WhitelistDecisionAllow:
			return true, "whitelist allow conclusion"
		case WhitelistDecisionDeny:
			return true, "whitelist deny conclusion"
		}
	}
	if hasHighConfidenceLocal(local, localScore) {
		return true, "local high-confidence conclusion"
	}
	if hasHighConfidenceCloud(cloud, cloudScore) {
		return true, "cloud high-confidence conclusion"
	}
	return false, ""
}

func hasHighConfidenceLocal(local *LocalAnalysis, localScore float64) bool {
	if local == nil {
		return false
	}
	if localScore >= 90 {
		return true
	}
	for _, match := range local.YaraResults {
		if match.Severity >= 90 {
			return true
		}
		for _, tag := range match.Tags {
			tagLower := strings.ToLower(strings.TrimSpace(tag))
			if tagLower == "high_confidence" || tagLower == "high-confidence" {
				return true
			}
		}
	}
	return false
}

func hasHighConfidenceCloud(cloud *CloudAnalysis, cloudScore float64) bool {
	if cloud == nil {
		return false
	}
	if cloudScore >= 80 {
		return true
	}
	if cloud.MaxProviderScore >= 80 {
		return true
	}
	for _, score := range cloud.ProviderScoreCard {
		if score >= 80 {
			return true
		}
	}
	return false
}

func (a *Analyzer) targetUploadable(meta TargetMetadata) (bool, string) {
	path := strings.TrimSpace(meta.TargetPath)
	if path == "" {
		return false, "missing target path"
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, "target path is not readable"
	}
	if info.IsDir() {
		return false, "target is a directory"
	}
	maxSize := a.CloudUploadMaxSize
	if maxSize <= 0 {
		maxSize = 20 * 1024 * 1024
	}
	if info.Size() > maxSize {
		return false, fmt.Sprintf("file exceeds max upload size (%d > %d)", info.Size(), maxSize)
	}
	return true, ""
}

func (a *Analyzer) highRiskShortCircuit(local *LocalAnalysis, localScore float64, cloud *CloudAnalysis, cloudScore float64) (float64, bool) {
	localHigh := 0.0
	if hasHighConfidenceLocal(local, localScore) {
		localHigh = math.Max(localScore, LocalScoreFromMatches(local.YaraResults))
	}
	cloudHigh := 0.0
	if hasHighConfidenceCloud(cloud, cloudScore) {
		cloudHigh = math.Max(cloudScore, cloud.MaxProviderScore)
		for _, score := range cloud.ProviderScoreCard {
			if score > cloudHigh {
				cloudHigh = score
			}
		}
	}
	if localHigh == 0 && cloudHigh == 0 {
		return 0, false
	}
	score := math.Max(localHigh, cloudHigh)
	if score < 81 {
		score = 81
	}
	return ClampScore(score), true
}

func whitelistTerminalScore(whitelist *WhitelistAnalysis) (float64, bool) {
	if whitelist == nil || !whitelist.Checked {
		return 0, false
	}
	switch whitelist.Decision {
	case WhitelistDecisionAllow:
		return 0, true
	case WhitelistDecisionDeny:
		return 100, true
	default:
		return 0, false
	}
}

func isWhitelistTerminal(whitelist *WhitelistAnalysis) bool {
	_, ok := whitelistTerminalScore(whitelist)
	return ok
}

func providersFromUploadTasks(tasks []CloudUploadTask) []string {
	providers := make([]string, 0, len(tasks))
	for _, task := range tasks {
		if task.Provider == "" {
			continue
		}
		providers = appendUnique(providers, task.Provider)
	}
	return providers
}

func summarizeUploadTasks(tasks []CloudUploadTask) (string, string) {
	if len(tasks) == 0 {
		return CloudUploadStatusSkipped, "no upload tasks generated"
	}
	hasCompleted := false
	hasPending := false
	hasFailed := false
	hasSkipped := false
	firstErr := ""
	for _, task := range tasks {
		switch task.Status {
		case CloudUploadStatusCompleted:
			hasCompleted = true
		case CloudUploadStatusPending:
			hasPending = true
		case CloudUploadStatusFailed:
			hasFailed = true
			if firstErr == "" && task.Error != "" {
				firstErr = task.Error
			}
		default:
			hasSkipped = true
			if firstErr == "" && task.Error != "" {
				firstErr = task.Error
			}
		}
	}
	switch {
	case hasCompleted:
		return CloudUploadStatusCompleted, ""
	case hasPending:
		return CloudUploadStatusPending, "provider processing pending"
	case hasFailed && !hasSkipped:
		if firstErr == "" {
			firstErr = "all upload tasks failed"
		}
		return CloudUploadStatusFailed, firstErr
	case hasFailed && hasSkipped:
		if firstErr == "" {
			firstErr = "partial upload failure"
		}
		return CloudUploadStatusFailed, firstErr
	default:
		if firstErr == "" {
			firstErr = "upload skipped by policy"
		}
		return CloudUploadStatusSkipped, firstErr
	}
}

func mergeUploadEvidence(cloud *CloudAnalysis, cloudScore float64, tasks []CloudUploadTask) (*CloudAnalysis, float64) {
	if len(tasks) == 0 {
		return cloud, cloudScore
	}
	if cloud == nil {
		cloud = &CloudAnalysis{}
	}
	if cloud.ProviderScoreCard == nil {
		cloud.ProviderScoreCard = make(map[string]float64)
	}
	mergedScore := cloudScore
	for _, task := range tasks {
		if task.Status != CloudUploadStatusCompleted {
			continue
		}
		cloud.CloudQueried = true
		if cloud.CloudProvider == "" {
			cloud.CloudProvider = "multi"
		}
		cloud.CloudProviders = appendUnique(cloud.CloudProviders, task.Provider)
		if task.Link != "" && cloud.CloudLink == "" {
			cloud.CloudLink = task.Link
		}
		if task.Score > cloud.MaxProviderScore {
			cloud.MaxProviderScore = task.Score
		}
		if task.Provider != "" {
			cloud.ProviderScoreCard[task.Provider] = task.Score
		}
		if task.Score > mergedScore {
			mergedScore = task.Score
		}
	}
	if cloud.CloudQueried && cloud.TotalEngines == 0 {
		malicious, total, ratio := scoreAsRatio(mergedScore)
		cloud.Malicious = malicious
		cloud.TotalEngines = total
		cloud.DetectionRate = ratio
	}
	return cloud, mergedScore
}

func hasTag(values []string, tokens ...string) bool {
	for _, value := range values {
		if tagHasAny(value, tokens...) {
			return true
		}
	}
	return false
}

func tagHasAny(value string, tokens ...string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, token := range tokens {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func isTimeoutErr(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func applyCloudRiskOverrides(score float64, cloud *CloudAnalysis) (float64, string) {
	score = ClampScore(score)
	baseLevel := RiskLevelFromScore(score)
	if cloud == nil {
		return score, baseLevel
	}

	switch {
	case cloud.LabelOverrideTriggered:
		if score < 95 {
			score = 95
		}
		return score, RiskLevelCritical
	case cloud.DetectionOverrideTriggered:
		if score < 60 {
			score = 60
		}
		return score, RiskLevelFromScore(score)
	case cloud.FailSafeTriggered:
		if score > 80 {
			return score, RiskLevelHigh
		}
		if score <= 20 {
			score = 30
		}
		if cloud.ProviderPendingCount > 0 {
			return score, RiskLevelPending
		}
		return score, RiskLevelSuspiciousOffline
	default:
		return score, baseLevel
	}
}
