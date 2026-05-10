package filescan

import (
	"context"
	"time"

	"edrsystem/internal/processscan"
)

// DefaultFilterEngine applies cache, signature, and reputation checks.
type DefaultFilterEngine struct {
	Cache      CacheStore
	Signature  SignatureVerifier
	Reputation ReputationClient
	Hostname   string
	Host       processscan.HostInfo
}

func (e *DefaultFilterEngine) Filter(ctx context.Context, task ScanTask) (FilterDecision, error) {
	meta, err := fileMeta(task.Path)
	result := baseResult(task, meta)
	if e.Hostname != "" {
		result.Hostname = strPtr(e.Hostname)
	}
	if e.Host.DisplayIP != nil {
		result.DisplayIP = e.Host.DisplayIP
	}
	if len(e.Host.ExternalIPs) > 0 {
		result.ExternalIPList = append([]string(nil), e.Host.ExternalIPs...)
	}
	if len(e.Host.InternalIPs) > 0 {
		result.InternalIPList = append([]string(nil), e.Host.InternalIPs...)
	}
	if result.ExternalIPList == nil {
		result.ExternalIPList = []string{}
	}
	if result.InternalIPList == nil {
		result.InternalIPList = []string{}
	}
	if err != nil {
		if isPermissionDeniedError(err) {
			return FilterDecision{}, err
		}
		result.ScanResult = scanResultPtr(ScanResultUnknown)
		return FilterDecision{Result: result, Final: true}, nil
	}

	if e.Cache != nil {
		entry, ok, err := e.Cache.Get(ctx, task.Path, meta.ModifiedTime)
		if err != nil {
			return FilterDecision{}, err
		}
		if ok && entry != nil {
			if cacheEntryMatchesFile(task.Path, entry) {
				result.ScanResult = scanResultPtr(entry.ScanResult)
				result.LastScanTime = timePtr(entry.LastScanTime)
				return FilterDecision{Result: result, Final: true}, nil
			}
		}
	}

	if e.Signature != nil {
		trusted, err := e.Signature.IsTrusted(ctx, task.Path)
		if err == nil && trusted {
			result.ScanResult = scanResultPtr(ScanResultSafe)
			return FilterDecision{Result: result, Final: true}, nil
		}
	}

	if e.Reputation != nil {
		hashes, hashErr := fileHashes(task.Path)
		if hashErr == nil {
			result.Hashes = hashes
		}
		req := ReputationRequest{
			Path:    task.Path,
			HashMd5: "",
			HashSha: valueOrEmpty(hashString(hashes, func(h *FileHashes) *string { return h.Sha256 })),
		}
		verdict, err := e.Reputation.Lookup(ctx, req)
		if err == nil {
			switch verdict {
			case ReputationMalicious:
				result.ScanResult = scanResultPtr(ScanResultMalicious)
				return FilterDecision{Result: result, Final: true}, nil
			case ReputationSafe:
				result.ScanResult = scanResultPtr(ScanResultSafe)
				return FilterDecision{Result: result, Final: true}, nil
			case ReputationUnknown:
				result.ScanResult = scanResultPtr(ScanResultUnknown)
				return FilterDecision{Result: result, Final: false}, nil
			}
		}
	}

	result.ScanResult = scanResultPtr(ScanResultUnknown)
	return FilterDecision{Result: result, Final: false}, nil
}

func baseResult(task ScanTask, meta *FileMeta) FileScanResult {
	result := FileScanResult{
		ScanMode: scanModePtr(task.Mode),
		Source:   strPtr(task.Source),
	}
	result.BasicInfo = basicInfoFromMeta(task.Path, meta)
	return result
}

func valueOrEmpty(val *string) string {
	if val == nil {
		return ""
	}
	return *val
}

func hashString(hashes *FileHashes, pick func(*FileHashes) *string) *string {
	if hashes == nil {
		return nil
	}
	return pick(hashes)
}

func cacheEntryMatchesFile(path string, entry *CacheEntry) bool {
	if entry == nil {
		return false
	}
	if entry.Hash == "" {
		return true
	}
	hashes, err := fileHashes(path)
	if err != nil || hashes == nil || hashes.Sha256 == nil {
		return false
	}
	return *hashes.Sha256 == entry.Hash
}

func nowPtr() *time.Time {
	now := time.Now().UTC()
	return &now
}
