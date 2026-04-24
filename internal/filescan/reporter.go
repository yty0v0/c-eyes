package filescan

import (
	"context"
	"time"
)

// DefaultResultReporter writes cache entries and returns results.
type DefaultResultReporter struct {
	Cache CacheStore
}

func (r *DefaultResultReporter) Report(ctx context.Context, result FileScanResult) (FileScanResult, error) {
	result = enrichResult(result)
	if result.LastScanTime == nil {
		result.LastScanTime = nowPtr()
	}
	if r.Cache != nil && result.ScanResult != nil {
		path := ""
		modTime := time.Time{}
		if result.BasicInfo != nil {
			if result.BasicInfo.FilePath != nil {
				path = *result.BasicInfo.FilePath
			}
			if result.BasicInfo.ModificationTime != nil {
				modTime = *result.BasicInfo.ModificationTime
			}
		}
		if path == "" || modTime.IsZero() {
			return result, nil
		}
		hash := ""
		if result.Hashes != nil {
			if result.Hashes.Sha256 != nil {
				hash = *result.Hashes.Sha256
			}
		}
		entry := CacheEntry{
			Path:         path,
			Hash:         hash,
			LastModified: modTime,
			ScanResult:   *result.ScanResult,
			LastScanTime: *result.LastScanTime,
		}
		_ = r.Cache.Put(ctx, entry)
	}
	return result, nil
}
