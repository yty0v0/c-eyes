## 1. Scaffolding & Types

- [x] 1.1 Create `internal/filescan` package skeleton and core types (`ScanMode`, `FileScanParams`, `FileScanResult`, `ScanTask`)
- [x] 1.2 Define interfaces: `TargetCollector`, `FilterEngine`, `DeepScanner`, `ResultReporter`, `CacheStore`, `ReputationClient`, `SignatureVerifier`

## 2. Target Collection

- [x] 2.1 Implement active process/module target collector (Windows/Linux)
- [x] 2.2 Implement persistence target collector (Run/RunOnce, services, scheduled tasks, startup folders; Linux best-effort)
- [x] 2.3 Implement high-risk directory collector (%USERPROFILE%/Downloads, %TEMP%, AppData, recycle bin)
- [x] 2.4 Implement recent-change collector for last 24 hours (USN Journal on Windows, inotify/mtime fallback on Linux)

## 3. Cache & Filter Engine

- [x] 3.1 Add SQLite cache store and `ScanCache` schema with upsert/query
- [x] 3.2 Implement filter engine short-circuit logic (cache -> signature -> reputation)
- [x] 3.3 Add unit tests for cache hit and filter order

## 4. Deep Scan

- [x] 4.1 Implement deep scanner interface with YARA hook or stub rule engine
- [x] 4.2 Add resource throttling (low priority thread, I/O limits where supported)
- [x] 4.3 Add unit tests for UNKNOWN -> deep scan path

## 5. Scheduler & Triggers

- [x] 5.1 Implement smart scan scheduler with task queue and Pause/Resume
- [x] 5.2 Implement idle trigger (Windows) and event trigger interface for driver push
- [x] 5.3 Add tests for trigger dispatch and pause behavior

## 6. CLI & Output

- [x] 6.1 Add `edr file scan` subcommand with `--mode`, `--path`, `--excel` validation
- [x] 6.2 Implement JSON output for `FileScanResult` list
- [x] 6.3 Implement Excel export for file scan with new headers
- [x] 6.4 Add CLI validation tests (missing path, invalid mode)

## 7. Integration

- [x] 7.1 Update `go.mod`/`go.sum` for SQLite and any optional dependencies
- [x] 7.2 Add docs or usage notes for file scan CLI
