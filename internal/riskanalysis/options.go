package riskanalysis

const (
	// DefaultYaraReadChunkSize controls per-read file chunk size for local YARA scans.
	DefaultYaraReadChunkSize = 4 * 1024 * 1024
	// DefaultProcessMemoryMaxBytes caps bytes captured from process memory scans.
	DefaultProcessMemoryMaxBytes = 16 * 1024 * 1024
)
