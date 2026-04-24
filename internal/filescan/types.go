package filescan

import "time"

// ScanMode defines file scan mode.
type ScanMode string

const (
	ScanModeFull  ScanMode = "full"
	ScanModePath  ScanMode = "path"
	ScanModeSmart ScanMode = "smart"
)

// ScanResult represents the final verdict of a scan.
type ScanResult string

const (
	ScanResultSafe      ScanResult = "SAFE"
	ScanResultMalicious ScanResult = "MALICIOUS"
	ScanResultUnknown   ScanResult = "UNKNOWN"
)

// FileScanParams defines inputs for a file scan.
type FileScanParams struct {
	Mode         ScanMode
	Path         string
	SmartEnabled bool
	MaxTargets   int
	Workers      int
	Progress     ProgressFunc
	OnTaskError  TaskErrorFunc
}

// ProgressFunc reports scan progress in terminal-friendly counters.
type ProgressFunc func(done, total int, stage string)

// TaskErrorFunc reports per-task scan failures without aborting the whole run.
type TaskErrorFunc func(task ScanTask, stage string, err error)

// ScanTask represents a file candidate to scan.
type ScanTask struct {
	Path   string
	Source string
	Mode   ScanMode
}

// FileScanResult is the normalized output for a single file scan.
type FileScanResult struct {
	ScanResult     *ScanResult        `json:"-"`
	ScanMode       *ScanMode          `json:"scan_mode"`
	SmartEnabled   *bool              `json:"smart_enabled"`
	Source         *string            `json:"source"`
	LastScanTime   *time.Time         `json:"-"`
	Hostname       *string            `json:"hostname"`
	DisplayIP      *string            `json:"displayIp"`
	ExternalIPList []string           `json:"externalIpList"`
	InternalIPList []string           `json:"internalIpList"`
	BasicInfo      *FileBasicInfo     `json:"basic_info"`
	Hashes         *FileHashes        `json:"hashes"`
	Signature      *FileSignatureInfo `json:"signature"`
	BinaryInfo     *FileBinaryInfo    `json:"binary_info"`
	Context        *FileContextInfo   `json:"context"`
}

// FileBasicInfo captures basic file metadata.
type FileBasicInfo struct {
	FilePath         *string    `json:"file_path"`
	FileName         *string    `json:"file_name"`
	FileSizeBytes    *int64     `json:"file_size_bytes"`
	CreationTime     *time.Time `json:"creation_time"`
	ModificationTime *time.Time `json:"modification_time"`
	AccessTime       *time.Time `json:"access_time"`
	Attributes       []string   `json:"attributes"`
	Owner            *string    `json:"owner"`
	Group            *string    `json:"group"`
	Mode             *string    `json:"mode"`
}

// FileHashes captures cryptographic and import hashes.
type FileHashes struct {
	Sha256  *string `json:"sha256"`
	Imphash *string `json:"imphash"`
}

// FileSignatureInfo captures Authenticode/signature details.
type FileSignatureInfo struct {
	IsSigned              *bool   `json:"is_signed"`
	SignatureValid        *bool   `json:"signature_valid"`
	SignerSubject         *string `json:"signer_subject"`
	CertificateThumbprint *string `json:"certificate_thumbprint"`
}

// FileImport describes imported libraries and functions.
type FileImport struct {
	Dll       *string  `json:"dll"`
	Functions []string `json:"functions"`
}

// FileSectionInfo captures per-section metrics.
type FileSectionInfo struct {
	Name    *string  `json:"name"`
	Size    *int64   `json:"size"`
	Entropy *float64 `json:"entropy"`
}

// FileVersionInfo captures embedded version metadata.
type FileVersionInfo struct {
	OriginalFilename *string `json:"original_filename"`
	FileDescription  *string `json:"file_description"`
}

// FileBinaryInfo captures PE/ELF internals.
type FileBinaryInfo struct {
	MagicBytes        *string           `json:"magic_bytes"`
	ImportedLibraries []FileImport      `json:"imported_libraries"`
	SectionsInfo      []FileSectionInfo `json:"sections_info"`
	VersionInfo       *FileVersionInfo  `json:"version_info"`
}

// FileContextInfo captures contextual metadata like MOTW.
type FileContextInfo struct {
	MotwZoneID  *int    `json:"motw_zone_id"`
	DownloadURL *string `json:"download_url"`
}

type FileMeta struct {
	Path         string
	Name         string
	Size         int64
	ModifiedTime time.Time
	CreationTime *time.Time
	AccessTime   *time.Time
	Attributes   []string
	Owner        *string
	Group        *string
	Mode         *string
}

func strPtr(val string) *string {
	return &val
}

func int64Ptr(val int64) *int64 {
	return &val
}

func float64Ptr(val float64) *float64 {
	return &val
}

func boolPtr(val bool) *bool {
	return &val
}

func timePtr(val time.Time) *time.Time {
	return &val
}

func scanModePtr(val ScanMode) *ScanMode {
	return &val
}

func scanResultPtr(val ScanResult) *ScanResult {
	return &val
}
