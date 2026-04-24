package netscan

import (
	"time"
)

// ScanMode identifies a probing strategy.
type ScanMode string

const (
	ModeARP             ScanMode = "A"
	ModeICMPEcho        ScanMode = "ICP"
	ModeICMPAddressMask ScanMode = "ICA"
	ModeICMPTimestamp   ScanMode = "ICT"
	ModeTCPConnect      ScanMode = "T"
	ModeTCPSYN          ScanMode = "TS"
	ModeUDP             ScanMode = "U"
	ModeNetBIOS         ScanMode = "N"
	ModeOXID            ScanMode = "O"
	DefaultScanMode     ScanMode = ModeARP
	DefaultMaxTargets            = 4096
	DefaultPPS                   = 80
	DefaultTimeoutMS             = 900
	DefaultJitterMS              = 25
	DefaultWorkers               = 24
	MaxWorkers                   = 256
	MaxPPS                       = 5000
	DefaultSortBy                = "lastSeen"
	DefaultSortOrder             = "desc"
)

var allModes = []ScanMode{
	ModeARP,
	ModeICMPEcho,
	ModeICMPAddressMask,
	ModeICMPTimestamp,
	ModeTCPConnect,
	ModeTCPSYN,
	ModeUDP,
	ModeNetBIOS,
	ModeOXID,
}

type modeCapability struct {
	SupportsIPv4       bool
	SupportsIPv6       bool
	PermissionRequired bool
	Source             string
}

var modeCapabilities = map[ScanMode]modeCapability{
	ModeARP: {
		SupportsIPv4:       true,
		SupportsIPv6:       false,
		PermissionRequired: false,
		Source:             "arp",
	},
	ModeICMPEcho: {
		SupportsIPv4:       true,
		SupportsIPv6:       true,
		PermissionRequired: true,
		Source:             "icmp",
	},
	ModeICMPAddressMask: {
		SupportsIPv4:       true,
		SupportsIPv6:       false,
		PermissionRequired: true,
		Source:             "icmp_addressmask",
	},
	ModeICMPTimestamp: {
		SupportsIPv4:       true,
		SupportsIPv6:       false,
		PermissionRequired: true,
		Source:             "icmp_timestamp",
	},
	ModeTCPConnect: {
		SupportsIPv4:       true,
		SupportsIPv6:       true,
		PermissionRequired: false,
		Source:             "tcp_connect",
	},
	ModeTCPSYN: {
		SupportsIPv4:       true,
		SupportsIPv6:       true,
		PermissionRequired: false,
		Source:             "tcp_syn",
	},
	ModeUDP: {
		SupportsIPv4:       true,
		SupportsIPv6:       true,
		PermissionRequired: false,
		Source:             "udp",
	},
	ModeNetBIOS: {
		SupportsIPv4:       true,
		SupportsIPv6:       false,
		PermissionRequired: false,
		Source:             "netbios",
	},
	ModeOXID: {
		SupportsIPv4:       true,
		SupportsIPv6:       true,
		PermissionRequired: false,
		Source:             "oxid",
	},
}

// ProgressFunc reports scan progress.
type ProgressFunc func(done, total int, stage string)

// Params contains execute and filter options for netscan.
type Params struct {
	Target     string
	TargetFile string
	Exclude    string
	ScanModes  []ScanMode
	IPv6       bool
	// ReachableSegments enables opt-in routed segment reachability discovery.
	ReachableSegments bool
	TCPPorts          []int
	UDPPorts          []int
	MaxTargets        int
	PPS               int
	TimeoutMs         int
	JitterMs          int
	Workers           int
	ManagedSource     string

	AssetStatus string
	Keyword     string
	SortBy      string
	SortOrder   string

	Progress ProgressFunc
}

// ReachableSegmentMetric captures routed segment discovery and verification evidence.
type ReachableSegmentMetric struct {
	CIDR               string   `json:"cidr"`
	DiscoverySources   []string `json:"discoverySources"`
	NextHop            *string  `json:"nextHop,omitempty"`
	Verified           bool     `json:"verified"`
	VerificationMethod *string  `json:"verificationMethod,omitempty"`
	VerificationTarget *string  `json:"verificationTarget,omitempty"`
}

type normalizedParams struct {
	Params
	Timeout time.Duration
	Jitter  time.Duration
}

// RuntimeMetrics exposes runtime adaptation diagnostics.
type RuntimeMetrics struct {
	WorkerCeiling              int                      `json:"workerCeiling"`
	EffectiveWorkers           int                      `json:"effectiveWorkers"`
	PPSCeiling                 int                      `json:"ppsCeiling"`
	EffectivePPS               int                      `json:"effectivePps"`
	SkippedModes               []string                 `json:"skippedModes"`
	PermissionFailures         []string                 `json:"permissionFailures"`
	ReachableCandidateSegments int                      `json:"reachableCandidateSegments"`
	ReachableVerifiedSegments  int                      `json:"reachableVerifiedSegments"`
	ReachableSegments          []ReachableSegmentMetric `json:"reachableSegments,omitempty"`
}

// ScanResult is the netscan aggregate envelope.
type ScanResult struct {
	Total    int            `json:"total"`
	Rows     []AssetRow     `json:"rows"`
	Metrics  RuntimeMetrics `json:"metrics"`
	Warnings []string       `json:"warnings,omitempty"`
}

// AssetRow is the normalized netscan output record.
type AssetRow struct {
	AssetID string `json:"assetId"`

	IPAddress string `json:"ipAddress"`
	IPVersion string `json:"ipVersion"`

	MACAddress *string `json:"macAddress,omitempty"`
	MACVendor  *string `json:"macVendor,omitempty"`
	Hostname   *string `json:"hostname,omitempty"`

	OSFamily   string `json:"osFamily"`
	DeviceType string `json:"deviceType"`

	AssetStatus string `json:"assetStatus"`
	Alive       bool   `json:"alive"`

	FirstSeen int64 `json:"firstSeen"`
	LastSeen  int64 `json:"lastSeen"`

	Confidence int `json:"confidence"`

	ScanModes     []string `json:"scanModes"`
	Sources       []string `json:"sources"`
	OpenPorts     []int    `json:"openPorts"`
	OpenTCPPorts  []int    `json:"openTcpPorts"`
	OpenUDPPorts  []int    `json:"openUdpPorts"`
	PortScanModes []string `json:"portScanModes"`

	IgnoredReason *string `json:"ignoredReason,omitempty"`
}
