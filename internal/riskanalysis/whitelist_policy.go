package riskanalysis

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WhitelistPolicy defines rule sets for whitelist funnel evaluation.
type WhitelistPolicy struct {
	Version             string                 `json:"version,omitempty"`
	TrustedPublishers   []TrustedPublisherRule `json:"trusted_publishers,omitempty"`
	RevokedCertificates []CertificateRule      `json:"revoked_certificates,omitempty"`
	VulnerableDrivers   []VulnerableDriverRule `json:"vulnerable_drivers,omitempty"`
	BusinessPathRules   []BusinessPathRule     `json:"business_path_rules,omitempty"`
	LolbinRules         []LOLBinRule           `json:"lolbin_rules,omitempty"`
	NSRLHashFiles       []string               `json:"nsrl_hash_files,omitempty"`
	EnterpriseHashFiles []string               `json:"enterprise_hash_files,omitempty"`
	NSRLHashes          []string               `json:"nsrl_hashes,omitempty"`
	EnterpriseHashes    []string               `json:"enterprise_hashes,omitempty"`
	LocalCacheTTL       string                 `json:"local_cache_ttl,omitempty"`
	LocalCacheCapacity  int                    `json:"local_cache_capacity,omitempty"`
}

type TrustedPublisherRule struct {
	ID           string   `json:"id,omitempty"`
	Publisher    string   `json:"publisher,omitempty"`
	Products     []string `json:"products,omitempty"`
	RequireValid bool     `json:"require_valid"`
}

type CertificateRule struct {
	ID         string `json:"id,omitempty"`
	Thumbprint string `json:"thumbprint,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
}

type VulnerableDriverRule struct {
	ID           string   `json:"id,omitempty"`
	Name         string   `json:"name,omitempty"`
	Hashes       []string `json:"hashes,omitempty"`
	PathContains []string `json:"path_contains,omitempty"`
	Signers      []string `json:"signers,omitempty"`
}

type BusinessPathRule struct {
	ID              string   `json:"id,omitempty"`
	PathPrefix      string   `json:"path_prefix,omitempty"`
	AllowedParents  []string `json:"allowed_parents,omitempty"`
	ParentPathHints []string `json:"parent_path_hints,omitempty"`
}

type LOLBinRule struct {
	ID       string              `json:"id,omitempty"`
	Binary   string              `json:"binary,omitempty"`
	Commands []LOLBinCommandRule `json:"commands,omitempty"`
}

type LOLBinCommandRule struct {
	ID      string `json:"id,omitempty"`
	Pattern string `json:"pattern,omitempty"`
	Match   string `json:"match,omitempty"` // exact|prefix|contains
}

// LoadWhitelistPolicy loads policy from configured file location.
func LoadWhitelistPolicy() (*WhitelistPolicy, string, error) {
	path := whitelistPolicyPath()
	if path == "" {
		policy := DefaultWhitelistPolicy()
		return &policy, "", nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}
	data = bytesTrimBOM(data)

	var policy WhitelistPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, path, fmt.Errorf("whitelist policy parse failed: %w", err)
	}
	policy.normalize()
	if err := policy.Validate(); err != nil {
		return nil, path, err
	}
	return &policy, path, nil
}

// DefaultWhitelistPolicy provides safe defaults when no policy file is present.
func DefaultWhitelistPolicy() WhitelistPolicy {
	return WhitelistPolicy{
		Version: "1",
		TrustedPublishers: []TrustedPublisherRule{
			{ID: "trusted-microsoft", Publisher: "microsoft", RequireValid: true},
			{ID: "trusted-google", Publisher: "google", RequireValid: true},
			{ID: "trusted-vmware", Publisher: "vmware", RequireValid: true},
			{ID: "trusted-adobe", Publisher: "adobe", RequireValid: true},
		},
		LolbinRules: []LOLBinRule{
			{ID: "lolbin-powershell", Binary: "powershell.exe"},
			{ID: "lolbin-cmd", Binary: "cmd.exe"},
			{ID: "lolbin-wmic", Binary: "wmic.exe"},
			{ID: "lolbin-certutil", Binary: "certutil.exe"},
		},
		VulnerableDrivers: []VulnerableDriverRule{
			{ID: "byovd-capcom", Name: "capcom.sys", PathContains: []string{`\\drivers\\capcom.sys`}},
			{ID: "byovd-gigabyte", Name: "gdrv.sys", PathContains: []string{`\\drivers\\gdrv.sys`}},
		},
		LocalCacheTTL:      (10 * time.Minute).String(),
		LocalCacheCapacity: 4096,
	}
}

func (p *WhitelistPolicy) Validate() error {
	if p == nil {
		return fmt.Errorf("whitelist policy is nil")
	}
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("whitelist policy missing version")
	}
	for _, rule := range p.LolbinRules {
		for _, cmd := range rule.Commands {
			match := strings.ToLower(strings.TrimSpace(cmd.Match))
			if match == "" {
				continue
			}
			switch match {
			case "exact", "prefix", "contains":
			default:
				return fmt.Errorf("lolbin command rule %q has invalid match mode %q", cmd.ID, cmd.Match)
			}
		}
	}
	return nil
}

func (p *WhitelistPolicy) normalize() {
	if p == nil {
		return
	}
	if strings.TrimSpace(p.Version) == "" {
		p.Version = "1"
	}
	if p.LocalCacheCapacity <= 0 {
		p.LocalCacheCapacity = 4096
	}
	if strings.TrimSpace(p.LocalCacheTTL) == "" {
		p.LocalCacheTTL = (10 * time.Minute).String()
	}

	for i := range p.TrustedPublishers {
		p.TrustedPublishers[i].Publisher = strings.ToLower(strings.TrimSpace(p.TrustedPublishers[i].Publisher))
		for j := range p.TrustedPublishers[i].Products {
			p.TrustedPublishers[i].Products[j] = strings.ToLower(strings.TrimSpace(p.TrustedPublishers[i].Products[j]))
		}
	}
	for i := range p.RevokedCertificates {
		p.RevokedCertificates[i].Thumbprint = normalizeHex(p.RevokedCertificates[i].Thumbprint)
		p.RevokedCertificates[i].Serial = normalizeHex(p.RevokedCertificates[i].Serial)
		p.RevokedCertificates[i].Issuer = strings.ToLower(strings.TrimSpace(p.RevokedCertificates[i].Issuer))
	}
	for i := range p.VulnerableDrivers {
		p.VulnerableDrivers[i].Name = strings.ToLower(strings.TrimSpace(p.VulnerableDrivers[i].Name))
		for j := range p.VulnerableDrivers[i].Hashes {
			p.VulnerableDrivers[i].Hashes[j] = normalizeHex(p.VulnerableDrivers[i].Hashes[j])
		}
		for j := range p.VulnerableDrivers[i].PathContains {
			p.VulnerableDrivers[i].PathContains[j] = strings.ToLower(strings.TrimSpace(p.VulnerableDrivers[i].PathContains[j]))
		}
		for j := range p.VulnerableDrivers[i].Signers {
			p.VulnerableDrivers[i].Signers[j] = strings.ToLower(strings.TrimSpace(p.VulnerableDrivers[i].Signers[j]))
		}
	}
	for i := range p.BusinessPathRules {
		p.BusinessPathRules[i].PathPrefix = normalizePathLike(p.BusinessPathRules[i].PathPrefix)
		for j := range p.BusinessPathRules[i].AllowedParents {
			p.BusinessPathRules[i].AllowedParents[j] = strings.ToLower(strings.TrimSpace(p.BusinessPathRules[i].AllowedParents[j]))
		}
		for j := range p.BusinessPathRules[i].ParentPathHints {
			p.BusinessPathRules[i].ParentPathHints[j] = normalizePathLike(p.BusinessPathRules[i].ParentPathHints[j])
		}
	}
	for i := range p.LolbinRules {
		p.LolbinRules[i].Binary = strings.ToLower(strings.TrimSpace(filepath.Base(p.LolbinRules[i].Binary)))
		for j := range p.LolbinRules[i].Commands {
			p.LolbinRules[i].Commands[j].Pattern = strings.TrimSpace(p.LolbinRules[i].Commands[j].Pattern)
			match := strings.ToLower(strings.TrimSpace(p.LolbinRules[i].Commands[j].Match))
			if match == "" {
				match = "exact"
			}
			p.LolbinRules[i].Commands[j].Match = match
		}
	}
	for i := range p.NSRLHashes {
		p.NSRLHashes[i] = normalizeHex(p.NSRLHashes[i])
	}
	for i := range p.EnterpriseHashes {
		p.EnterpriseHashes[i] = normalizeHex(p.EnterpriseHashes[i])
	}
}

func whitelistPolicyPath() string {
	if path := strings.TrimSpace(os.Getenv("C_EYES_WHITELIST_POLICY")); path != "" {
		if fileExists(path) {
			return path
		}
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidate := filepath.Join(exeDir, "c-eyes-whitelist.json")
		if fileExists(candidate) {
			return candidate
		}
	}
	if fileExists("c-eyes-whitelist.json") {
		return "c-eyes-whitelist.json"
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidate := filepath.Join(home, ".c-eyes", "whitelist.json")
		if fileExists(candidate) {
			return candidate
		}
	}
	return ""
}

func normalizeHex(val string) string {
	val = strings.TrimSpace(strings.ToLower(val))
	val = strings.ReplaceAll(val, " ", "")
	val = strings.ReplaceAll(val, ":", "")
	val = strings.ReplaceAll(val, "-", "")
	return val
}

func normalizePathLike(val string) string {
	val = strings.TrimSpace(strings.ToLower(val))
	val = strings.ReplaceAll(val, "/", `\`)
	return val
}
