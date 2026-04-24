//go:build yarax && !cgo

package riskanalysis

import "errors"

// ErrYaraXCgoDisabled indicates CGO is required for yara-x.
var ErrYaraXCgoDisabled = errors.New("yara-x requires cgo (CGO_ENABLED=1)")

// YaraXConfig describes local rule settings.
type YaraXConfig struct {
	RulesPath     string
	ReadChunkSize int
}

// NewYaraXEngine creates a degraded engine when cgo is disabled.
func NewYaraXEngine(config YaraXConfig) (YaraXEngine, error) {
	return newNoopYaraXEngine(config, ErrYaraXCgoDisabled.Error())
}
