//go:build !yarax

package riskanalysis

import "errors"

// ErrYaraXUnavailable indicates the build lacks yara-x integration.
var ErrYaraXUnavailable = errors.New("yara-x integration not enabled (build with -tags yarax)")

// YaraXConfig describes local rule settings.
type YaraXConfig struct {
	RulesPath     string
	ReadChunkSize int
}

// NewYaraXEngine creates a degraded engine when yarax is not enabled.
func NewYaraXEngine(config YaraXConfig) (YaraXEngine, error) {
	return newNoopYaraXEngine(config, ErrYaraXUnavailable.Error())
}
