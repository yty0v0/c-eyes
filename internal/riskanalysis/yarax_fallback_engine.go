package riskanalysis

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type noopYaraXEngine struct {
	warning string
}

func (e *noopYaraXEngine) MatchFile(ctx context.Context, path string) ([]YaraRuleMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []YaraRuleMatch{}, nil
}

func (e *noopYaraXEngine) MatchBytes(ctx context.Context, data []byte) ([]YaraRuleMatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []YaraRuleMatch{}, nil
}

func (e *noopYaraXEngine) YaraXWarning() string {
	if e == nil {
		return ""
	}
	return e.warning
}

type yaraXWarningProvider interface {
	YaraXWarning() string
}

// YaraXEngineWarning returns a non-empty string when engine is in degraded mode.
func YaraXEngineWarning(engine YaraXEngine) string {
	if provider, ok := engine.(yaraXWarningProvider); ok {
		return strings.TrimSpace(provider.YaraXWarning())
	}
	return ""
}

func newNoopYaraXEngine(config YaraXConfig, warning string) (YaraXEngine, error) {
	if err := validateYaraRulesPath(config.RulesPath); err != nil {
		return nil, err
	}
	return &noopYaraXEngine{warning: strings.TrimSpace(warning)}, nil
}

func validateYaraRulesPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("yara-x rules path is required")
	}

	stat, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return nil
	}

	root := filepath.Clean(path)
	ruleFoundErr := errors.New("rule_found")
	err = filepath.WalkDir(root, func(current string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(d.Name())) {
		case ".yar", ".yara", ".yr":
			return ruleFoundErr
		default:
			return nil
		}
	})
	if err == nil {
		return fmt.Errorf("no yara rules found under %s", root)
	}
	if errors.Is(err, ruleFoundErr) {
		return nil
	}
	return err
}
