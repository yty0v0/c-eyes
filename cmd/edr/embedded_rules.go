package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	embeddedrules "edrsystem/rules/yaraRules"
)

var (
	embeddedRulesOnce sync.Once
	embeddedRulesDir  string
	embeddedRulesErr  error
)

func ensureEmbeddedRulesDir() (string, error) {
	embeddedRulesOnce.Do(func() {
		tmpDir, err := os.MkdirTemp("", "c-eyes-yara-rules-")
		if err != nil {
			embeddedRulesErr = err
			return
		}

		err = fs.WalkDir(embeddedrules.RulesFS, ".", func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			cleaned := filepath.Clean(path)
			if cleaned == "." {
				return nil
			}

			dstPath := filepath.Join(tmpDir, cleaned)
			if d.IsDir() {
				return os.MkdirAll(dstPath, 0o755)
			}

			ext := strings.ToLower(filepath.Ext(d.Name()))
			switch ext {
			case ".yar", ".yara", ".yr":
			default:
				return nil
			}

			content, err := embeddedrules.RulesFS.ReadFile(path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
				return err
			}
			return os.WriteFile(dstPath, content, 0o644)
		})
		if err != nil {
			embeddedRulesErr = err
			return
		}

		embeddedRulesDir = tmpDir
	})

	return embeddedRulesDir, embeddedRulesErr
}
