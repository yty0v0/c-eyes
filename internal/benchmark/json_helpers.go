package benchmark

import (
	"encoding/json"
	"fmt"
)

func mustMarshalPrettyJSON(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Sprint(value)
	}
	return string(data)
}

func composeStructuredEvidence(legacyOutput string, structured any) string {
	return mustMarshalPrettyJSON(map[string]any{
		"legacy_output": legacyOutput,
		"structured":    structured,
	})
}
