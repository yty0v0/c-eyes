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
