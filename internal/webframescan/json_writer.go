package webframescan

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON writes normalized framework records in JSON format.
func WriteJSON(w io.Writer, result WebFrameScanResult) error {
	if w == nil {
		return fmt.Errorf("json output writer is nil")
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
