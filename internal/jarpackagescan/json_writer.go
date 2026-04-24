package jarpackagescan

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON writes normalized jar package records in JSON format.
func WriteJSON(w io.Writer, result JarPackageScanResult) error {
	if w == nil {
		return fmt.Errorf("json output writer is nil")
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
