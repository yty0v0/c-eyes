package accountscan

import "time"

var nowFn = time.Now

func nullableString(v string) *string {
	if v == "" {
		return nil
	}
	return strPtr(v)
}
