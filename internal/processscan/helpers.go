package processscan

func nullableString(val string, fallback string) *string {
	if val != "" {
		return strPtr(val)
	}
	if fallback != "" {
		return strPtr(fallback)
	}
	return nil
}
