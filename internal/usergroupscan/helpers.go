package usergroupscan

func nullableString(v string) *string {
	if v == "" {
		return nil
	}
	return strPtr(v)
}
