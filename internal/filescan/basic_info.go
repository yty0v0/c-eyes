package filescan

func basicInfoFromMeta(path string, meta *FileMeta) *FileBasicInfo {
	basic := &FileBasicInfo{
		FilePath: strPtr(path),
	}
	if meta == nil {
		return basic
	}

	if meta.Path != "" {
		basic.FilePath = strPtr(meta.Path)
	}
	if meta.Name != "" {
		basic.FileName = strPtr(meta.Name)
	}
	basic.FileSizeBytes = int64Ptr(meta.Size)

	mod := normalizeTime(meta.ModifiedTime)
	basic.ModificationTime = &mod

	if meta.CreationTime != nil {
		creation := normalizeTime(*meta.CreationTime)
		basic.CreationTime = &creation
	}
	if meta.AccessTime != nil {
		access := normalizeTime(*meta.AccessTime)
		basic.AccessTime = &access
	}
	if len(meta.Attributes) > 0 {
		basic.Attributes = meta.Attributes
	}
	if meta.Owner != nil {
		basic.Owner = meta.Owner
	}
	if meta.Group != nil {
		basic.Group = meta.Group
	}
	if meta.Mode != nil {
		basic.Mode = meta.Mode
	}
	return basic
}
