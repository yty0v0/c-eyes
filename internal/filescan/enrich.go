package filescan

func enrichResult(result FileScanResult) FileScanResult {
	path := ""
	if result.BasicInfo != nil && result.BasicInfo.FilePath != nil {
		path = *result.BasicInfo.FilePath
	}
	if path == "" {
		return result
	}

	if result.BasicInfo == nil || result.BasicInfo.ModificationTime == nil || result.BasicInfo.FileName == nil {
		if meta, err := fileMeta(path); err == nil {
			result.BasicInfo = basicInfoFromMeta(path, meta)
		}
	}

	if result.Hashes == nil || result.Hashes.Sha256 == nil || result.Hashes.Imphash == nil {
		if hashes, err := fileHashes(path); err == nil {
			if result.Hashes == nil {
				result.Hashes = hashes
			} else {
				mergeHashes(result.Hashes, hashes)
			}
		}
	}

	if result.Signature == nil {
		if sig := signatureInfo(path); sig != nil {
			result.Signature = sig
		}
	}

	if result.BinaryInfo == nil {
		if binary := binaryInfo(path); binary != nil {
			result.BinaryInfo = binary
		}
	}

	if result.Context == nil {
		if ctx := fileContextInfo(path); ctx != nil {
			result.Context = ctx
		}
	}

	return result
}

func mergeHashes(dst *FileHashes, src *FileHashes) {
	if dst == nil || src == nil {
		return
	}
	if dst.Sha256 == nil {
		dst.Sha256 = src.Sha256
	}
	if dst.Imphash == nil {
		dst.Imphash = src.Imphash
	}
}
