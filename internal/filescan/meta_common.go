package filescan

import (
	"os"
	"path/filepath"
)

func fileMeta(path string) (*FileMeta, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	meta := &FileMeta{
		Path:         path,
		Name:         filepath.Base(path),
		Size:         info.Size(),
		ModifiedTime: info.ModTime(),
	}
	fillFileMetaPlatform(path, info, meta)
	return meta, nil
}
