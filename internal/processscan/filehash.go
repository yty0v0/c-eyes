package processscan

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"os"
)

func fileMD5(path string) (*string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	h := md5.New()
	if _, err := io.Copy(h, file); err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	return strPtr(sum), nil
}

func fileSize(path string) (*int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	size := info.Size()
	return int64Ptr(size), nil
}
