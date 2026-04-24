package filescan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"time"
)

func fileHashes(path string) (*FileHashes, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hSha := sha256.New()
	if _, err := io.Copy(hSha, file); err != nil {
		return nil, err
	}
	shaSum := hex.EncodeToString(hSha.Sum(nil))

	hashes := &FileHashes{
		Sha256: strPtr(shaSum),
	}

	hashes.Imphash = imphashForFile(path)
	return hashes, nil
}

func normalizeTime(val time.Time) time.Time {
	return val.UTC()
}
