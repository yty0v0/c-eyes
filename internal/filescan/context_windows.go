//go:build windows

package filescan

import (
	"os"
	"strconv"
	"strings"
)

func fileContextInfo(path string) *FileContextInfo {
	zonePath := path + ":Zone.Identifier"
	payload, err := os.ReadFile(zonePath)
	if err != nil {
		return nil
	}

	var zoneID *int
	var downloadURL *string
	lines := strings.Split(string(payload), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "ZoneId=") {
			val := strings.TrimPrefix(line, "ZoneId=")
			if id, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				zoneID = &id
			}
			continue
		}
		if strings.HasPrefix(line, "HostUrl=") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "HostUrl="))
			if val != "" {
				downloadURL = &val
			}
			continue
		}
		if strings.HasPrefix(line, "ReferrerUrl=") && downloadURL == nil {
			val := strings.TrimSpace(strings.TrimPrefix(line, "ReferrerUrl="))
			if val != "" {
				downloadURL = &val
			}
		}
	}

	if zoneID == nil && downloadURL == nil {
		return nil
	}
	return &FileContextInfo{
		MotwZoneID:  zoneID,
		DownloadURL: downloadURL,
	}
}
