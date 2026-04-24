package main

import (
	"path/filepath"
	"testing"

	"edrsystem/internal/accountscan"
)

func TestWriteAccountExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.xlsx")
	rows := []accountscan.AccountInfo{
		{
			Name: accountscanStrPtr("alice"),
			UID:  accountscanInt64Ptr(1001),
			GID:  accountscanInt64Ptr(1001),
		},
	}
	if err := writeAccountExcel(path, rows); err != nil {
		t.Fatalf("writeAccountExcel error: %v", err)
	}
}

func accountscanStrPtr(v string) *string {
	return &v
}

func accountscanInt64Ptr(v int64) *int64 {
	return &v
}
