package main

import (
	"path/filepath"
	"testing"

	"edrsystem/internal/usergroupscan"
)

func TestWriteUserGroupExcel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "user-group.xlsx")
	rows := []usergroupscan.UserGroupInfo{
		{
			Name: userGroupStrPtr("developers"),
			GID:  userGroupInt64Ptr(1000),
			Members: []usergroupscan.GroupMember{
				{Name: userGroupStrPtr("alice")},
			},
		},
	}
	if err := writeUserGroupExcel(path, rows); err != nil {
		t.Fatalf("writeUserGroupExcel error: %v", err)
	}
}

func userGroupStrPtr(v string) *string {
	return &v
}

func userGroupInt64Ptr(v int64) *int64 {
	return &v
}
