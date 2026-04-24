//go:build linux

package usergroupscan

import (
	"context"
	"os"
)

const linuxGroupPath = "/etc/group"

func collectUserGroups(ctx context.Context) ([]UserGroupInfo, error) {
	_ = ctx

	data, err := os.ReadFile(linuxGroupPath)
	if err != nil {
		return nil, err
	}

	entries := parseGroupFile(data)
	out := make([]UserGroupInfo, 0, len(entries))
	for _, entry := range entries {
		members := make([]GroupMember, 0, len(entry.Members))
		for _, member := range entry.Members {
			members = append(members, GroupMember{
				Name: strPtr(member),
				Type: nil,
			})
		}
		out = append(out, UserGroupInfo{
			Name:    strPtr(entry.Name),
			GID:     int64Ptr(entry.GID),
			Members: members,
		})
	}
	return out, nil
}
