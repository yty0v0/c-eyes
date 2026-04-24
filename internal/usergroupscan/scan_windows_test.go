//go:build windows

package usergroupscan

import (
	"context"
	"testing"
)

type mockWindowsGroupAPI struct{}

func (m *mockWindowsGroupAPI) EnumLocalGroups() ([]windowsGroup, error) {
	return []windowsGroup{
		{
			Name:        "Administrators",
			Description: "Built-in administrators group",
		},
	}, nil
}

func (m *mockWindowsGroupAPI) GroupMembers(name string) ([]GroupMember, error) {
	_ = name
	return []GroupMember{
		{Name: strPtr("DESKTOP\\alice"), Type: intPtr(1)},
		{Name: strPtr("DESKTOP\\alice"), Type: intPtr(1)},
		{Name: strPtr("DESKTOP\\bob"), Type: intPtr(1)},
	}, nil
}

func TestCollectUserGroupsWithMockWindowsAPI(t *testing.T) {
	orig := windowsGroupAPIProvider
	windowsGroupAPIProvider = func() windowsGroupAPI { return &mockWindowsGroupAPI{} }
	defer func() { windowsGroupAPIProvider = orig }()

	got, err := collectUserGroups(context.Background())
	if err != nil {
		t.Fatalf("collectUserGroups error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 group, got %d", len(got))
	}
	group := got[0]
	if group.Name == nil || *group.Name != "Administrators" {
		t.Fatalf("unexpected name: %+v", group.Name)
	}
	if group.Description == nil || *group.Description == "" {
		t.Fatalf("unexpected description: %+v", group.Description)
	}
	if len(group.Members) != 3 {
		t.Fatalf("expected members from mock provider, got %d", len(group.Members))
	}
}
