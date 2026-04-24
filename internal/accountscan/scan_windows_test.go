//go:build windows

package accountscan

import (
	"context"
	"testing"
)

type mockWindowsAPI struct{}

func (m *mockWindowsAPI) EnumUsers() ([]windowsUser, error) {
	return []windowsUser{
		{
			Name:           "alice",
			FullName:       "Alice",
			Comment:        "local user",
			Flags:          0,
			LastLogon:      1_700_000_000,
			PasswordAge:    3600,
			UserID:         1001,
			PrimaryGroupID: 513,
			HomeDir:        "C:\\Users\\alice",
		},
	}, nil
}

func (m *mockWindowsAPI) LocalGroups(name string) ([]string, error) {
	_ = name
	return []string{"Users", "Administrators"}, nil
}

func (m *mockWindowsAPI) GlobalGroups(name string) ([]string, error) {
	_ = name
	return []string{"Users"}, nil
}

func (m *mockWindowsAPI) SID(name string) (string, error) {
	_ = name
	return "S-1-5-21-1-2-3-1001", nil
}

func TestCollectAccountsWithMockWindowsAPI(t *testing.T) {
	orig := windowsAPIProvider
	windowsAPIProvider = func() windowsAccountAPI { return &mockWindowsAPI{} }
	defer func() { windowsAPIProvider = orig }()

	got, err := collectAccounts(context.Background())
	if err != nil {
		t.Fatalf("collectAccounts error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 account, got %d", len(got))
	}
	account := got[0]
	if account.Name == nil || *account.Name != "alice" {
		t.Fatalf("unexpected name: %+v", account.Name)
	}
	if account.Type == nil || *account.Type != accountTypeUser {
		t.Fatalf("unexpected type: %+v", account.Type)
	}
	if len(account.Groups) != 2 {
		t.Fatalf("expected deduped groups, got %v", account.Groups)
	}
	if account.UID == nil || *account.UID != 1001 {
		t.Fatalf("unexpected uid: %+v", account.UID)
	}
	if account.GID == nil || *account.GID != 513 {
		t.Fatalf("unexpected gid: %+v", account.GID)
	}
}
