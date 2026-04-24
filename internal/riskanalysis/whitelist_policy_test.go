package riskanalysis

import "testing"

func TestWhitelistPolicyValidateInvalidMatchMode(t *testing.T) {
	policy := WhitelistPolicy{
		Version: "1",
		LolbinRules: []LOLBinRule{
			{
				Binary: "powershell.exe",
				Commands: []LOLBinCommandRule{
					{ID: "bad", Pattern: "powershell.exe", Match: "regex"},
				},
			},
		},
	}
	policy.normalize()
	if err := policy.Validate(); err == nil {
		t.Fatal("expected validation error for invalid match mode")
	}
}

func TestDefaultWhitelistPolicyHasSafeDefaults(t *testing.T) {
	policy := DefaultWhitelistPolicy()
	policy.normalize()
	if err := policy.Validate(); err != nil {
		t.Fatalf("default policy should validate, got %v", err)
	}
	if len(policy.TrustedPublishers) == 0 {
		t.Fatal("expected default trusted publishers")
	}
	if len(policy.LolbinRules) == 0 {
		t.Fatal("expected default lolbin rules")
	}
}
