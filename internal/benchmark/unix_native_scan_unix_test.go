//go:build !windows

package benchmark

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestComposeStructuredEvidencePreservesLegacyOutput(t *testing.T) {
	t.Parallel()

	type sample struct {
		Name string `json:"name"`
	}

	payload := composeStructuredEvidence("raw legacy output", []sample{{Name: "alpha"}})
	var decoded struct {
		LegacyOutput string   `json:"legacy_output"`
		Structured   []sample `json:"structured"`
	}
	if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
		t.Fatalf("composeStructuredEvidence returned invalid json: %v", err)
	}
	if decoded.LegacyOutput != "raw legacy output" {
		t.Fatalf("expected legacy output to be preserved, got %q", decoded.LegacyOutput)
	}
	if len(decoded.Structured) != 1 || decoded.Structured[0].Name != "alpha" {
		t.Fatalf("expected structured payload to be preserved, got %#v", decoded.Structured)
	}
}

func TestCollectUnixInterfacesIncludesDownInterfaces(t *testing.T) {
	t.Parallel()

	rows, err := collectUnixInterfaces()
	if err != nil {
		t.Fatalf("collectUnixInterfaces returned error: %v", err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces returned error: %v", err)
	}
	if len(rows) == 0 || len(ifaces) == 0 {
		t.Skip("no interfaces available in runtime environment")
	}

	gotNames := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		gotNames[strings.TrimSpace(row.Name)] = struct{}{}
	}

	for _, iface := range ifaces {
		name := strings.TrimSpace(iface.Name)
		if name == "" {
			continue
		}
		if _, ok := gotNames[name]; !ok {
			t.Fatalf("expected interface %q to be included", name)
		}
	}
}
