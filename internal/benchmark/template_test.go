package benchmark

import (
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeTemplateDefaultAuto(t *testing.T) {
	t.Parallel()

	got, err := NormalizeTemplate("")
	if err != nil {
		t.Fatalf("NormalizeTemplate returned error: %v", err)
	}
	if got != TemplateAuto {
		t.Fatalf("expected %q, got %q", TemplateAuto, got)
	}
}

func TestNormalizeTemplateRejectsInvalid(t *testing.T) {
	t.Parallel()

	_, err := NormalizeTemplate("invalid")
	if err == nil {
		t.Fatal("expected invalid template error")
	}
}

func TestDetectLinuxTemplateFromOSRelease(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		want    Template
	}{
		{
			name: "EulerOS by id",
			content: `
ID=euleros
ID_LIKE="rhel fedora"
`,
			want: TemplateEulerOS,
		},
		{
			name: "Kylin by id_like",
			content: `
ID="linux"
ID_LIKE="kylin ubuntu"
`,
			want: TemplateKylin,
		},
		{
			name: "fallback linux",
			content: `
ID=ubuntu
ID_LIKE=debian
`,
			want: TemplateLinux,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := detectLinuxTemplateFromOSRelease(tc.content)
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestResolveTemplateAutoUsesRuntimeTemplate(t *testing.T) {
	t.Parallel()

	want, err := detectTemplateFromRuntime(runtime.GOOS)
	if err != nil {
		t.Fatalf("detectTemplateFromRuntime returned error: %v", err)
	}

	got, err := resolveTemplate(TemplateAuto)
	if err != nil {
		t.Fatalf("resolveTemplate returned error: %v", err)
	}
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestResolveTemplateAcceptsExplicitRuntimeTemplate(t *testing.T) {
	t.Parallel()

	expected, err := detectTemplateFromRuntime(runtime.GOOS)
	if err != nil {
		t.Fatalf("detectTemplateFromRuntime returned error: %v", err)
	}

	got, err := resolveTemplate(expected)
	if err != nil {
		t.Fatalf("resolveTemplate returned error: %v", err)
	}
	if got != expected {
		t.Fatalf("expected %q, got %q", expected, got)
	}
}

func TestResolveTemplateRejectsMismatchedExplicitTemplate(t *testing.T) {
	t.Parallel()

	var mismatched Template
	switch runtime.GOOS {
	case "windows":
		mismatched = TemplateLinux
	case "linux":
		mismatched = TemplateWindows
	default:
		t.Skipf("skip unsupported runtime for mismatch test: %s", runtime.GOOS)
	}

	_, err := resolveTemplate(mismatched)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "does not match current system") {
		t.Fatalf("unexpected error: %v", err)
	}
}
