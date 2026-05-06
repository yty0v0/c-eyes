//go:build linux

package benchmark

import (
	"context"
	"testing"
)

func TestUnixFailedLoginCollectorsAreMapped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		template Template
		checkID  string
	}{
		{name: "linux", template: TemplateLinux, checkID: "11"},
		{name: "euleros", template: TemplateEulerOS, checkID: "11"},
		{name: "kylin", template: TemplateKylin, checkID: "5"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, handled, err := collectUnixNativeCheck(context.Background(), tc.template, tc.checkID, &unixBenchmarkCollectorState{})
			if err != nil {
				t.Fatalf("collectUnixNativeCheck(%s, %s) error = %v", tc.template, tc.checkID, err)
			}
			if !handled {
				t.Fatalf("collectUnixNativeCheck(%s, %s) was not handled", tc.template, tc.checkID)
			}
		})
	}
}
