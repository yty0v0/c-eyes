package jarpackagescan

import (
	"context"
	"strings"
	"testing"

	"edrsystem/internal/processscan"
	"edrsystem/internal/webframescan"
)

func TestExtractJarPathsFromProcessAdversarialInputs(t *testing.T) {
	tests := []struct {
		name string
		proc processscan.ProcessInfo
		want int
	}{
		{
			name: "command injection tokens are ignored",
			proc: processscan.ProcessInfo{
				Path:      strPtr("/usr/bin/java"),
				StartArgs: strPtr("-jar ../app/core-1.2.3.jar ; rm -rf / --not-executed"),
			},
			want: 1,
		},
		{
			name: "quoted windows path and duplicate are deduped",
			proc: processscan.ProcessInfo{
				Path:      strPtr(`C:\Program Files\Java\bin\java.exe`),
				StartArgs: strPtr(`-jar "..\\lib\\Core-2.0.0.JAR" -cp ..\\lib\\core-2.0.0.jar`),
			},
			want: 1,
		},
		{
			name: "non jar payload should be ignored",
			proc: processscan.ProcessInfo{
				Path:      strPtr("/usr/bin/python3"),
				StartArgs: strPtr("-m http.server --bind 0.0.0.0"),
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJarPathsFromProcess(tt.proc)
			if len(got) != tt.want {
				t.Fatalf("expected %d jar paths, got %d: %+v", tt.want, len(got), got)
			}
			seen := map[string]struct{}{}
			for _, path := range got {
				if !strings.HasSuffix(strings.ToLower(path), ".jar") {
					t.Fatalf("unexpected non-jar path: %q", path)
				}
				key := strings.ToLower(path)
				if _, ok := seen[key]; ok {
					t.Fatalf("unexpected duplicated path: %q", path)
				}
				seen[key] = struct{}{}
			}
		})
	}
}

func TestMergeRowsAdversarialConflictResolution(t *testing.T) {
	rows := []JarPackageRecord{
		{
			Hostname:       strPtr("NODE-01"),
			Name:           strPtr("Core-1.2.3.jar"),
			Path:           strPtr(`/opt/app/lib/core-1.2.3.jar`),
			InternalIPList: []string{"10.0.0.8"},
			HostTagList:    []string{"prod"},
			Version:        strPtr("1.2.3"),
			Type:           intPtr(8),
			Executable:     boolPtr(false),
		},
		{
			Hostname:       strPtr("node-01"),
			Name:           strPtr("core-1.2.3.jar"),
			Path:           strPtr(`/opt/app/lib/CORE-1.2.3.JAR`),
			ExternalIPList: []string{"203.0.113.9"},
			HostTagList:    []string{"critical"},
		},
	}

	merged := mergeRows(rows)
	if len(merged) != 1 {
		t.Fatalf("expected merge result size=1, got %d", len(merged))
	}
	row := merged[0]
	if len(row.InternalIPList) != 1 || row.InternalIPList[0] != "10.0.0.8" {
		t.Fatalf("expected internal ip to be preserved, got %+v", row.InternalIPList)
	}
	if len(row.ExternalIPList) != 1 || row.ExternalIPList[0] != "203.0.113.9" {
		t.Fatalf("expected external ip to be merged, got %+v", row.ExternalIPList)
	}
	if len(row.HostTagList) != 2 {
		t.Fatalf("expected tag list merge, got %+v", row.HostTagList)
	}
	if row.Version == nil || *row.Version != "1.2.3" {
		t.Fatalf("expected version fallback keep, got %+v", row.Version)
	}
}

func TestScanSurvivesProcessCollectorFailure(t *testing.T) {
	origWeb := scanWebFrameFn
	origProc := scanProcessFn
	scanWebFrameFn = func(ctx context.Context, params webframescan.WebFrameScanParams) (webframescan.WebFrameScanResult, error) {
		_ = ctx
		_ = params
		return webframescan.WebFrameScanResult{
			Rows: []webframescan.WebFrameRecord{
				{
					Hostname:   strPtr("resilient-node"),
					ServerName: strPtr("tomcat"),
					JarList: []webframescan.JarRecord{
						{AbsDir: strPtr("/opt/tomcat/lib"), JarName: strPtr("spring-core-6.1.2.jar")},
					},
				},
			},
		}, nil
	}
	scanProcessFn = func(ctx context.Context, params processscan.ProcessScanParams) ([]processscan.ProcessInfo, error) {
		_ = ctx
		_ = params
		return nil, context.DeadlineExceeded
	}
	defer func() {
		scanWebFrameFn = origWeb
		scanProcessFn = origProc
	}()

	result, err := Scan(context.Background(), JarPackageScanParams{})
	if err != nil {
		t.Fatalf("scan should not fail when process collector fails: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected fallback from webframe rows, got total=%d", result.Total)
	}
}

func FuzzExtractJarPathsFromProcess(f *testing.F) {
	f.Add("-jar /opt/app/core-1.2.3.jar", "/usr/bin/java")
	f.Add(`-jar "..\\lib\\demo-2.0.0.jar"`, `C:\Java\bin\java.exe`)
	f.Add("--class-path lib/a.jar:lib/b.jar", "")

	f.Fuzz(func(t *testing.T, startArgs string, procPath string) {
		proc := processscan.ProcessInfo{StartArgs: &startArgs, Path: &procPath}
		paths := extractJarPathsFromProcess(proc)
		seen := map[string]struct{}{}
		for _, path := range paths {
			if !strings.HasSuffix(strings.ToLower(path), ".jar") {
				t.Fatalf("non-jar path escaped parser: %q", path)
			}
			key := strings.ToLower(path)
			if _, ok := seen[key]; ok {
				t.Fatalf("duplicate normalized path produced: %q", path)
			}
			seen[key] = struct{}{}
		}
	})
}
