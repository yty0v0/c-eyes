package jarpackagescan

import (
	"context"
	"strings"
	"testing"

	"edrsystem/internal/processscan"
	"edrsystem/internal/webframescan"
)

func TestScanStaticDynamicMergeLinuxFixture(t *testing.T) {
	origWeb := scanWebFrameFn
	origProc := scanProcessFn
	scanWebFrameFn = func(ctx context.Context, params webframescan.WebFrameScanParams) (webframescan.WebFrameScanResult, error) {
		_ = ctx
		_ = params
		return webframescan.WebFrameScanResult{
			Rows: []webframescan.WebFrameRecord{
				{
					Hostname:       strPtr("linux-node"),
					ServerName:     strPtr("tomcat"),
					InternalIPList: []string{"10.0.0.9"},
					JarList: []webframescan.JarRecord{
						{
							AbsDir:  strPtr("/opt/tomcat/lib"),
							JarName: strPtr("spring-core-6.1.2.jar"),
						},
					},
				},
			},
		}, nil
	}
	scanProcessFn = func(ctx context.Context, params processscan.ProcessScanParams) ([]processscan.ProcessInfo, error) {
		_ = ctx
		_ = params
		return []processscan.ProcessInfo{
			{
				Hostname:       strPtr("linux-node"),
				ExternalIPList: []string{"203.0.113.8"},
				StartArgs:      strPtr("-jar /opt/tomcat/lib/spring-core-6.1.2.jar"),
				Name:           strPtr("java"),
			},
		}, nil
	}
	defer func() {
		scanWebFrameFn = origWeb
		scanProcessFn = origProc
	}()

	result, err := Scan(context.Background(), JarPackageScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected merged total=1, got %d", result.Total)
	}
	row := result.Rows[0]
	if len(row.InternalIPList) != 1 || row.InternalIPList[0] != "10.0.0.9" {
		t.Fatalf("expected merged internalIpList, got %+v", row.InternalIPList)
	}
	if len(row.ExternalIPList) != 1 || row.ExternalIPList[0] != "203.0.113.8" {
		t.Fatalf("expected merged externalIpList, got %+v", row.ExternalIPList)
	}
	if row.Type == nil || *row.Type != 3 {
		t.Fatalf("expected type=3 for web bundled jar, got %+v", row.Type)
	}
}

func TestScanStaticDynamicMergeWindowsFixture(t *testing.T) {
	origWeb := scanWebFrameFn
	origProc := scanProcessFn
	scanWebFrameFn = func(ctx context.Context, params webframescan.WebFrameScanParams) (webframescan.WebFrameScanResult, error) {
		_ = ctx
		_ = params
		return webframescan.WebFrameScanResult{
			Rows: []webframescan.WebFrameRecord{
				{
					Hostname:   strPtr("win-node"),
					ServerName: strPtr("tomcat"),
					JarList: []webframescan.JarRecord{
						{
							AbsDir:  strPtr(`C:\Tomcat\lib`),
							JarName: strPtr("commons-lang3-3.14.0.jar"),
						},
					},
				},
			},
		}, nil
	}
	scanProcessFn = func(ctx context.Context, params processscan.ProcessScanParams) ([]processscan.ProcessInfo, error) {
		_ = ctx
		_ = params
		return []processscan.ProcessInfo{
			{
				Hostname:  strPtr("win-node"),
				StartArgs: strPtr(`-jar "C:\Tomcat\lib\commons-lang3-3.14.0.jar"`),
				Name:      strPtr("java"),
			},
		}, nil
	}
	defer func() {
		scanWebFrameFn = origWeb
		scanProcessFn = origProc
	}()

	result, err := Scan(context.Background(), JarPackageScanParams{})
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if result.Total != 1 {
		t.Fatalf("expected merged total=1, got %d", result.Total)
	}
	row := result.Rows[0]
	if row.Version == nil || *row.Version != "3.14.0" {
		t.Fatalf("expected parsed version=3.14.0, got %+v", row.Version)
	}
	if row.Path == nil || !strings.Contains(strings.ToLower(*row.Path), strings.ToLower("commons-lang3-3.14.0.jar")) {
		t.Fatalf("unexpected merged path: %+v", row.Path)
	}
}
