package softwarescan

import (
	"testing"

	"edrsystem/internal/processscan"
)

func TestDetectSoftwareNameIgnoresUnrelatedArgsKeyword(t *testing.T) {
	proc := processscan.ProcessInfo{
		Name:      strPtr("c-eyes"),
		Path:      strPtr("/usr/local/bin/c-eyes"),
		StartArgs: strPtr("hostscan --custom application -appName nginx"),
	}

	got := detectSoftwareName(proc)
	if got != "c-eyes" {
		t.Fatalf("expected software name c-eyes, got %q", got)
	}
}

func TestDetectSoftwareNameTomcatFromJavaMarkers(t *testing.T) {
	proc := processscan.ProcessInfo{
		Name: strPtr("java"),
		Path: strPtr("/usr/lib/jvm/java-17-openjdk/bin/java"),
		StartArgs: strPtr(
			"-Dcatalina.base=/opt/tomcat -Dcatalina.home=/opt/tomcat org.apache.catalina.startup.Bootstrap start",
		),
	}

	got := detectSoftwareName(proc)
	if got != "tomcat" {
		t.Fatalf("expected software name tomcat, got %q", got)
	}
}

func TestSoftwareFromProcessNotMislabelledByArgsKeyword(t *testing.T) {
	proc := processscan.ProcessInfo{
		PID:       intPtr(1234),
		Name:      strPtr("c-eyes"),
		Path:      strPtr("/usr/local/bin/c-eyes"),
		StartArgs: strPtr("hostscan --custom application -appName nginx -o /tmp/out.json"),
		Uname:     strPtr("root"),
	}

	row, ok := softwareFromProcess(proc)
	if !ok {
		t.Fatalf("expected process to be collected")
	}
	if row.Name == nil || *row.Name != "c-eyes" {
		t.Fatalf("expected row name c-eyes, got %+v", row.Name)
	}
}

