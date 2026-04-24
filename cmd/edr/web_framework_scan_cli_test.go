package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestWebFrameworkScanDefaultJSONOutputCLIPath(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperWebFrameworkScanCommand", "--")
	cmd.Env = append(os.Environ(), "GO_WANT_WEB_FRAME_HELPER=1")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("web-framework-scan helper failed: %v, stderr=%s", err, stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("stdout is not valid json: %v, output=%s", err, stdout.String())
	}

	if _, ok := payload["total"]; !ok {
		t.Fatalf("json missing total: %+v", payload)
	}
	if _, ok := payload["rows"].([]any); !ok {
		t.Fatalf("json rows is not an array: %+v", payload["rows"])
	}
}

func TestHelperWebFrameworkScanCommand(t *testing.T) {
	if os.Getenv("GO_WANT_WEB_FRAME_HELPER") != "1" {
		return
	}
	webFrameworkScan([]string{})
	os.Exit(0)
}
