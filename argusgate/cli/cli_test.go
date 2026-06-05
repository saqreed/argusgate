package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunHelpAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "argusgate fixtures scan") {
		t.Fatalf("help missing fixture command: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "argusgate version 0.1.2") {
		t.Fatalf("unexpected version output: %s", stdout.String())
	}
}

func TestFixturesScanSafeExitsZeroAndWritesReport(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "safe-report.json")
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"fixtures", "scan",
		"--path", repoPath(t, "examples", "fixtures", "safe-tools.yaml"),
		"--policy", repoPath(t, "examples", "policies", "default.yaml"),
		"--report", reportPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("safe scan exit code = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "ArgusGate scan summary") {
		t.Fatalf("missing text summary: %s", stdout.String())
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("report not written: %v", err)
	}
}

func TestFixturesScanMaliciousExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"fixtures", "scan",
		"--path", repoPath(t, "examples", "fixtures", "malicious-tools.yaml"),
		"--policy", repoPath(t, "examples", "policies", "default.yaml"),
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("malicious scan exit code = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Exit: fail") {
		t.Fatalf("summary should explain failing exit: %s", stdout.String())
	}
}

func TestFormatJSONAndQuiet(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"fixtures", "scan",
		"--path", repoPath(t, "examples", "fixtures", "safe-tools.yaml"),
		"--format", "json",
		"--quiet",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("json scan exit code = %d, stderr=%s", code, stderr.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &decoded); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if decoded["source_type"] != "fixtures" {
		t.Fatalf("unexpected source_type: %#v", decoded["source_type"])
	}
}

func TestInvalidInputsExitTwo(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"missing fixture", []string{"fixtures", "scan", "--path", filepath.Join(t.TempDir(), "missing.yaml")}},
		{"invalid format", []string{"fixtures", "scan", "--path", repoPath(t, "examples", "fixtures", "safe-tools.yaml"), "--format", "xml"}},
		{"invalid fail on", []string{"fixtures", "scan", "--path", repoPath(t, "examples", "fixtures", "safe-tools.yaml"), "--fail-on", "info"}},
		{"invalid policy", []string{"policy", "validate", "--policy", writeTempPolicy(t, "version: '0.1'\ndefaults:\n  fail_on: bad\n")}},
		{"report write error", []string{"fixtures", "scan", "--path", repoPath(t, "examples", "fixtures", "safe-tools.yaml"), "--report", t.TempDir()}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tc.args, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if stderr.Len() == 0 {
				t.Fatalf("expected explanatory stderr for %s", tc.name)
			}
		})
	}
}

func TestPolicyValidate(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"policy", "validate", "--policy", repoPath(t, "examples", "policies", "default.yaml")}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("policy validate exit code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Policy valid") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
}

func repoPath(t *testing.T, elems ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	parts := append([]string{root}, elems...)
	return filepath.Join(parts...)
}

func writeTempPolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	return path
}
