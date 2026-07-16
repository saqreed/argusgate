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
	if !strings.Contains(stdout.String(), "argusgate version 0.3.0") {
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

func TestFormatSARIFAndSARIFFile(t *testing.T) {
	sarifPath := filepath.Join(t.TempDir(), "argusgate.sarif")
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"fixtures", "scan",
		"--path", repoPath(t, "examples", "fixtures", "malicious-tools.yaml"),
		"--policy", repoPath(t, "examples", "policies", "default.yaml"),
		"--format", "sarif",
		"--sarif", sarifPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("sarif scan exit code = %d, stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var stdoutSARIF map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &stdoutSARIF); err != nil {
		t.Fatalf("stdout is not SARIF JSON: %v\n%s", err, stdout.String())
	}
	if stdoutSARIF["version"] != "2.1.0" {
		t.Fatalf("unexpected stdout SARIF version: %#v", stdoutSARIF["version"])
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("SARIF file not written: %v", err)
	}
	var fileSARIF map[string]any
	if err := json.Unmarshal(data, &fileSARIF); err != nil {
		t.Fatalf("SARIF file is not JSON: %v\n%s", err, string(data))
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

func TestSubcommandHelpExitsZero(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--help"},
		{"policy", "--help"},
		{"fixtures", "--help"},
		{"inspect", "--help"},
		{"baseline", "--help"},
		{"rules", "--help"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 0 {
			t.Fatalf("%v exit code = %d, stderr=%s", args, code, stderr.String())
		}
	}
}

func TestBaselineCreateScanDriftAndUpdate(t *testing.T) {
	fixturePath := filepath.Join(t.TempDir(), "fixture.yaml")
	source, err := os.ReadFile(repoPath(t, "examples", "fixtures", "safe-tools.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixturePath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(t.TempDir(), "baseline.json")

	var stdout, stderr bytes.Buffer
	if code := Run([]string{
		"baseline", "create", "--fixtures", fixturePath, "--output", baselinePath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("baseline create exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("baseline was not created: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{
		"fixtures", "scan", "--path", fixturePath, "--baseline", baselinePath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("unchanged baseline scan exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	changed := strings.Replace(string(source), "Read a file under ./examples", "Read and export a file under ./examples", 1)
	if err := os.WriteFile(fixturePath, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{
		"fixtures", "scan", "--path", fixturePath, "--baseline", baselinePath,
	}, &stdout, &stderr); code != 1 {
		t.Fatalf("drift scan exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "AG-BASE002") {
		t.Fatalf("drift finding not shown: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{
		"baseline", "update", "--fixtures", fixturePath, "--baseline", baselinePath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("baseline update exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{
		"fixtures", "scan", "--path", fixturePath, "--baseline", baselinePath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("updated baseline scan exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestBaselineCreateRefusesExistingOutput(t *testing.T) {
	output := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(output, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"baseline", "create",
		"--fixtures", repoPath(t, "examples", "fixtures", "safe-tools.yaml"),
		"--output", output,
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "do not replace" {
		t.Fatalf("existing baseline was modified: %q", data)
	}
}

func TestRulesListAndShow(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"rules", "list", "--format", "json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("rules list exit=%d stderr=%s", code, stderr.String())
	}
	var entries []map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &entries); err != nil {
		t.Fatalf("rules list is not JSON: %v\n%s", err, stdout.String())
	}
	if len(entries) == 0 {
		t.Fatal("rules list is empty")
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"rules", "show", "AG-MCP001"}, &stdout, &stderr); code != 0 {
		t.Fatalf("rules show exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Invalid or missing tool input schema") {
		t.Fatalf("unexpected rules show output: %s", stdout.String())
	}
}

func TestInspectRejectsNonHTTPSBeforeNetwork(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"inspect", "--url", "http://127.0.0.1:65535/mcp"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "requires an https:// endpoint") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestUnexpectedArgumentExitsTwo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"fixtures", "scan", "--path", repoPath(t, "examples", "fixtures", "safe-tools.yaml"), "unexpected"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "unexpected argument") {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
}

func TestErrorsRemoveTerminalControlSequences(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"fixtures", "scan", "--path", repoPath(t, "examples", "fixtures", "safe-tools.yaml"), "--format", "\x1b[31mxml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit code = %d", code)
	}
	if strings.ContainsRune(stderr.String(), '\x1b') {
		t.Fatalf("terminal escape leaked to stderr: %q", stderr.String())
	}
}

func TestOutputPathMustNotOverwriteInputOrAnotherOutput(t *testing.T) {
	input := repoPath(t, "examples", "fixtures", "safe-tools.yaml")
	same := filepath.Join(t.TempDir(), "same-output")
	cases := [][]string{
		{"fixtures", "scan", "--path", input, "--report", input},
		{"fixtures", "scan", "--path", input, "--report", same, "--sarif", same},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("%v exit code = %d, stderr=%s", args, code, stderr.String())
		}
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
