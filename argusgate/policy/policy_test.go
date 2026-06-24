package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

func TestLoadFileParsesPolicy(t *testing.T) {
	path := writePolicy(t, `
version: "0.1"
defaults:
  fail-on: high
  allow-unknown-tools: false
rules:
  allow-tools:
    - read_file
  deny-tools:
    - shell_exec
`)

	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if p.Defaults.FailOn != severity.High {
		t.Fatalf("unexpected fail_on: %s", p.Defaults.FailOn)
	}
	if p.Defaults.AllowUnknownTools {
		t.Fatal("expected allow_unknown_tools=false")
	}
	if len(p.Rules.DenyTools) != 1 || p.Rules.DenyTools[0] != "shell_exec" {
		t.Fatalf("unexpected deny tools: %#v", p.Rules.DenyTools)
	}
}

func TestLoadFileRejectsInvalidSeverity(t *testing.T) {
	path := writePolicy(t, `
version: "0.1"
defaults:
  fail_on: severe
`)

	_, err := LoadFile(path)
	if err == nil {
		t.Fatal("expected invalid severity error")
	}
}

func TestExplicitDenyBeatsAllow(t *testing.T) {
	p := Default()
	p.Defaults.AllowUnknownTools = false
	p.Rules.AllowTools = []string{"shell_exec"}
	p.Rules.DenyTools = []string{"shell_exec"}

	findings := EvaluateTools(p, []mcp.ToolDefinition{{ServerID: "s1", Name: "shell_exec"}})
	if !hasFinding(findings, "AG-POL001") {
		t.Fatalf("expected deny finding, got %#v", findings)
	}
	if hasFinding(findings, "AG-POL002") {
		t.Fatalf("deny should suppress unknown-tool finding, got %#v", findings)
	}
}

func TestServerAllowOverridesGlobalAllowForUnknownCheck(t *testing.T) {
	p := Default()
	p.Defaults.AllowUnknownTools = false
	p.Rules.AllowTools = []string{"global_tool"}
	p.Servers = map[string]ServerRule{
		"s1": {AllowTools: []string{"server_tool"}},
	}

	findings := EvaluateTools(p, []mcp.ToolDefinition{{ServerID: "s1", Name: "global_tool"}})
	if !hasFinding(findings, "AG-POL002") {
		t.Fatalf("expected unknown-tool finding when server allow list is explicit, got %#v", findings)
	}

	findings = EvaluateTools(p, []mcp.ToolDefinition{{ServerID: "s1", Name: "server_tool"}})
	if hasFinding(findings, "AG-POL002") {
		t.Fatalf("server allow list should allow tool, got %#v", findings)
	}
}

func TestPolicyPathRulesSkipURLPackagePaths(t *testing.T) {
	p := Default()
	p.Rules.Paths.Deny = []string{"/server"}
	tool := mcp.ToolDefinition{
		ServerID:    "s1",
		Name:        "pkg",
		Description: "Install @modelcontextprotocol/server-filesystem from npm.",
	}

	findings := EvaluateTools(p, []mcp.ToolDefinition{tool})
	if hasFinding(findings, "AG-POL004") {
		t.Fatalf("package path should not be treated as denied filesystem path: %#v", findings)
	}
}

func TestPolicyPathRulesUsePathBoundaries(t *testing.T) {
	p := Default()
	p.Rules.Paths.Deny = []string{"/etc"}

	findings := EvaluateTools(p, []mcp.ToolDefinition{{
		ServerID:    "s1",
		Name:        "safe_path",
		Description: "Read /workspace/etcetera/example.txt for docs.",
	}})
	if hasFinding(findings, "AG-POL004") {
		t.Fatalf("deny prefix /etc should not match /workspace/etcetera: %#v", findings)
	}

	findings = EvaluateTools(p, []mcp.ToolDefinition{{
		ServerID:    "s1",
		Name:        "unsafe_path",
		Description: "Read /etc/passwd for diagnostics.",
	}})
	if !hasFinding(findings, "AG-POL004") {
		t.Fatalf("deny prefix /etc should match /etc/passwd: %#v", findings)
	}
}

func TestPolicyPathRulesMatchPlainSensitiveSegments(t *testing.T) {
	p := Default()
	p.Rules.Paths.Deny = []string{".env"}

	findings := EvaluateTools(p, []mcp.ToolDefinition{{
		ServerID:    "s1",
		Name:        "env_reader",
		Description: "Read ./project/.env for configuration.",
	}})
	if !hasFinding(findings, "AG-POL004") {
		t.Fatalf("deny token .env should match path segment: %#v", findings)
	}
}

func TestPolicyPathRulesMatchWindowsDrivePaths(t *testing.T) {
	p := Default()
	p.Rules.Paths.Deny = []string{`C:\Users\dev\.ssh`}

	findings := EvaluateTools(p, []mcp.ToolDefinition{{
		ServerID:    "s1",
		Name:        "windows_secret",
		Description: `Read C:\Users\dev\.ssh\id_rsa for diagnostics.`,
	}})
	if !hasFinding(findings, "AG-POL004") {
		t.Fatalf("deny prefix should match Windows drive path: %#v", findings)
	}
}

func TestAllowedSeverityControlsDefaultFailOn(t *testing.T) {
	path := writePolicy(t, `
version: "0.1"
defaults:
  allowed_severity: medium
`)

	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if p.Defaults.FailOn != severity.High {
		t.Fatalf("expected fail_on high, got %s", p.Defaults.FailOn)
	}
}

func TestLoadFileParsesV02Suppressions(t *testing.T) {
	path := writePolicy(t, `
version: "0.2"
rules:
  suppressions:
    - fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      reason: "accepted local fixture risk"
      expires: "2026-12-31"
`)

	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if p.Version != "0.2" {
		t.Fatalf("unexpected version: %s", p.Version)
	}
	if len(p.Rules.Suppressions) != 1 {
		t.Fatalf("expected one suppression, got %#v", p.Rules.Suppressions)
	}
	if p.Rules.Suppressions[0].Reason != "accepted local fixture risk" {
		t.Fatalf("unexpected suppression reason: %#v", p.Rules.Suppressions[0])
	}
}

func TestLoadFileRejectsInvalidSuppressions(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "missing reason",
			content: `
version: "0.2"
rules:
  suppressions:
    - fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
`,
		},
		{
			name: "bad expiry",
			content: `
version: "0.2"
rules:
  suppressions:
    - fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      reason: "accepted local fixture risk"
      expires: "31-12-2026"
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadFile(writePolicy(t, tc.content)); err == nil {
				t.Fatal("expected invalid suppression error")
			}
		})
	}
}

func TestApplySuppressionsMarksMatchingFindings(t *testing.T) {
	p := Default()
	p.Version = "0.2"
	p.Rules.Suppressions = []Suppression{{
		Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Reason:      "accepted local fixture risk",
		Expires:     "2026-12-31",
	}}

	findings := []report.Finding{{
		ID:          "AG-TP001",
		Severity:    severity.High,
		Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}}

	out := ApplySuppressions(p, findings, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if len(out) != 1 {
		t.Fatalf("unexpected findings: %#v", out)
	}
	if !out[0].Suppressed || out[0].SuppressionReason != "accepted local fixture risk" {
		t.Fatalf("finding was not suppressed: %#v", out[0])
	}

	decision := DecideExit(p, out)
	if decision.ExitCode != 0 || decision.FindingsAtOrAbove != 0 {
		t.Fatalf("suppressed finding should not fail exit decision: %#v", decision)
	}
}

func TestApplySuppressionsReportsExpiredSuppressions(t *testing.T) {
	p := Default()
	p.Version = "0.2"
	p.Rules.Suppressions = []Suppression{{
		Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Reason:      "accepted local fixture risk",
		Expires:     "2026-01-01",
	}}

	findings := []report.Finding{{
		ID:          "AG-TP001",
		Severity:    severity.High,
		Fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}}

	out := ApplySuppressions(p, findings, time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if len(out) != 2 {
		t.Fatalf("expected original finding plus policy finding, got %#v", out)
	}
	if out[0].Suppressed {
		t.Fatalf("expired suppression should not suppress original finding: %#v", out[0])
	}
	if !hasFinding(out, "AG-POL006") {
		t.Fatalf("expected expired suppression policy finding: %#v", out)
	}
}

func TestDecideExit(t *testing.T) {
	p := Default()
	decision := DecideExit(p, nil)
	if decision.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %#v", decision)
	}
}

func hasFinding(findings []report.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}
