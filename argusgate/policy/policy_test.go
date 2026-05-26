package policy

import (
	"os"
	"path/filepath"
	"testing"

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
