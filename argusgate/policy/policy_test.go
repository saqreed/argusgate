package policy

import (
	"os"
	"path/filepath"
	"strings"
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

func TestAllowedPathIgnoresSentencePunctuation(t *testing.T) {
	p := Default()
	p.Rules.Paths.Allow = []string{"./examples"}
	tool := mcp.ToolDefinition{ServerID: "s1", Name: "read_file", Description: "Read only under ./examples."}
	findings := EvaluateTools(p, []mcp.ToolDefinition{tool})
	if hasFinding(findings, "AG-POL005") {
		t.Fatalf("sentence punctuation must not change path prefix matching: %#v", findings)
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

func TestLoadFileParsesV03TrustRules(t *testing.T) {
	path := writePolicy(t, `
version: "0.3"
defaults:
  allow_unknown_prompts: false
  allow_unknown_resources: false
rules:
  allow_prompts: [review]
  deny_prompts: [unsafe]
  resource_uris:
    allow: ["file:///workspace"]
    deny: ["file:///workspace/secrets"]
servers:
  local:
    allow_prompts: [local_review]
    resource_uris:
      allow: ["file:///local"]
`)

	p, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	if p.Version != "0.3" || p.Defaults.AllowUnknownPrompts || p.Defaults.AllowUnknownResources {
		t.Fatalf("unexpected defaults: %#v", p.Defaults)
	}
	if len(p.Rules.AllowPrompts) != 1 || len(p.Rules.ResourceURIs.Deny) != 1 {
		t.Fatalf("v0.3 rules were not parsed: %#v", p.Rules)
	}
	if len(p.Servers["local"].AllowPrompts) != 1 {
		t.Fatalf("server prompt rules were not parsed: %#v", p.Servers)
	}
}

func TestV01AndV02PoliciesDefaultNewTrustControlsToAdvisory(t *testing.T) {
	for _, version := range []string{"0.1", "0.2"} {
		p, err := LoadFile(writePolicy(t, "version: \""+version+"\"\n"))
		if err != nil {
			t.Fatalf("load v%s policy: %v", version, err)
		}
		if !p.Defaults.AllowUnknownPrompts || !p.Defaults.AllowUnknownResources {
			t.Fatalf("v%s policy changed behavior: %#v", version, p.Defaults)
		}
	}
}

func TestOlderPolicyVersionsRejectV03TrustFields(t *testing.T) {
	for _, content := range []string{
		"version: \"0.2\"\ndefaults:\n  allow_unknown_prompts: false\n",
		"version: \"0.2\"\nrules:\n  deny_prompts: [unsafe]\n",
		"version: \"0.1\"\nservers:\n  local:\n    resource_uris:\n      deny: [file:///secrets]\n",
	} {
		if _, err := LoadFile(writePolicy(t, content)); err == nil || !strings.Contains(err.Error(), "version \"0.3\"") {
			t.Fatalf("expected v0.3 requirement for:\n%s\ngot %v", content, err)
		}
	}
}

func TestPromptAndResourcePolicyPrecedence(t *testing.T) {
	p := Default()
	p.Version = "0.3"
	p.Defaults.AllowUnknownPrompts = false
	p.Defaults.AllowUnknownResources = false
	p.Rules.AllowPrompts = []string{"global"}
	p.Rules.DenyPrompts = []string{"denied"}
	p.Rules.ResourceURIs.Allow = []string{"https://trusted.example/api"}
	p.Rules.ResourceURIs.Deny = []string{"https://trusted.example/api/private"}
	p.Servers = map[string]ServerRule{
		"s1": {
			AllowPrompts: []string{"server"},
			ResourceURIs: PathRules{Allow: []string{"file:///workspace"}},
		},
	}
	artifacts := []mcp.Artifact{
		mcp.ArtifactFromPrompt(mcp.PromptDefinition{ServerID: "s1", Name: "global"}),
		mcp.ArtifactFromPrompt(mcp.PromptDefinition{ServerID: "s1", Name: "server"}),
		mcp.ArtifactFromPrompt(mcp.PromptDefinition{ServerID: "s1", Name: "denied"}),
		mcp.ArtifactFromResource(mcp.ResourceDefinition{ServerID: "s1", Name: "safe", URI: "file:///workspace/docs"}),
		mcp.ArtifactFromResource(mcp.ResourceDefinition{ServerID: "s1", Name: "private", URI: "https://trusted.example/api/private/item"}),
	}
	findings := EvaluateArtifacts(p, artifacts)
	if !hasFinding(findings, "AG-POL007") || !hasFinding(findings, "AG-POL008") || !hasFinding(findings, "AG-POL009") {
		t.Fatalf("expected deny/unknown findings, got %#v", findings)
	}
}

func TestResourceURIPrefixUsesAuthorityAndPathBoundaries(t *testing.T) {
	p := Default()
	p.Version = "0.3"
	p.Defaults.AllowUnknownResources = false
	p.Rules.ResourceURIs.Allow = []string{"https://trusted.example/api", "file:///workspace"}

	allowed := []mcp.Artifact{
		mcp.ArtifactFromResource(mcp.ResourceDefinition{ServerID: "s1", Name: "api", URI: "https://trusted.example/api/items"}),
		mcp.ArtifactFromResource(mcp.ResourceDefinition{ServerID: "s1", Name: "file", URI: "file:///workspace/docs"}),
	}
	if findings := EvaluateArtifacts(p, allowed); hasFinding(findings, "AG-POL010") {
		t.Fatalf("approved URI namespaces were rejected: %#v", findings)
	}

	blocked := []mcp.Artifact{
		mcp.ArtifactFromResource(mcp.ResourceDefinition{ServerID: "s1", Name: "host-confusion", URI: "https://trusted.example.evil/api"}),
		mcp.ArtifactFromResource(mcp.ResourceDefinition{ServerID: "s1", Name: "path-confusion", URI: "file:///workspace-secrets"}),
	}
	findings := EvaluateArtifacts(p, blocked)
	count := 0
	for _, finding := range findings {
		if finding.ID == "AG-POL010" {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected two URI boundary findings, got %#v", findings)
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

func TestApplySuppressionsCannotSuppressScannerLimit(t *testing.T) {
	fingerprint := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	p := Default()
	p.Version = "0.2"
	p.Rules.Suppressions = []Suppression{{Fingerprint: fingerprint, Reason: "must not apply"}}
	findings := []report.Finding{{ID: "AG-SCAN001", Severity: severity.Critical, Fingerprint: fingerprint}}

	out := ApplySuppressions(p, findings, time.Now().UTC())
	if len(out) != 1 || out[0].Suppressed {
		t.Fatalf("scanner limit must remain unsuppressed: %#v", out)
	}
	if decision := DecideExit(p, out); decision.ExitCode != 1 {
		t.Fatalf("scanner limit must fail the scan: %#v", decision)
	}
}

func TestDecideExit(t *testing.T) {
	p := Default()
	decision := DecideExit(p, nil)
	if decision.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %#v", decision)
	}
}

func TestSummarizeRedactsProjectName(t *testing.T) {
	p := Default()
	p.Project.Name = "token=FAKE_TOKEN_DO_NOT_USE_1234567890"
	if summary := Summarize(p); strings.Contains(summary.Name, "FAKE_TOKEN_DO_NOT_USE_1234567890") {
		t.Fatalf("project name leaked through policy summary: %#v", summary)
	}
}

func TestLoadFileRejectsUnknownAndCollidingKeys(t *testing.T) {
	unknown := writePolicy(t, "version: '0.2'\nrules:\n  deny_toolz: [shell_exec]\n")
	if _, err := LoadFile(unknown); err == nil || !strings.Contains(err.Error(), "field deny_toolz not found") {
		t.Fatalf("expected unknown field error, got %v", err)
	}

	collision := writePolicy(t, "version: '0.2'\ndefaults:\n  fail-on: high\n  fail_on: medium\n")
	if _, err := LoadFile(collision); err == nil || !strings.Contains(err.Error(), "normalize to the same field") {
		t.Fatalf("expected normalized key collision, got %v", err)
	}
}

func TestLoadFileRejectsUnsafePolicyAmbiguity(t *testing.T) {
	cases := []string{
		"defaults:\n  fail_on: high\n",
		"version: '0.2'\ndefaults:\n  fail_on: info\n",
		"version: '0.1'\nrules:\n  suppressions:\n    - fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n      reason: not supported\n",
		"version: '0.2'\nrules:\n  deny_tools: ['']\n",
		"version: '0.2'\nrules:\n  suppressions:\n    - fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n      reason: first\n    - fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n      reason: second\n",
		"version: '0.2'\n---\nversion: '0.2'\n",
		"version: '0.2'\nrules:\n  1: value\n",
	}
	for _, content := range cases {
		if _, err := LoadFile(writePolicy(t, content)); err == nil {
			t.Fatalf("expected policy error for:\n%s", content)
		}
	}
}

func TestLoadFileRejectsOversizedPolicy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-policy.yaml")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", int(MaxPolicyBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestLoadFileRejectsExcessiveNesting(t *testing.T) {
	nested := strings.Repeat(`{"x":`, mcp.MaxNestingDepth+2) + `"value"` + strings.Repeat("}", mcp.MaxNestingDepth+2)
	path := writePolicy(t, `{"version":"0.3","unknown":`+nested+`}`)
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "nesting exceeds maximum depth") {
		t.Fatalf("expected nesting limit error, got %v", err)
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
