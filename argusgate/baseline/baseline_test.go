package baseline

import (
	"strings"
	"testing"
	"time"

	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

func TestCreateIsStableAndDoesNotExposeSecrets(t *testing.T) {
	first := baselineTestDocument()
	second := baselineTestDocument()
	second.Tools[0].Description = strings.ReplaceAll(second.Tools[0].Description, "\n", "\r\n")
	second.Tools[0].InputSchema = map[string]any{
		"required": []any{"path", "mode"},
		"type":     "object",
		"properties": map[string]any{
			"mode": map[string]any{"enum": []any{"write", "read"}},
		},
	}
	first.Tools[0].InputSchema = map[string]any{
		"properties": map[string]any{
			"mode": map[string]any{"enum": []any{"read", "write"}},
		},
		"type":     "object",
		"required": []any{"mode", "path"},
	}

	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	left, err := Create(first, "0.3.0", now)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Create(second, "0.3.0", now)
	if err != nil {
		t.Fatal(err)
	}
	leftHash := artifactHash(left, "tool", "read_file")
	rightHash := artifactHash(right, "tool", "read_file")
	if leftHash != rightHash {
		t.Fatalf("contract hashes differ: %s != %s", leftHash, rightHash)
	}
	raw, err := JSONBytes(left)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, secret := range []string{"FAKE_TOKEN_DO_NOT_USE", "Bearer FAKE", "super-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("baseline leaked %q: %s", secret, text)
		}
	}
}

func TestCompareReportsAddedChangedRemovedAndServerChanges(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	expected, err := Create(baselineTestDocument(), "0.3.0", now)
	if err != nil {
		t.Fatal(err)
	}
	currentDoc := baselineTestDocument()
	currentDoc.Servers[0].Command = "different-command"
	currentDoc.Tools[0].Description = "changed contract"
	currentDoc.Prompts = nil
	currentDoc.Resources = append(currentDoc.Resources, mcp.ResourceDefinition{
		ServerID: "test", Name: "new-resource", URI: "file:///tmp/new",
	})
	current, err := Create(currentDoc, "0.3.0", now)
	if err != nil {
		t.Fatal(err)
	}
	findings, summary := Compare(expected, current, "baseline.json")
	if summary.Added != 1 || summary.Changed != 1 || summary.Removed != 1 || summary.ServerChanged != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	for _, id := range []string{"AG-BASE001", "AG-BASE002", "AG-BASE003", "AG-BASE004"} {
		if !hasBaselineFinding(findings, id) {
			t.Fatalf("missing %s in %+v", id, findings)
		}
	}
}

func TestCompareReportsServersAddedAndRemovedWithoutArtifacts(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	expected, err := Create(mcp.Document{
		Servers: []mcp.ServerConfig{{ID: "old", URL: "https://old.example/mcp"}},
	}, "0.3.0", now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := Create(mcp.Document{
		Servers: []mcp.ServerConfig{{ID: "new", URL: "https://new.example/mcp"}},
	}, "0.3.0", now)
	if err != nil {
		t.Fatal(err)
	}
	findings, summary := Compare(expected, current, "baseline.json")
	if summary.ServerChanged != 2 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	added := false
	removed := false
	for _, finding := range findings {
		if finding.ID == "AG-BASE004" && finding.ChangeType == "added" && finding.Severity == severity.High {
			added = true
		}
		if finding.ID == "AG-BASE004" && finding.ChangeType == "removed" {
			removed = true
		}
	}
	if !added || !removed {
		t.Fatalf("missing server drift findings: %#v", findings)
	}
}

func baselineTestDocument() mcp.Document {
	tool := mcp.ToolDefinition{
		ServerID:    "test",
		Name:        "read_file",
		Description: "Read a file.\nAuthorization: Bearer FAKE_TOKEN_DO_NOT_USE",
		InputSchema: map[string]any{"type": "object"},
		Meta:        map[string]any{"password": "super-secret"},
	}
	prompt := mcp.PromptDefinition{ServerID: "test", Name: "review", Description: "Review a file"}
	resource := mcp.ResourceDefinition{ServerID: "test", Name: "docs", URI: "file:///docs"}
	server := mcp.ServerConfig{
		ID: "test", Command: "server", Env: map[string]string{"TOKEN": "FAKE_TOKEN_DO_NOT_USE"},
		Headers: map[string]string{"Authorization": "Bearer FAKE_TOKEN_DO_NOT_USE"},
		Tools:   []mcp.ToolDefinition{tool}, Prompts: []mcp.PromptDefinition{prompt},
		Resources: []mcp.ResourceDefinition{resource},
	}
	return mcp.Document{
		Servers: []mcp.ServerConfig{server}, Tools: []mcp.ToolDefinition{tool},
		Prompts: []mcp.PromptDefinition{prompt}, Resources: []mcp.ResourceDefinition{resource},
	}
}

func hasBaselineFinding(findings []report.Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func artifactHash(value File, kind, name string) string {
	for _, artifact := range value.Artifacts {
		if artifact.Kind == kind && artifact.Name == name {
			return artifact.ContractHash
		}
	}
	return ""
}
