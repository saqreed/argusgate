package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

func TestBuildSortsFindingsAndRedactsEvidence(t *testing.T) {
	r := Build(Input{
		ScannedAt:  time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC),
		Version:    "0.1.5",
		SourceType: "fixtures",
		SourcePath: "fixture.yaml",
		Servers: []mcp.ServerConfig{{
			ID:  "api",
			URL: "https://user:SUPER_SECRET_PASSWORD@example.com/mcp?token=FAKE_TOKEN_DO_NOT_USE_1234567890",
		}},
		Tools: []mcp.ToolDefinition{{
			ServerID:    "s1",
			Name:        "tool",
			Description: "token=FAKE_TOKEN_DO_NOT_USE_1234567890",
		}},
		Findings: []Finding{
			{ID: "LOW", Severity: severity.Low, Evidence: "safe", SuppressionReason: "token=FAKE_TOKEN_DO_NOT_USE_1234567890"},
			{ID: "HIGH", Severity: severity.High, Evidence: "Bearer FAKE_TOKEN_DO_NOT_USE_1234567890"},
		},
		RedactFindingText: true,
	})

	if r.ScannedAt != "2026-05-22T12:00:00Z" {
		t.Fatalf("unexpected scanned_at: %s", r.ScannedAt)
	}
	if len(r.Findings) != 2 || r.Findings[0].ID != "HIGH" {
		t.Fatalf("findings not sorted by severity: %#v", r.Findings)
	}
	if strings.Contains(r.Findings[0].Evidence, "FAKE_TOKEN_DO_NOT_USE_1234567890") {
		t.Fatalf("secret leaked in finding evidence: %s", r.Findings[0].Evidence)
	}
	for _, finding := range r.Findings {
		if strings.Contains(finding.SuppressionReason, "FAKE_TOKEN_DO_NOT_USE_1234567890") {
			t.Fatalf("secret leaked in suppression reason: %s", finding.SuppressionReason)
		}
	}
	if strings.Contains(r.Tools[0].DescriptionExcerpt, "FAKE_TOKEN_DO_NOT_USE_1234567890") {
		t.Fatalf("secret leaked in tool excerpt: %s", r.Tools[0].DescriptionExcerpt)
	}
	if strings.Contains(r.Servers[0].URL, "SUPER_SECRET_PASSWORD") || strings.Contains(r.Servers[0].URL, "FAKE_TOKEN_DO_NOT_USE_1234567890") {
		t.Fatalf("secret leaked in server URL summary: %s", r.Servers[0].URL)
	}
	if r.Findings[0].Fingerprint == "" {
		t.Fatalf("expected stable finding fingerprint: %#v", r.Findings[0])
	}
}

func TestBuildCreatesStableFingerprintsFromRedactedEvidence(t *testing.T) {
	secret := "FAKE_TOKEN_DO_NOT_USE_1234567890"
	input := Input{
		ScannedAt:  time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC),
		Version:    "0.2.0",
		SourceType: "fixtures",
		SourcePath: "fixture.yaml",
		Findings: []Finding{{
			ID:          "AG-SE001",
			Severity:    severity.High,
			Category:    "secret-exposure",
			ServerID:    "s1",
			ToolName:    "token_loader",
			Location:    "tools[token_loader].description",
			Evidence:    "Bearer " + secret,
			Explanation: "test finding",
			Confidence:  "high",
		}},
		RedactFindingText: true,
	}

	first := Build(input)
	second := Build(input)
	if first.Findings[0].Fingerprint == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if first.Findings[0].Fingerprint != second.Findings[0].Fingerprint {
		t.Fatalf("fingerprint should be stable: %s != %s", first.Findings[0].Fingerprint, second.Findings[0].Fingerprint)
	}
	if strings.Contains(first.Findings[0].Fingerprint, secret) {
		t.Fatalf("fingerprint must not contain raw secret: %s", first.Findings[0].Fingerprint)
	}
}

func TestDeduplicateFindingsUsesStableFingerprint(t *testing.T) {
	finding := Finding{ID: "AG-TEST", Category: "test", Severity: severity.High, Location: "tools[x]", Evidence: "same"}
	got := DeduplicateFindings([]Finding{finding, finding})
	if len(got) != 1 || got[0].Fingerprint == "" {
		t.Fatalf("expected one fingerprinted finding, got %#v", got)
	}
}

func TestSARIFBytesProducesSARIFReport(t *testing.T) {
	r := Report{
		ArgusGateVersion: "0.2.0",
		SourcePath:       "fixtures.yaml",
		Findings: []Finding{{
			ID:              "AG-TP001",
			Title:           "Suspicious tool instruction detected",
			Severity:        severity.High,
			Category:        "tool-poisoning",
			OWASPMCPMapping: "MCP03 Tool Poisoning",
			ServerID:        "s1",
			ToolName:        "search",
			Location:        "tools[search].description",
			Fingerprint:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			Explanation:     "test finding",
			Recommendation:  "review",
			Confidence:      "high",
		}},
	}

	data, err := SARIFBytes(r)
	if err != nil {
		t.Fatalf("SARIFBytes failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, string(data))
	}
	if decoded["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %#v", decoded["version"])
	}
	runs := decoded["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	result := results[0].(map[string]any)
	if result["ruleId"] != "AG-TP001" || result["level"] != "error" {
		t.Fatalf("unexpected SARIF result: %#v", result)
	}
}

func TestBuildRedactsSecretLikeIdentifiersAndSummaries(t *testing.T) {
	secret := "FAKE_TOKEN_DO_NOT_USE_1234567890"
	r := Build(Input{
		ScannedAt:  time.Date(2026, 5, 22, 12, 0, 0, 0, time.UTC),
		Version:    "0.1.5",
		SourceType: "fixtures",
		SourcePath: "fixture.yaml",
		Servers: []mcp.ServerConfig{{
			ID:      "token=" + secret,
			Name:    "Authorization: Bearer " + secret,
			Command: "server --token=" + secret,
			URL:     "https://example.test/mcp",
		}},
		Tools: []mcp.ToolDefinition{{
			ServerID:    "token=" + secret,
			Name:        "Bearer " + secret,
			Title:       "password=" + secret,
			Description: "safe description",
		}},
		Findings: []Finding{{
			ID:          "HIGH",
			Severity:    severity.High,
			ServerID:    "token=" + secret,
			ToolName:    "Bearer " + secret,
			Location:    "tools[Bearer " + secret + "].description",
			Evidence:    "Bearer " + secret,
			Explanation: "test finding",
			Confidence:  "high",
		}},
		RedactFindingText: true,
	})

	data, err := JSONBytes(r)
	if err != nil {
		t.Fatalf("JSONBytes failed: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("secret leaked in report JSON: %s", string(data))
	}
}

func TestJSONBytesProducesReportJSON(t *testing.T) {
	data, err := JSONBytes(Report{ArgusGateVersion: "0.1.5"})
	if err != nil {
		t.Fatalf("JSONBytes failed: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded.ArgusGateVersion != "0.1.5" {
		t.Fatalf("unexpected version: %s", decoded.ArgusGateVersion)
	}
}
