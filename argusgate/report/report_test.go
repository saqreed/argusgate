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
			{ID: "LOW", Severity: severity.Low, Evidence: "safe"},
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
	if strings.Contains(r.Tools[0].DescriptionExcerpt, "FAKE_TOKEN_DO_NOT_USE_1234567890") {
		t.Fatalf("secret leaked in tool excerpt: %s", r.Tools[0].DescriptionExcerpt)
	}
	if strings.Contains(r.Servers[0].URL, "SUPER_SECRET_PASSWORD") || strings.Contains(r.Servers[0].URL, "FAKE_TOKEN_DO_NOT_USE_1234567890") {
		t.Fatalf("secret leaked in server URL summary: %s", r.Servers[0].URL)
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
