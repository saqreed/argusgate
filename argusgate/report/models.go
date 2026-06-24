package report

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type Finding struct {
	ID                string         `json:"id"`
	Title             string         `json:"title"`
	Severity          severity.Level `json:"severity"`
	Category          string         `json:"category"`
	OWASPMCPMapping   string         `json:"owasp_mcp_mapping,omitempty"`
	ServerID          string         `json:"server_id,omitempty"`
	ToolName          string         `json:"tool_name,omitempty"`
	Location          string         `json:"location,omitempty"`
	Evidence          string         `json:"evidence,omitempty"`
	Explanation       string         `json:"explanation"`
	Recommendation    string         `json:"recommendation,omitempty"`
	Confidence        string         `json:"confidence"`
	Fingerprint       string         `json:"fingerprint,omitempty"`
	Suppressed        bool           `json:"suppressed,omitempty"`
	SuppressionReason string         `json:"suppression_reason,omitempty"`
}

type ServerSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Transport string `json:"transport,omitempty"`
	Command   string `json:"command,omitempty"`
	URL       string `json:"url,omitempty"`
	ToolCount int    `json:"tool_count"`
}

type ToolSummary struct {
	ServerID           string `json:"server_id"`
	Name               string `json:"name"`
	Title              string `json:"title,omitempty"`
	DescriptionExcerpt string `json:"description_excerpt,omitempty"`
}

type Report struct {
	ScannedAt        string          `json:"scanned_at"`
	ArgusGateVersion string          `json:"argusgate_version"`
	SourceType       string          `json:"source_type"`
	SourcePath       string          `json:"source_path"`
	Servers          []ServerSummary `json:"servers"`
	Tools            []ToolSummary   `json:"tools"`
	Findings         []Finding       `json:"findings"`
	SeveritySummary  map[string]int  `json:"severity_summary"`
	PolicySummary    any             `json:"policy_summary"`
	ExitDecision     any             `json:"exit_decision"`
}

type Input struct {
	ScannedAt         time.Time
	Version           string
	SourceType        string
	SourcePath        string
	Servers           []mcp.ServerConfig
	Tools             []mcp.ToolDefinition
	Findings          []Finding
	PolicySummary     any
	ExitDecision      any
	RedactFindingText bool
}

func Build(input Input) Report {
	scannedAt := input.ScannedAt
	if scannedAt.IsZero() {
		scannedAt = time.Now().UTC()
	}

	findings := make([]Finding, len(input.Findings))
	copy(findings, input.Findings)
	for i := range findings {
		if input.RedactFindingText {
			findings[i].ServerID = redact.Text(findings[i].ServerID)
			findings[i].ToolName = redact.Text(findings[i].ToolName)
			findings[i].Location = redact.Text(findings[i].Location)
			findings[i].Evidence = redact.Text(findings[i].Evidence)
		}
		if findings[i].Fingerprint == "" {
			findings[i].Fingerprint = Fingerprint(findings[i])
		}
	}
	sortFindings(findings)

	return Report{
		ScannedAt:        scannedAt.UTC().Format(time.RFC3339),
		ArgusGateVersion: input.Version,
		SourceType:       input.SourceType,
		SourcePath:       input.SourcePath,
		Servers:          summarizeServers(input.Servers),
		Tools:            summarizeTools(input.Tools),
		Findings:         findings,
		SeveritySummary:  summarizeSeverities(findings),
		PolicySummary:    input.PolicySummary,
		ExitDecision:     input.ExitDecision,
	}
}

func EnsureFingerprints(findings []Finding) []Finding {
	out := make([]Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if out[i].Fingerprint == "" {
			out[i].Fingerprint = Fingerprint(out[i])
		}
	}
	return out
}

func Fingerprint(f Finding) string {
	parts := []string{
		normalizeFingerprintPart(f.ID),
		normalizeFingerprintPart(f.Category),
		normalizeFingerprintPart(f.ServerID),
		normalizeFingerprintPart(f.ToolName),
		normalizeFingerprintPart(f.Location),
		normalizeFingerprintPart(f.Evidence),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

func normalizeFingerprintPart(value string) string {
	redacted := redact.Text(value)
	return strings.ToLower(strings.Join(strings.Fields(redacted), " "))
}

func summarizeServers(servers []mcp.ServerConfig) []ServerSummary {
	out := make([]ServerSummary, 0, len(servers))
	for _, server := range servers {
		out = append(out, ServerSummary{
			ID:        redact.Text(server.ID),
			Name:      redact.Text(server.Name),
			Transport: redact.Text(server.Transport),
			Command:   redact.Text(server.Command),
			URL:       redact.Snippet(server.URL, 240),
			ToolCount: len(server.Tools),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func summarizeTools(tools []mcp.ToolDefinition) []ToolSummary {
	out := make([]ToolSummary, 0, len(tools))
	for _, tool := range tools {
		out = append(out, ToolSummary{
			ServerID:           redact.Text(tool.ServerID),
			Name:               redact.Text(tool.Name),
			Title:              redact.Text(tool.Title),
			DescriptionExcerpt: redact.Snippet(tool.Description, 140),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerID == out[j].ServerID {
			return out[i].Name < out[j].Name
		}
		return out[i].ServerID < out[j].ServerID
	})
	return out
}

func summarizeSeverities(findings []Finding) map[string]int {
	summary := map[string]int{}
	for _, level := range severity.All() {
		summary[level.String()] = 0
	}
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		summary[finding.Severity.String()]++
	}
	return summary
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity.AtLeast(findings[j].Severity)
		}
		if findings[i].ServerID != findings[j].ServerID {
			return findings[i].ServerID < findings[j].ServerID
		}
		if findings[i].ToolName != findings[j].ToolName {
			return findings[i].ToolName < findings[j].ToolName
		}
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Location != findings[j].Location {
			return findings[i].Location < findings[j].Location
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
}
