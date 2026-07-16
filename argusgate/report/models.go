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
	SubjectType       string         `json:"subject_type,omitempty"`
	SubjectName       string         `json:"subject_name,omitempty"`
	ChangeType        string         `json:"change_type,omitempty"`
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
	ID                    string `json:"id"`
	Name                  string `json:"name,omitempty"`
	Version               string `json:"version,omitempty"`
	Transport             string `json:"transport,omitempty"`
	ProtocolVersion       string `json:"protocol_version,omitempty"`
	Command               string `json:"command,omitempty"`
	URL                   string `json:"url,omitempty"`
	ToolCount             int    `json:"tool_count"`
	PromptCount           int    `json:"prompt_count"`
	ResourceCount         int    `json:"resource_count"`
	ResourceTemplateCount int    `json:"resource_template_count"`
}

type ToolSummary struct {
	ServerID           string `json:"server_id"`
	Name               string `json:"name"`
	Title              string `json:"title,omitempty"`
	DescriptionExcerpt string `json:"description_excerpt,omitempty"`
}

type PromptSummary struct {
	ServerID           string `json:"server_id"`
	Name               string `json:"name"`
	Title              string `json:"title,omitempty"`
	DescriptionExcerpt string `json:"description_excerpt,omitempty"`
	ArgumentCount      int    `json:"argument_count"`
}

type ResourceSummary struct {
	ServerID           string `json:"server_id"`
	Name               string `json:"name"`
	Title              string `json:"title,omitempty"`
	URI                string `json:"uri"`
	DescriptionExcerpt string `json:"description_excerpt,omitempty"`
	MIMEType           string `json:"mime_type,omitempty"`
}

type ResourceTemplateSummary struct {
	ServerID           string `json:"server_id"`
	Name               string `json:"name"`
	Title              string `json:"title,omitempty"`
	URITemplate        string `json:"uri_template"`
	DescriptionExcerpt string `json:"description_excerpt,omitempty"`
	MIMEType           string `json:"mime_type,omitempty"`
}

type Report struct {
	ScannedAt         string                    `json:"scanned_at"`
	ArgusGateVersion  string                    `json:"argusgate_version"`
	SourceType        string                    `json:"source_type"`
	SourcePath        string                    `json:"source_path"`
	ProtocolVersion   string                    `json:"protocol_version,omitempty"`
	Servers           []ServerSummary           `json:"servers"`
	Tools             []ToolSummary             `json:"tools"`
	Prompts           []PromptSummary           `json:"prompts"`
	Resources         []ResourceSummary         `json:"resources"`
	ResourceTemplates []ResourceTemplateSummary `json:"resource_templates"`
	Findings          []Finding                 `json:"findings"`
	SeveritySummary   map[string]int            `json:"severity_summary"`
	PolicySummary     any                       `json:"policy_summary"`
	BaselineSummary   any                       `json:"baseline_summary,omitempty"`
	ExitDecision      any                       `json:"exit_decision"`
}

type Input struct {
	ScannedAt         time.Time
	Version           string
	SourceType        string
	SourcePath        string
	ProtocolVersion   string
	Servers           []mcp.ServerConfig
	Tools             []mcp.ToolDefinition
	Prompts           []mcp.PromptDefinition
	Resources         []mcp.ResourceDefinition
	ResourceTemplates []mcp.ResourceTemplateDefinition
	Findings          []Finding
	PolicySummary     any
	BaselineSummary   any
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
			findings[i].SubjectType = redact.Text(findings[i].SubjectType)
			findings[i].SubjectName = redact.Text(findings[i].SubjectName)
			findings[i].ChangeType = redact.Text(findings[i].ChangeType)
			findings[i].Location = redact.Text(findings[i].Location)
			findings[i].Evidence = redact.Text(findings[i].Evidence)
			findings[i].SuppressionReason = redact.Text(findings[i].SuppressionReason)
		}
		if findings[i].Fingerprint == "" {
			findings[i].Fingerprint = Fingerprint(findings[i])
		}
	}
	sortFindings(findings)

	return Report{
		ScannedAt:         scannedAt.UTC().Format(time.RFC3339),
		ArgusGateVersion:  input.Version,
		SourceType:        input.SourceType,
		SourcePath:        redact.Text(input.SourcePath),
		ProtocolVersion:   redact.Text(input.ProtocolVersion),
		Servers:           summarizeServers(input.Servers),
		Tools:             summarizeTools(input.Tools),
		Prompts:           summarizePrompts(input.Prompts),
		Resources:         summarizeResources(input.Resources),
		ResourceTemplates: summarizeResourceTemplates(input.ResourceTemplates),
		Findings:          findings,
		SeveritySummary:   summarizeSeverities(findings),
		PolicySummary:     input.PolicySummary,
		BaselineSummary:   input.BaselineSummary,
		ExitDecision:      input.ExitDecision,
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

func DeduplicateFindings(findings []Finding) []Finding {
	out := make([]Finding, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range EnsureFingerprints(findings) {
		if _, exists := seen[finding.Fingerprint]; exists {
			continue
		}
		seen[finding.Fingerprint] = struct{}{}
		out = append(out, finding)
	}
	return out
}

func Fingerprint(f Finding) string {
	parts := []string{
		normalizeFingerprintPart(f.ID),
		normalizeFingerprintPart(f.Category),
		normalizeFingerprintPart(f.ServerID),
		normalizeFingerprintPart(f.ToolName),
		normalizeFingerprintPart(f.SubjectType),
		normalizeFingerprintPart(f.SubjectName),
		normalizeFingerprintPart(f.ChangeType),
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
			ID:                    redact.Text(server.ID),
			Name:                  redact.Text(server.Name),
			Version:               redact.Text(server.Version),
			Transport:             redact.Text(server.Transport),
			ProtocolVersion:       redact.Text(server.ProtocolVersion),
			Command:               redact.Text(server.Command),
			URL:                   redact.Snippet(server.URL, 240),
			ToolCount:             len(server.Tools),
			PromptCount:           len(server.Prompts),
			ResourceCount:         len(server.Resources),
			ResourceTemplateCount: len(server.ResourceTemplates),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func summarizePrompts(prompts []mcp.PromptDefinition) []PromptSummary {
	out := make([]PromptSummary, 0, len(prompts))
	for _, prompt := range prompts {
		out = append(out, PromptSummary{
			ServerID:           redact.Text(prompt.ServerID),
			Name:               redact.Text(prompt.Name),
			Title:              redact.Text(prompt.Title),
			DescriptionExcerpt: redact.Snippet(prompt.Description, 140),
			ArgumentCount:      len(prompt.Arguments),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerID != out[j].ServerID {
			return out[i].ServerID < out[j].ServerID
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func summarizeResources(resources []mcp.ResourceDefinition) []ResourceSummary {
	out := make([]ResourceSummary, 0, len(resources))
	for _, resource := range resources {
		out = append(out, ResourceSummary{
			ServerID:           redact.Text(resource.ServerID),
			Name:               redact.Text(resource.Name),
			Title:              redact.Text(resource.Title),
			URI:                redact.Snippet(resource.URI, 240),
			DescriptionExcerpt: redact.Snippet(resource.Description, 140),
			MIMEType:           redact.Text(resource.MIMEType),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerID != out[j].ServerID {
			return out[i].ServerID < out[j].ServerID
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func summarizeResourceTemplates(templates []mcp.ResourceTemplateDefinition) []ResourceTemplateSummary {
	out := make([]ResourceTemplateSummary, 0, len(templates))
	for _, template := range templates {
		out = append(out, ResourceTemplateSummary{
			ServerID:           redact.Text(template.ServerID),
			Name:               redact.Text(template.Name),
			Title:              redact.Text(template.Title),
			URITemplate:        redact.Snippet(template.URITemplate, 240),
			DescriptionExcerpt: redact.Snippet(template.Description, 140),
			MIMEType:           redact.Text(template.MIMEType),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerID != out[j].ServerID {
			return out[i].ServerID < out[j].ServerID
		}
		return out[i].Name < out[j].Name
	})
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
		if findings[i].SubjectType != findings[j].SubjectType {
			return findings[i].SubjectType < findings[j].SubjectType
		}
		if findings[i].SubjectName != findings[j].SubjectName {
			return findings[i].SubjectName < findings[j].SubjectName
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
