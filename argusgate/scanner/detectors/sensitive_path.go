package detectors

import (
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type SensitivePathDetector struct{}

var sensitivePathContains = []string{
	"~/.ssh",
	"/etc/passwd",
	"/etc/shadow",
	"~/.aws",
	".aws/credentials",
	"~/.config/gcloud",
	"~/.azure",
	"browser profiles",
	"chrome/user data",
}

var sensitivePathSegments = []string{
	".env",
	"id_rsa",
	"id_ed25519",
	"kubeconfig",
	"credentials",
	"tokens",
}

func (d SensitivePathDetector) ScanServer(server mcp.ServerConfig) []report.Finding {
	var findings []report.Finding
	for _, blob := range mcp.ServerTextBlobs(server) {
		findings = append(findings, sensitivePathFindings(server.ID, "", blob.Location, blob.Text)...)
	}
	return findings
}

func (d SensitivePathDetector) ScanTool(tool mcp.ToolDefinition) []report.Finding {
	var findings []report.Finding
	for _, blob := range mcp.ToolTextBlobs(tool) {
		findings = append(findings, sensitivePathFindings(tool.ServerID, tool.Name, blob.Location, blob.Text)...)
	}
	return findings
}

func sensitivePathFindings(serverID, toolName, location, text string) []report.Finding {
	lower := strings.ToLower(strings.ReplaceAll(text, "\\", "/"))
	var findings []report.Finding
	seen := map[string]struct{}{}
	for _, pattern := range sensitivePathContains {
		if _, ok := seen[pattern]; ok {
			continue
		}
		if !strings.Contains(lower, strings.ToLower(pattern)) {
			continue
		}
		seen[pattern] = struct{}{}
		findings = append(findings, sensitivePathFinding(serverID, toolName, location, text))
	}
	for _, segment := range sensitivePathSegments {
		if _, ok := seen[segment]; ok {
			continue
		}
		if !containsSensitivePathSegment(lower, segment) {
			continue
		}
		seen[segment] = struct{}{}
		findings = append(findings, sensitivePathFinding(serverID, toolName, location, text))
	}
	return findings
}

func sensitivePathFinding(serverID, toolName, location, text string) report.Finding {
	return report.Finding{
		ID:              "AG-PATH001",
		Title:           "Sensitive path referenced in MCP metadata",
		Severity:        severity.High,
		Category:        "sensitive-path",
		OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
		ServerID:        serverID,
		ToolName:        toolName,
		Location:        location,
		Evidence:        redact.Snippet(text, 180),
		Explanation:     "A config or metadata field references a path commonly associated with secrets or sensitive host data.",
		Recommendation:  "Avoid exposing sensitive host paths to MCP tools; constrain file access to explicit low-risk directories.",
		Confidence:      "high",
	}
}

func containsSensitivePathSegment(text, segment string) bool {
	start := 0
	for {
		index := strings.Index(text[start:], segment)
		if index == -1 {
			return false
		}
		index += start
		end := index + len(segment)

		beforeBoundary := index == 0 || isBoundary(text[index-1]) || isPathSeparator(text[index-1])
		afterBoundary := end == len(text) || isBoundary(text[end]) || isPathSeparator(text[end])
		beforePath := index > 0 && isPathSeparator(text[index-1])
		afterPath := end < len(text) && isPathSeparator(text[end])
		afterExtension := end < len(text) && text[end] == '.'
		hasPathContext := beforePath || afterPath || afterExtension
		standaloneSensitiveFile := segment != "credentials" && segment != "tokens" && beforeBoundary && afterBoundary
		if beforeBoundary && hasPathContext || standaloneSensitiveFile {
			return true
		}
		start = end
	}
}

func isPathSeparator(ch byte) bool {
	return ch == '/' || ch == '\\' || ch == '~'
}

func isBoundary(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '"' || ch == '\'' || ch == ',' || ch == ';' || ch == ')' || ch == '('
}
