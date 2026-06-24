package detectors

import (
	"regexp"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type SecretExposureDetector struct{}

var secretPatterns = []struct {
	id         string
	title      string
	rx         *regexp.Regexp
	confidence string
}{
	{"AG-SE001", "Bearer token found in metadata", regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,}`), "high"},
	{"AG-SE009", "Basic authorization value found in metadata", regexp.MustCompile(`(?i)Basic\s+[A-Za-z0-9+/=]{8,}`), "high"},
	{"AG-SE002", "Secret-like key/value found in metadata", regexp.MustCompile(`(?i)(api[_-]?key|token|password|passwd|secret|private[_-]?key|authorization)\s*[:=]\s*["']?[^"'\s,;]{4,}`), "medium"},
	{"AG-SE003", "Private key block found in metadata", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), "high"},
	{"AG-SE004", "Connection string found in metadata", regexp.MustCompile(`(?i)(postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s"']+`), "high"},
	{"AG-SE005", "JWT-like token found in metadata", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "medium"},
	{"AG-SE006", "GitHub token-like value found in metadata", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b`), "high"},
	{"AG-SE007", "Cloud access key-like value found in metadata", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), "high"},
	{"AG-SE008", "API key-like value found in metadata", regexp.MustCompile(`\bsk-[A-Za-z0-9][A-Za-z0-9_-]{16,}\b`), "medium"},
	{"AG-SE010", "URL userinfo credential found in metadata", regexp.MustCompile(`(?i)\b(?:https?|mcp)://[^:/\s"']+:[^@\s"']+@`), "high"},
	{"AG-SE011", "Slack token-like value found in metadata", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`), "high"},
	{"AG-SE012", "npm token-like value found in metadata", regexp.MustCompile(`\bnpm_[A-Za-z0-9_-]{20,}\b`), "high"},
	{"AG-SE013", "PyPI token-like value found in metadata", regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{20,}\b`), "high"},
	{"AG-SE014", "Google API key-like value found in metadata", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{20,}\b`), "high"},
}

func (d SecretExposureDetector) ScanServer(server mcp.ServerConfig) []report.Finding {
	var findings []report.Finding
	for _, blob := range mcp.ServerTextBlobs(server) {
		findings = append(findings, secretFindings(server.ID, "", blob.Location, blob.Text)...)
	}
	return findings
}

func (d SecretExposureDetector) ScanTool(tool mcp.ToolDefinition) []report.Finding {
	var findings []report.Finding
	for _, blob := range mcp.ToolTextBlobs(tool) {
		findings = append(findings, secretFindings(tool.ServerID, tool.Name, blob.Location, blob.Text)...)
	}
	return findings
}

func secretFindings(serverID, toolName, location, text string) []report.Finding {
	var findings []report.Finding
	for _, pattern := range secretPatterns {
		matches := pattern.rx.FindAllString(text, -1)
		for _, match := range matches {
			findings = append(findings, report.Finding{
				ID:              pattern.id,
				Title:           pattern.title,
				Severity:        severity.High,
				Category:        "secret-exposure",
				OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure",
				ServerID:        serverID,
				ToolName:        toolName,
				Location:        location,
				Evidence:        redact.Snippet(match, 180),
				Explanation:     "A config or metadata field contains a value that resembles a secret.",
				Recommendation:  "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime.",
				Confidence:      pattern.confidence,
			})
		}
	}
	return findings
}
