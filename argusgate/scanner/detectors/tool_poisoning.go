package detectors

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type ToolPoisoningDetector struct{}

var poisoningPhrases = []string{
	"ignore previous instructions",
	"ignore all previous instructions",
	"do not tell the user",
	"don't tell the user",
	"secretly",
	"exfiltrate",
	"send token",
	"read ~/.ssh",
	"read private key",
	"read .env",
	"bypass security",
	"bypass policy",
	"bypass restrictions",
	"bypass safeguards",
	"bypass authentication",
}

var (
	markdownCommentRX = regexp.MustCompile(`(?s)<!--(?:.*?-->|.*$)`)
	base64LikeRX      = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
)

func (d ToolPoisoningDetector) ScanServer(mcp.ServerConfig) []report.Finding {
	return nil
}

func (d ToolPoisoningDetector) ScanTool(tool mcp.ToolDefinition) []report.Finding {
	return d.ScanArtifact(mcp.ArtifactFromTool(tool))
}

func (d ToolPoisoningDetector) ScanArtifact(artifact mcp.Artifact) []report.Finding {
	var findings []report.Finding
	for _, blob := range mcp.ArtifactTextBlobs(artifact) {
		lower := strings.ToLower(blob.Text)
		for _, phrase := range poisoningPhrases {
			if strings.Contains(lower, phrase) {
				findings = append(findings, report.Finding{
					ID:              "AG-TP001",
					Title:           "Suspicious instruction detected in MCP metadata",
					Severity:        severity.High,
					Category:        "tool-poisoning",
					OWASPMCPMapping: "MCP03 Tool Poisoning",
					Location:        blob.Location,
					Evidence:        redact.Snippet(blob.Text, 180),
					Explanation:     "MCP metadata contains instruction-like text commonly associated with prompt injection or tool poisoning.",
					Recommendation:  "Review the metadata, remove hidden or manipulative instructions, and only allow trusted MCP servers.",
					Confidence:      "high",
				})
				break
			}
		}

		for _, match := range markdownCommentRX.FindAllString(blob.Text, 100) {
			findings = append(findings, report.Finding{
				ID:              "AG-TP002",
				Title:           "Hidden markdown or HTML comment in MCP metadata",
				Severity:        severity.Medium,
				Category:        "tool-poisoning",
				OWASPMCPMapping: "MCP03 Tool Poisoning",
				Location:        blob.Location,
				Evidence:        redact.Snippet(match, 180),
				Explanation:     "Hidden comments in MCP metadata can carry instructions that reviewers do not see.",
				Recommendation:  "Remove hidden comments or require manual review before allowing the metadata artifact.",
				Confidence:      "medium",
			})
		}

		for _, encoded := range base64LikeRX.FindAllString(blob.Text, 100) {
			if len(encoded) > 4096 {
				continue
			}
			decoded, ok := decodeBase64Payload(encoded)
			if !ok {
				continue
			}
			decodedLower := strings.ToLower(decoded)
			for _, phrase := range poisoningPhrases {
				if strings.Contains(decodedLower, phrase) {
					findings = append(findings, report.Finding{
						ID:              "AG-TP003",
						Title:           "Suspicious base64-like payload in MCP metadata",
						Severity:        severity.High,
						Category:        "tool-poisoning",
						OWASPMCPMapping: "MCP03 Tool Poisoning",
						Location:        blob.Location,
						Evidence:        redact.Snippet(decoded, 180),
						Explanation:     "A base64-like metadata value decodes to suspicious instruction text.",
						Recommendation:  "Remove encoded instructions and treat the metadata source as untrusted until reviewed.",
						Confidence:      "medium",
					})
					break
				}
			}
		}

		if containsSuspiciousInvisibleCharacter(blob.Text) {
			findings = append(findings, report.Finding{
				ID:              "AG-TP004",
				Title:           "Invisible control character in MCP metadata",
				Severity:        severity.Medium,
				Category:        "tool-poisoning",
				OWASPMCPMapping: "MCP03 Tool Poisoning",
				Location:        blob.Location,
				Evidence:        suspiciousInvisibleEvidence(blob.Text),
				Explanation:     "MCP metadata contains invisible or zero-width characters that can hide instructions from reviewers.",
				Recommendation:  "Remove invisible formatting characters from tool metadata and review the original source.",
				Confidence:      "medium",
			})
		}
	}
	for i := range findings {
		findings[i] = withArtifactIdentity(findings[i], artifact)
	}
	return findings
}

func suspiciousInvisibleEvidence(value string) string {
	for _, ch := range value {
		switch ch {
		case '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060':
			return fmt.Sprintf("invisible character U+%04X", ch)
		}
		if ch < 32 && ch != '\n' && ch != '\r' && ch != '\t' {
			return fmt.Sprintf("control character U+%04X", ch)
		}
	}
	return "invisible control character"
}

func containsSuspiciousInvisibleCharacter(value string) bool {
	for _, ch := range value {
		switch ch {
		case '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060':
			return true
		}
		if ch < 32 && ch != '\n' && ch != '\r' && ch != '\t' {
			return true
		}
	}
	return false
}

func decodeBase64Payload(value string) (string, bool) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && looksPrintable(decoded) {
			return string(decoded), true
		}
	}
	return "", false
}

func looksPrintable(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	printable := 0
	for _, ch := range value {
		if ch == '\n' || ch == '\r' || ch == '\t' || (ch >= 32 && ch <= 126) {
			printable++
		}
	}
	return printable*100/len(value) >= 85
}
