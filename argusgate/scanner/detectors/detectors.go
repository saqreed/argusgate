package detectors

import (
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type Detector interface {
	ScanTool(tool mcp.ToolDefinition) []report.Finding
	ScanServer(server mcp.ServerConfig) []report.Finding
}

func DefaultDetectors() []Detector {
	return []Detector{
		ToolPoisoningDetector{},
		SecretExposureDetector{},
		DangerousCapabilityDetector{},
		SensitivePathDetector{},
		SQLRiskDetector{},
	}
}

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
	"bypass",
}

var (
	markdownCommentRX = regexp.MustCompile(`(?s)<!--.*?-->`)
	base64LikeRX      = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
)

func (d ToolPoisoningDetector) ScanServer(mcp.ServerConfig) []report.Finding {
	return nil
}

func (d ToolPoisoningDetector) ScanTool(tool mcp.ToolDefinition) []report.Finding {
	var findings []report.Finding
	for _, blob := range mcp.ToolTextBlobs(tool) {
		lower := strings.ToLower(blob.Text)
		for _, phrase := range poisoningPhrases {
			if strings.Contains(lower, phrase) {
				findings = append(findings, report.Finding{
					ID:              "AG-TP001",
					Title:           "Suspicious tool instruction detected",
					Severity:        severity.High,
					Category:        "tool-poisoning",
					OWASPMCPMapping: "MCP03 Tool Poisoning",
					ServerID:        tool.ServerID,
					ToolName:        tool.Name,
					Location:        blob.Location,
					Evidence:        redact.Snippet(blob.Text, 180),
					Explanation:     "Tool metadata contains instruction-like text commonly associated with prompt injection or tool poisoning.",
					Recommendation:  "Review the tool metadata, remove hidden or manipulative instructions, and only allow trusted MCP servers.",
					Confidence:      "high",
				})
				break
			}
		}

		for _, match := range markdownCommentRX.FindAllString(blob.Text, -1) {
			findings = append(findings, report.Finding{
				ID:              "AG-TP002",
				Title:           "Hidden markdown or HTML comment in tool metadata",
				Severity:        severity.Medium,
				Category:        "tool-poisoning",
				OWASPMCPMapping: "MCP03 Tool Poisoning",
				ServerID:        tool.ServerID,
				ToolName:        tool.Name,
				Location:        blob.Location,
				Evidence:        redact.Snippet(match, 180),
				Explanation:     "Hidden comments in tool descriptions can carry instructions that users do not see.",
				Recommendation:  "Remove hidden comments from tool metadata or require manual review before allowing the tool.",
				Confidence:      "medium",
			})
		}

		for _, encoded := range base64LikeRX.FindAllString(blob.Text, -1) {
			decoded, ok := decodeBase64Payload(encoded)
			if !ok {
				continue
			}
			decodedLower := strings.ToLower(decoded)
			for _, phrase := range poisoningPhrases {
				if strings.Contains(decodedLower, phrase) {
					findings = append(findings, report.Finding{
						ID:              "AG-TP003",
						Title:           "Suspicious base64-like payload in tool metadata",
						Severity:        severity.High,
						Category:        "tool-poisoning",
						OWASPMCPMapping: "MCP03 Tool Poisoning",
						ServerID:        tool.ServerID,
						ToolName:        tool.Name,
						Location:        blob.Location,
						Evidence:        redact.Snippet(decoded, 180),
						Explanation:     "A base64-like metadata value decodes to suspicious instruction text.",
						Recommendation:  "Remove encoded instructions and treat the tool as untrusted until reviewed.",
						Confidence:      "medium",
					})
					break
				}
			}
		}
	}
	return findings
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

type SecretExposureDetector struct{}

var secretPatterns = []struct {
	id         string
	title      string
	rx         *regexp.Regexp
	confidence string
}{
	{"AG-SE001", "Bearer token found in metadata", regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,}`), "high"},
	{"AG-SE002", "Secret-like key/value found in metadata", regexp.MustCompile(`(?i)(api[_-]?key|token|password|passwd|secret|private[_-]?key|authorization)\s*[:=]\s*["']?[^"'\s,;]{4,}`), "medium"},
	{"AG-SE003", "Private key block found in metadata", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), "high"},
	{"AG-SE004", "Connection string found in metadata", regexp.MustCompile(`(?i)(postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s"']+`), "high"},
	{"AG-SE005", "JWT-like token found in metadata", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "medium"},
	{"AG-SE006", "GitHub token-like value found in metadata", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b`), "high"},
	{"AG-SE007", "Cloud access key-like value found in metadata", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), "high"},
	{"AG-SE008", "API key-like value found in metadata", regexp.MustCompile(`\bsk-[A-Za-z0-9][A-Za-z0-9_-]{16,}\b`), "medium"},
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

type DangerousCapabilityDetector struct{}

var capabilityRules = []struct {
	id          string
	title       string
	severity    severity.Level
	category    string
	mapping     string
	patterns    []string
	explanation string
}{
	{
		id:       "AG-DC001",
		title:    "Shell or arbitrary command execution capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"shell_exec", "run_command", "execute arbitrary shell", "arbitrary command", "command runner", "powershell", "bash", "subprocess",
		},
		explanation: "The tool appears able to execute shell commands or arbitrary host commands.",
	},
	{
		id:       "AG-DC002",
		title:    "File write or destructive filesystem capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"write_file", "delete_file", "file write", "write arbitrary files", "delete arbitrary files", "chmod", "overwrite",
		},
		explanation: "The tool appears able to write, delete, or modify files.",
	},
	{
		id:       "AG-DC003",
		title:    "Unrestricted file read capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"read_any_file", "read arbitrary files", "unrestricted file", "any absolute path", "read files from unrestricted paths",
		},
		explanation: "The tool appears able to read files without a clearly restricted path scope.",
	},
	{
		id:       "AG-DC004",
		title:    "Network request capability",
		severity: severity.Medium,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"http request", "network request", "fetch url", "open urls", "webhook", "call external api",
		},
		explanation: "The tool appears able to make network requests.",
	},
	{
		id:       "AG-DC005",
		title:    "Browser automation capability",
		severity: severity.Medium,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"browser automation", "playwright", "selenium", "click buttons", "submit forms",
		},
		explanation: "The tool appears able to drive a browser or interact with web pages.",
	},
	{
		id:       "AG-DC006",
		title:    "Credential or secret management capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure",
		patterns: []string{
			"credential", "secret manager", "private key", "api key", "bearer token", "access token",
		},
		explanation: "The tool appears to access credentials or secret material.",
	},
	{
		id:       "AG-DC007",
		title:    "Container or cluster administration capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"docker", "kubectl", "kubernetes", "kubeconfig", "cluster resources", "containers",
		},
		explanation: "The tool appears able to operate Docker, Kubernetes, containers, or cluster resources.",
	},
	{
		id:       "AG-DC008",
		title:    "Database write capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"database write", "sql admin", "update", "delete", "drop table", "insert", "alter", "truncate",
		},
		explanation: "The tool appears able to modify database state.",
	},
}

func (d DangerousCapabilityDetector) ScanServer(mcp.ServerConfig) []report.Finding {
	return nil
}

func (d DangerousCapabilityDetector) ScanTool(tool mcp.ToolDefinition) []report.Finding {
	var findings []report.Finding
	seenRule := map[string]struct{}{}
	for _, blob := range mcp.ToolTextBlobs(tool) {
		lower := strings.ToLower(blob.Text)
		for _, rule := range capabilityRules {
			if _, ok := seenRule[rule.id]; ok {
				continue
			}
			if rule.id == "AG-DC008" {
				if !looksDatabaseRelated(tool, blob.Text) || !containsDatabaseWriteTerm(lower) {
					continue
				}
			} else if !containsAny(lower, rule.patterns) {
				continue
			}
			seenRule[rule.id] = struct{}{}
			findings = append(findings, report.Finding{
				ID:              rule.id,
				Title:           rule.title,
				Severity:        rule.severity,
				Category:        rule.category,
				OWASPMCPMapping: rule.mapping,
				ServerID:        tool.ServerID,
				ToolName:        tool.Name,
				Location:        blob.Location,
				Evidence:        redact.Snippet(blob.Text, 180),
				Explanation:     rule.explanation,
				Recommendation:  "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected.",
				Confidence:      "medium",
			})
		}
	}
	return findings
}

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
		findings = append(findings, report.Finding{
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
		})
	}
	for _, segment := range sensitivePathSegments {
		if _, ok := seen[segment]; ok {
			continue
		}
		if !containsSensitivePathSegment(lower, segment) {
			continue
		}
		seen[segment] = struct{}{}
		findings = append(findings, report.Finding{
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
		})
	}
	return findings
}

type SQLRiskDetector struct{}

var (
	sqlWriteRX = regexp.MustCompile(`(?i)\b(drop|delete|update|insert|alter|truncate)\b|copy\s+.+\s+to\s+program|xp_cmdshell|load_extension|sys_eval`)
	sqlReadRX  = regexp.MustCompile(`(?i)\b(select|with)\b`)
	dbWriteRX  = regexp.MustCompile(`(?i)\b(drop|delete|update|insert|alter|truncate|merge|create|grant|revoke)\b|copy\s+.+\s+to\s+program|xp_cmdshell|load_extension|sys_eval`)
)

func (d SQLRiskDetector) ScanServer(mcp.ServerConfig) []report.Finding {
	return nil
}

func (d SQLRiskDetector) ScanTool(tool mcp.ToolDefinition) []report.Finding {
	var findings []report.Finding
	seen := map[string]struct{}{}
	for _, blob := range mcp.ToolTextBlobs(tool) {
		if !looksDatabaseRelated(tool, blob.Text) {
			continue
		}
		if sqlWriteRX.MatchString(blob.Text) {
			if _, ok := seen["AG-SQL001"]; ok {
				continue
			}
			seen["AG-SQL001"] = struct{}{}
			findings = append(findings, report.Finding{
				ID:              "AG-SQL001",
				Title:           "SQL write or administrative operation detected",
				Severity:        severity.High,
				Category:        "sql-risk",
				OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
				ServerID:        tool.ServerID,
				ToolName:        tool.Name,
				Location:        blob.Location,
				Evidence:        redact.Snippet(blob.Text, 180),
				Explanation:     "A database-related tool references SQL operations that can modify schema or data, or invoke dangerous database extensions.",
				Recommendation:  "Restrict database tools to read-only credentials and deny write-capable query execution unless explicitly required.",
				Confidence:      "high",
			})
			continue
		}
		if sqlReadRX.MatchString(blob.Text) {
			if _, ok := seen["AG-SQL002"]; ok {
				continue
			}
			seen["AG-SQL002"] = struct{}{}
			findings = append(findings, report.Finding{
				ID:              "AG-SQL002",
				Title:           "SQL read-only capability detected",
				Severity:        severity.Low,
				Category:        "sql-risk",
				OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
				ServerID:        tool.ServerID,
				ToolName:        tool.Name,
				Location:        blob.Location,
				Evidence:        redact.Snippet(blob.Text, 180),
				Explanation:     "A database-related tool appears to support read-only SQL. This is still sensitive because query access can expose data.",
				Recommendation:  "Use read-only credentials, least-privilege schemas, and query limits for SQL tools.",
				Confidence:      "medium",
			})
		}
	}
	return findings
}

func looksDatabaseRelated(tool mcp.ToolDefinition, text string) bool {
	combined := strings.ToLower(tool.Name + " " + tool.Title + " " + tool.Description + " " + text)
	return containsAny(combined, []string{"sql", "database", "db_", "query", "postgres", "mysql", "sqlite", "bigquery", "warehouse"})
}

func containsDatabaseWriteTerm(text string) bool {
	return dbWriteRX.MatchString(text)
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, strings.ToLower(needle)) {
			return true
		}
	}
	return false
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
