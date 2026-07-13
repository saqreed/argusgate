package detectors

import (
	"regexp"
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type SQLRiskDetector struct{}

var (
	sqlWriteRX           = regexp.MustCompile(`(?i)\b(drop|delete|update|insert|alter|truncate)\b|copy\s+.+\s+to\s+program|xp_cmdshell|load_extension|sys_eval`)
	sqlReadRX            = regexp.MustCompile(`(?i)\b(select|with)\b`)
	dbWriteRX            = regexp.MustCompile(`(?i)\b(drop|delete|update|insert|alter|truncate|merge|create|grant|revoke)\b|copy\s+.+\s+to\s+program|xp_cmdshell|load_extension|sys_eval`)
	sqlNegativeContextRX = regexp.MustCompile(`(?i)\b(read[- ]only|select[- ]only|does not support|not support|no write|without write|without modifying|blocks?|rejects?|forbids?|disallows?|prohibits?|prevents?)\b`)
	sqlPositiveContextRX = regexp.MustCompile(`(?i)\b(can|may|supports?|allows?|executes?|runs?|write[- ]capable|admin)\b[^.]{0,120}\b(drop|delete|update|insert|alter|truncate|merge|create|grant|revoke)\b`)
	sqlWriteSyntaxRX     = regexp.MustCompile(`(?i)\b(update\s+[A-Za-z0-9_."` + "`" + `\[\]-]+\s+set|delete\s+from|insert\s+into|drop\s+(table|database|schema)|alter\s+(table|database|schema)|truncate\s+table|merge\s+into|create\s+(table|database|schema)|grant\s+.+\s+to|revoke\s+.+\s+from)\b`)
	sqlWriteListRX       = regexp.MustCompile(`(?i)\b(run|execute|support|allow|including|statements?|operations?|write|admin)\w*\b[^.]{0,160}\b(drop|delete|update|insert|alter|truncate|merge|create|grant|revoke)\b`)
	sqlExtensionRX       = regexp.MustCompile(`(?i)copy\s+.+\s+to\s+program|xp_cmdshell|load_extension|sys_eval`)
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
		if containsSQLWriteRisk(blob.Text) {
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
	return containsDatabaseWriteRisk(text)
}

func containsSQLWriteRisk(text string) bool {
	return containsWriteRisk(text, sqlWriteRX)
}

func containsDatabaseWriteRisk(text string) bool {
	return containsWriteRisk(text, dbWriteRX)
}

func containsWriteRisk(text string, rx *regexp.Regexp) bool {
	for _, loc := range rx.FindAllStringIndex(text, -1) {
		if isWriteMentionNegated(text, loc) {
			continue
		}
		sentence := sentenceAround(text, loc)
		if sqlExtensionRX.MatchString(sentence) || sqlWriteSyntaxRX.MatchString(sentence) || sqlPositiveContextRX.MatchString(sentence) || sqlWriteListRX.MatchString(sentence) {
			return true
		}
	}
	return false
}

func isWriteMentionNegated(text string, loc []int) bool {
	sentence := sentenceAround(text, loc)
	if !sqlNegativeContextRX.MatchString(sentence) {
		return false
	}
	return !hasPositiveSQLWriteContext(sentence)
}

func hasPositiveSQLWriteContext(text string) bool {
	for _, loc := range sqlPositiveContextRX.FindAllStringIndex(text, -1) {
		prefixStart := loc[0] - 16
		if prefixStart < 0 {
			prefixStart = 0
		}
		prefix := strings.ToLower(text[prefixStart:loc[0]])
		if strings.Contains(prefix, "does not ") || strings.Contains(prefix, "not ") || strings.Contains(prefix, "no write ") {
			continue
		}
		return true
	}
	return false
}

func sentenceAround(text string, loc []int) string {
	start := loc[0]
	for start > 0 {
		if isSentenceBoundary(text[start-1]) {
			break
		}
		start--
	}
	end := loc[1]
	for end < len(text) {
		if isSentenceBoundary(text[end]) {
			break
		}
		end++
	}
	return text[start:end]
}

func isSentenceBoundary(ch byte) bool {
	return ch == '.' || ch == '\n' || ch == '\r' || ch == ';'
}
