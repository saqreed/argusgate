package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

var policyPathCandidate = regexp.MustCompile(`(?i)(~[/\\][^\s"'<>),;]+|(?:/[A-Za-z0-9._-]+){1,}|(?:\./[A-Za-z0-9._/-]+)|[A-Za-z0-9._-]*(?:id_rsa|id_ed25519|kubeconfig|credentials|tokens|\.env)[A-Za-z0-9._/-]*)`)

func EvaluateTools(p Policy, tools []mcp.ToolDefinition) []report.Finding {
	var findings []report.Finding
	for _, tool := range tools {
		findings = append(findings, evaluateTool(p, tool)...)
	}
	return findings
}

func EvaluateServers(p Policy, servers []mcp.ServerConfig) []report.Finding {
	var findings []report.Finding
	for _, server := range servers {
		for _, blob := range mcp.ServerTextBlobs(server) {
			findings = append(findings, evaluateKeywords(p, server.ID, "", blob.Location, blob.Text)...)
			findings = append(findings, evaluatePathRules(p, server.ID, "", blob.Location, blob.Text)...)
		}
	}
	return findings
}

func DecideExit(p Policy, findings []report.Finding) ExitDecision {
	failOn := p.Defaults.FailOn
	if !failOn.IsValid() {
		failOn = severity.High
	}

	highest := severity.Info
	count := 0
	for _, finding := range findings {
		if finding.Severity.AtLeast(highest) {
			highest = finding.Severity
		}
		if finding.Severity.AtLeast(failOn) {
			count++
		}
	}

	if count > 0 {
		return ExitDecision{
			ExitCode:          1,
			FailOn:            failOn,
			HighestSeverity:   highest,
			FindingsAtOrAbove: count,
			Reason:            fmt.Sprintf("%d finding(s) at or above %s", count, failOn),
		}
	}
	return ExitDecision{
		ExitCode:          0,
		FailOn:            failOn,
		HighestSeverity:   highest,
		FindingsAtOrAbove: 0,
		Reason:            fmt.Sprintf("no findings at or above %s", failOn),
	}
}

func evaluateTool(p Policy, tool mcp.ToolDefinition) []report.Finding {
	var findings []report.Finding
	serverRules := p.Servers[tool.ServerID]

	denied := containsFold(p.Rules.DenyTools, tool.Name) || containsFold(serverRules.DenyTools, tool.Name)
	if denied {
		findings = append(findings, report.Finding{
			ID:              "AG-POL001",
			Title:           "Tool denied by policy",
			Severity:        severity.High,
			Category:        "policy-violation",
			OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
			ServerID:        tool.ServerID,
			ToolName:        tool.Name,
			Location:        "policy.rules.deny_tools",
			Evidence:        redact.Snippet(tool.Name, 120),
			Explanation:     "The tool name matches a configured deny list.",
			Recommendation:  "Remove the tool from the MCP configuration or update the policy only after review.",
			Confidence:      "high",
		})
	}

	if !denied && shouldFlagUnknownTool(p, serverRules, tool.Name) {
		findings = append(findings, report.Finding{
			ID:              "AG-POL002",
			Title:           "Tool is not explicitly allowed by policy",
			Severity:        severity.Medium,
			Category:        "policy-violation",
			OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
			ServerID:        tool.ServerID,
			ToolName:        tool.Name,
			Location:        "policy.rules.allow_tools",
			Evidence:        redact.Snippet(tool.Name, 120),
			Explanation:     "The policy is configured to reject unknown tools, and this tool is not in an allow list.",
			Recommendation:  "Add the tool to an allow list after review, or keep allow_unknown_tools enabled for advisory-only scans.",
			Confidence:      "high",
		})
	}

	for _, blob := range mcp.ToolTextBlobs(tool) {
		findings = append(findings, evaluateKeywords(p, tool.ServerID, tool.Name, blob.Location, blob.Text)...)
		findings = append(findings, evaluatePathRules(p, tool.ServerID, tool.Name, blob.Location, blob.Text)...)
	}

	return findings
}

func evaluateKeywords(p Policy, serverID, toolName, location, text string) []report.Finding {
	var findings []report.Finding
	lower := strings.ToLower(text)
	for _, keyword := range p.Rules.DenyKeywords {
		if keyword == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(keyword)) {
			findings = append(findings, report.Finding{
				ID:              "AG-POL003",
				Title:           "Denied keyword matched policy",
				Severity:        severity.High,
				Category:        "policy-violation",
				OWASPMCPMapping: "MCP03 Tool Poisoning",
				ServerID:        serverID,
				ToolName:        toolName,
				Location:        location,
				Evidence:        redact.Snippet(text, 180),
				Explanation:     "A metadata field contains a keyword denied by policy.",
				Recommendation:  "Review the metadata and remove the suspicious instruction or deny the tool.",
				Confidence:      "high",
			})
		}
	}
	return findings
}

func evaluatePathRules(p Policy, serverID, toolName, location, text string) []report.Finding {
	candidates := extractPolicyPathCandidates(text)
	if len(candidates) == 0 {
		return nil
	}

	var findings []report.Finding
	for _, candidate := range candidates {
		if matchesAnyPrefix(candidate, p.Rules.Paths.Deny) {
			findings = append(findings, report.Finding{
				ID:              "AG-POL004",
				Title:           "Path denied by policy",
				Severity:        severity.High,
				Category:        "policy-violation",
				OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
				ServerID:        serverID,
				ToolName:        toolName,
				Location:        location,
				Evidence:        redact.Snippet(candidate, 180),
				Explanation:     "A path-like value matches a denied path prefix.",
				Recommendation:  "Restrict the tool to approved paths or remove the denied path reference.",
				Confidence:      "high",
			})
			continue
		}
		if len(p.Rules.Paths.Allow) > 0 && !matchesAnyPrefix(candidate, p.Rules.Paths.Allow) {
			findings = append(findings, report.Finding{
				ID:              "AG-POL005",
				Title:           "Path is outside allowed policy prefixes",
				Severity:        severity.Medium,
				Category:        "policy-violation",
				OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
				ServerID:        serverID,
				ToolName:        toolName,
				Location:        location,
				Evidence:        redact.Snippet(candidate, 180),
				Explanation:     "A path-like value does not match any allowed path prefix.",
				Recommendation:  "Constrain paths to an allowed prefix or expand the policy after review.",
				Confidence:      "medium",
			})
		}
	}
	return findings
}

func extractPolicyPathCandidates(text string) []string {
	matches := policyPathCandidate.FindAllStringIndex(text, -1)
	if len(matches) == 0 {
		return nil
	}

	candidates := make([]string, 0, len(matches))
	for _, match := range matches {
		candidate := text[match[0]:match[1]]
		if shouldSkipPathCandidate(text, match[0], candidate) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func shouldSkipPathCandidate(text string, start int, candidate string) bool {
	if !strings.HasPrefix(candidate, "/") {
		return false
	}
	if start == 0 {
		return false
	}
	prev := text[start-1]
	if prev == ':' || prev == '/' {
		return true
	}
	return isPathAdjacentIdentifier(prev)
}

func isPathAdjacentIdentifier(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') ||
		(ch >= 'a' && ch <= 'z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '_' ||
		ch == '-' ||
		ch == '.' ||
		ch == '@'
}

func shouldFlagUnknownTool(p Policy, serverRules ServerRule, toolName string) bool {
	if p.Defaults.AllowUnknownTools {
		return false
	}
	if isAllowedTool(p, serverRules, toolName) {
		return false
	}
	return true
}

func isAllowedTool(p Policy, serverRules ServerRule, toolName string) bool {
	if len(serverRules.AllowTools) > 0 {
		return containsFold(serverRules.AllowTools, toolName)
	}
	return containsFold(p.Rules.AllowTools, toolName)
}

func containsFold(values []string, needle string) bool {
	for _, value := range values {
		if strings.EqualFold(value, needle) {
			return true
		}
	}
	return false
}

func matchesAnyPrefix(candidate string, prefixes []string) bool {
	normalizedCandidate := normalizePathText(candidate)
	for _, prefix := range prefixes {
		normalizedPrefix := normalizePathText(prefix)
		if normalizedPrefix == "" {
			continue
		}
		if strings.HasPrefix(normalizedCandidate, normalizedPrefix) || strings.Contains(normalizedCandidate, normalizedPrefix) {
			return true
		}
	}
	return false
}

func normalizePathText(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
}
