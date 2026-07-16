package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

var policyPathCandidate = regexp.MustCompile(`(?i)(~[/\\][^\s"'<>),;]+|[A-Za-z]:[/\\][^\s"'<>),;]+|(?:/[A-Za-z0-9._-]+){1,}|(?:\./[A-Za-z0-9._/-]+)|[A-Za-z0-9._-]*(?:id_rsa|id_ed25519|kubeconfig|credentials|tokens|\.env)[A-Za-z0-9._/-]*)`)

func EvaluateTools(p Policy, tools []mcp.ToolDefinition) []report.Finding {
	artifacts := make([]mcp.Artifact, 0, len(tools))
	for _, tool := range tools {
		artifacts = append(artifacts, mcp.ArtifactFromTool(tool))
	}
	return EvaluateArtifacts(p, artifacts)
}

func EvaluateArtifacts(p Policy, artifacts []mcp.Artifact) []report.Finding {
	var findings []report.Finding
	for _, artifact := range artifacts {
		findings = append(findings, evaluateArtifact(p, artifact)...)
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
		if finding.Suppressed {
			continue
		}
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
			Reason:            fmt.Sprintf("%d unsuppressed finding(s) at or above %s", count, failOn),
		}
	}
	return ExitDecision{
		ExitCode:          0,
		FailOn:            failOn,
		HighestSeverity:   highest,
		FindingsAtOrAbove: 0,
		Reason:            fmt.Sprintf("no unsuppressed findings at or above %s", failOn),
	}
}

func ApplySuppressions(p Policy, findings []report.Finding, now time.Time) []report.Finding {
	if len(p.Rules.Suppressions) == 0 {
		out := make([]report.Finding, len(findings))
		copy(out, findings)
		return out
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	active := map[string]string{}
	expiredFindings := make([]report.Finding, 0)
	for _, suppression := range p.Rules.Suppressions {
		fingerprint := strings.ToLower(strings.TrimSpace(suppression.Fingerprint))
		reason := strings.TrimSpace(suppression.Reason)
		if suppressionExpired(suppression, now) {
			expiredFindings = append(expiredFindings, expiredSuppressionFinding(fingerprint, reason, suppression.Expires))
			continue
		}
		active[fingerprint] = reason
	}

	out := make([]report.Finding, 0, len(findings)+len(expiredFindings))
	for _, finding := range findings {
		if finding.ID == "AG-SCAN001" {
			out = append(out, finding)
			continue
		}
		if reason, ok := active[strings.ToLower(strings.TrimSpace(finding.Fingerprint))]; ok && finding.Fingerprint != "" {
			finding.Suppressed = true
			finding.SuppressionReason = reason
		}
		out = append(out, finding)
	}
	out = append(out, expiredFindings...)
	return out
}

func suppressionExpired(s Suppression, now time.Time) bool {
	if strings.TrimSpace(s.Expires) == "" {
		return false
	}
	expires, err := time.Parse(time.DateOnly, s.Expires)
	if err != nil {
		return true
	}
	cutoff := time.Date(expires.Year(), expires.Month(), expires.Day(), 23, 59, 59, int(time.Second-time.Nanosecond), time.UTC)
	return now.UTC().After(cutoff)
}

func expiredSuppressionFinding(fingerprint, reason, expires string) report.Finding {
	return report.Finding{
		ID:                "AG-POL006",
		Title:             "Policy suppression has expired",
		Severity:          severity.Medium,
		Category:          "policy-violation",
		OWASPMCPMapping:   "MCP02 Scope Creep / Excessive Permissions",
		Location:          "policy.rules.suppressions",
		Evidence:          redact.Snippet(fingerprint, 120),
		Explanation:       fmt.Sprintf("A suppression expired on %s and was not applied.", expires),
		Recommendation:    "Remove expired suppressions or renew them only after reviewing the finding again.",
		Confidence:        "high",
		SuppressionReason: reason,
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

func evaluateArtifact(p Policy, artifact mcp.Artifact) []report.Finding {
	var findings []report.Finding
	switch artifact.Kind {
	case mcp.ArtifactTool:
		if artifact.ToolDefinition != nil {
			findings = append(findings, evaluateTool(p, *artifact.ToolDefinition)...)
		}
	case mcp.ArtifactPrompt:
		findings = append(findings, evaluatePrompt(p, artifact)...)
	case mcp.ArtifactResource, mcp.ArtifactResourceTemplate:
		findings = append(findings, evaluateResourceURI(p, artifact)...)
	}
	if artifact.Kind != mcp.ArtifactTool {
		for _, blob := range mcp.ArtifactTextBlobs(artifact) {
			found := evaluateKeywords(p, artifact.ServerID, "", blob.Location, blob.Text)
			found = append(found, evaluatePathRules(p, artifact.ServerID, "", blob.Location, blob.Text)...)
			for i := range found {
				found[i] = withPolicyArtifactIdentity(found[i], artifact)
			}
			findings = append(findings, found...)
		}
	}
	for i := range findings {
		if findings[i].SubjectType == "" {
			findings[i] = withPolicyArtifactIdentity(findings[i], artifact)
		}
	}
	return findings
}

func evaluatePrompt(p Policy, artifact mcp.Artifact) []report.Finding {
	serverRules := p.Servers[artifact.ServerID]
	denied := containsFold(p.Rules.DenyPrompts, artifact.Name) || containsFold(serverRules.DenyPrompts, artifact.Name)
	if denied {
		return []report.Finding{withPolicyArtifactIdentity(report.Finding{
			ID:              "AG-POL007",
			Title:           "Prompt denied by policy",
			Severity:        severity.High,
			Category:        "policy-violation",
			OWASPMCPMapping: "MCP06 Prompt Injection via Contextual Payloads",
			Location:        "policy.rules.deny_prompts",
			Evidence:        redact.Snippet(artifact.Name, 120),
			Explanation:     "The prompt name matches a configured deny list.",
			Recommendation:  "Remove the prompt or update the policy only after reviewing its metadata and arguments.",
			Confidence:      "high",
		}, artifact)}
	}
	if p.Defaults.AllowUnknownPrompts || isAllowedPrompt(p, serverRules, artifact.Name) {
		return nil
	}
	return []report.Finding{withPolicyArtifactIdentity(report.Finding{
		ID:              "AG-POL008",
		Title:           "Prompt is not explicitly allowed by policy",
		Severity:        severity.Medium,
		Category:        "policy-violation",
		OWASPMCPMapping: "MCP06 Prompt Injection via Contextual Payloads",
		Location:        "policy.rules.allow_prompts",
		Evidence:        redact.Snippet(artifact.Name, 120),
		Explanation:     "The policy rejects unknown prompts, and this prompt is not in an allow list.",
		Recommendation:  "Add the prompt after review or enable allow_unknown_prompts for advisory-only scans.",
		Confidence:      "high",
	}, artifact)}
}

func evaluateResourceURI(p Policy, artifact mcp.Artifact) []report.Finding {
	uri := artifact.URI
	if artifact.Kind == mcp.ArtifactResourceTemplate {
		uri = artifact.URITemplate
	}
	serverRules := p.Servers[artifact.ServerID]
	denied := matchesAnyURIPrefix(uri, p.Rules.ResourceURIs.Deny) ||
		matchesAnyURIPrefix(uri, serverRules.ResourceURIs.Deny)
	if denied {
		return []report.Finding{withPolicyArtifactIdentity(report.Finding{
			ID:              "AG-POL009",
			Title:           "Resource URI denied by policy",
			Severity:        severity.High,
			Category:        "policy-violation",
			OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
			Location:        "policy.rules.resource_uris.deny",
			Evidence:        redact.Snippet(uri, 180),
			Explanation:     "The resource URI or URI template matches a denied prefix.",
			Recommendation:  "Remove the resource or restrict it to an approved URI namespace.",
			Confidence:      "high",
		}, artifact)}
	}
	if p.Defaults.AllowUnknownResources || isAllowedResourceURI(p, serverRules, uri) {
		return nil
	}
	return []report.Finding{withPolicyArtifactIdentity(report.Finding{
		ID:              "AG-POL010",
		Title:           "Resource URI is not explicitly allowed by policy",
		Severity:        severity.Medium,
		Category:        "policy-violation",
		OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
		Location:        "policy.rules.resource_uris.allow",
		Evidence:        redact.Snippet(uri, 180),
		Explanation:     "The policy rejects unknown resources, and this URI is outside the configured allow prefixes.",
		Recommendation:  "Add an explicit URI prefix after review or enable allow_unknown_resources for advisory-only scans.",
		Confidence:      "high",
	}, artifact)}
}

func withPolicyArtifactIdentity(finding report.Finding, artifact mcp.Artifact) report.Finding {
	finding.ServerID = artifact.ServerID
	finding.SubjectType = string(artifact.Kind)
	finding.SubjectName = artifact.Name
	if artifact.Kind == mcp.ArtifactTool {
		finding.ToolName = artifact.Name
	}
	return finding
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
		candidate := trimPathPunctuation(text[match[0]:match[1]])
		if candidate == "" {
			continue
		}
		if shouldSkipPathCandidate(text, match[0], candidate) {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates
}

func trimPathPunctuation(candidate string) string {
	if strings.ContainsAny(candidate, "/\\") {
		return strings.TrimRight(candidate, ".:")
	}
	return candidate
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

func isAllowedPrompt(p Policy, serverRules ServerRule, promptName string) bool {
	if len(serverRules.AllowPrompts) > 0 {
		return containsFold(serverRules.AllowPrompts, promptName)
	}
	return containsFold(p.Rules.AllowPrompts, promptName)
}

func isAllowedResourceURI(p Policy, serverRules ServerRule, uri string) bool {
	if len(serverRules.ResourceURIs.Allow) > 0 {
		return matchesAnyURIPrefix(uri, serverRules.ResourceURIs.Allow)
	}
	return matchesAnyURIPrefix(uri, p.Rules.ResourceURIs.Allow)
}

func matchesAnyURIPrefix(candidate string, prefixes []string) bool {
	candidate = strings.TrimSpace(candidate)
	for _, prefix := range prefixes {
		prefix = strings.TrimSpace(prefix)
		if prefix != "" && uriHasPrefix(candidate, prefix) {
			return true
		}
	}
	return false
}

func uriHasPrefix(candidate, prefix string) bool {
	candidateURL, candidateErr := url.Parse(candidate)
	prefixURL, prefixErr := url.Parse(prefix)
	if candidateErr == nil && prefixErr == nil && prefixURL.Scheme != "" {
		if !strings.EqualFold(candidateURL.Scheme, prefixURL.Scheme) {
			return false
		}
		if !strings.EqualFold(candidateURL.Host, prefixURL.Host) {
			return false
		}
		if prefixURL.RawQuery != "" && candidateURL.RawQuery != prefixURL.RawQuery {
			return false
		}
		if prefixURL.Opaque != "" || candidateURL.Opaque != "" {
			return hasURINamespacePrefix(strings.ToLower(candidateURL.Opaque), strings.ToLower(prefixURL.Opaque))
		}
		return hasURINamespacePrefix(candidateURL.EscapedPath(), prefixURL.EscapedPath())
	}
	return hasURINamespacePrefix(strings.ToLower(candidate), strings.ToLower(prefix))
}

func hasURINamespacePrefix(candidate, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if candidate == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(candidate, prefix)
	}
	return strings.HasPrefix(candidate, prefix+"/")
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
		if isPathLikePrefix(normalizedPrefix) && hasPathPrefix(normalizedCandidate, normalizedPrefix) {
			return true
		}
		if !isPathLikePrefix(normalizedPrefix) && containsPathSegment(normalizedCandidate, normalizedPrefix) {
			return true
		}
	}
	return false
}

func normalizePathText(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
}

func isPathLikePrefix(value string) bool {
	return strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "~/") ||
		strings.HasPrefix(value, "./") ||
		strings.Contains(value, "/")
}

func hasPathPrefix(candidate, prefix string) bool {
	if candidate == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(candidate, prefix)
	}
	return strings.HasPrefix(candidate, prefix+"/")
}

func containsPathSegment(candidate, segment string) bool {
	for _, part := range strings.Split(candidate, "/") {
		if part == segment || strings.HasPrefix(part, segment+".") {
			return true
		}
	}
	return false
}
