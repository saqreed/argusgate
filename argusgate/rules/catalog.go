package rules

import (
	"sort"
	"strings"

	"github.com/saqreed/argusgate/argusgate/scanner/detectors"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type Entry struct {
	ID              string         `json:"id"`
	Title           string         `json:"title"`
	Severity        severity.Level `json:"severity"`
	Category        string         `json:"category"`
	Confidence      string         `json:"confidence"`
	OWASPMCPMapping string         `json:"owasp_mcp_mapping,omitempty"`
	Recommendation  string         `json:"recommendation,omitempty"`
}

func List() []Entry {
	entries := make([]Entry, 0)
	for _, metadata := range detectors.RuleRegistry() {
		entries = append(entries, Entry{
			ID: metadata.ID, Title: metadata.Title, Severity: metadata.Severity,
			Category: metadata.Category, Confidence: "varies",
			OWASPMCPMapping: metadata.OWASPMCPMapping, Recommendation: metadata.Recommendation,
		})
	}
	entries = append(entries, nonDetectorRules()...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

func Find(id string) (Entry, bool) {
	for _, entry := range List() {
		if strings.EqualFold(entry.ID, strings.TrimSpace(id)) {
			return entry, true
		}
	}
	return Entry{}, false
}

func nonDetectorRules() []Entry {
	return []Entry{
		rule("AG-BASE001", "New MCP metadata artifact is not in the baseline", severity.High, "baseline-drift", "high", "MCP03 Tool Poisoning", "Review the new metadata and update the baseline only after approval."),
		rule("AG-BASE002", "MCP metadata contract changed", severity.High, "baseline-drift", "high", "MCP03 Tool Poisoning", "Review the change for rug pull or scope expansion before updating the baseline."),
		rule("AG-BASE003", "MCP metadata artifact was removed", severity.Info, "baseline-drift", "high", "MCP03 Tool Poisoning", "Confirm that the removal is expected."),
		rule("AG-BASE004", "Server launch or endpoint contract changed", severity.High, "baseline-drift", "high", "MCP03 Tool Poisoning", "Review command, endpoint, transport, capabilities, and credential key changes."),
		rule("AG-POL001", "Tool denied by policy", severity.High, "policy-violation", "high", "MCP02 Scope Creep / Excessive Permissions", "Remove the tool or change policy only after review."),
		rule("AG-POL002", "Tool is not explicitly allowed by policy", severity.Medium, "policy-violation", "high", "MCP02 Scope Creep / Excessive Permissions", "Approve the tool explicitly or allow unknown tools."),
		rule("AG-POL003", "Denied keyword matched policy", severity.High, "policy-violation", "high", "MCP03 Tool Poisoning", "Remove the denied metadata or reject the artifact."),
		rule("AG-POL004", "Path denied by policy", severity.High, "policy-violation", "high", "MCP02 Scope Creep / Excessive Permissions", "Restrict the artifact to approved paths."),
		rule("AG-POL005", "Path is outside allowed policy prefixes", severity.Medium, "policy-violation", "medium", "MCP02 Scope Creep / Excessive Permissions", "Constrain paths or approve an additional prefix."),
		rule("AG-POL006", "Policy suppression has expired", severity.Medium, "policy-violation", "high", "MCP02 Scope Creep / Excessive Permissions", "Review the finding again before renewing the suppression."),
		rule("AG-POL007", "Prompt denied by policy", severity.High, "policy-violation", "high", "MCP06 Prompt Injection via Contextual Payloads", "Remove or explicitly review the prompt."),
		rule("AG-POL008", "Prompt is not explicitly allowed by policy", severity.Medium, "policy-violation", "high", "MCP06 Prompt Injection via Contextual Payloads", "Approve the prompt explicitly or allow unknown prompts."),
		rule("AG-POL009", "Resource URI denied by policy", severity.High, "policy-violation", "high", "MCP02 Scope Creep / Excessive Permissions", "Remove the resource or restrict it to an approved namespace."),
		rule("AG-POL010", "Resource URI is not explicitly allowed by policy", severity.Medium, "policy-violation", "high", "MCP02 Scope Creep / Excessive Permissions", "Approve the URI prefix or allow unknown resources."),
		rule("AG-SCAN001", "Finding limit reached", severity.Critical, "scanner-limit", "high", "", "Split the input and treat incomplete analysis as unsafe."),
	}
}

func rule(id, title string, level severity.Level, category, confidence, mapping, recommendation string) Entry {
	return Entry{
		ID: id, Title: title, Severity: level, Category: category,
		Confidence: confidence, OWASPMCPMapping: mapping, Recommendation: recommendation,
	}
}
