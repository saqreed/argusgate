package detectors

import (
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type Detector interface {
	ScanArtifact(artifact mcp.Artifact) []report.Finding
	ScanServer(server mcp.ServerConfig) []report.Finding
}

type RuleMetadata struct {
	ID              string
	Title           string
	Severity        severity.Level
	Category        string
	OWASPMCPMapping string
	Recommendation  string
}

func DefaultDetectors() []Detector {
	return []Detector{
		ToolPoisoningDetector{},
		SecretExposureDetector{},
		DangerousCapabilityDetector{},
		SensitivePathDetector{},
		SQLRiskDetector{},
		MCPMetadataDetector{},
	}
}

func RuleRegistry() map[string]RuleMetadata {
	out := make(map[string]RuleMetadata, len(ruleRegistry))
	for id, metadata := range ruleRegistry {
		out[id] = metadata
	}
	return out
}

func withArtifactIdentity(finding report.Finding, artifact mcp.Artifact) report.Finding {
	finding.ServerID = artifact.ServerID
	finding.SubjectType = string(artifact.Kind)
	finding.SubjectName = artifact.Name
	if artifact.Kind == mcp.ArtifactTool {
		finding.ToolName = artifact.Name
	}
	return finding
}

var ruleRegistry = map[string]RuleMetadata{
	"AG-TP001":   {ID: "AG-TP001", Title: "Suspicious instruction detected in MCP metadata", Severity: severity.High, Category: "tool-poisoning", OWASPMCPMapping: "MCP03 Tool Poisoning", Recommendation: "Review the metadata, remove hidden or manipulative instructions, and only allow trusted MCP servers."},
	"AG-TP002":   {ID: "AG-TP002", Title: "Hidden markdown or HTML comment in MCP metadata", Severity: severity.Medium, Category: "tool-poisoning", OWASPMCPMapping: "MCP03 Tool Poisoning", Recommendation: "Remove hidden comments or require manual review before allowing the metadata artifact."},
	"AG-TP003":   {ID: "AG-TP003", Title: "Suspicious base64-like payload in MCP metadata", Severity: severity.High, Category: "tool-poisoning", OWASPMCPMapping: "MCP03 Tool Poisoning", Recommendation: "Remove encoded instructions and treat the metadata source as untrusted until reviewed."},
	"AG-TP004":   {ID: "AG-TP004", Title: "Invisible control character in MCP metadata", Severity: severity.Medium, Category: "tool-poisoning", OWASPMCPMapping: "MCP03 Tool Poisoning", Recommendation: "Remove invisible formatting characters from MCP metadata and review the original source."},
	"AG-SE001":   {ID: "AG-SE001", Title: "Bearer token found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE002":   {ID: "AG-SE002", Title: "Secret-like key/value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE003":   {ID: "AG-SE003", Title: "Private key block found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE004":   {ID: "AG-SE004", Title: "Connection string found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE005":   {ID: "AG-SE005", Title: "JWT-like token found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE006":   {ID: "AG-SE006", Title: "GitHub token-like value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE007":   {ID: "AG-SE007", Title: "Cloud access key-like value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE008":   {ID: "AG-SE008", Title: "API key-like value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE009":   {ID: "AG-SE009", Title: "Basic authorization value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE010":   {ID: "AG-SE010", Title: "URL userinfo credential found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE011":   {ID: "AG-SE011", Title: "Slack token-like value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE012":   {ID: "AG-SE012", Title: "npm token-like value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE013":   {ID: "AG-SE013", Title: "PyPI token-like value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE014":   {ID: "AG-SE014", Title: "Google API key-like value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE015":   {ID: "AG-SE015", Title: "GitLab token-like value found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-SE016":   {ID: "AG-SE016", Title: "Secret-like command-line argument found in metadata", Severity: severity.High, Category: "secret-exposure", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Remove secrets from MCP config and metadata. Use scoped credentials from a secret manager at runtime."},
	"AG-DC001":   {ID: "AG-DC001", Title: "Shell or arbitrary command execution capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC002":   {ID: "AG-DC002", Title: "File write or destructive filesystem capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC003":   {ID: "AG-DC003", Title: "Unrestricted file read capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC004":   {ID: "AG-DC004", Title: "Network request capability", Severity: severity.Medium, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC005":   {ID: "AG-DC005", Title: "Browser automation capability", Severity: severity.Medium, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC006":   {ID: "AG-DC006", Title: "Credential or secret management capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC007":   {ID: "AG-DC007", Title: "Container or cluster administration capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC008":   {ID: "AG-DC008", Title: "Database write capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC009":   {ID: "AG-DC009", Title: "Host system administration capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC010":   {ID: "AG-DC010", Title: "Cloud CLI administration capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC011":   {ID: "AG-DC011", Title: "Infrastructure-as-code mutation capability", Severity: severity.High, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-DC012":   {ID: "AG-DC012", Title: "Package manager execution capability", Severity: severity.Medium, Category: "dangerous-capability", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected."},
	"AG-PATH001": {ID: "AG-PATH001", Title: "Sensitive path referenced in MCP metadata", Severity: severity.High, Category: "sensitive-path", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Avoid exposing sensitive host paths to MCP tools; constrain file access to explicit low-risk directories."},
	"AG-SQL001":  {ID: "AG-SQL001", Title: "SQL write or administrative operation detected", Severity: severity.High, Category: "sql-risk", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Restrict database tools to read-only credentials and deny write-capable query execution unless explicitly required."},
	"AG-SQL002":  {ID: "AG-SQL002", Title: "SQL read-only capability detected", Severity: severity.Low, Category: "sql-risk", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Use read-only credentials, least-privilege schemas, and query limits for SQL tools."},
	"AG-MCP001":  {ID: "AG-MCP001", Title: "Invalid or missing tool input schema", Severity: severity.High, Category: "mcp-contract", OWASPMCPMapping: "MCP03 Tool Poisoning", Recommendation: "Require a valid object-root JSON Schema for every tool input contract."},
	"AG-MCP002":  {ID: "AG-MCP002", Title: "Tool annotations contradict declared capability", Severity: severity.High, Category: "mcp-contract", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Treat annotations as untrusted hints and correct the tool contract before approval."},
	"AG-MCP003":  {ID: "AG-MCP003", Title: "Resource uses an insecure HTTP URI", Severity: severity.Medium, Category: "mcp-contract", OWASPMCPMapping: "MCP01 Token Mismanagement & Secret Exposure", Recommendation: "Use HTTPS for network resources or a non-network URI scheme appropriate for local resources."},
	"AG-MCP004":  {ID: "AG-MCP004", Title: "Invalid resource URI contract", Severity: severity.Medium, Category: "mcp-contract", OWASPMCPMapping: "MCP03 Tool Poisoning", Recommendation: "Correct the advertised URI or URI template before approval."},
	"AG-MCP005":  {ID: "AG-MCP005", Title: "Invalid tool output schema", Severity: severity.Medium, Category: "mcp-contract", OWASPMCPMapping: "MCP03 Tool Poisoning", Recommendation: "Use an object-root output schema or omit it until the contract is valid."},
	"AG-MCP006":  {ID: "AG-MCP006", Title: "Invalid tool safety annotation type", Severity: severity.Medium, Category: "mcp-contract", OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions", Recommendation: "Use boolean standard safety hints and treat annotations as advisory."},
	"AG-MCP007":  {ID: "AG-MCP007", Title: "MCP metadata nesting exceeds safe depth", Severity: severity.High, Category: "mcp-contract", OWASPMCPMapping: "MCP03 Tool Poisoning", Recommendation: "Reject deeply nested metadata and require a bounded, reviewable contract."},
}
