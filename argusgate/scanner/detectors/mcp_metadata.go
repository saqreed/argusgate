package detectors

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
	"github.com/yosida95/uritemplate/v3"
)

type MCPMetadataDetector struct{}

func (MCPMetadataDetector) ScanServer(server mcp.ServerConfig) []report.Finding {
	if !mcp.ExceedsMaxNesting(server.Capabilities) && !mcp.ExceedsMaxNesting(server.Raw) {
		return nil
	}
	return []report.Finding{{
		ID:              "AG-MCP007",
		Title:           "MCP metadata nesting exceeds safe depth",
		Severity:        severity.High,
		Category:        "mcp-contract",
		OWASPMCPMapping: "MCP03 Tool Poisoning",
		ServerID:        server.ID,
		SubjectType:     "server",
		SubjectName:     server.ID,
		Location:        fmt.Sprintf("servers[%s].metadata", server.ID),
		Evidence:        fmt.Sprintf("nesting depth exceeds %d", mcp.MaxNestingDepth),
		Explanation:     "Deeply nested metadata can exhaust scanner or client resources and cannot be reviewed reliably.",
		Recommendation:  "Reject the server metadata and require a bounded, reviewable contract.",
		Confidence:      "high",
	}}
}

func (MCPMetadataDetector) ScanArtifact(artifact mcp.Artifact) []report.Finding {
	var findings []report.Finding
	if artifactExceedsMaxNesting(artifact) {
		findings = append(findings, withArtifactIdentity(report.Finding{
			ID:              "AG-MCP007",
			Title:           "MCP metadata nesting exceeds safe depth",
			Severity:        severity.High,
			Category:        "mcp-contract",
			OWASPMCPMapping: "MCP03 Tool Poisoning",
			Location:        fmt.Sprintf("%ss[%s].metadata", artifact.Kind, artifact.Name),
			Evidence:        fmt.Sprintf("nesting depth exceeds %d", mcp.MaxNestingDepth),
			Explanation:     "Deeply nested metadata can exhaust scanner or client resources and cannot be reviewed reliably.",
			Recommendation:  "Reject the metadata artifact and require a bounded, reviewable contract.",
			Confidence:      "high",
		}, artifact))
	}
	return append(findings, scanMCPArtifactContract(artifact)...)
}

func scanMCPArtifactContract(artifact mcp.Artifact) []report.Finding {
	var findings []report.Finding
	if artifact.Kind == mcp.ArtifactTool {
		findings = append(findings, validateToolSchema(artifact)...)
		findings = append(findings, validateToolOutputSchema(artifact)...)
		findings = append(findings, validateToolAnnotations(artifact)...)
	}
	resourceContract := ""
	if artifact.Kind == mcp.ArtifactResource {
		resourceContract = artifact.URI
	}
	if artifact.Kind == mcp.ArtifactResourceTemplate {
		resourceContract = artifact.URITemplate
	}
	if resourceContract != "" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(resourceContract)), "http://") {
		location := fmt.Sprintf("resources[%s].uri", artifact.Name)
		if artifact.Kind == mcp.ArtifactResourceTemplate {
			location = fmt.Sprintf("resource_templates[%s].uriTemplate", artifact.Name)
		}
		findings = append(findings, withArtifactIdentity(report.Finding{
			ID:              "AG-MCP003",
			Title:           "Resource uses an insecure HTTP URI",
			Severity:        severity.Medium,
			Category:        "mcp-contract",
			OWASPMCPMapping: "MCP01 Token Mismanagement & Secret Exposure",
			Location:        location,
			Evidence:        redact.Snippet(resourceContract, 180),
			Explanation:     "The resource metadata points to a cleartext HTTP endpoint that can be modified or observed in transit.",
			Recommendation:  "Use HTTPS for network resources or a non-network URI scheme appropriate for local resources.",
			Confidence:      "high",
		}, artifact))
	}
	if artifact.Kind == mcp.ArtifactResource {
		if err := validateResourceURI(artifact.URI); err != nil {
			findings = append(findings, invalidResourceContractFinding(artifact, artifact.URI, err))
		}
	}
	if artifact.Kind == mcp.ArtifactResourceTemplate {
		if _, err := uritemplate.New(artifact.URITemplate); err != nil {
			findings = append(findings, invalidResourceContractFinding(artifact, artifact.URITemplate, err))
		} else if err := validateResourceURI(artifact.URITemplate); err != nil {
			findings = append(findings, invalidResourceContractFinding(artifact, artifact.URITemplate, err))
		}
	}
	return findings
}

func artifactExceedsMaxNesting(artifact mcp.Artifact) bool {
	for _, value := range []any{
		artifact.InputSchema,
		artifact.OutputSchema,
		artifact.Execution,
		artifact.Arguments,
		artifact.Annotations,
		artifact.Meta,
		artifact.Raw,
	} {
		if mcp.ExceedsMaxNesting(value) {
			return true
		}
	}
	return false
}

func validateToolSchema(artifact mcp.Artifact) []report.Finding {
	schemaType, typeOK := artifact.InputSchema["type"].(string)
	if len(artifact.InputSchema) > 0 && typeOK && schemaType == "object" {
		return nil
	}
	evidence := "inputSchema is missing"
	if len(artifact.InputSchema) > 0 {
		evidence = fmt.Sprintf("inputSchema.type=%v", artifact.InputSchema["type"])
	}
	return []report.Finding{withArtifactIdentity(report.Finding{
		ID:              "AG-MCP001",
		Title:           "Invalid or missing tool input schema",
		Severity:        severity.High,
		Category:        "mcp-contract",
		OWASPMCPMapping: "MCP03 Tool Poisoning",
		Location:        fmt.Sprintf("tools[%s].inputSchema", artifact.Name),
		Evidence:        redact.Snippet(evidence, 180),
		Explanation:     "MCP tools require an object-root input schema. Missing or ambiguous schemas make argument review and policy enforcement unreliable.",
		Recommendation:  "Require a valid object-root JSON Schema for every tool input contract.",
		Confidence:      "high",
	}, artifact)}
}

func validateToolOutputSchema(artifact mcp.Artifact) []report.Finding {
	if len(artifact.OutputSchema) == 0 {
		return nil
	}
	if schemaType, ok := artifact.OutputSchema["type"].(string); ok && schemaType == "object" {
		return nil
	}
	return []report.Finding{withArtifactIdentity(report.Finding{
		ID:              "AG-MCP005",
		Title:           "Invalid tool output schema",
		Severity:        severity.Medium,
		Category:        "mcp-contract",
		OWASPMCPMapping: "MCP03 Tool Poisoning",
		Location:        fmt.Sprintf("tools[%s].outputSchema", artifact.Name),
		Evidence:        redact.Snippet(fmt.Sprintf("outputSchema.type=%v", artifact.OutputSchema["type"]), 180),
		Explanation:     "When present, a tool output schema should use an object root so clients can validate structured results consistently.",
		Recommendation:  "Correct the output schema or remove it until the server can advertise a valid object-root contract.",
		Confidence:      "high",
	}, artifact)}
}

func validateToolAnnotations(artifact mcp.Artifact) []report.Finding {
	var findings []report.Finding
	for _, name := range []string{"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"} {
		value, exists := artifact.Annotations[name]
		if !exists {
			continue
		}
		if _, ok := value.(bool); !ok {
			findings = append(findings, withArtifactIdentity(report.Finding{
				ID:              "AG-MCP006",
				Title:           "Invalid tool safety annotation type",
				Severity:        severity.Medium,
				Category:        "mcp-contract",
				OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
				Location:        fmt.Sprintf("tools[%s].annotations.%s", artifact.Name, name),
				Evidence:        redact.Snippet(fmt.Sprintf("%s=%v", name, value), 180),
				Explanation:     "A standard MCP tool safety annotation uses a non-boolean value, so clients may ignore or misinterpret it.",
				Recommendation:  "Use boolean values for standard tool safety hints and treat all annotations as untrusted advisory metadata.",
				Confidence:      "high",
			}, artifact))
		}
	}
	readOnly, readOnlySet := artifact.Annotations["readOnlyHint"].(bool)
	destructive, destructiveSet := artifact.Annotations["destructiveHint"].(bool)
	if !readOnlySet || !readOnly {
		return findings
	}

	reason := ""
	if destructiveSet && destructive {
		reason = "readOnlyHint=true and destructiveHint=true"
	} else {
		lower := strings.ToLower(artifact.Name + " " + artifact.Title + " " + artifact.Description)
		contradictions := []string{
			"write file", "delete file", "modify file", "execute command", "run command",
			"shell command", "insert into", "update database", "delete from", "drop table",
			"create resource", "deploy", "kubectl apply", "docker run",
		}
		for _, phrase := range contradictions {
			if strings.Contains(lower, phrase) {
				reason = "readOnlyHint=true but metadata declares " + phrase
				break
			}
		}
	}
	if reason == "" {
		return findings
	}
	findings = append(findings, withArtifactIdentity(report.Finding{
		ID:              "AG-MCP002",
		Title:           "Tool annotations contradict declared capability",
		Severity:        severity.High,
		Category:        "mcp-contract",
		OWASPMCPMapping: "MCP02 Scope Creep / Excessive Permissions",
		Location:        fmt.Sprintf("tools[%s].annotations", artifact.Name),
		Evidence:        redact.Snippet(reason, 180),
		Explanation:     "The tool's read-only annotation conflicts with another annotation or with its own capability description.",
		Recommendation:  "Treat annotations as untrusted hints and correct the tool contract before approval.",
		Confidence:      "high",
	}, artifact))
	return findings
}

func validateResourceURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme == "" {
		return fmt.Errorf("URI scheme is required")
	}
	if (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host == "" {
		return fmt.Errorf("%s URI host is required", parsed.Scheme)
	}
	return nil
}

func invalidResourceContractFinding(artifact mcp.Artifact, raw string, err error) report.Finding {
	field := "uri"
	if artifact.Kind == mcp.ArtifactResourceTemplate {
		field = "uriTemplate"
	}
	return withArtifactIdentity(report.Finding{
		ID:              "AG-MCP004",
		Title:           "Invalid resource URI contract",
		Severity:        severity.Medium,
		Category:        "mcp-contract",
		OWASPMCPMapping: "MCP03 Tool Poisoning",
		Location:        fmt.Sprintf("%ss[%s].%s", artifact.Kind, artifact.Name, field),
		Evidence:        redact.Snippet(fmt.Sprintf("%s (%v)", raw, err), 180),
		Explanation:     "The advertised resource URI or URI template is syntactically invalid or lacks a URI scheme.",
		Recommendation:  "Correct the advertised URI contract before allowing clients to depend on it.",
		Confidence:      "high",
	}, artifact)
}
