package baseline

import (
	"fmt"
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

func Compare(expected, current File, path string) ([]report.Finding, Summary) {
	summary := Summary{Path: redact.Text(path), Version: expected.Version}
	var findings []report.Finding

	expectedServers := make(map[string]ServerEntry, len(expected.Servers))
	for _, entry := range expected.Servers {
		expectedServers[entry.Identity] = entry
	}
	for _, entry := range current.Servers {
		prior, exists := expectedServers[entry.Identity]
		if !exists {
			summary.ServerChanged++
			findings = append(findings, baselineFinding(
				"AG-BASE004",
				"Server was added after baseline review",
				severity.High,
				entry.ID,
				"server",
				entry.ID,
				"added",
				"", entry.ContractHash,
				"A server appeared after the reviewed baseline was created.",
				"Review its endpoint, launch contract, capabilities, and metadata before updating the baseline.",
			))
			continue
		}
		delete(expectedServers, entry.Identity)
		if prior.ContractHash != entry.ContractHash {
			summary.ServerChanged++
			findings = append(findings, baselineFinding(
				"AG-BASE004",
				"Server launch or endpoint contract changed",
				severity.High,
				entry.ID,
				"server",
				entry.ID,
				"changed",
				prior.ContractHash, entry.ContractHash,
				"The server command, transport, endpoint, capabilities, or credential key names changed since the reviewed baseline.",
				"Review the server configuration and update the baseline only after approving the change.",
			))
		}
	}
	for _, entry := range expected.Servers {
		if _, removed := expectedServers[entry.Identity]; !removed {
			continue
		}
		summary.ServerChanged++
		findings = append(findings, baselineFinding(
			"AG-BASE004",
			"Server was removed after baseline review",
			severity.Info,
			entry.ID,
			"server",
			entry.ID,
			"removed",
			entry.ContractHash, "",
			"A previously reviewed server is no longer present.",
			"Confirm that the removal is expected before refreshing the baseline.",
		))
	}

	expectedArtifacts := make(map[string]ArtifactEntry, len(expected.Artifacts))
	for _, entry := range expected.Artifacts {
		expectedArtifacts[entry.SubjectIdentity] = entry
	}
	serverNames := make(map[string]string, len(current.Servers)+len(expected.Servers))
	for _, entry := range expected.Servers {
		serverNames[entry.Identity] = entry.ID
	}
	for _, entry := range current.Servers {
		serverNames[entry.Identity] = entry.ID
	}
	for _, entry := range current.Artifacts {
		prior, exists := expectedArtifacts[entry.SubjectIdentity]
		if !exists {
			summary.Added++
			findings = append(findings, baselineFinding(
				"AG-BASE001",
				"New MCP metadata artifact is not in the baseline",
				severity.High,
				serverNames[entry.ServerIdentity],
				entry.Kind,
				entry.Name,
				"added",
				"", entry.ContractHash,
				"A tool, prompt, resource, or resource template appeared after the reviewed baseline was created.",
				"Review the new metadata and update the baseline only after approving it.",
			))
			continue
		}
		delete(expectedArtifacts, entry.SubjectIdentity)
		if prior.ContractHash != entry.ContractHash {
			summary.Changed++
			findings = append(findings, baselineFinding(
				"AG-BASE002",
				"MCP metadata contract changed",
				severity.High,
				serverNames[entry.ServerIdentity],
				entry.Kind,
				entry.Name,
				"changed",
				prior.ContractHash, entry.ContractHash,
				"The artifact description, schema, annotations, URI, arguments, or metadata changed since review.",
				"Review the contract change for rug pull or scope expansion and update the baseline only after approval.",
			))
		}
	}
	for _, entry := range expected.Artifacts {
		if _, removed := expectedArtifacts[entry.SubjectIdentity]; !removed {
			continue
		}
		summary.Removed++
		findings = append(findings, baselineFinding(
			"AG-BASE003",
			"MCP metadata artifact was removed",
			severity.Info,
			serverNames[entry.ServerIdentity],
			entry.Kind,
			entry.Name,
			"removed",
			entry.ContractHash, "",
			"A previously reviewed artifact is no longer advertised.",
			"Confirm the removal is expected and refresh the baseline during normal review.",
		))
	}
	return findings, summary
}

func baselineFinding(
	id, title string,
	level severity.Level,
	serverID, subjectType, subjectName, changeType, previousHash, currentHash, explanation, recommendation string,
) report.Finding {
	return report.Finding{
		ID:                   id,
		Title:                title,
		Severity:             level,
		Category:             "baseline-drift",
		OWASPMCPMapping:      "MCP03 Tool Poisoning",
		ServerID:             serverID,
		SubjectType:          subjectType,
		SubjectName:          subjectName,
		ChangeType:           changeType,
		PreviousContractHash: reportableHash(previousHash),
		CurrentContractHash:  reportableHash(currentHash),
		Location:             fmt.Sprintf("baseline.%s[%s]", subjectType, subjectName),
		Evidence:             fmt.Sprintf("%s %s", subjectType, changeType),
		Explanation:          explanation,
		Recommendation:       recommendation,
		Confidence:           "high",
	}
}

func reportableHash(value string) string {
	if !isSHA256(value) {
		return ""
	}
	return strings.ToLower(value)
}
