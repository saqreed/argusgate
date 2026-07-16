package report

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name,omitempty"`
	ShortDescription     sarifText          `json:"shortDescription,omitempty"`
	FullDescription      sarifText          `json:"fullDescription,omitempty"`
	Help                 sarifMarkdown      `json:"help,omitempty"`
	Properties           map[string]string  `json:"properties,omitempty"`
	DefaultConfiguration sarifDefaultConfig `json:"defaultConfiguration,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text,omitempty"`
}

type sarifMarkdown struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

func SARIFBytes(r Report) ([]byte, error) {
	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "ArgusGate",
				Version:        r.ArgusGateVersion,
				InformationURI: "https://github.com/saqreed/argusgate",
				Rules:          sarifRules(r.Findings),
			}},
			Results: sarifResults(r),
		}},
	}
	return json.Marshal(log)
}

func sarifRules(findings []Finding) []sarifRule {
	seen := map[string]sarifRule{}
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		seen[finding.ID] = sarifRule{
			ID:               finding.ID,
			Name:             finding.Title,
			ShortDescription: sarifText{Text: finding.Title},
			FullDescription:  sarifText{Text: finding.Explanation},
			Help: sarifMarkdown{
				Text:     finding.Recommendation,
				Markdown: finding.Recommendation,
			},
			DefaultConfiguration: sarifDefaultConfig{Level: sarifLevel(finding.Severity)},
			Properties: map[string]string{
				"category":          finding.Category,
				"owasp_mcp_mapping": finding.OWASPMCPMapping,
			},
		}
	}
	rules := make([]sarifRule, 0, len(seen))
	for _, rule := range seen {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})
	return rules
}

func sarifResults(r Report) []sarifResult {
	results := make([]sarifResult, 0, len(r.Findings))
	for _, finding := range r.Findings {
		if finding.Suppressed {
			continue
		}
		result := sarifResult{
			RuleID:  finding.ID,
			Level:   sarifLevel(finding.Severity),
			Message: sarifText{Text: finding.Title},
			PartialFingerprints: map[string]string{
				"argusgateFingerprint": finding.Fingerprint,
			},
			Properties: map[string]string{
				"severity":          finding.Severity.String(),
				"category":          finding.Category,
				"owasp_mcp_mapping": finding.OWASPMCPMapping,
				"server_id":         finding.ServerID,
				"tool_name":         finding.ToolName,
				"subject_type":      finding.SubjectType,
				"subject_name":      finding.SubjectName,
				"change_type":       finding.ChangeType,
				"location":          finding.Location,
				"confidence":        finding.Confidence,
			},
		}
		if r.SourcePath != "" {
			result.Locations = []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: strings.ReplaceAll(r.SourcePath, "\\", "/")},
				},
				LogicalLocations: []sarifLogicalLocation{{
					Name:               findingSubjectName(finding),
					FullyQualifiedName: finding.Location,
					Kind:               sarifLogicalKind(finding),
				}},
			}}
		}
		results = append(results, result)
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Level != results[j].Level {
			return results[i].Level < results[j].Level
		}
		return results[i].RuleID < results[j].RuleID
	})
	return results
}

func findingSubjectName(finding Finding) string {
	if finding.SubjectName != "" {
		return finding.SubjectName
	}
	return finding.ToolName
}

func sarifLogicalKind(finding Finding) string {
	switch finding.SubjectType {
	case "prompt":
		return "resource"
	case "resource", "resource_template":
		return "resource"
	default:
		return "function"
	}
}

func sarifLevel(level severity.Level) string {
	switch level {
	case severity.Critical, severity.High:
		return "error"
	case severity.Medium:
		return "warning"
	default:
		return "note"
	}
}
