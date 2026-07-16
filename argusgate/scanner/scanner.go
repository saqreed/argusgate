package scanner

import (
	"fmt"
	"time"

	"github.com/saqreed/argusgate/argusgate/baseline"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/policy"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/detectors"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

const Version = "0.3.0"
const MaxFindings = 10000

type Options struct {
	Baseline     *baseline.File
	BaselinePath string
}

func ScanFixtures(path string, p policy.Policy) (report.Report, error) {
	return ScanFixturesWithOptions(path, p, Options{})
}

func ScanFixturesWithOptions(path string, p policy.Policy, options Options) (report.Report, error) {
	doc, err := mcp.LoadFixtures(path)
	if err != nil {
		return report.Report{}, err
	}
	return ScanDocumentWithOptions("fixtures", doc, p, options)
}

func ScanConfig(path string, p policy.Policy) (report.Report, error) {
	return ScanConfigWithOptions(path, p, Options{})
}

func ScanConfigWithOptions(path string, p policy.Policy, options Options) (report.Report, error) {
	doc, err := mcp.LoadConfig(path)
	if err != nil {
		return report.Report{}, err
	}
	return ScanDocumentWithOptions("config", doc, p, options)
}

func ScanDocument(sourceType string, doc mcp.Document, p policy.Policy) report.Report {
	return scanDocument(sourceType, doc, p, time.Now().UTC(), nil, nil)
}

func ScanDocumentWithOptions(sourceType string, doc mcp.Document, p policy.Policy, options Options) (report.Report, error) {
	scannedAt := time.Now().UTC()
	var baselineFindings []report.Finding
	var baselineSummary any
	if options.Baseline != nil {
		current, err := baseline.Create(doc, Version, scannedAt)
		if err != nil {
			return report.Report{}, fmt.Errorf("create current baseline state: %w", err)
		}
		baselineFindings, baselineSummary = baseline.Compare(*options.Baseline, current, options.BaselinePath)
	}
	return scanDocument(sourceType, doc, p, scannedAt, baselineFindings, baselineSummary), nil
}

func scanDocument(
	sourceType string,
	doc mcp.Document,
	p policy.Policy,
	scannedAt time.Time,
	baselineFindings []report.Finding,
	baselineSummary any,
) report.Report {
	var findings []report.Finding
	truncated := false

scanLoop:
	for _, detector := range detectors.DefaultDetectors() {
		for _, server := range doc.Servers {
			if appendLimited(&findings, detector.ScanServer(server)) {
				truncated = true
				break scanLoop
			}
		}
		for _, artifact := range mcp.DocumentArtifacts(doc) {
			if appendLimited(&findings, detector.ScanArtifact(artifact)) {
				truncated = true
				break scanLoop
			}
		}
	}

	if !truncated && appendLimited(&findings, policy.EvaluateServers(p, doc.Servers)) {
		truncated = true
	}
	if !truncated && appendLimited(&findings, policy.EvaluateArtifacts(p, mcp.DocumentArtifacts(doc))) {
		truncated = true
	}
	if !truncated && appendLimited(&findings, baselineFindings) {
		truncated = true
	}
	if truncated {
		findings = append(findings, report.Finding{
			ID:             "AG-SCAN001",
			Title:          "Finding limit reached",
			Severity:       severity.Critical,
			Category:       "scanner-limit",
			Location:       "scanner",
			Evidence:       fmt.Sprintf("report truncated at %d findings", MaxFindings),
			Explanation:    "The input produced more findings than ArgusGate can safely retain in one report, so analysis was stopped early.",
			Recommendation: "Split the input into smaller files and review it as potentially hostile.",
			Confidence:     "high",
		})
	}
	findings = report.DeduplicateFindings(findings)
	findings = policy.ApplySuppressions(p, findings, scannedAt)
	findings = report.DeduplicateFindings(findings)
	decision := policy.DecideExit(p, findings)

	return report.Build(report.Input{
		ScannedAt:         scannedAt,
		Version:           Version,
		SourceType:        sourceType,
		SourcePath:        doc.SourcePath,
		ProtocolVersion:   doc.ProtocolVersion,
		Servers:           doc.Servers,
		Tools:             doc.Tools,
		Prompts:           doc.Prompts,
		Resources:         doc.Resources,
		ResourceTemplates: doc.ResourceTemplates,
		Findings:          findings,
		PolicySummary:     policy.Summarize(p),
		BaselineSummary:   baselineSummary,
		ExitDecision:      decision,
		RedactFindingText: true,
	})
}

func appendLimited(destination *[]report.Finding, additions []report.Finding) bool {
	remaining := MaxFindings - len(*destination)
	if remaining <= 0 {
		return len(additions) > 0
	}
	if len(additions) <= remaining {
		*destination = append(*destination, additions...)
		return false
	}
	*destination = append(*destination, additions[:remaining]...)
	return true
}
