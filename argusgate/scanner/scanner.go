package scanner

import (
	"fmt"
	"time"

	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/policy"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/detectors"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

const Version = "0.2.5"
const MaxFindings = 10000

func ScanFixtures(path string, p policy.Policy) (report.Report, error) {
	doc, err := mcp.LoadFixtures(path)
	if err != nil {
		return report.Report{}, err
	}
	return ScanDocument("fixtures", doc, p), nil
}

func ScanConfig(path string, p policy.Policy) (report.Report, error) {
	doc, err := mcp.LoadConfig(path)
	if err != nil {
		return report.Report{}, err
	}
	return ScanDocument("config", doc, p), nil
}

func ScanDocument(sourceType string, doc mcp.Document, p policy.Policy) report.Report {
	scannedAt := time.Now().UTC()
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
		for _, tool := range doc.Tools {
			if appendLimited(&findings, detector.ScanTool(tool)) {
				truncated = true
				break scanLoop
			}
		}
	}

	if !truncated && appendLimited(&findings, policy.EvaluateServers(p, doc.Servers)) {
		truncated = true
	}
	if !truncated && appendLimited(&findings, policy.EvaluateTools(p, doc.Tools)) {
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
		Servers:           doc.Servers,
		Tools:             doc.Tools,
		Findings:          findings,
		PolicySummary:     policy.Summarize(p),
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
