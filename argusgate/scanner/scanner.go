package scanner

import (
	"time"

	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/policy"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/detectors"
)

const Version = "0.2.0"

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
	for _, detector := range detectors.DefaultDetectors() {
		for _, server := range doc.Servers {
			findings = append(findings, detector.ScanServer(server)...)
		}
		for _, tool := range doc.Tools {
			findings = append(findings, detector.ScanTool(tool)...)
		}
	}

	findings = append(findings, policy.EvaluateServers(p, doc.Servers)...)
	findings = append(findings, policy.EvaluateTools(p, doc.Tools)...)
	findings = report.EnsureFingerprints(findings)
	findings = policy.ApplySuppressions(p, findings, scannedAt)
	findings = report.EnsureFingerprints(findings)
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
