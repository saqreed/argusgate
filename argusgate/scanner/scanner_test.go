package scanner

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/saqreed/argusgate/argusgate/baseline"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/policy"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

func TestScanSafeFixtureHasNoHighFindings(t *testing.T) {
	r, err := ScanFixtures(repoPath(t, "examples", "fixtures", "safe-tools.yaml"), policy.Default())
	if err != nil {
		t.Fatalf("ScanFixtures failed: %v", err)
	}
	for _, finding := range r.Findings {
		if finding.Severity.AtLeast(severity.High) {
			t.Fatalf("safe fixture produced high finding: %#v", finding)
		}
	}
}

func TestScanMaliciousFixtureHasHighFindings(t *testing.T) {
	p, err := policy.LoadFile(repoPath(t, "examples", "policies", "default.yaml"))
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	r, err := ScanFixtures(repoPath(t, "examples", "fixtures", "malicious-tools.yaml"), p)
	if err != nil {
		t.Fatalf("ScanFixtures failed: %v", err)
	}
	if r.SeveritySummary["high"] == 0 && r.SeveritySummary["critical"] == 0 {
		t.Fatalf("malicious fixture did not produce high findings: %#v", r.Findings)
	}
}

func TestScanConfigDetectsFakeBearerToken(t *testing.T) {
	p, err := policy.LoadFile(repoPath(t, "examples", "policies", "default.yaml"))
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	r, err := ScanConfig(repoPath(t, "examples", "configs", "mcp-config.yaml"), p)
	if err != nil {
		t.Fatalf("ScanConfig failed: %v", err)
	}
	if !reportHasFinding(r, "AG-SE001") {
		t.Fatalf("expected fake bearer token finding, got %#v", r.Findings)
	}
}

func TestReportJSONRoundTrip(t *testing.T) {
	r, err := ScanFixtures(repoPath(t, "examples", "fixtures", "safe-tools.yaml"), policy.Default())
	if err != nil {
		t.Fatalf("ScanFixtures failed: %v", err)
	}
	data, err := report.JSONBytes(r)
	if err != nil {
		t.Fatalf("JSONBytes failed: %v", err)
	}
	var decoded report.Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("JSON roundtrip failed: %v", err)
	}
	if decoded.SourceType != "fixtures" || decoded.ArgusGateVersion != Version {
		t.Fatalf("unexpected decoded report: %#v", decoded)
	}
}

func TestScanReportIncludesFingerprints(t *testing.T) {
	p, err := policy.LoadFile(repoPath(t, "examples", "policies", "default.yaml"))
	if err != nil {
		t.Fatalf("LoadFile failed: %v", err)
	}
	r, err := ScanFixtures(repoPath(t, "examples", "fixtures", "malicious-tools.yaml"), p)
	if err != nil {
		t.Fatalf("ScanFixtures failed: %v", err)
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, finding := range r.Findings {
		if finding.Fingerprint == "" {
			t.Fatalf("finding missing fingerprint: %#v", finding)
		}
	}
}

func TestScanAppliesPolicySuppressionsToExitDecision(t *testing.T) {
	docPath := repoPath(t, "examples", "fixtures", "malicious-tools.yaml")
	base, err := ScanFixtures(docPath, policy.Default())
	if err != nil {
		t.Fatalf("ScanFixtures failed: %v", err)
	}
	var target string
	for _, finding := range base.Findings {
		if finding.Severity.AtLeast(severity.High) {
			target = finding.Fingerprint
			break
		}
	}
	if target == "" {
		t.Fatalf("expected high finding fingerprint: %#v", base.Findings)
	}

	p := policy.Default()
	p.Version = "0.2"
	p.Rules.Suppressions = []policy.Suppression{{
		Fingerprint: target,
		Reason:      "accepted fixture risk",
		Expires:     "2099-12-31",
	}}
	r, err := ScanFixtures(docPath, p)
	if err != nil {
		t.Fatalf("ScanFixtures failed: %v", err)
	}
	if !hasSuppressedFinding(r, target) {
		t.Fatalf("expected suppressed finding %s, got %#v", target, r.Findings)
	}
}

func TestScanWithBaselineDetectsMetadataDrift(t *testing.T) {
	doc, err := mcp.LoadFixtures(repoPath(t, "examples", "fixtures", "safe-tools.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	reviewed, err := baseline.Create(doc, Version, time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := ScanDocumentWithOptions("fixtures", doc, policy.Default(), Options{Baseline: &reviewed, BaselinePath: "baseline.json"})
	if err != nil {
		t.Fatal(err)
	}
	if reportHasFinding(unchanged, "AG-BASE001") || reportHasFinding(unchanged, "AG-BASE002") {
		t.Fatalf("unchanged metadata produced drift: %#v", unchanged.Findings)
	}

	doc.Tools[0].Description = "Changed metadata contract."
	changed, err := ScanDocumentWithOptions("fixtures", doc, policy.Default(), Options{Baseline: &reviewed, BaselinePath: "baseline.json"})
	if err != nil {
		t.Fatal(err)
	}
	if !reportHasFinding(changed, "AG-BASE002") {
		t.Fatalf("changed metadata did not produce drift: %#v", changed.Findings)
	}
	decision, ok := changed.ExitDecision.(policy.ExitDecision)
	if !ok || decision.ExitCode != 1 {
		t.Fatalf("drift should fail at the default threshold: %#v", changed.ExitDecision)
	}
}

func TestAppendLimitedCapsFindings(t *testing.T) {
	findings := make([]report.Finding, MaxFindings-1)
	truncated := appendLimited(&findings, []report.Finding{{ID: "one"}, {ID: "two"}})
	if !truncated || len(findings) != MaxFindings || findings[len(findings)-1].ID != "one" {
		t.Fatalf("unexpected limit result: truncated=%v len=%d last=%#v", truncated, len(findings), findings[len(findings)-1])
	}
}

func reportHasFinding(r report.Report, id string) bool {
	for _, finding := range r.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func hasSuppressedFinding(r report.Report, fingerprint string) bool {
	for _, finding := range r.Findings {
		if finding.Fingerprint == fingerprint && finding.Suppressed {
			return true
		}
	}
	return false
}

func repoPath(t *testing.T, elems ...string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	parts := append([]string{root}, elems...)
	return filepath.Join(parts...)
}
