package scanner

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

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

func reportHasFinding(r report.Report, id string) bool {
	for _, finding := range r.Findings {
		if finding.ID == id {
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
