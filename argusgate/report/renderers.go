package report

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
)

func JSONBytes(r Report) ([]byte, error) {
	return json.Marshal(r)
}

func WriteTerminalSummary(w io.Writer, r Report) {
	fmt.Fprintln(w, "ArgusGate scan summary")
	fmt.Fprintf(w, "Source: %s (%s)\n", redact.Terminal(r.SourcePath), redact.Terminal(r.SourceType))
	fmt.Fprintf(w, "Servers: %d\n", len(r.Servers))
	fmt.Fprintf(w, "Tools: %d\n", len(r.Tools))
	fmt.Fprintf(w, "Prompts: %d\n", len(r.Prompts))
	fmt.Fprintf(w, "Resources: %d\n", len(r.Resources))
	fmt.Fprintf(w, "Resource templates: %d\n", len(r.ResourceTemplates))
	fmt.Fprintf(w, "Findings: %d\n", countUnsuppressed(r.Findings))
	if suppressed := countSuppressed(r.Findings); suppressed > 0 {
		fmt.Fprintf(w, "Suppressed: %d\n", suppressed)
	}
	fmt.Fprintf(w, "Severity: critical=%d high=%d medium=%d low=%d info=%d\n",
		r.SeveritySummary["critical"],
		r.SeveritySummary["high"],
		r.SeveritySummary["medium"],
		r.SeveritySummary["low"],
		r.SeveritySummary["info"],
	)
	if exitCode, reason, ok := exitDecisionText(r.ExitDecision); ok {
		status := "pass"
		if exitCode != 0 {
			status = "fail"
		}
		fmt.Fprintf(w, "Exit: %s (code=%d, %s)\n", status, exitCode, reason)
	}
	shown := 0
	totalUnsuppressed := countUnsuppressed(r.Findings)
	for _, finding := range r.Findings {
		if finding.Suppressed {
			continue
		}
		if shown >= 5 {
			fmt.Fprintf(w, "... and %d more findings\n", totalUnsuppressed-shown)
			break
		}
		fmt.Fprintf(w, "- [%s] %s (%s", finding.Severity, redact.Terminal(finding.Title), redact.Terminal(finding.ID))
		if finding.ServerID != "" {
			fmt.Fprintf(w, " server=%s", redact.Terminal(finding.ServerID))
		}
		if finding.ToolName != "" {
			fmt.Fprintf(w, " tool=%s", redact.Terminal(finding.ToolName))
		} else if finding.SubjectType != "" || finding.SubjectName != "" {
			fmt.Fprintf(w, " subject=%s:%s", redact.Terminal(finding.SubjectType), redact.Terminal(finding.SubjectName))
		}
		if finding.ChangeType != "" {
			fmt.Fprintf(w, " change=%s", redact.Terminal(finding.ChangeType))
		}
		fmt.Fprintln(w, ")")
		shown++
	}
}

func countSuppressed(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.Suppressed {
			count++
		}
	}
	return count
}

func countUnsuppressed(findings []Finding) int {
	return len(findings) - countSuppressed(findings)
}

func exitDecisionText(value any) (int, string, bool) {
	v := reflect.ValueOf(value)
	if !v.IsValid() {
		return 0, "", false
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return 0, "", false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0, "", false
	}

	codeField := v.FieldByName("ExitCode")
	reasonField := v.FieldByName("Reason")
	if !codeField.IsValid() || !reasonField.IsValid() || codeField.Kind() != reflect.Int || reasonField.Kind() != reflect.String {
		return 0, "", false
	}
	return int(codeField.Int()), reasonField.String(), true
}
