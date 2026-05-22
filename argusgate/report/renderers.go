package report

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

func JSONBytes(r Report) ([]byte, error) {
	return json.Marshal(r)
}

func WriteTerminalSummary(w io.Writer, r Report) {
	fmt.Fprintln(w, "ArgusGate scan summary")
	fmt.Fprintf(w, "Source: %s (%s)\n", r.SourcePath, r.SourceType)
	fmt.Fprintf(w, "Servers: %d\n", len(r.Servers))
	fmt.Fprintf(w, "Tools: %d\n", len(r.Tools))
	fmt.Fprintf(w, "Findings: %d\n", len(r.Findings))
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
	for i, finding := range r.Findings {
		if i >= 5 {
			fmt.Fprintf(w, "... and %d more findings\n", len(r.Findings)-i)
			break
		}
		fmt.Fprintf(w, "- [%s] %s (%s", finding.Severity, finding.Title, finding.ID)
		if finding.ServerID != "" {
			fmt.Fprintf(w, " server=%s", finding.ServerID)
		}
		if finding.ToolName != "" {
			fmt.Fprintf(w, " tool=%s", finding.ToolName)
		}
		fmt.Fprintln(w, ")")
	}
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
