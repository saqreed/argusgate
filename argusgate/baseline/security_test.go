package baseline

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/saqreed/argusgate/argusgate/mcp"
)

func TestSecurityBaselinePreservesPrimitiveChanges(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after any
	}{
		{"boolean", true, false},
		{"integer", int64(10), int64(20)},
		{"float", 1.25, 1.5},
		{"large integer", uint64(9007199254740992), uint64(9007199254740993)},
		{"JSON number", json.Number("10"), json.Number("20")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := hashCanonical(map[string]any{"value": tc.before})
			if err != nil {
				t.Fatal(err)
			}
			after, err := hashCanonical(map[string]any{"value": tc.after})
			if err != nil {
				t.Fatal(err)
			}
			if before == after {
				t.Fatal("changed primitive retained the same contract hash")
			}
		})
	}
}

func TestSecurityBaselineDetectsAnnotationAndPromptChanges(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	doc := mcp.Document{
		Servers: []mcp.ServerConfig{{ID: "s"}},
		Tools:   []mcp.ToolDefinition{{ServerID: "s", Name: "read", Annotations: map[string]any{"readOnlyHint": true}}},
		Prompts: []mcp.PromptDefinition{{ServerID: "s", Name: "review", Arguments: []mcp.PromptArgument{{Name: "path", Required: true}}}},
	}
	before, err := Create(doc, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	doc.Tools[0].Annotations["readOnlyHint"] = false
	doc.Prompts[0].Arguments[0].Required = false
	after, err := Create(doc, "test", now)
	if err != nil {
		t.Fatal(err)
	}
	_, summary := Compare(before, after, "baseline.json")
	if summary.Changed != 2 {
		t.Fatalf("expected two changed contracts, got %+v", summary)
	}
}
