package argusgate_test

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCompositeActionMetadata(t *testing.T) {
	raw, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Name   string                    `yaml:"name"`
		Inputs map[string]map[string]any `yaml:"inputs"`
		Runs   struct {
			Using string `yaml:"using"`
			Steps []struct {
				ID    string `yaml:"id"`
				Shell string `yaml:"shell"`
				Run   string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &metadata); err != nil {
		t.Fatalf("parse action.yml: %v", err)
	}
	if metadata.Name == "" || metadata.Runs.Using != "composite" {
		t.Fatalf("invalid action metadata: %#v", metadata)
	}
	for _, name := range []string{"source-type", "source", "policy", "baseline", "report", "sarif", "version"} {
		if _, ok := metadata.Inputs[name]; !ok {
			t.Fatalf("missing action input %q", name)
		}
	}
	if len(metadata.Runs.Steps) != 3 {
		t.Fatalf("expected three action steps, got %d", len(metadata.Runs.Steps))
	}
	for i, step := range metadata.Runs.Steps {
		if step.Shell != "pwsh" || step.Run == "" {
			t.Fatalf("invalid action step %d: %#v", i, step)
		}
	}
}
