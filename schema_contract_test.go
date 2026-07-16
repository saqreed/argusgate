package argusgate_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/saqreed/argusgate/argusgate/baseline"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/policy"
	"github.com/saqreed/argusgate/argusgate/scanner"
	"gopkg.in/yaml.v3"
)

func TestPublishedSchemasValidateProjectArtifacts(t *testing.T) {
	reportSchema := loadSchema(t, "docs/schemas/report.schema.json")
	policySchema := loadSchema(t, "docs/schemas/policy.schema.json")
	baselineSchema := loadSchema(t, "docs/schemas/baseline.schema.json")

	scanReport, err := scanner.ScanFixtures("examples/fixtures/safe-tools.yaml", policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	validateJSONValue(t, reportSchema, scanReport)

	doc, err := mcp.LoadFixtures("examples/fixtures/safe-tools.yaml")
	if err != nil {
		t.Fatal(err)
	}
	baselineFile, err := baseline.Create(doc, scanner.Version, time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	validateJSONValue(t, baselineSchema, baselineFile)
	baselineReport, err := scanner.ScanDocumentWithOptions("fixtures", doc, policy.Default(), scanner.Options{
		Baseline: &baselineFile, BaselinePath: "argusgate-baseline.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	validateJSONValue(t, reportSchema, baselineReport)

	v03Policy, err := policy.LoadFile("examples/policies/v03-trust.yaml")
	if err != nil {
		t.Fatal(err)
	}
	v03Report, err := scanner.ScanFixtures("examples/fixtures/v03-metadata.yaml", v03Policy)
	if err != nil {
		t.Fatal(err)
	}
	validateJSONValue(t, reportSchema, v03Report)

	for _, path := range []string{
		"examples/policies/default.yaml",
		"examples/policies/v02-suppressions.yaml",
		"examples/policies/v03-trust.yaml",
	} {
		validateYAMLFile(t, policySchema, path)
	}
}

func TestPolicySchemaRejectsV03FieldsInOlderPolicy(t *testing.T) {
	schema := loadSchema(t, "docs/schemas/policy.schema.json")
	instance := map[string]any{
		"version": "0.2",
		"rules": map[string]any{
			"deny_prompts": []any{"unsafe"},
		},
	}
	if err := schema.Validate(instance); err == nil {
		t.Fatal("policy schema accepted v0.3 fields under version 0.2")
	}
}

func loadSchema(t *testing.T, path string) *jsonschema.Resolved {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return resolved
}

func validateJSONValue(t *testing.T, schema *jsonschema.Resolved, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("schema validation failed: %v\n%s", err, raw)
	}
}

func validateYAMLFile(t *testing.T, schema *jsonschema.Resolved, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var instance any
	if err := yaml.Unmarshal(raw, &instance); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("%s failed schema validation: %v", path, err)
	}
}
