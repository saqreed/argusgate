package policy

import (
	"testing"

	"github.com/saqreed/argusgate/argusgate/mcp"
)

func TestSecurityPolicyNormalizesTraversal(t *testing.T) {
	for _, candidate := range []string{"./examples/../private/data", "./examples/nested/../../private/data"} {
		p := Default()
		p.Rules.Paths.Allow = []string{"./examples"}
		p.Rules.Paths.Deny = []string{"./private"}
		findings := EvaluateTools(p, []mcp.ToolDefinition{{ServerID: "s", Name: "read", Description: "Read " + candidate}})
		if !hasFinding(findings, "AG-POL004") {
			t.Errorf("normalized denied path missed: %s", candidate)
		}
	}
	if matchesAnyPrefix("./examples/../outside/data", []string{"./examples"}) {
		t.Fatal("traversal matched allow prefix")
	}
	if !matchesAnyPrefix("./examples/nested/../data", []string{"./examples"}) {
		t.Fatal("safe normalized path was rejected")
	}
	if matchesAnyPrefix("./examples-extra/data", []string{"./examples"}) {
		t.Fatal("namespace boundary was lost")
	}
	p := Default()
	p.Rules.Paths.Allow = []string{"./examples"}
	if !hasFinding(EvaluateTools(p, []mcp.ToolDefinition{{Name: "read", Description: "Read ./examples/.."}}), "AG-POL005") {
		t.Fatal("terminal parent traversal was trimmed before normalization")
	}
}

func TestSecurityResourceURINormalizesTraversal(t *testing.T) {
	if !uriHasPrefix("https://trusted.example/docs", "https://trusted.example") {
		t.Fatal("whole-origin namespace was rejected")
	}
	for _, uri := range []string{
		"https://trusted.example/api/../admin",
		"https://trusted.example/api/%2e%2e/admin",
		"https://trusted.example/api/%2e%2e%2fadmin",
	} {
		p := Default()
		p.Version = "0.3"
		p.Defaults.AllowUnknownResources = false
		p.Rules.ResourceURIs.Allow = []string{"https://trusted.example/api"}
		p.Rules.ResourceURIs.Deny = []string{"https://trusted.example/admin"}
		findings := EvaluateArtifacts(p, []mcp.Artifact{mcp.ArtifactFromResource(mcp.ResourceDefinition{ServerID: "s", Name: "docs", URI: uri})})
		if !hasFinding(findings, "AG-POL009") {
			t.Errorf("normalized denied URI missed: %s (%+v)", uri, findings)
		}
	}
	if uriHasPrefix("https://trusted.example/api/../outside", "https://trusted.example/api") {
		t.Fatal("URI traversal matched allowed namespace")
	}
	if !uriHasPrefix("https://trusted.example/api/sub/../docs", "https://trusted.example/api") {
		t.Fatal("safe normalized URI was rejected")
	}
	if uriHasPrefix("https://trusted.example/API/docs", "https://trusted.example/api") {
		t.Fatal("URI path case sensitivity was lost")
	}
	if uriHasPrefix("file:../private", "file:///workspace") {
		t.Fatal("opaque URI matched hierarchical namespace")
	}
	if uriHasPrefix("urn:/private", "urn:approved") {
		t.Fatal("hierarchical URI matched opaque namespace")
	}
}
