package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFixturesParsesTopLevelTools(t *testing.T) {
	path := writeTempFile(t, `
tools:
  - name: read_file
    description: Read a file.
`)

	doc, err := LoadFixtures(path)
	if err != nil {
		t.Fatalf("LoadFixtures failed: %v", err)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].ID != "fixtures" {
		t.Fatalf("expected synthetic fixtures server, got %#v", doc.Servers)
	}
	if len(doc.Tools) != 1 || doc.Tools[0].Name != "read_file" || doc.Tools[0].ServerID != "fixtures" {
		t.Fatalf("unexpected tools: %#v", doc.Tools)
	}
}

func TestLoadFixturesRespectsTopLevelToolServerID(t *testing.T) {
	path := writeTempFile(t, `
tools:
  - server_id: reporting
    name: sql_readonly
    description: Read reporting data.
`)

	doc, err := LoadFixtures(path)
	if err != nil {
		t.Fatalf("LoadFixtures failed: %v", err)
	}
	if len(doc.Tools) != 1 || doc.Tools[0].ServerID != "reporting" {
		t.Fatalf("expected top-level tool server_id to be preserved, got %#v", doc.Tools)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].ID != "reporting" || len(doc.Servers[0].Tools) != 1 {
		t.Fatalf("expected synthetic server to match top-level server_id, got %#v", doc.Servers)
	}
}

func TestLoadFixturesUnnamedServerToolsUseParsedServerID(t *testing.T) {
	path := writeTempFile(t, `
servers:
  - command: local-server
    tools:
      - name: read_file
        description: Read files.
`)

	doc, err := LoadFixtures(path)
	if err != nil {
		t.Fatalf("LoadFixtures failed: %v", err)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].ID != "unknown-server" {
		t.Fatalf("expected fallback server ID, got %#v", doc.Servers)
	}
	if len(doc.Tools) != 1 || doc.Tools[0].ServerID != "unknown-server" {
		t.Fatalf("expected nested tool to inherit fallback server ID, got %#v", doc.Tools)
	}
}

func TestLoadFixturesParsesJSONRPCResultTools(t *testing.T) {
	path := writeTempFile(t, `
result:
  tools:
    - name: jsonrpc_tool
      description: Tool from tools/list response.
`)

	doc, err := LoadFixtures(path)
	if err != nil {
		t.Fatalf("LoadFixtures failed: %v", err)
	}
	if len(doc.Tools) != 1 || doc.Tools[0].Name != "jsonrpc_tool" {
		t.Fatalf("expected JSON-RPC result tools to be parsed, got %#v", doc.Tools)
	}
}

func TestLoadFixturesParsesAllMCPMetadataKinds(t *testing.T) {
	path := writeTempFile(t, `
protocolVersion: "2025-11-25"
prompts:
  review:
    description: Review a file.
    arguments:
      - name: path
        required: true
resources:
  docs:
    uri: file:///docs
    mimeType: text/plain
resourceTemplates:
  files:
    uriTemplate: file:///{path}
    description: Files by path.
tools:
  read_file:
    description: Read a file.
    inputSchema:
      type: object
`)

	doc, err := LoadFixtures(path)
	if err != nil {
		t.Fatalf("LoadFixtures failed: %v", err)
	}
	if doc.ProtocolVersion != "2025-11-25" {
		t.Fatalf("unexpected protocol version: %q", doc.ProtocolVersion)
	}
	if len(doc.Tools) != 1 || len(doc.Prompts) != 1 || len(doc.Resources) != 1 || len(doc.ResourceTemplates) != 1 {
		t.Fatalf("unexpected metadata counts: tools=%d prompts=%d resources=%d templates=%d", len(doc.Tools), len(doc.Prompts), len(doc.Resources), len(doc.ResourceTemplates))
	}
	if len(doc.Prompts[0].Arguments) != 1 || !doc.Prompts[0].Arguments[0].Required {
		t.Fatalf("prompt arguments were not parsed: %#v", doc.Prompts[0])
	}
	if doc.Resources[0].URI != "file:///docs" || doc.ResourceTemplates[0].URITemplate != "file:///{path}" {
		t.Fatalf("resource metadata was not parsed: %#v %#v", doc.Resources[0], doc.ResourceTemplates[0])
	}
	if len(doc.Servers) != 1 || len(doc.Servers[0].Prompts) != 1 || len(doc.Servers[0].Resources) != 1 {
		t.Fatalf("synthetic server did not receive metadata: %#v", doc.Servers)
	}
}

func TestLoadFixturesParsesJSONRPCResultMetadata(t *testing.T) {
	path := writeTempFile(t, `
result:
  prompts:
    - name: review
  resources:
    - name: docs
      uri: file:///docs
  resourceTemplates:
    - name: files
      uriTemplate: file:///{path}
`)

	doc, err := LoadFixtures(path)
	if err != nil {
		t.Fatalf("LoadFixtures failed: %v", err)
	}
	if len(doc.Prompts) != 1 || len(doc.Resources) != 1 || len(doc.ResourceTemplates) != 1 {
		t.Fatalf("unexpected JSON-RPC metadata: %#v", doc)
	}
}

func TestLoadFixturesParsesToolMap(t *testing.T) {
	path := writeTempFile(t, `
tools:
  read_file:
    description: Read a file.
`)

	doc, err := LoadFixtures(path)
	if err != nil {
		t.Fatalf("LoadFixtures failed: %v", err)
	}
	if len(doc.Tools) != 1 || doc.Tools[0].Name != "read_file" {
		t.Fatalf("expected map-style tool name to be parsed, got %#v", doc.Tools)
	}
}

func TestLoadConfigParsesNamedMCPServers(t *testing.T) {
	path := writeTempFile(t, `
mcpServers:
  local-filesystem:
    command: npx
    args:
      - -y
      - server
    env:
      MODE: example
`)

	doc, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if len(doc.Servers) != 1 {
		t.Fatalf("expected one server, got %d", len(doc.Servers))
	}
	server := doc.Servers[0]
	if server.ID != "local-filesystem" || server.Command != "npx" || server.Env["MODE"] != "example" {
		t.Fatalf("unexpected server: %#v", server)
	}
}

func TestLoadConfigRejectsNonObject(t *testing.T) {
	path := writeTempFile(t, `["not", "object"]`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadConfigRejectsInvalidNamedServerShape(t *testing.T) {
	path := writeTempFile(t, `
mcpServers:
  local-filesystem: npx
`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected invalid server shape error")
	}
}

func TestLoadFixturesRejectsInvalidToolListItem(t *testing.T) {
	path := writeTempFile(t, `
tools:
  - read_file
`)
	if _, err := LoadFixtures(path); err == nil {
		t.Fatal("expected invalid tool shape error")
	}
}

func TestLoadDocumentRejectsEmptyRecognizedContent(t *testing.T) {
	if _, err := LoadFixtures(writeTempFile(t, `description: typo`)); err == nil {
		t.Fatal("expected fixture without tools to fail")
	}
	if _, err := LoadConfig(writeTempFile(t, `mcpServer: {}`)); err == nil {
		t.Fatal("expected config without servers to fail")
	}
}

func TestLoadDocumentRejectsMissingNamesAndDuplicates(t *testing.T) {
	missingName := writeTempFile(t, "tools:\n  - description: missing name\n")
	if _, err := LoadFixtures(missingName); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("expected missing tool name error, got %v", err)
	}

	duplicate := writeTempFile(t, "tools:\n  - name: read_file\n  - name: READ_FILE\n")
	if _, err := LoadFixtures(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate tool") {
		t.Fatalf("expected duplicate tool error, got %v", err)
	}
}

func TestLoadDocumentRejectsMissingResourceURIsAndDuplicatePrompts(t *testing.T) {
	missingURI := writeTempFile(t, "resources:\n  - name: docs\n")
	if _, err := LoadFixtures(missingURI); err == nil || !strings.Contains(err.Error(), "uri is required") {
		t.Fatalf("expected missing resource URI error, got %v", err)
	}

	duplicate := writeTempFile(t, "prompts:\n  - name: review\n  - name: REVIEW\n")
	if _, err := LoadFixtures(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate prompt") {
		t.Fatalf("expected duplicate prompt error, got %v", err)
	}
}

func TestLoadDocumentRejectsInvalidPromptArguments(t *testing.T) {
	missingName := writeTempFile(t, "prompts:\n  - name: review\n    arguments:\n      - required: true\n")
	if _, err := LoadFixtures(missingName); err == nil || !strings.Contains(err.Error(), "arguments[0].name is required") {
		t.Fatalf("expected missing prompt argument name, got %v", err)
	}

	duplicate := writeTempFile(t, "prompts:\n  - name: review\n    arguments:\n      - name: path\n      - name: PATH\n")
	if _, err := LoadFixtures(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate prompt argument") {
		t.Fatalf("expected duplicate prompt argument, got %v", err)
	}
}

func TestLoadDocumentRejectsInvalidKnownFieldType(t *testing.T) {
	path := writeTempFile(t, "mcpServers:\n  local:\n    command: 42\n")
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "command: expected string") {
		t.Fatalf("expected field type error, got %v", err)
	}
}

func TestLoadDocumentRejectsMultipleYAMLDocuments(t *testing.T) {
	path := writeTempFile(t, "tools:\n  - name: first\n---\ntools:\n  - name: second\n")
	if _, err := LoadFixtures(path); err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected multiple document error, got %v", err)
	}
}

func TestLoadDocumentRejectsNonStringMappingKeys(t *testing.T) {
	path := writeTempFile(t, "tools:\n  1:\n    description: numeric key\n")
	if _, err := LoadFixtures(path); err == nil || !strings.Contains(err.Error(), "mapping keys must be strings") {
		t.Fatalf("expected mapping key error, got %v", err)
	}
}

func TestLoadDocumentRejectsOversizedInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.yaml")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", int(MaxDocumentBytes)+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFixtures(path); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestLoadDocumentRejectsExcessiveNesting(t *testing.T) {
	nested := strings.Repeat(`{"x":`, MaxNestingDepth+2) + `"value"` + strings.Repeat("}", MaxNestingDepth+2)
	path := writeTempFile(t, `{"tools":[{"name":"deep","inputSchema":{"type":"object","nested":`+nested+`}}]}`)
	if _, err := LoadFixtures(path); err == nil || !strings.Contains(err.Error(), "nesting exceeds maximum depth") {
		t.Fatalf("expected nesting limit error, got %v", err)
	}
}

func TestLoadDocumentRejectsInvalidResourceSize(t *testing.T) {
	for _, size := range []string{"-1", "1.5"} {
		path := writeTempFile(t, "resources:\n  - name: docs\n    uri: file:///docs\n    size: "+size+"\n")
		if _, err := LoadFixtures(path); err == nil || !strings.Contains(err.Error(), "non-negative integer") {
			t.Fatalf("expected invalid resource size for %s, got %v", size, err)
		}
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
