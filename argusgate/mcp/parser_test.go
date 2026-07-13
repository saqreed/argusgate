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

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
