package mcp

import (
	"os"
	"path/filepath"
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

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
