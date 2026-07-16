package fileio

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadLimitedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.yaml")
	if err := os.WriteFile(path, []byte("tools: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLimitedFile(path, 64); err != nil {
		t.Fatalf("expected file to be read: %v", err)
	}
	if _, err := ReadLimitedFile(path, 4); err == nil || !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestReadLimitedFileRejectsDirectory(t *testing.T) {
	if _, err := ReadLimitedFile(t.TempDir(), 64); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected regular-file error, got %v", err)
	}
}

func TestWritePrivateFileReplacesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := WritePrivateFile(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Fatalf("unexpected content %q", data)
	}
}

func TestWritePrivateFileExclusiveDoesNotReplaceExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := WritePrivateFileExclusive(path, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFileExclusive(path, []byte("second")); err == nil {
		t.Fatal("expected exclusive write to reject existing output")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first" {
		t.Fatalf("existing file was modified: %q", data)
	}
}

func TestWritePrivateFileRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated Windows privileges")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "report")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFile(link, []byte("replace")); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
