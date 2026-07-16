package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTextRedactsSecrets(t *testing.T) {
	input := `Authorization: Bearer FAKE_TOKEN_DO_NOT_USE_1234567890 password="FAKE_PASSWORD_DO_NOT_USE"`
	got := Text(input)
	if got == input {
		t.Fatalf("expected redaction, got unchanged text")
	}
	if containsAny(got, []string{"FAKE_TOKEN_DO_NOT_USE_1234567890", "FAKE_PASSWORD_DO_NOT_USE"}) {
		t.Fatalf("secret leaked after redaction: %s", got)
	}
}

func TestSnippetRedactsBeforeTruncating(t *testing.T) {
	got := Snippet("token=FAKE_TOKEN_DO_NOT_USE_1234567890 and some other text", 30)
	if containsAny(got, []string{"FAKE_TOKEN_DO_NOT_USE_1234567890"}) {
		t.Fatalf("secret leaked in snippet: %s", got)
	}
}

func TestTextRedactsCommonTokenShapesAndURLSecrets(t *testing.T) {
	input := strings.Join([]string{
		"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
		"AKIAIOSFODNN7EXAMPLE",
		"sk-FAKEFAKEFAKEFAKEFAKEFAKE",
		"https://FAKE_TOKEN_DO_NOT_USE_1234567890:SUPER_SECRET_PASSWORD@example.com/mcp?token=FAKE_TOKEN_DO_NOT_USE_1234567890",
	}, " ")
	got := Text(input)
	if containsAny(got, []string{
		"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
		"AKIAIOSFODNN7EXAMPLE",
		"sk-FAKEFAKEFAKEFAKEFAKEFAKE",
		"SUPER_SECRET_PASSWORD",
		"FAKE_TOKEN_DO_NOT_USE_1234567890",
	}) {
		t.Fatalf("secret leaked after redaction: %s", got)
	}
}

func TestSnippetTruncatesUTF8Safely(t *testing.T) {
	got := Snippet("ключ token=FAKE_TOKEN_DO_NOT_USE_1234567890 значение", 6)
	if !utf8.ValidString(got) {
		t.Fatalf("snippet is not valid UTF-8: %q", got)
	}
	if containsAny(got, []string{"FAKE_TOKEN_DO_NOT_USE_1234567890"}) {
		t.Fatalf("secret leaked in snippet: %s", got)
	}
}

func TestTextRedactsUnterminatedPrivateKey(t *testing.T) {
	input := "-----BEGIN PRIVATE KEY-----\nFAKE_PRIVATE_KEY_DO_NOT_USE"
	got := Text(input)
	if strings.Contains(got, "FAKE_PRIVATE_KEY_DO_NOT_USE") {
		t.Fatalf("unterminated private key leaked: %s", got)
	}
}

func TestTextRedactsQuotedAndCommandLineSecrets(t *testing.T) {
	input := `password="FAKE PASSWORD DO NOT USE" --token FAKE_TOKEN_DO_NOT_USE_1234567890`
	got := Text(input)
	if strings.Contains(got, "FAKE PASSWORD DO NOT USE") || strings.Contains(got, "FAKE_TOKEN_DO_NOT_USE_1234567890") {
		t.Fatalf("secret leaked after redaction: %s", got)
	}
}

func TestTerminalRemovesControlSequences(t *testing.T) {
	got := Terminal("safe\x1b[31m\nforged")
	if strings.ContainsRune(got, '\x1b') || strings.ContainsAny(got, "\r\n") {
		t.Fatalf("terminal controls survived: %q", got)
	}
	if got != "safe forged" {
		t.Fatalf("unexpected terminal text: %q", got)
	}
}

func TestIsSensitiveKey(t *testing.T) {
	for _, key := range []string{"password", "api_key", "access-token", "Authorization", "client_secret"} {
		if !IsSensitiveKey(key) {
			t.Fatalf("expected %q to be sensitive", key)
		}
	}
	for _, key := range []string{"monkey", "keynote", "tokenizer", "description"} {
		if IsSensitiveKey(key) {
			t.Fatalf("did not expect %q to be sensitive", key)
		}
	}
}

func containsAny(text string, values []string) bool {
	for _, value := range values {
		for i := 0; i+len(value) <= len(text); i++ {
			if text[i:i+len(value)] == value {
				return true
			}
		}
	}
	return false
}
