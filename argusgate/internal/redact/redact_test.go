package redact

import (
	"strings"
	"testing"
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
		"https://user:SUPER_SECRET_PASSWORD@example.com/mcp?token=FAKE_TOKEN_DO_NOT_USE_1234567890",
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
