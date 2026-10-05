package redact

import (
	"fmt"
	"strings"
	"testing"
)

func TestSecurityQuotedAssignments(t *testing.T) {
	for _, input := range []string{
		`{"password":"FAKE_SECRET_DO_NOT_USE"}`,
		`'clientSecret': 'FAKE_SECRET_DO_NOT_USE'`,
		`password="FAKE_PREFIX\"FAKE_SUFFIX_DO_NOT_USE"`,
		`password='FAKE_PREFIX''FAKE_SUFFIX_DO_NOT_USE'`,
		`password="FAKE_SECRET_DO_NOT_USE`,
		fmt.Sprintf("password=%q", "FAKE_PREFIX\"FAKE_SUFFIX_DO_NOT_USE"),
		`--client-secret "FAKE SECRET DO NOT USE"`,
		`password=[REDACTED_SECRET]FAKE_SUFFIX_DO_NOT_USE`,
	} {
		t.Run(input, func(t *testing.T) {
			for _, output := range []string{Text(input), Snippet(input, 180), Terminal(input)} {
				if strings.Contains(output, "FAKE") {
					t.Fatalf("secret was retained: %q", output)
				}
				if !strings.Contains(output, "[REDACTED_SECRET]") {
					t.Fatalf("redaction marker missing: %q", output)
				}
			}
			if once := Text(input); Text(once) != once {
				t.Fatalf("redaction is not idempotent: %q -> %q", once, Text(once))
			}
		})
	}
}

func TestSecurityRedactionLeavesNonSecretFields(t *testing.T) {
	input := `{"description":"Read documents", "tokenizer":"word", "monkey":"animal"}`
	if Text(input) != input {
		t.Fatal("non-secret fields were redacted")
	}
}

func TestSecuritySensitiveKeyAliases(t *testing.T) {
	for _, key := range []string{"clientSecret", "accessToken", "refreshToken", "apiKey", "privateKey", "X-API-Key"} {
		if !IsSensitiveKey(key) {
			t.Errorf("sensitive alias not recognized: %s", key)
		}
	}
}
