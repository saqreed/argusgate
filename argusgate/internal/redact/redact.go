package redact

import (
	"regexp"
	"strings"
)

type rule struct {
	rx          *regexp.Regexp
	replacement string
}

var redactors = []rule{
	{regexp.MustCompile(`(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`(?i)(Basic\s+)([A-Za-z0-9+/=]{8,})`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`(?i)((?:api[_-]?key|token|password|passwd|secret|private[_-]?key|authorization|access[_-]?token)\s*[:=]\s*["']?)([^"'\s,;]{4,})`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`(?i)((?:postgres|postgresql|mysql|mongodb|redis|amqp)://)([^\s"']+)`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`(?i)((?:https?|mcp)://[^:/\s"']+:)([^@\s"']+)(@)`), `${1}[REDACTED_SECRET]${3}`},
	{regexp.MustCompile(`(?i)([?&](?:api[_-]?key|token|password|passwd|secret|access[_-]?token)=)([^&#\s"']+)`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), `[REDACTED_JWT]`},
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), `[REDACTED_PRIVATE_KEY]`},
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9][A-Za-z0-9_-]{16,}\b`), `[REDACTED_SECRET]`},
}

func Text(value string) string {
	result := value
	for _, redactor := range redactors {
		result = redactor.rx.ReplaceAllString(result, redactor.replacement)
	}
	return result
}

func Snippet(value string, max int) string {
	clean := strings.Join(strings.Fields(Text(value)), " ")
	runes := []rune(clean)
	if max <= 0 || len(runes) <= max {
		return clean
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}
