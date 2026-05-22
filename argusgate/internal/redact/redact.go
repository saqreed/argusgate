package redact

import (
	"regexp"
	"strings"
)

var redactors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})`),
	regexp.MustCompile(`(?i)((?:api[_-]?key|token|password|passwd|secret|private[_-]?key|authorization)\s*[:=]\s*["']?)([^"'\s,;]{4,})`),
	regexp.MustCompile(`(?i)((?:postgres|postgresql|mysql|mongodb|redis|amqp)://)([^\s"']+)`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

func Text(value string) string {
	result := value
	for i, rx := range redactors {
		switch i {
		case 0, 1, 2:
			result = rx.ReplaceAllString(result, `${1}[REDACTED_SECRET]`)
		case 3:
			result = rx.ReplaceAllString(result, `[REDACTED_JWT]`)
		case 4:
			result = rx.ReplaceAllString(result, `[REDACTED_PRIVATE_KEY]`)
		}
	}
	return result
}

func Snippet(value string, max int) string {
	clean := strings.Join(strings.Fields(Text(value)), " ")
	if max <= 0 || len(clean) <= max {
		return clean
	}
	if max <= 3 {
		return clean[:max]
	}
	return clean[:max-3] + "..."
}
