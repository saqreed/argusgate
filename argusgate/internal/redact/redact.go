package redact

import (
	"regexp"
	"strings"
	"unicode"
)

type rule struct {
	rx          *regexp.Regexp
	replacement string
}

var redactors = []rule{
	{regexp.MustCompile(`(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`(?i)(Basic\s+)([A-Za-z0-9+/=]{8,})`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`(?i)((?:postgres|postgresql|mysql|mongodb|redis|amqp)://)([^\s"']+)`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`(?i)((?:https?|mcp)://)([^@\s"']+:[^@\s"']+)(@)`), `${1}[REDACTED_SECRET]${3}`},
	{regexp.MustCompile(`(?i)([?&](?:api[_-]?key|token|password|passwd|secret|access[_-]?token)=)([^&#\s"']+)`), `${1}[REDACTED_SECRET]`},
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), `[REDACTED_JWT]`},
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`), `[REDACTED_PRIVATE_KEY]`},
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9][A-Za-z0-9_-]{16,}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9_-]{20,}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\bpypi-[A-Za-z0-9_-]{20,}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{20,}\b`), `[REDACTED_SECRET]`},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), `[REDACTED_SECRET]`},
}

var ansiEscapeRX = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var sensitiveKeyRX = regexp.MustCompile(`(?i)(^|[_-])(api[_-]?key|token|password|passwd|secret|private[_-]?key|authorization|access[_-]?token|credential)s?($|[_-])`)

func Text(value string) string {
	result := value
	for _, redactor := range redactors {
		result = redactor.rx.ReplaceAllString(result, redactor.replacement)
	}
	var out strings.Builder
	previous := 0
	for _, span := range secretAssignments(result, -1, allAssignments) {
		out.WriteString(result[previous:span.valueStart])
		if span.quote != 0 {
			out.WriteByte(span.quote)
		}
		out.WriteString("[REDACTED_SECRET]")
		if span.quote != 0 {
			out.WriteByte(span.quote)
		}
		previous = span.end
	}
	if previous == 0 {
		return result
	}
	out.WriteString(result[previous:])
	return out.String()
}

func IsSensitiveKey(value string) bool {
	var normalized strings.Builder
	var previous rune
	for _, ch := range strings.TrimSpace(value) {
		if unicode.IsUpper(ch) && (unicode.IsLower(previous) || unicode.IsDigit(previous)) {
			normalized.WriteByte('_')
		}
		normalized.WriteRune(ch)
		previous = ch
	}
	return sensitiveKeyRX.MatchString(normalized.String())
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

// Terminal removes terminal control sequences after secret redaction.
func Terminal(value string) string {
	value = ansiEscapeRX.ReplaceAllString(Text(value), "")
	value = strings.Map(func(ch rune) rune {
		if unicode.IsControl(ch) {
			return ' '
		}
		return ch
	}, value)
	return strings.Join(strings.Fields(value), " ")
}
