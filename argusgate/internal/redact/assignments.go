package redact

import (
	"regexp"
	"strings"
)

var assignmentStartRX = regexp.MustCompile(`(?:["']?)([A-Za-z][A-Za-z0-9_-]*)(?:["']?)\s*[:=]\s*|--([A-Za-z][A-Za-z0-9_-]*)\s+`)

type assignmentSpan struct {
	start, valueStart, end int
	quote                  byte
	flag                   bool
}

type assignmentKind int

const (
	allAssignments assignmentKind = iota
	keyValueAssignment
	commandLineAssignment
)

// KeyValueAssignments shares escape-aware secret boundaries with the detector.
func KeyValueAssignments(value string, limit int) []string {
	return assignmentTexts(value, limit, keyValueAssignment)
}

func CommandLineAssignments(value string, limit int) []string {
	return assignmentTexts(value, limit, commandLineAssignment)
}

func assignmentTexts(value string, limit int, kind assignmentKind) []string {
	var out []string
	for _, span := range secretAssignments(value, limit, kind) {
		out = append(out, value[span.start:span.end])
	}
	return out
}

func secretAssignments(value string, limit int, kind assignmentKind) []assignmentSpan {
	var spans []assignmentSpan
	for offset := 0; offset < len(value) && (limit < 0 || len(spans) < limit); {
		match := assignmentStartRX.FindStringSubmatchIndex(value[offset:])
		if match == nil {
			break
		}
		start, valueStart := offset+match[0], offset+match[1]
		keyStart, keyEnd := match[2], match[3]
		flag := keyStart < 0
		if flag {
			keyStart, keyEnd = match[4], match[5]
		}
		key := value[offset+keyStart : offset+keyEnd]
		offset = valueStart
		if !IsSensitiveKey(key) || valueStart == len(value) {
			continue
		}
		end, quote := assignmentValueEnd(value, valueStart)
		if end > valueStart {
			offset = end
			if kind == keyValueAssignment && flag || kind == commandLineAssignment && !flag {
				continue
			}
			spans = append(spans, assignmentSpan{start: start, valueStart: valueStart, end: end, quote: quote, flag: flag})
		}
	}
	return spans
}

func assignmentValueEnd(value string, start int) (int, byte) {
	quote := value[start]
	if quote == '"' || quote == '\'' {
		for i := start + 1; i < len(value); i++ {
			if value[i] == '\\' && i+1 < len(value) {
				i++
				continue
			}
			if value[i] == quote {
				if quote == '\'' && i+1 < len(value) && value[i+1] == quote {
					i++
					continue
				}
				return i + 1, quote
			}
		}
		// Unterminated quoted secrets fail closed through the end of the text.
		return len(value), quote
	}
	end := start
	for _, template := range []struct{ open, close string }{{"${", "}"}, {"{{", "}}"}, {"<", ">"}} {
		if strings.HasPrefix(value[start:], template.open) {
			if closing := strings.Index(value[start+len(template.open):], template.close); closing >= 0 {
				end = start + len(template.open) + closing + len(template.close)
			}
			break
		}
	}
	for end < len(value) && !strings.ContainsRune(" \t\r\n,;}\"'&", rune(value[end])) {
		end++
	}
	return end, 0
}
