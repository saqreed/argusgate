package detectors

import "strings"

func containsAny(text string, needles []string) bool {
	text = strings.ToLower(text)
	for _, needle := range needles {
		if containsPattern(text, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func containsPattern(text, needle string) bool {
	if needle == "" {
		return false
	}
	if hasNonTermChar(needle) {
		return strings.Contains(text, needle)
	}
	start := 0
	for {
		index := strings.Index(text[start:], needle)
		if index == -1 {
			return false
		}
		index += start
		end := index + len(needle)
		beforeBoundary := index == 0 || isTermBoundary(text[index-1])
		afterBoundary := end == len(text) || isTermBoundary(text[end])
		if beforeBoundary && afterBoundary {
			return true
		}
		start = end
	}
}

func hasNonTermChar(value string) bool {
	for i := 0; i < len(value); i++ {
		if !isASCIIAlphaNumeric(value[i]) {
			return true
		}
	}
	return false
}

func isTermBoundary(ch byte) bool {
	return !(isASCIIAlphaNumeric(ch) || ch == '_')
}

func isASCIIAlphaNumeric(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
}
