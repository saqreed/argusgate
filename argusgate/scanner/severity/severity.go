package severity

import (
	"fmt"
	"strings"
)

type Level string

const (
	Info     Level = "info"
	Low      Level = "low"
	Medium   Level = "medium"
	High     Level = "high"
	Critical Level = "critical"
)

var ordered = []Level{Info, Low, Medium, High, Critical}

func Parse(value string) (Level, error) {
	level := Level(strings.ToLower(strings.TrimSpace(value)))
	if level.IsValid() {
		return level, nil
	}
	return "", fmt.Errorf("invalid severity %q", value)
}

func (l Level) String() string {
	return string(l)
}

func (l Level) IsValid() bool {
	_, ok := rank(l)
	return ok
}

func (l Level) AtLeast(other Level) bool {
	left, okLeft := rank(l)
	right, okRight := rank(other)
	return okLeft && okRight && left >= right
}

func NextAbove(level Level) Level {
	for i, candidate := range ordered {
		if candidate == level {
			if i+1 >= len(ordered) {
				return Critical
			}
			return ordered[i+1]
		}
	}
	return High
}

func All() []Level {
	result := make([]Level, len(ordered))
	copy(result, ordered)
	return result
}

func rank(level Level) (int, bool) {
	for i, candidate := range ordered {
		if candidate == level {
			return i, true
		}
	}
	return 0, false
}
