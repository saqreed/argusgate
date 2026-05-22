package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/saqreed/argusgate/argusgate/scanner/severity"
	"gopkg.in/yaml.v3"
)

type rawPolicy struct {
	Version  string                `yaml:"version"`
	Project  Project               `yaml:"project"`
	Defaults rawDefaults           `yaml:"defaults"`
	Rules    Rules                 `yaml:"rules"`
	Servers  map[string]ServerRule `yaml:"servers"`
}

type rawDefaults struct {
	FailOn            string `yaml:"fail_on"`
	AllowedSeverity   string `yaml:"allowed_severity"`
	AllowUnknownTools *bool  `yaml:"allow_unknown_tools"`
}

func LoadFile(path string) (Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy %s: %w", path, err)
	}

	var decoded any
	if err := yaml.Unmarshal(raw, &decoded); err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	normalized := normalizePolicyKeys(decoded)
	normalizedBytes, err := yaml.Marshal(normalized)
	if err != nil {
		return Policy{}, fmt.Errorf("normalize policy %s: %w", path, err)
	}

	var rawPol rawPolicy
	if err := yaml.Unmarshal(normalizedBytes, &rawPol); err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}

	p, err := fromRaw(rawPol)
	if err != nil {
		return Policy{}, fmt.Errorf("validate policy %s: %w", path, err)
	}
	p.SourcePath = path
	return p, nil
}

func Validate(p Policy) error {
	if p.Version == "" {
		return fmt.Errorf("policy version is required")
	}
	if !p.Defaults.FailOn.IsValid() {
		return fmt.Errorf("invalid fail_on severity %q", p.Defaults.FailOn)
	}
	if p.Defaults.AllowedSeverity != "" && !p.Defaults.AllowedSeverity.IsValid() {
		return fmt.Errorf("invalid allowed_severity %q", p.Defaults.AllowedSeverity)
	}
	return nil
}

func fromRaw(raw rawPolicy) (Policy, error) {
	p := Default()
	if raw.Version != "" {
		p.Version = raw.Version
	}
	p.Project = raw.Project
	p.Rules = raw.Rules
	if raw.Servers != nil {
		p.Servers = raw.Servers
	}

	if raw.Defaults.AllowUnknownTools == nil {
		p.Defaults.AllowUnknownTools = true
	} else {
		p.Defaults.AllowUnknownTools = *raw.Defaults.AllowUnknownTools
	}

	if strings.TrimSpace(raw.Defaults.AllowedSeverity) != "" {
		allowed, err := severity.Parse(raw.Defaults.AllowedSeverity)
		if err != nil {
			return Policy{}, fmt.Errorf("defaults.allowed_severity: %w", err)
		}
		p.Defaults.AllowedSeverity = allowed
	}

	if strings.TrimSpace(raw.Defaults.FailOn) != "" {
		failOn, err := severity.Parse(raw.Defaults.FailOn)
		if err != nil {
			return Policy{}, fmt.Errorf("defaults.fail_on: %w", err)
		}
		p.Defaults.FailOn = failOn
	} else if p.Defaults.AllowedSeverity != "" {
		p.Defaults.FailOn = severity.NextAbove(p.Defaults.AllowedSeverity)
	}

	if err := Validate(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func normalizePolicyKeys(value any) any {
	return normalizePolicyValue("", value)
}

func normalizePolicyValue(parentKey string, value any) any {
	switch typed := value.(type) {
	case map[string]any:
		if parentKey == "servers" {
			out := make(map[string]any, len(typed))
			for key, item := range typed {
				out[key] = normalizePolicyValue("server_rule", item)
			}
			return out
		}
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			normalizedKey := normalizeKey(key)
			out[normalizedKey] = normalizePolicyValue(normalizedKey, item)
		}
		return out
	case map[any]any:
		if parentKey == "servers" {
			out := make(map[string]any, len(typed))
			for key, item := range typed {
				out[fmt.Sprint(key)] = normalizePolicyValue("server_rule", item)
			}
			return out
		}
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			normalizedKey := normalizeKey(fmt.Sprint(key))
			out[normalizedKey] = normalizePolicyValue(normalizedKey, item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = normalizePolicyValue(parentKey, item)
		}
		return out
	default:
		return value
	}
}

func normalizeKey(key string) string {
	return strings.ReplaceAll(key, "-", "_")
}
