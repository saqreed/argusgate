package policy

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/saqreed/argusgate/argusgate/internal/fileio"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
	"gopkg.in/yaml.v3"
)

const (
	MaxPolicyBytes       int64 = 1 << 20
	maxPolicyListEntries       = 1024
)

var suppressionFingerprintRX = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

type rawPolicy struct {
	Version  string                `yaml:"version"`
	Project  Project               `yaml:"project"`
	Defaults rawDefaults           `yaml:"defaults"`
	Rules    Rules                 `yaml:"rules"`
	Servers  map[string]ServerRule `yaml:"servers"`
}

type rawDefaults struct {
	FailOn                string `yaml:"fail_on"`
	AllowedSeverity       string `yaml:"allowed_severity"`
	AllowUnknownTools     *bool  `yaml:"allow_unknown_tools"`
	AllowUnknownPrompts   *bool  `yaml:"allow_unknown_prompts"`
	AllowUnknownResources *bool  `yaml:"allow_unknown_resources"`
}

func LoadFile(path string) (Policy, error) {
	raw, err := fileio.ReadLimitedFile(path, MaxPolicyBytes)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy %s: %w", path, err)
	}

	var decoded any
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&decoded); err != nil {
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Policy{}, fmt.Errorf("parse policy %s: multiple YAML documents are not supported", path)
		}
		return Policy{}, fmt.Errorf("parse policy %s: %w", path, err)
	}
	normalized, err := normalizePolicyKeys(decoded)
	if err != nil {
		return Policy{}, fmt.Errorf("normalize policy %s: %w", path, err)
	}
	normalizedBytes, err := yaml.Marshal(normalized)
	if err != nil {
		return Policy{}, fmt.Errorf("normalize policy %s: %w", path, err)
	}

	var rawPol rawPolicy
	strictDecoder := yaml.NewDecoder(bytes.NewReader(normalizedBytes))
	strictDecoder.KnownFields(true)
	if err := strictDecoder.Decode(&rawPol); err != nil {
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
	if p.Version != "0.1" && p.Version != "0.2" && p.Version != "0.3" {
		return fmt.Errorf("unsupported policy version %q", p.Version)
	}
	if !p.Defaults.FailOn.IsValid() {
		return fmt.Errorf("invalid fail_on severity %q", p.Defaults.FailOn)
	}
	if p.Defaults.FailOn == severity.Info {
		return fmt.Errorf("fail_on must be low, medium, high, or critical")
	}
	if p.Defaults.AllowedSeverity != "" && !p.Defaults.AllowedSeverity.IsValid() {
		return fmt.Errorf("invalid allowed_severity %q", p.Defaults.AllowedSeverity)
	}
	if p.Version == "0.1" && len(p.Rules.Suppressions) > 0 {
		return fmt.Errorf("rules.suppressions requires policy version \"0.2\" or newer")
	}
	if len(p.Rules.Suppressions) > maxPolicyListEntries {
		return fmt.Errorf("rules.suppressions has %d entries; maximum is %d", len(p.Rules.Suppressions), maxPolicyListEntries)
	}
	if err := validatePolicyLists(p); err != nil {
		return err
	}
	seenSuppressions := make(map[string]struct{}, len(p.Rules.Suppressions))
	for i, suppression := range p.Rules.Suppressions {
		fingerprint := strings.ToLower(strings.TrimSpace(suppression.Fingerprint))
		if !suppressionFingerprintRX.MatchString(fingerprint) {
			return fmt.Errorf("rules.suppressions[%d].fingerprint must be a 64-character sha256 hex value", i)
		}
		if _, exists := seenSuppressions[fingerprint]; exists {
			return fmt.Errorf("rules.suppressions[%d].fingerprint is duplicated", i)
		}
		seenSuppressions[fingerprint] = struct{}{}
		if strings.TrimSpace(suppression.Reason) == "" {
			return fmt.Errorf("rules.suppressions[%d].reason is required", i)
		}
		if strings.TrimSpace(suppression.Expires) != "" {
			if _, err := time.Parse(time.DateOnly, suppression.Expires); err != nil {
				return fmt.Errorf("rules.suppressions[%d].expires must use YYYY-MM-DD", i)
			}
		}
	}
	return nil
}

func fromRaw(raw rawPolicy) (Policy, error) {
	if strings.TrimSpace(raw.Version) == "" {
		return Policy{}, fmt.Errorf("policy version is required")
	}
	if raw.Version != "0.3" && rawUsesV03Fields(raw) {
		return Policy{}, fmt.Errorf("prompt and resource trust rules require policy version \"0.3\"")
	}
	p := Default()
	p.Version = raw.Version
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
	if raw.Defaults.AllowUnknownPrompts == nil {
		p.Defaults.AllowUnknownPrompts = true
	} else {
		p.Defaults.AllowUnknownPrompts = *raw.Defaults.AllowUnknownPrompts
	}
	if raw.Defaults.AllowUnknownResources == nil {
		p.Defaults.AllowUnknownResources = true
	} else {
		p.Defaults.AllowUnknownResources = *raw.Defaults.AllowUnknownResources
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

func rawUsesV03Fields(raw rawPolicy) bool {
	if raw.Defaults.AllowUnknownPrompts != nil || raw.Defaults.AllowUnknownResources != nil {
		return true
	}
	if len(raw.Rules.AllowPrompts) > 0 || len(raw.Rules.DenyPrompts) > 0 ||
		len(raw.Rules.ResourceURIs.Allow) > 0 || len(raw.Rules.ResourceURIs.Deny) > 0 {
		return true
	}
	for _, rule := range raw.Servers {
		if len(rule.AllowPrompts) > 0 || len(rule.DenyPrompts) > 0 ||
			len(rule.ResourceURIs.Allow) > 0 || len(rule.ResourceURIs.Deny) > 0 {
			return true
		}
	}
	return false
}

func validatePolicyLists(p Policy) error {
	type listRule struct {
		name   string
		values []string
	}
	lists := []listRule{
		{"rules.allow_tools", p.Rules.AllowTools},
		{"rules.deny_tools", p.Rules.DenyTools},
		{"rules.allow_prompts", p.Rules.AllowPrompts},
		{"rules.deny_prompts", p.Rules.DenyPrompts},
		{"rules.deny_keywords", p.Rules.DenyKeywords},
		{"rules.paths.allow", p.Rules.Paths.Allow},
		{"rules.paths.deny", p.Rules.Paths.Deny},
		{"rules.resource_uris.allow", p.Rules.ResourceURIs.Allow},
		{"rules.resource_uris.deny", p.Rules.ResourceURIs.Deny},
	}
	serverIDs := make([]string, 0, len(p.Servers))
	for serverID := range p.Servers {
		serverIDs = append(serverIDs, serverID)
	}
	sort.Strings(serverIDs)
	for _, serverID := range serverIDs {
		rule := p.Servers[serverID]
		lists = append(lists,
			listRule{"servers." + serverID + ".allow_tools", rule.AllowTools},
			listRule{"servers." + serverID + ".deny_tools", rule.DenyTools},
			listRule{"servers." + serverID + ".allow_prompts", rule.AllowPrompts},
			listRule{"servers." + serverID + ".deny_prompts", rule.DenyPrompts},
			listRule{"servers." + serverID + ".resource_uris.allow", rule.ResourceURIs.Allow},
			listRule{"servers." + serverID + ".resource_uris.deny", rule.ResourceURIs.Deny},
		)
	}
	for _, list := range lists {
		if len(list.values) > maxPolicyListEntries {
			return fmt.Errorf("%s has %d entries; maximum is %d", list.name, len(list.values), maxPolicyListEntries)
		}
		for i, value := range list.values {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s[%d] must not be empty", list.name, i)
			}
		}
	}
	return nil
}

func normalizePolicyKeys(value any) (any, error) {
	return normalizePolicyValue("", value, 0)
}

func normalizePolicyValue(parentKey string, value any, depth int) (any, error) {
	if depth > mcp.MaxNestingDepth {
		return nil, fmt.Errorf("policy nesting exceeds maximum depth of %d", mcp.MaxNestingDepth)
	}
	switch typed := value.(type) {
	case map[string]any:
		if parentKey == "servers" {
			out := make(map[string]any, len(typed))
			for key, item := range typed {
				normalized, err := normalizePolicyValue("server_rule", item, depth+1)
				if err != nil {
					return nil, err
				}
				out[key] = normalized
			}
			return out, nil
		}
		out := make(map[string]any, len(typed))
		original := make(map[string]string, len(typed))
		for key, item := range typed {
			normalizedKey := normalizeKey(key)
			if prior, exists := original[normalizedKey]; exists && prior != key {
				return nil, fmt.Errorf("keys %q and %q normalize to the same field %q", prior, key, normalizedKey)
			}
			normalized, err := normalizePolicyValue(normalizedKey, item, depth+1)
			if err != nil {
				return nil, err
			}
			original[normalizedKey] = key
			out[normalizedKey] = normalized
		}
		return out, nil
	case map[any]any:
		if parentKey == "servers" {
			out := make(map[string]any, len(typed))
			for key, item := range typed {
				stringKey, ok := key.(string)
				if !ok {
					return nil, fmt.Errorf("policy mapping keys must be strings, got %T", key)
				}
				normalized, err := normalizePolicyValue("server_rule", item, depth+1)
				if err != nil {
					return nil, err
				}
				out[stringKey] = normalized
			}
			return out, nil
		}
		out := make(map[string]any, len(typed))
		original := make(map[string]string, len(typed))
		for key, item := range typed {
			originalKey, ok := key.(string)
			if !ok {
				return nil, fmt.Errorf("policy mapping keys must be strings, got %T", key)
			}
			normalizedKey := normalizeKey(originalKey)
			if prior, exists := original[normalizedKey]; exists && prior != originalKey {
				return nil, fmt.Errorf("keys %q and %q normalize to the same field %q", prior, originalKey, normalizedKey)
			}
			normalized, err := normalizePolicyValue(normalizedKey, item, depth+1)
			if err != nil {
				return nil, err
			}
			original[normalizedKey] = originalKey
			out[normalizedKey] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			normalized, err := normalizePolicyValue(parentKey, item, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = normalized
		}
		return out, nil
	default:
		return value, nil
	}
}

func normalizeKey(key string) string {
	return strings.ReplaceAll(key, "-", "_")
}
