package policy

import (
	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type Policy struct {
	Version    string                `json:"version" yaml:"version"`
	Project    Project               `json:"project" yaml:"project"`
	Defaults   Defaults              `json:"defaults" yaml:"defaults"`
	Rules      Rules                 `json:"rules" yaml:"rules"`
	Servers    map[string]ServerRule `json:"servers" yaml:"servers"`
	SourcePath string                `json:"-" yaml:"-"`
}

type Project struct {
	Name string `json:"name" yaml:"name"`
}

type Defaults struct {
	FailOn                severity.Level `json:"fail_on" yaml:"fail_on"`
	AllowedSeverity       severity.Level `json:"allowed_severity,omitempty" yaml:"allowed_severity,omitempty"`
	AllowUnknownTools     bool           `json:"allow_unknown_tools" yaml:"allow_unknown_tools"`
	AllowUnknownPrompts   bool           `json:"allow_unknown_prompts" yaml:"allow_unknown_prompts"`
	AllowUnknownResources bool           `json:"allow_unknown_resources" yaml:"allow_unknown_resources"`
}

type Rules struct {
	AllowTools   []string      `json:"allow_tools,omitempty" yaml:"allow_tools,omitempty"`
	DenyTools    []string      `json:"deny_tools,omitempty" yaml:"deny_tools,omitempty"`
	AllowPrompts []string      `json:"allow_prompts,omitempty" yaml:"allow_prompts,omitempty"`
	DenyPrompts  []string      `json:"deny_prompts,omitempty" yaml:"deny_prompts,omitempty"`
	DenyKeywords []string      `json:"deny_keywords,omitempty" yaml:"deny_keywords,omitempty"`
	Paths        PathRules     `json:"paths,omitempty" yaml:"paths,omitempty"`
	ResourceURIs PathRules     `json:"resource_uris,omitempty" yaml:"resource_uris,omitempty"`
	Suppressions []Suppression `json:"suppressions,omitempty" yaml:"suppressions,omitempty"`
}

type PathRules struct {
	Deny  []string `json:"deny,omitempty" yaml:"deny,omitempty"`
	Allow []string `json:"allow,omitempty" yaml:"allow,omitempty"`
}

type Suppression struct {
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Reason      string `json:"reason" yaml:"reason"`
	Expires     string `json:"expires,omitempty" yaml:"expires,omitempty"`
}

type ServerRule struct {
	AllowTools   []string  `json:"allow_tools,omitempty" yaml:"allow_tools,omitempty"`
	DenyTools    []string  `json:"deny_tools,omitempty" yaml:"deny_tools,omitempty"`
	AllowPrompts []string  `json:"allow_prompts,omitempty" yaml:"allow_prompts,omitempty"`
	DenyPrompts  []string  `json:"deny_prompts,omitempty" yaml:"deny_prompts,omitempty"`
	ResourceURIs PathRules `json:"resource_uris,omitempty" yaml:"resource_uris,omitempty"`
}

type Summary struct {
	Name                  string         `json:"name,omitempty"`
	Version               string         `json:"version"`
	FailOn                severity.Level `json:"fail_on"`
	AllowUnknownTools     bool           `json:"allow_unknown_tools"`
	AllowUnknownPrompts   bool           `json:"allow_unknown_prompts"`
	AllowUnknownResources bool           `json:"allow_unknown_resources"`
	DeniedTools           int            `json:"denied_tools"`
	DeniedPrompts         int            `json:"denied_prompts"`
	DeniedKeywords        int            `json:"denied_keywords"`
	DeniedPaths           int            `json:"denied_paths"`
	AllowedPaths          int            `json:"allowed_paths"`
	DeniedResourceURIs    int            `json:"denied_resource_uris"`
	AllowedResourceURIs   int            `json:"allowed_resource_uris"`
	Suppressions          int            `json:"suppressions"`
	ServerRules           int            `json:"server_rules"`
}

type ExitDecision struct {
	ExitCode          int            `json:"exit_code"`
	FailOn            severity.Level `json:"fail_on"`
	HighestSeverity   severity.Level `json:"highest_severity"`
	FindingsAtOrAbove int            `json:"findings_at_or_above"`
	Reason            string         `json:"reason"`
}

func Default() Policy {
	return Policy{
		Version: "0.1",
		Defaults: Defaults{
			FailOn:                severity.High,
			AllowUnknownTools:     true,
			AllowUnknownPrompts:   true,
			AllowUnknownResources: true,
		},
		Servers: map[string]ServerRule{},
	}
}

func Summarize(p Policy) Summary {
	return Summary{
		Name:                  redact.Text(p.Project.Name),
		Version:               p.Version,
		FailOn:                p.Defaults.FailOn,
		AllowUnknownTools:     p.Defaults.AllowUnknownTools,
		AllowUnknownPrompts:   p.Defaults.AllowUnknownPrompts,
		AllowUnknownResources: p.Defaults.AllowUnknownResources,
		DeniedTools:           len(p.Rules.DenyTools),
		DeniedPrompts:         len(p.Rules.DenyPrompts),
		DeniedKeywords:        len(p.Rules.DenyKeywords),
		DeniedPaths:           len(p.Rules.Paths.Deny),
		AllowedPaths:          len(p.Rules.Paths.Allow),
		DeniedResourceURIs:    len(p.Rules.ResourceURIs.Deny),
		AllowedResourceURIs:   len(p.Rules.ResourceURIs.Allow),
		Suppressions:          len(p.Rules.Suppressions),
		ServerRules:           len(p.Servers),
	}
}
