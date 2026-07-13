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
	FailOn            severity.Level `json:"fail_on" yaml:"fail_on"`
	AllowedSeverity   severity.Level `json:"allowed_severity,omitempty" yaml:"allowed_severity,omitempty"`
	AllowUnknownTools bool           `json:"allow_unknown_tools" yaml:"allow_unknown_tools"`
}

type Rules struct {
	AllowTools   []string      `json:"allow_tools,omitempty" yaml:"allow_tools,omitempty"`
	DenyTools    []string      `json:"deny_tools,omitempty" yaml:"deny_tools,omitempty"`
	DenyKeywords []string      `json:"deny_keywords,omitempty" yaml:"deny_keywords,omitempty"`
	Paths        PathRules     `json:"paths,omitempty" yaml:"paths,omitempty"`
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
	AllowTools []string `json:"allow_tools,omitempty" yaml:"allow_tools,omitempty"`
	DenyTools  []string `json:"deny_tools,omitempty" yaml:"deny_tools,omitempty"`
}

type Summary struct {
	Name              string         `json:"name,omitempty"`
	Version           string         `json:"version"`
	FailOn            severity.Level `json:"fail_on"`
	AllowUnknownTools bool           `json:"allow_unknown_tools"`
	DeniedTools       int            `json:"denied_tools"`
	DeniedKeywords    int            `json:"denied_keywords"`
	DeniedPaths       int            `json:"denied_paths"`
	AllowedPaths      int            `json:"allowed_paths"`
	Suppressions      int            `json:"suppressions"`
	ServerRules       int            `json:"server_rules"`
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
			FailOn:            severity.High,
			AllowUnknownTools: true,
		},
		Servers: map[string]ServerRule{},
	}
}

func Summarize(p Policy) Summary {
	return Summary{
		Name:              redact.Text(p.Project.Name),
		Version:           p.Version,
		FailOn:            p.Defaults.FailOn,
		AllowUnknownTools: p.Defaults.AllowUnknownTools,
		DeniedTools:       len(p.Rules.DenyTools),
		DeniedKeywords:    len(p.Rules.DenyKeywords),
		DeniedPaths:       len(p.Rules.Paths.Deny),
		AllowedPaths:      len(p.Rules.Paths.Allow),
		Suppressions:      len(p.Rules.Suppressions),
		ServerRules:       len(p.Servers),
	}
}
