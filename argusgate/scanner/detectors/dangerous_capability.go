package detectors

import (
	"strings"

	"github.com/saqreed/argusgate/argusgate/internal/redact"
	"github.com/saqreed/argusgate/argusgate/mcp"
	"github.com/saqreed/argusgate/argusgate/report"
	"github.com/saqreed/argusgate/argusgate/scanner/severity"
)

type DangerousCapabilityDetector struct{}

var capabilityRules = []struct {
	id          string
	title       string
	severity    severity.Level
	category    string
	mapping     string
	patterns    []string
	explanation string
}{
	{
		id:       "AG-DC001",
		title:    "Shell or arbitrary command execution capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"shell_exec", "run_command", "execute arbitrary shell", "execute shell commands", "arbitrary command", "command runner", "powershell", "bash", "subprocess",
		},
		explanation: "The tool appears able to execute shell commands or arbitrary host commands.",
	},
	{
		id:       "AG-DC002",
		title:    "File write or destructive filesystem capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"write_file", "delete_file", "file write", "write arbitrary files", "delete arbitrary files", "chmod", "overwrite",
		},
		explanation: "The tool appears able to write, delete, or modify files.",
	},
	{
		id:       "AG-DC003",
		title:    "Unrestricted file read capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"read_any_file", "read arbitrary files", "unrestricted file", "any absolute path", "read files from unrestricted paths",
		},
		explanation: "The tool appears able to read files without a clearly restricted path scope.",
	},
	{
		id:       "AG-DC004",
		title:    "Network request capability",
		severity: severity.Medium,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"http request", "network request", "fetch url", "open urls", "webhook", "call external api",
		},
		explanation: "The tool appears able to make network requests.",
	},
	{
		id:       "AG-DC005",
		title:    "Browser automation capability",
		severity: severity.Medium,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"browser automation", "playwright", "selenium", "click buttons", "submit forms",
		},
		explanation: "The tool appears able to drive a browser or interact with web pages.",
	},
	{
		id:       "AG-DC006",
		title:    "Credential or secret management capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP04 Tool Metadata Poisoning / Sensitive Data Exposure",
		patterns: []string{
			"credential", "secret manager", "private key", "api key", "bearer token", "access token",
		},
		explanation: "The tool appears to access credentials or secret material.",
	},
	{
		id:       "AG-DC007",
		title:    "Container or cluster administration capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"docker", "kubectl", "kubernetes", "kubeconfig", "cluster resources", "containers",
		},
		explanation: "The tool appears able to operate Docker, Kubernetes, containers, or cluster resources.",
	},
	{
		id:       "AG-DC008",
		title:    "Database write capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"database write", "sql admin", "update", "delete", "drop table", "insert", "alter", "truncate",
		},
		explanation: "The tool appears able to modify database state.",
	},
	{
		id:       "AG-DC009",
		title:    "Host system administration capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"systemctl", "launchctl", "schtasks", "windows registry", "system services", "host firewall", "sudo",
		},
		explanation: "The tool appears able to administer host system services, startup tasks, registry settings, firewall rules, or privileged host operations.",
	},
	{
		id:       "AG-DC010",
		title:    "Cloud CLI administration capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"aws", "gcloud", "az commands", "azure cli", "cloud accounts", "cloud resources",
		},
		explanation: "The tool appears able to invoke cloud provider CLIs or administer cloud resources.",
	},
	{
		id:       "AG-DC011",
		title:    "Infrastructure-as-code mutation capability",
		severity: severity.High,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"terraform apply", "terraform destroy", "tofu apply", "pulumi up", "infrastructure state",
		},
		explanation: "The tool appears able to mutate infrastructure through infrastructure-as-code tooling.",
	},
	{
		id:       "AG-DC012",
		title:    "Package manager execution capability",
		severity: severity.Medium,
		category: "dangerous-capability",
		mapping:  "MCP02 Scope Creep / Excessive Permissions",
		patterns: []string{
			"npm install", "pip install", "pnpm install", "yarn add", "go install", "cargo install", "package manager",
		},
		explanation: "The tool appears able to install packages or execute package manager workflows.",
	},
}

func (d DangerousCapabilityDetector) ScanServer(mcp.ServerConfig) []report.Finding {
	return nil
}

func (d DangerousCapabilityDetector) ScanTool(tool mcp.ToolDefinition) []report.Finding {
	var findings []report.Finding
	seenRule := map[string]struct{}{}
	for _, blob := range mcp.ToolTextBlobs(tool) {
		lower := strings.ToLower(blob.Text)
		for _, rule := range capabilityRules {
			if _, ok := seenRule[rule.id]; ok {
				continue
			}
			if rule.id == "AG-DC008" {
				if !looksDatabaseRelated(tool, blob.Text) || !containsDatabaseWriteTerm(lower) {
					continue
				}
			} else if !containsAny(lower, rule.patterns) || capabilityMentionNegated(rule.id, blob.Text) {
				continue
			}
			seenRule[rule.id] = struct{}{}
			findings = append(findings, report.Finding{
				ID:              rule.id,
				Title:           rule.title,
				Severity:        rule.severity,
				Category:        rule.category,
				OWASPMCPMapping: rule.mapping,
				ServerID:        tool.ServerID,
				ToolName:        tool.Name,
				Location:        blob.Location,
				Evidence:        redact.Snippet(blob.Text, 180),
				Explanation:     rule.explanation,
				Recommendation:  "Review whether this capability is necessary, restrict it with least privilege, and deny the tool if it is not expected.",
				Confidence:      "medium",
			})
		}
	}
	return findings
}

func capabilityMentionNegated(ruleID, text string) bool {
	if ruleID != "AG-DC001" {
		return false
	}
	lower := strings.ToLower(text)
	negatedPhrases := []string{
		"does not execute shell",
		"does not execute commands",
		"does not run commands",
		"does not run shell",
		"no shell execution",
		"without shell execution",
		"cannot execute shell",
		"cannot run commands",
	}
	return containsAny(lower, negatedPhrases)
}
