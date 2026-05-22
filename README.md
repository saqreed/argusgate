# ArgusGate

ArgusGate is an open-source security scanner and policy gateway for Model Context Protocol servers.

It helps developers and DevOps/SecOps teams inspect MCP tool metadata, detect suspicious tool descriptions, identify risky capabilities, validate security policies, and generate CI-friendly reports before connecting AI agents to internal systems.

ArgusGate is experimental. It performs heuristic static analysis. It is not a complete security boundary and does not replace sandboxing, least-privilege credentials, network isolation, code review, or runtime monitoring.

## Why It Exists

MCP servers can expose tools that read files, run commands, query databases, automate browsers, call APIs, and operate infrastructure. A malicious or compromised server can also hide instructions in tool descriptions or leak secrets through config and metadata.

ArgusGate v0.1.0 focuses on a small useful baseline: local offline scans, policy checks, readable terminal output, JSON reports, and CI-ready exit codes.

## Install From Source

Requirements:

- Go 1.24 or newer.

```bash
mkdir -p bin
go build -o ./bin/argusgate ./cmd/argusgate
```

During development:

```bash
go run ./cmd/argusgate --help
```

## Quick Start

Validate the example policy:

```bash
go run ./cmd/argusgate policy validate --policy examples/policies/default.yaml
```

Scan the safe fixture:

```bash
go run ./cmd/argusgate fixtures scan --path examples/fixtures/safe-tools.yaml --policy examples/policies/default.yaml --report safe-report.json
```

Scan the malicious fixture:

```bash
go run ./cmd/argusgate fixtures scan --path examples/fixtures/malicious-tools.yaml --policy examples/policies/default.yaml --report malicious-report.json
```

The malicious fixture is expected to exit `1` because it contains high-severity findings.

Emit JSON to stdout:

```bash
go run ./cmd/argusgate fixtures scan --path examples/fixtures/safe-tools.yaml --format json
```

Override the policy fail threshold:

```bash
go run ./cmd/argusgate fixtures scan --path examples/fixtures/safe-tools.yaml --policy examples/policies/default.yaml --fail-on medium
```

Scan a local MCP config:

```bash
go run ./cmd/argusgate scan --config examples/configs/mcp-config.yaml --policy examples/policies/default.yaml --report config-report.json
```

## CLI

```text
argusgate --help
argusgate --version
argusgate scan --config <path> [--policy <path>] [--report <path>] [--fail-on high] [--format text|json] [--quiet]
argusgate policy validate --policy <path>
argusgate fixtures scan --path <path> [--policy <path>] [--report <path>] [--fail-on high] [--format text|json] [--quiet]
```

Exit codes:

- `0`: no findings at or above the configured fail level
- `1`: findings at or above the configured fail level
- `2`: invalid config, invalid policy, parser error, report write error, or internal error

## Policy Example

```yaml
version: "0.1"
project:
  name: "argusgate-example"
defaults:
  fail_on: "high"
  allow_unknown_tools: true
rules:
  deny_tools:
    - "shell_exec"
    - "run_command"
    - "file_write"
  deny_keywords:
    - "ignore previous instructions"
    - "do not tell the user"
    - "private key"
    - "exfiltrate"
  paths:
    deny:
      - "~/.ssh"
      - "/etc"
      - ".env"
      - "kubeconfig"
    allow:
      - "./examples"
      - "./testdata"
servers:
  local-filesystem:
    allow_tools:
      - "read_file"
      - "list_directory"
    deny_tools:
      - "write_file"
      - "delete_file"
```

Policy precedence is documented in [docs/policy-format.md](docs/policy-format.md).

## JSON Report

Reports include:

- `scanned_at`
- `argusgate_version`
- `source_type`
- `source_path`
- `servers`
- `tools`
- `findings`
- `severity_summary`
- `policy_summary`
- `exit_decision`

Example shape:

```json
{
  "scanned_at": "2026-05-22T12:00:00Z",
  "argusgate_version": "0.1.0",
  "source_type": "fixtures",
  "source_path": "examples/fixtures/malicious-tools.yaml",
  "servers": [],
  "tools": [],
  "findings": [],
  "severity_summary": {
    "critical": 0,
    "high": 0,
    "info": 0,
    "low": 0,
    "medium": 0
  },
  "policy_summary": {},
  "exit_decision": {}
}
```

Finding evidence is redacted when it looks secret-like.

## CI Usage

Example GitHub Actions step:

```yaml
- name: ArgusGate fixture scan
  run: |
    go run ./cmd/argusgate fixtures scan \
      --path examples/fixtures/malicious-tools.yaml \
      --policy examples/policies/default.yaml \
      --report argusgate-report.json
```

The repository CI runs:

```bash
go test ./...
go vet ./...
mkdir -p bin && go build -o ./bin/argusgate ./cmd/argusgate
```

## Current Limitations

- Static analysis is heuristic and can miss issues.
- Findings can include false positives.
- The scanner does not connect to live MCP servers.
- The scanner does not execute tool commands or invoke MCP tools.
- No runtime proxy/gateway is implemented in v0.1.0.
- No database, web UI, OAuth/RBAC, Kubernetes deployment, or SaaS workflow is included.

## Roadmap

- More fixture coverage and detector tuning.
- Tool pinning and rug-pull detection.
- Optional live MCP metadata inspection.
- Runtime MCP gateway/proxy after the scanner and policy engine stabilize.
- Audit logging and telemetry for future runtime enforcement.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep examples safe and local. Never include real credentials in issues, docs, fixtures, tests, or reports.

## License

Apache-2.0. See [LICENSE](LICENSE).
