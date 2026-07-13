# ArgusGate

ArgusGate is an open-source security scanner and policy gateway for Model Context Protocol servers.

It helps developers and DevOps/SecOps teams inspect MCP tool metadata, detect suspicious tool descriptions, identify risky capabilities, validate security policies, and generate CI-friendly reports before connecting AI agents to internal systems.

ArgusGate is experimental. It performs heuristic static analysis. It is not a complete security boundary and does not replace sandboxing, least-privilege credentials, network isolation, code review, or runtime monitoring.

## Why It Exists

MCP servers can expose tools that read files, run commands, query databases, automate browsers, call APIs, and operate infrastructure. A malicious or compromised server can also hide instructions in tool descriptions or leak secrets through config and metadata.

ArgusGate v0.2.5 focuses on a hardened CLI-first scanner: bounded local input parsing, strict policy checks, controlled suppressions, stable finding fingerprints, JSON reports, SARIF output, and CI-ready exit codes.

## Install From Release

Download the archive for your operating system and CPU from [GitHub Releases](https://github.com/saqreed/argusgate/releases).

Release archives are published for Linux, macOS, and Windows on `amd64` and `arm64`. Each release also includes `SHA256SUMS.txt`.

Linux or macOS:

```bash
tar -xzf argusgate_v0.2.5_linux_amd64.tar.gz
cd argusgate_v0.2.5_linux_amd64
./argusgate --version
```

Windows PowerShell:

```powershell
Expand-Archive .\argusgate_v0.2.5_windows_amd64.zip
cd .\argusgate_v0.2.5_windows_amd64\argusgate_v0.2.5_windows_amd64
.\argusgate.exe --version
```

See [docs/release.md](docs/release.md) for checksum verification and maintainer release notes.

## Install From Source

Requirements:

- Go 1.24 or newer.

```bash
mkdir -p bin
go build -o ./bin/argusgate ./cmd/argusgate
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force bin | Out-Null
go build -o .\bin\argusgate.exe .\cmd\argusgate
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

Write JSON and SARIF reports:

```bash
go run ./cmd/argusgate fixtures scan \
  --path examples/fixtures/malicious-tools.yaml \
  --policy examples/policies/default.yaml \
  --report malicious-report.json \
  --sarif malicious.sarif
```

Emit JSON to stdout:

```bash
go run ./cmd/argusgate fixtures scan --path examples/fixtures/safe-tools.yaml --format json
```

Emit SARIF to stdout:

```bash
go run ./cmd/argusgate fixtures scan --path examples/fixtures/malicious-tools.yaml --format sarif
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
argusgate scan --config <path> [--policy <path>] [--report <path>] [--sarif <path>] [--fail-on high] [--format text|json|sarif] [--quiet]
argusgate policy validate --policy <path>
argusgate fixtures scan --path <path> [--policy <path>] [--report <path>] [--sarif <path>] [--fail-on high] [--format text|json|sarif] [--quiet]
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

v0.2 policies can suppress reviewed findings by stable fingerprint:

```yaml
version: "0.2"
rules:
  suppressions:
    - fingerprint: "0000000000000000000000000000000000000000000000000000000000000000"
      reason: "accepted local fixture risk"
      expires: "2099-12-31"
```

Suppressed findings remain visible in JSON reports with `suppressed: true`, but they do not affect the scan exit code.

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
  "argusgate_version": "0.2.5",
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

The report schema is available at [docs/schemas/report.schema.json](docs/schemas/report.schema.json). The policy schema is available at [docs/schemas/policy.schema.json](docs/schemas/policy.schema.json).

## SARIF And GitHub Code Scanning

ArgusGate can write SARIF 2.1.0 for GitHub Code Scanning:

```bash
go run ./cmd/argusgate fixtures scan \
  --path examples/fixtures/malicious-tools.yaml \
  --policy examples/policies/default.yaml \
  --sarif argusgate.sarif
```

Example GitHub Actions snippet:

```yaml
- name: Build ArgusGate
  run: go build -o ./bin/argusgate ./cmd/argusgate

- name: ArgusGate scan
  run: |
    ./bin/argusgate fixtures scan \
      --path examples/fixtures/malicious-tools.yaml \
      --policy examples/policies/default.yaml \
      --report argusgate-report.json \
      --sarif argusgate.sarif

- name: Upload ArgusGate SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@641a925cfafe92d0fdf8b239ba4053e3f8d99d6d # v3
  with:
    sarif_file: argusgate.sarif
```

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
go mod verify
go test -race ./...
go vet ./...
mkdir -p bin && go build -o ./bin/argusgate ./cmd/argusgate
```

## Current Limitations

- Static analysis is heuristic and can miss issues.
- Findings can include false positives.
- The scanner does not connect to live MCP servers.
- The scanner does not execute tool commands or invoke MCP tools.
- Input files are limited to 16 MiB, policies to 1 MiB, and reports to 10,000 retained findings per scan.
- Strict policy parsing rejects unknown fields, empty rule entries, ambiguous normalized keys, and unsupported v0.1 suppressions.
- No runtime proxy/gateway is implemented in v0.2.5.
- No database, web UI, OAuth/RBAC, Kubernetes deployment, or SaaS workflow is included.

## Roadmap

- More fixture coverage and detector tuning.
- Packaged reusable GitHub Action.
- Tool pinning and rug-pull detection.
- Optional live MCP metadata inspection.
- Runtime MCP gateway/proxy after the scanner and policy engine stabilize.
- Audit logging and telemetry for future runtime enforcement.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep examples safe and local. Never include real credentials in issues, docs, fixtures, tests, or reports.

## License

Apache-2.0. See [LICENSE](LICENSE).
