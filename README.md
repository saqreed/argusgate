# ArgusGate

[![CI](https://github.com/saqreed/argusgate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/saqreed/argusgate/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/saqreed/argusgate?include_prereleases)](https://github.com/saqreed/argusgate/releases)
[![License](https://img.shields.io/github/license/saqreed/argusgate)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/saqreed/argusgate)](go.mod)

Open-source security scanner and policy gate for Model Context Protocol (MCP) servers.

ArgusGate helps developers, DevOps/SecOps teams, and security reviewers inspect MCP server configurations and advertised contracts before trusting them in MCP clients. It scans tool, prompt, resource, and resource-template metadata, flags suspicious instructions and risky capabilities, and evaluates review policy in CI.

**Experimental:** detections are heuristic. ArgusGate is not a sandbox or a complete security boundary. Use it alongside sandboxing, least-privilege credentials, network controls, code review, and runtime monitoring.

Local config and fixture scans stay offline and never start MCP server commands. Explicit HTTPS inspection lists metadata only: it does not invoke tools, retrieve prompts or resources, or start stdio servers.

## Try It In A Minute

From a repository checkout with Go 1.26.8 or newer, scan an intentionally risky local fixture:

```bash
go run ./cmd/argusgate fixtures scan --path examples/fixtures/malicious-tools.yaml
```

Excerpt from the current output:

```text
Findings: 21
Severity: critical=0 high=18 medium=3 low=0 info=0
Exit: fail (code=1, 18 unsuppressed finding(s) at or above high)
- [high] SQL write or administrative operation detected (AG-SQL001 server=malicious tool=db_query)
- [high] Suspicious base64-like payload in MCP metadata (AG-TP003 server=malicious tool=encoded_instruction)
```

Exit `1` is expected here: the fixture contains risky metadata and fake secret placeholders. The scan does not execute the advertised capabilities or contact a server. First-time source builds may download Go dependencies.

## Why ArgusGate?

- Review advertised MCP capabilities before trusting a server.
- Detect suspicious instructions and secret-like values across tools, prompts, resources, and templates.
- Identify shell, filesystem, database, browser, and infrastructure capability signals.
- Apply versioned policy-as-code with CI-friendly exit decisions.
- Compare metadata and configuration against explicitly reviewed baselines.
- Export findings as JSON or SARIF for review and GitHub Code Scanning.
- Inspect a selected HTTPS endpoint's metadata without invoking its tools.

## Use Cases

- Review a new MCP server before connecting it to an MCP client.
- Audit local configurations and exported tool, prompt, and resource catalogs.
- Check for suspicious descriptions, exposed credentials, or dangerous advertised capabilities.
- Detect metadata/configuration drift after a server or dependency update.
- Gate MCP metadata changes in CI with policy and a reviewed baseline.
- Send findings to GitHub Code Scanning through SARIF.
- Perform an explicit, constrained metadata-only review of a remote HTTPS MCP endpoint.

v0.3.1 is a security patch release with fixes for secret redaction, policy namespace traversal, baseline drift detection, and server instruction scanning. See [CHANGELOG.md](CHANGELOG.md) for details and baseline compatibility notes.

## Install

Download the archive for your operating system and CPU from [GitHub Releases](https://github.com/saqreed/argusgate/releases), then verify it against `SHA256SUMS.txt` before running it. See [checksum verification](docs/release.md#user-checksum-verification).

Linux `amd64` example (macOS archives use `darwin`):

```bash
tar -xzf argusgate_v0.3.1_linux_amd64.tar.gz
cd argusgate_v0.3.1_linux_amd64
./argusgate --version
```

Windows PowerShell:

```powershell
Expand-Archive .\argusgate_v0.3.1_windows_amd64.zip
cd .\argusgate_v0.3.1_windows_amd64\argusgate_v0.3.1_windows_amd64
.\argusgate.exe --version
```

Build from source with Go 1.26.8 or newer:

```bash
git clone https://github.com/saqreed/argusgate.git
cd argusgate
mkdir -p bin
go build -o ./bin/argusgate ./cmd/argusgate
```

On Windows, build with `go build -o .\bin\argusgate.exe ./cmd/argusgate` and use `.\bin\argusgate.exe` in place of `./bin/argusgate` below.

## Quick Start

Validate a policy:

```bash
./bin/argusgate policy validate --policy examples/policies/default.yaml
```

Scan a safe local fixture:

```bash
./bin/argusgate fixtures scan \
  --path examples/fixtures/safe-tools.yaml \
  --policy examples/policies/default.yaml \
  --report safe-report.json
```

Scan the v0.3 metadata catalog:

```bash
./bin/argusgate fixtures scan \
  --path examples/fixtures/v03-metadata.yaml \
  --policy examples/policies/v03-trust.yaml \
  --report v03-report.json \
  --sarif v03.sarif
```

The v0.3 fixture intentionally contains high-risk metadata and is expected to exit `1`.

## Baseline Workflow

Create a reviewed baseline:

```bash
./bin/argusgate baseline create \
  --fixtures examples/fixtures/safe-tools.yaml \
  --output argusgate-baseline.json
```

Fail CI if an artifact is added or its reviewed contract changes:

```bash
./bin/argusgate fixtures scan \
  --path examples/fixtures/safe-tools.yaml \
  --baseline argusgate-baseline.json \
  --report argusgate-report.json
```

Refresh a baseline only after reviewing the new metadata:

```bash
./bin/argusgate baseline update \
  --fixtures examples/fixtures/safe-tools.yaml \
  --baseline argusgate-baseline.json
```

Baselines store normalized SHA-256 identities and contract hashes. Environment and header values are not stored.

After a canonicalization or redaction fix, older baselines and suppression fingerprints can produce new findings. Review the metadata before explicitly updating the baseline or policy; updates are never automatic.

## Opt-In Live Inspection

Live inspection is explicit and metadata-only:

```bash
./bin/argusgate inspect \
  --url https://mcp.example.test/mcp \
  --policy examples/policies/v03-trust.yaml \
  --report live-report.json \
  --sarif live.sarif
```

Use an environment-backed bearer token when required:

```bash
export MCP_INSPECTION_TOKEN="replace-with-runtime-secret"
./bin/argusgate inspect \
  --url https://mcp.example.test/mcp \
  --token-env MCP_INSPECTION_TOKEN
```

Inspection accepts HTTPS Streamable HTTP endpoints only. Redirects, standalone SSE, retries, credentials in URLs, secret-like query parameters, cross-origin requests, `tools/call`, `prompts/get`, and `resources/read` are blocked. Values of any permitted query parameters are redacted before the endpoint is stored in reports or baselines.

Server initialization instructions are scanned alongside other metadata. Inspection errors identify the failed operation but omit untrusted remote diagnostics because they can echo credentials. Check authentication, endpoint configuration, and TLS when a generic request failure is reported; do not publish credential-bearing server logs.

## CLI

MCP contract checks flag missing tool schemas and contradictory safety annotations. Use `rules list` and `rules show` to browse stable rule IDs and their documented heuristics.

```text
argusgate --help
argusgate --version
argusgate scan --config <path> [scan flags]
argusgate fixtures scan --path <path> [scan flags]
argusgate inspect --url <https-url> [scan flags] [inspection flags]
argusgate policy validate --policy <path>
argusgate baseline create (--config <path> | --fixtures <path> | --url <https-url>) --output <path>
argusgate baseline update (--config <path> | --fixtures <path> | --url <https-url>) --baseline <path>
argusgate rules list [--format text|json]
argusgate rules show <rule-id> [--format text|json]
```

Scan flags:

- `--policy <path>`
- `--baseline <path>`
- `--report <path>`
- `--sarif <path>`
- `--fail-on low|medium|high|critical`
- `--format text|json|sarif`
- `--quiet`

Exit codes:

- `0`: no unsuppressed finding meets the fail threshold
- `1`: one or more unsuppressed findings meet the fail threshold
- `2`: invalid input, invalid policy, inspection failure, output failure, or internal error

## Policy 0.3

```yaml
version: "0.3"
defaults:
  fail_on: high
  allow_unknown_tools: true
  allow_unknown_prompts: false
  allow_unknown_resources: false
rules:
  deny_tools:
    - shell_exec
  allow_prompts:
    - review_release
  deny_prompts:
    - hidden_override
  resource_uris:
    allow:
      - file:///workspace/docs
      - https://docs.example.test/public
    deny:
      - file:///home/example/.ssh
```

Policies `0.1` and `0.2` remain supported. Prompt and resource rules require `version: "0.3"`. Full precedence and suppression behavior are documented in [docs/policy-format.md](docs/policy-format.md).

## GitHub Action

The composite action downloads the selected ArgusGate release and verifies its archive against the published SHA-256 checksum before execution.

```yaml
name: ArgusGate

on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - name: Scan MCP metadata
        id: argusgate
        uses: saqreed/argusgate@v0.3.1
        with:
          source-type: fixtures
          source: examples/fixtures/v03-metadata.yaml
          policy: examples/policies/v03-trust.yaml
          report: argusgate-report.json
          sarif: argusgate.sarif

      - name: Upload SARIF
        if: always() && hashFiles('argusgate.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: ${{ steps.argusgate.outputs.sarif }}
```

Pin the action to a release tag. For live inspection, pass only the environment variable name through `token-env`; store the value in GitHub Actions secrets.

## Reports And Schemas

JSON reports include server and metadata summaries, findings, stable fingerprints, unsuppressed severity totals, policy summary, optional baseline summary, and the exit decision.

- [Report schema](docs/schemas/report.schema.json)
- [Policy schema](docs/schemas/policy.schema.json)
- [Baseline schema](docs/schemas/baseline.schema.json)

SARIF output uses SARIF 2.1.0 and omits suppressed findings.

## Current Limitations

- Static findings can include false positives and false negatives.
- Live inspection verifies advertised metadata, not server implementation behavior.
- Only HTTPS Streamable HTTP metadata inspection is supported.
- OAuth browser flows, stdio server startup, tool calls, prompt retrieval, and resource reads are not implemented.
- Baselines detect metadata/config drift but do not prove artifact provenance.
- No runtime proxy, database, web UI, RBAC, Kubernetes deployment, or SaaS service is included.
- Inputs and reports are bounded to reduce resource-exhaustion risk.
- Dynamic live numeric metadata at or above `2^53` in absolute value is rejected because of SDK precision limits; use offline fixtures for exact large integers.
- Live inspection has a 15-second default timeout, 16 MiB per-response limit, 64 MiB session-response budget, 100-page limit, and 10,000-artifact limit.

## Roadmap

- More MCP contract and metadata consistency checks.
- Signed release provenance and stronger supply-chain verification.
- Better baseline review output and machine-readable diffs.
- Additional opt-in authentication methods for metadata inspection.
- Runtime gateway enforcement only after the scanner and policy model stabilize.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [good first issues](https://github.com/saqreed/argusgate/labels/good%20first%20issue), or [help wanted](https://github.com/saqreed/argusgate/labels/help%20wanted). Use [Discussions](https://github.com/saqreed/argusgate/discussions) for questions and ideas.

For suspected vulnerabilities in ArgusGate itself, follow [SECURITY.md](SECURITY.md) rather than posting exploit details publicly. Never include real credentials in issues, fixtures, tests, reports, or documentation.

## License

Apache-2.0. See [LICENSE](LICENSE).
