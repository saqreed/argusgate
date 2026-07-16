# ArgusGate

ArgusGate is an open-source security scanner and policy gateway foundation for Model Context Protocol servers.

It helps teams inspect MCP configs and advertised metadata, detect risky capabilities and suspicious instructions, compare servers against reviewed baselines, enforce policy in CI, and produce JSON or SARIF reports.

ArgusGate is experimental. Its detections are heuristic, and it is not a complete security boundary. Use it alongside sandboxing, least-privilege credentials, network controls, code review, and runtime monitoring.

## What v0.3.0 Adds

- Tools, prompts, resources, and resource-template scanning.
- Reviewed metadata baselines for drift and rug-pull detection.
- Opt-in HTTPS Streamable HTTP metadata inspection.
- Policy `0.3` controls for prompts and resource URI namespaces.
- MCP contract checks for missing tool schemas and contradictory annotations.
- A searchable stable rule catalog.
- A checksum-verified composite GitHub Action.

Local config and fixture scans remain fully offline. ArgusGate never starts commands from MCP configs.

## Install

Download the archive for your operating system and CPU from [GitHub Releases](https://github.com/saqreed/argusgate/releases), then verify it against `SHA256SUMS.txt`.

Linux or macOS:

```bash
tar -xzf argusgate_v0.3.0_linux_amd64.tar.gz
cd argusgate_v0.3.0_linux_amd64
./argusgate --version
```

Windows PowerShell:

```powershell
Expand-Archive .\argusgate_v0.3.0_windows_amd64.zip
cd .\argusgate_v0.3.0_windows_amd64\argusgate_v0.3.0_windows_amd64
.\argusgate.exe --version
```

Build from source with Go 1.25 or newer:

```bash
mkdir -p bin
go build -o ./bin/argusgate ./cmd/argusgate
```

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

## CLI

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
      - uses: actions/checkout@v4

      - name: Scan MCP metadata
        id: argusgate
        uses: saqreed/argusgate@v0.3.0
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
- Live inspection has a 15-second default timeout, 16 MiB per-response limit, 64 MiB session-response budget, 100-page limit, and 10,000-artifact limit.

## Roadmap

- More MCP contract and metadata consistency checks.
- Signed release provenance and stronger supply-chain verification.
- Better baseline review output and machine-readable diffs.
- Additional opt-in authentication methods for metadata inspection.
- Runtime gateway enforcement only after the scanner and policy model stabilize.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Never include real credentials in issues, fixtures, tests, reports, or documentation.

## License

Apache-2.0. See [LICENSE](LICENSE).
