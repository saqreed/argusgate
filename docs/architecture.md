# Architecture

ArgusGate is currently a CLI-first Go project. The MVP is intentionally offline and file-based.

## Package Layout

- `cmd/argusgate`: CLI entrypoint.
- `argusgate/cli`: command parsing and exit-code handling.
- `argusgate/mcp`: MCP-like config and fixture parsers plus tool/server models.
- `argusgate/policy`: YAML policy parser, validator, policy findings, and exit decisions.
- `argusgate/scanner`: scan orchestration.
- `argusgate/scanner/detectors`: heuristic security detectors, split by detector family with stable rule metadata.
- `argusgate/scanner/severity`: severity ordering and threshold logic.
- `argusgate/report`: JSON report model, stable finding fingerprints, terminal summary renderer, and SARIF renderer.
- `argusgate/internal/redact`: secret redaction helpers.

## Data Flow

```mermaid
flowchart LR
    CLI[argusgate CLI] --> Parser[MCP config or fixture parser]
    CLI --> Policy[Policy parser and validator]
    Parser --> Scanner[Scanner orchestration]
    Policy --> Scanner
    Scanner --> Detectors[Security detectors]
    Scanner --> Evaluator[Policy evaluator]
    Detectors --> Report[Report builder]
    Evaluator --> Report
    Report --> Terminal[Terminal summary]
    Report --> JSON[JSON report]
    Report --> SARIF[SARIF report]
```

## MVP Runtime Behavior

The scanner reads local files, parses server and tool metadata, applies detectors, applies policy rules, assigns stable finding fingerprints, applies policy suppressions, redacts secret-like evidence, writes optional JSON and SARIF reports, and exits with a CI-friendly code.

It does not execute commands from MCP configs. It does not connect to external services. It does not call tools.

CLI output can be a text summary, JSON, or SARIF on stdout. JSON reports are generated from the same report model used for file output, so CI consumers receive the same fields regardless of output mode. SARIF output omits suppressed findings so reviewed risks do not create code scanning alerts.

## Detector Layout

Detectors are intentionally small and offline:

- tool poisoning: suspicious instructions, hidden markdown/HTML comments, encoded instructions, and invisible characters;
- secret exposure: token-like values, private-key placeholders, connection strings, authorization headers, and URL credentials;
- dangerous capability: shell, filesystem mutation, unrestricted file reads, network, browser automation, credentials, Docker/Kubernetes, cloud CLI, infrastructure-as-code, package manager, host administration, and database mutation capabilities;
- sensitive paths: host credential paths and sensitive file path segments;
- SQL risk: read-only and write/admin SQL signals.

The detector rule registry gives each rule a stable ID, severity, category, OWASP MCP mapping, and recommendation for reports and future integrations.

## Release Pipeline

The CI workflow runs tests, vet, and a Linux CLI build on pushes and pull requests. The release workflow runs on version tags, repeats test and vet checks, cross-compiles static CLI binaries for Linux, macOS, and Windows, packages release archives, generates `SHA256SUMS.txt`, and publishes a GitHub prerelease with the generated assets.

## Future Gateway Shape

The policy and report packages are kept separate so a future MCP proxy can reuse them. A runtime gateway would add transport support, invocation argument checks, audit logging, and enforcement decisions. That gateway is not implemented in the MVP.
