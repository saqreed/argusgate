# ArgusGate Product Scope

## Project Goal

ArgusGate helps developers and DevOps/SecOps teams inspect MCP server configurations and tool metadata before connecting AI agents to internal systems.

The first useful version is a local, CLI-first scanner with policy validation and CI-friendly reports. It is intentionally not a complete runtime security boundary.

## MVP Scope

- Parse local MCP-like server configuration files in JSON or YAML.
- Parse local MCP tool fixture files in JSON or YAML.
- Validate a small YAML policy format.
- Detect tool-poisoning indicators, secret exposure, dangerous capabilities, sensitive paths, SQL write risks, and policy violations.
- Generate structured JSON and SARIF reports with deterministic fields useful for automation.
- Print a short human-readable terminal summary.
- Support `--fail-on`, `--format text|json|sarif`, `--sarif`, `--quiet`, and `--version` for release-ready CLI use.
- Support reviewed finding suppressions by stable fingerprint in policy `version: "0.2"`.
- Publish GitHub release archives and checksums for common Linux, macOS, and Windows targets.
- Return CI-friendly exit codes:
  - `0`: no findings at or above the fail threshold
  - `1`: findings at or above the fail threshold
  - `2`: invalid config, invalid policy, parser error, or internal error

## Non-Goals

- No web dashboard.
- No database, queue, or centralized service.
- No OAuth, RBAC, or enterprise tenant model.
- No Kubernetes or SaaS deployment.
- No automatic remediation that edits user files.
- No full MCP runtime proxy in the MVP.
- No automatic live MCP connection unless explicitly requested in a later version.

## Threat Model Summary

The MVP focuses on static signals for:

- malicious or compromised MCP servers that hide instructions in tool descriptions or metadata;
- accidental or malicious secret exposure in config, examples, headers, environment variables, or tool metadata;
- tools that expose shell, filesystem, network, database-write, credential, Docker, Kubernetes, or system operations;
- path references that target sensitive host locations;
- SQL metadata that suggests write-capable or command-capable database access;
- policy drift between allowed/denied tools, paths, keywords, and configured fail thresholds.

## Future Roadmap

- Runtime MCP proxy/gateway with policy enforcement.
- Live MCP metadata inspection over supported transports.
- Tool pinning and rug-pull detection.
- Audit logging and telemetry exports.
- Role-aware policy model.
- Packaged GitHub Action.
- Optional sandbox guidance for high-risk MCP servers.

## Competitor Positioning

ArgusGate starts closest to an MCP security scanner, but its architecture keeps the policy engine reusable for a future gateway. It should not clone existing tools. Its intended position is a small, transparent, open-source layer for MCP security review in local development and CI.
