# Changelog

All notable changes to ArgusGate will be documented in this file.

## 0.1.0 - 2026-05-22

### Added

- CLI commands:
  - `argusgate scan`
  - `argusgate policy validate`
  - `argusgate fixtures scan`
- Local JSON/YAML MCP config and fixture parsing.
- YAML policy parser with fail thresholds, allow/deny tools, denied keywords, and path rules.
- Static detectors for tool poisoning, secret exposure, dangerous capabilities, sensitive paths, SQL risks, and policy violations.
- Human-readable terminal summaries and JSON reports.
- CI-friendly exit codes.
- Example configs, policies, safe fixtures, and malicious fixtures.
- Initial documentation, CI, and open-source metadata.

### Security

- Secret-like finding evidence is redacted before terminal or JSON report output.
- Local scans do not execute configured MCP commands or call tools.
