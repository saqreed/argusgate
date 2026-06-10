# Changelog

All notable changes to ArgusGate will be documented in this file.

## 0.1.3 - 2026-06-10

### Fixed

- Reduced SQL false positives when read-only tools mention unsupported write statements such as `UPDATE`, `DELETE`, or `DROP`.
- Reduced dangerous capability false positives by matching single-word capability indicators on term boundaries instead of arbitrary substrings.
- Detected and redacted Basic authorization values in server and tool metadata.
- Made redacted evidence snippets UTF-8 safe when truncating non-ASCII text.

## 0.1.2 - 2026-06-06

### Fixed

- Redacted common token shapes such as GitHub tokens, cloud access keys, OpenAI-style API keys, URL basic-auth passwords, and token query parameters.
- Redacted server URLs in JSON report summaries so credentials embedded in endpoints do not leak through report metadata.
- Detected common token shapes in tool, server, config, and fixture metadata.
- Parsed JSON-RPC-style `result.tools` fixture files from MCP `tools/list` responses.
- Parsed map-style fixture tool definitions where the map key is the tool name.
- Ignored `deep-research-report.md` so internal research notes do not get re-added to the public repository.

## 0.1.1 - 2026-05-26

### Fixed

- Preserved explicit `server_id` on top-level fixture tools and made synthetic fixture servers match those IDs.
- Fixed nested tools under unnamed servers so they inherit the parsed fallback server ID instead of `fixtures`.
- Reduced false positives in policy path matching by treating path rules as path prefixes or path segments instead of arbitrary substrings.
- Reduced false positives where generic text about credentials or documentation updates was reported as sensitive paths or database write capability.
- Detected URL-safe base64-like tool-poisoning payloads in tool metadata.
- Fixed GitHub Actions CLI build output so Linux runners do not try to write a binary over the `argusgate/` source directory.
- Updated source build instructions to write binaries under `bin/`.
- Replaced the shortened license text with the canonical Apache-2.0 license so GitHub detects the project license correctly.

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
