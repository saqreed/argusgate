# Changelog

All notable changes to ArgusGate will be documented in this file.

## 0.3.0 - 2026-07-16

### Added

- Added tools, prompts, resources, and resource-template models and scanning across local fixtures, configs, reports, and SARIF.
- Added reviewed baseline creation, update, and scan comparison for server and metadata contract drift.
- Added opt-in HTTPS Streamable HTTP metadata inspection using the official MCP Go SDK.
- Added policy `version: "0.3"` with prompt allow/deny rules, resource URI namespaces, and server-specific overrides.
- Added MCP contract findings for missing object-root tool schemas, contradictory annotations, and cleartext HTTP resources.
- Added `argusgate rules list|show` with stable detector, policy, baseline, and scanner rule metadata.
- Added report, policy, and baseline JSON schemas.
- Added a checksum-verified composite GitHub Action for config, fixture, and URL scans.

### Changed

- Updated the project to Go 1.25 and the official MCP Go SDK.
- Expanded JSON reports and terminal summaries with protocol, prompt, resource, template, and baseline information.
- Release archives now include machine-readable schemas.
- CI now smoke-tests the composite action runner in addition to race tests, vet, and builds.

### Security

- Live inspection blocks redirects, retries, standalone SSE, cross-origin credential forwarding, credentials in URLs, secret-like query parameters, unexpected HTTP methods, and all non-metadata MCP methods.
- Inspection request size, response size, timeout, pagination, and advertised artifact counts are bounded.
- Local and live metadata traversal is bounded to prevent excessive nesting from exhausting scanner resources.
- Permitted live endpoint query values are redacted before URLs enter reports, errors, or baselines.
- Baselines omit environment/header values and redact secret-like metadata before hashing.
- Resource URI policy matching now compares URI authorities and path boundaries instead of unsafe string prefixes.
- Windows output replacement uses atomic replace semantics rather than delete-and-rename behavior.

## 0.2.5 - 2026-07-13

### Added

- Added bounded regular-file reads: MCP configs and fixtures are limited to 16 MiB, policies to 1 MiB, and non-regular inputs are rejected.
- Added semantic MCP validation for required tool names, duplicate server/tool identities, known field types, multiple YAML documents, and empty scans.
- Added server command and argument capability analysis for shell, container, cloud, infrastructure, and package-manager execution signals.
- Added GitLab token-like and secret-bearing command-line argument detection and redaction.
- Added a fail-safe 10,000-finding report limit with critical `AG-SCAN001` truncation reporting.

### Changed

- Policy parsing is now strict: unknown fields, normalized-key collisions, empty rule entries, duplicate suppressions, invalid `fail_on: info`, and v0.1 suppressions are rejected.
- JSON and SARIF output files are written through private temporary files and atomically replaced without following output symlinks.
- Config map traversal and finding deduplication are deterministic.
- CI now verifies modules, runs the Go race detector on Linux, pins GitHub Actions to commit SHAs, and requires all six release archives.

### Fixed

- Prevented `--report` or `--sarif` from overwriting scan inputs, policy files, or each other.
- Prevented suppressions from hiding fail-safe `AG-SCAN001` incomplete-analysis findings.
- Fixed subcommand `--help` returning exit code `2` and rejected ignored trailing CLI arguments.
- Prevented terminal control sequences in untrusted paths and metadata from reaching human-readable output.
- Redacted secret-like values from suppression reasons and policy project names.
- Detected unterminated private-key blocks without exposing their contents.
- Detected secret-bearing environment and metadata key/value pairs while ignoring environment-variable references.
- Reduced false positives for generic cache-bypass text, passive AWS references, and non-capability credential mentions.
- Reduced path-policy false positives when an allowed path ends a sentence with punctuation.
- Normalized Windows paths in SARIF artifact URIs.

### Security

- Official `govulncheck` analysis found no reachable Go vulnerabilities for this release candidate.
- Input, policy, match, and finding limits reduce memory-exhaustion risk from hostile local fixtures.

## 0.2.0 - 2026-06-24

### Added

- Added stable SHA-256 finding fingerprints to JSON reports for repeat scans and policy suppressions.
- Added policy `version: "0.2"` suppressions by finding fingerprint with required reasons and optional expiry dates.
- Added SARIF 2.1.0 output through `--format sarif` and `--sarif <path>` for GitHub Code Scanning workflows.
- Added JSON schemas for ArgusGate reports and policies under `docs/schemas/`.
- Added detector rule metadata and expanded v0.2 risk catalog fixtures.
- Added detector coverage for invisible metadata characters, Slack/npm/PyPI/Google API token-like values, cloud CLIs, infrastructure-as-code tools, and package-manager execution.

### Changed

- Split scanner detectors into focused files by detector family.
- Updated terminal summaries and exit decisions to count unsuppressed findings separately from suppressed findings.
- Updated README and policy documentation for suppressions, SARIF output, schemas, and v0.2 limitations.

### Fixed

- Reduced false positives for descriptions that explicitly say they do not execute shell commands.
- Kept suppressed findings visible in JSON reports while excluding them from CI fail decisions and SARIF results.

## 0.1.5 - 2026-06-23

### Added

- Added a tag-driven GitHub Release workflow that builds Linux, macOS, and Windows archives for `amd64` and `arm64`.
- Added `SHA256SUMS.txt` generation for release asset verification.
- Added release documentation for maintainers and users.

### Changed

- Documented installing ArgusGate from GitHub release archives before source builds.
- Restricted CI workflow permissions to read-only repository contents.
- Added `.gitattributes` for consistent line endings across Go, YAML, Markdown, and JSON files.

## 0.1.4 - 2026-06-17

### Fixed

- Redacted secret-like server IDs, tool names, finding locations, server summaries, and tool summaries in JSON reports.
- Redacted the full URL userinfo segment so token-like usernames in `user:password@host` URLs do not leak.
- Detected URL userinfo credentials such as `https://user:password@example.test` as secret exposure findings.
- Rejected invalid MCP config and fixture shapes instead of silently scanning empty server or tool objects.
- Matched Windows drive paths in policy path rules.
- Detected host system administration capabilities such as `systemctl`, `launchctl`, scheduled tasks, registry operations, firewall operations, and privileged host operations.
- Reduced SQL false positives when metadata says write statements are blocked, rejected, forbidden, disallowed, prohibited, or prevented.

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
