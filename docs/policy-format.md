# Policy Format

ArgusGate policies are YAML files.

## Top-Level Fields

- `version`: policy format version. Use `"0.1"` for v0.1-compatible policies or `"0.2"` for suppressions.
- `project.name`: optional project label for reports.
- `defaults.fail_on`: severity threshold that produces exit code `1`.
- `defaults.allowed_severity`: optional highest allowed severity. If `fail_on` is omitted, ArgusGate fails on the next severity above this value.
- `defaults.allow_unknown_tools`: whether tools outside allow lists are advisory or policy violations.
- `rules.allow_tools`: global tool allow list.
- `rules.deny_tools`: global tool deny list.
- `rules.deny_keywords`: metadata keywords that produce policy findings.
- `rules.paths.deny`: denied path prefixes or sensitive path segments.
- `rules.paths.allow`: allowed path prefixes.
- `rules.suppressions`: v0.2 list of reviewed finding fingerprints that should not fail CI.
- `servers.<server_id>.allow_tools`: server-specific allow list.
- `servers.<server_id>.deny_tools`: server-specific deny list.

Hyphenated field names such as `deny-tools` are accepted as aliases for underscore names. Server IDs are preserved exactly.

## Severities

Valid severities:

- `info`
- `low`
- `medium`
- `high`
- `critical`

`defaults.fail_on` controls the process exit code only. It does not suppress findings. A scan still records all detector and policy findings.

Suppressed findings are still recorded in JSON reports with `suppressed: true`, but they are excluded from severity summaries, SARIF results, and exit-code decisions.

## Precedence

ArgusGate applies policy rules in this order:

1. Explicit deny beats allow. A tool in `deny_tools` is reported even if it also appears in an allow list.
2. Server-specific tool rules apply only to that server ID.
3. If `servers.<server_id>.allow_tools` is set, that server-specific allow list is used for unknown-tool checks on that server.
4. If no server-specific allow list is set, `rules.allow_tools` is used for unknown-tool checks.
5. If `defaults.allow_unknown_tools` is `true`, tools outside allow lists are not policy violations.
6. If `defaults.allow_unknown_tools` is `false`, tools outside the effective allow list are reported as policy violations.
7. Path deny rules beat path allow rules.
8. Missing policy falls back to default MVP policy: `fail_on: high` and `allow_unknown_tools: true`.
9. v0.2 suppressions are applied after detector and policy findings are created, but before the exit decision is calculated.
10. `defaults.fail_on` controls exit code only. It never prevents findings from being recorded.

Path rules are intentionally conservative. Values that look like paths, such as `/etc`, `./examples`, or `C:\Users\dev\.ssh`, are treated as path prefixes and must match the start of the candidate path on a path boundary. Plain values, such as `.env` or `kubeconfig`, match path segments. ArgusGate does not treat arbitrary substring matches as path policy violations.

## Example

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
  deny_keywords:
    - "ignore previous instructions"
    - "private key"
  paths:
    deny:
      - "~/.ssh"
      - "/etc"
    allow:
      - "./examples"
servers:
  local-filesystem:
    allow_tools:
      - "read_file"
    deny_tools:
      - "write_file"
```

## Suppressions

Suppressions are available in policy `version: "0.2"`. A suppression matches only a stable finding fingerprint from a previous ArgusGate JSON report.

```yaml
version: "0.2"
rules:
  suppressions:
    - fingerprint: "0000000000000000000000000000000000000000000000000000000000000000"
      reason: "accepted local fixture risk after review"
      expires: "2099-12-31"
```

Rules:

- `fingerprint` must be a 64-character SHA-256 hex string.
- `reason` is required.
- `expires` is optional and must use `YYYY-MM-DD`.
- Expired suppressions are ignored and reported as medium policy finding `AG-POL006`.
- Suppressed findings remain in JSON reports for auditability.
- Suppressed findings do not affect exit code or SARIF output.

See [schemas/policy.schema.json](schemas/policy.schema.json) for the machine-readable schema.

## Exit Decisions

ArgusGate exits with `1` when at least one unsuppressed finding is at or above `defaults.fail_on`. Parser errors, invalid policies, and internal errors exit with `2`.
