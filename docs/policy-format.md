# Policy Format

ArgusGate policies are strict YAML documents. Unknown fields, ambiguous hyphen/underscore aliases, duplicate suppression fingerprints, empty rules, multiple YAML documents, and oversized files are rejected.

## Versions

- `0.1`: tool, keyword, and path rules.
- `0.2`: adds finding suppressions.
- `0.3`: adds prompt and resource URI trust rules.

Older policy versions remain compatible. Prompt/resource fields require `version: "0.3"` so new semantics cannot be enabled accidentally in an older policy.

## Fields

### Defaults

- `fail_on`: `low`, `medium`, `high`, or `critical`.
- `allowed_severity`: optional highest allowed severity; used only when `fail_on` is omitted.
- `allow_unknown_tools`: report tools outside effective allow lists when false.
- `allow_unknown_prompts`: v0.3 equivalent for prompts.
- `allow_unknown_resources`: v0.3 equivalent for resources and resource templates.

### Global Rules

- `allow_tools`, `deny_tools`
- `allow_prompts`, `deny_prompts`
- `deny_keywords`
- `paths.allow`, `paths.deny`
- `resource_uris.allow`, `resource_uris.deny`
- `suppressions`

### Server Rules

- `servers.<id>.allow_tools`, `deny_tools`
- `servers.<id>.allow_prompts`, `deny_prompts`
- `servers.<id>.resource_uris.allow`, `resource_uris.deny`

Server IDs are matched exactly. Hyphenated field aliases such as `deny-tools` are normalized, but defining both normalized forms is an error.

## Precedence

1. Explicit deny beats allow.
2. Global denies always remain active.
3. Server-specific deny rules add restrictions for that server.
4. A non-empty server-specific allow list replaces the corresponding global allow list for unknown-item checks on that server.
5. Otherwise, the global allow list is used.
6. Unknown tools, prompts, and resources follow their respective `allow_unknown_*` defaults.
7. Path and resource URI deny rules beat allow rules.
8. Suppressions apply after detector and policy findings are created and fingerprinted.
9. Suppressed findings remain in JSON for auditability but do not affect severity summaries, SARIF, or exit decisions.
10. `fail_on` controls only the exit decision; it never prevents findings from being recorded.

Missing policy uses safe advisory defaults: `fail_on: high`, unknown tools/prompts/resources allowed, and no suppressions.

## Resource URI Matching

For absolute URIs, ArgusGate compares:

- scheme case-insensitively;
- authority/host case-insensitively;
- path on namespace boundaries.

For example, `https://trusted.example/api` matches `https://trusted.example/api/items`, but does not match `https://trusted.example.evil/api` or `https://trusted.example/api-private`.

## Suppressions

Suppressions require policy `0.2` or newer:

```yaml
version: "0.3"
rules:
  suppressions:
    - fingerprint: "0000000000000000000000000000000000000000000000000000000000000000"
      reason: "accepted after review"
      expires: "2099-12-31"
```

- `fingerprint` is a 64-character SHA-256 hex value from a report.
- `reason` is required.
- `expires` is optional and uses `YYYY-MM-DD`.
- Expired suppressions produce medium `AG-POL006`.
- Critical scanner-limit finding `AG-SCAN001` cannot be suppressed.

## Example

See [examples/policies/v03-trust.yaml](../examples/policies/v03-trust.yaml) and the [policy JSON Schema](schemas/policy.schema.json).
