# ArgusGate Product Scope

## Goal

ArgusGate helps teams review MCP server configurations and advertised contracts before they are trusted by MCP clients.

## v0.3.0 Scope

- Local JSON/YAML config and fixture scanning.
- Tool, prompt, resource, and resource-template metadata models.
- Heuristic detectors and stable rule IDs.
- Strict policy versions `0.1`, `0.2`, and `0.3`.
- Reviewed baselines for metadata/config drift.
- Explicit HTTPS Streamable HTTP metadata inspection.
- Human, JSON, and SARIF output.
- Checksum-verified GitHub Action and release binaries.
- CI exit codes `0`, `1`, and `2`.

## Non-Goals

- No web dashboard or database.
- No SaaS or tenant model.
- No OAuth browser flow or enterprise RBAC.
- No Kubernetes deployment.
- No stdio server execution.
- No tool calls, prompt retrieval, or resource reads.
- No full runtime MCP proxy.
- No automatic baseline updates or file remediation.

## Future Work

- Richer baseline diffs and review UX.
- Additional MCP contract checks and detector tuning.
- Signed release provenance.
- Additional opt-in noninteractive authentication modes.
- Runtime enforcement only after scanner and policy contracts stabilize.

## Positioning

ArgusGate is a transparent open-source MCP security review layer. It combines static scanning, policy evaluation, reviewed metadata baselines, CI output, and constrained metadata inspection without claiming complete protection.
