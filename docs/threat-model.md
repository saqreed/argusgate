# Threat Model

## Assets

- MCP client hosts and CI runners.
- Credentials, private files, browser profiles, databases, cloud accounts, and infrastructure exposed through MCP servers.
- Reviewed MCP metadata and policy decisions.
- JSON/SARIF reports and baselines.

## Adversaries

- A malicious or compromised MCP server.
- A dependency update that changes advertised capabilities after review.
- A configuration author who accidentally embeds credentials.
- A hostile endpoint attempting redirects, oversized responses, pagination loops, or unexpected MCP methods during inspection.

## Covered Threats

- Hidden or coercive instructions in tools, prompts, annotations, schemas, and metadata.
- Secret-like values in configs and metadata.
- Shell, filesystem, network, browser, database, credential, container, cluster, cloud, package-manager, and host-control capabilities.
- Sensitive host paths and risky resource URIs.
- SQL write/admin capability signals.
- Missing or ambiguous tool input schemas.
- Contradictory tool annotations.
- Added or changed MCP metadata after baseline review.
- Policy drift across tools, prompts, paths, and resource URI namespaces.

## Inspection Controls

- Explicit opt-in only.
- HTTPS only.
- No redirects or automatic retries.
- Same-origin transport enforcement.
- Environment-backed authorization headers.
- JSON-RPC method allow list limited to initialization and metadata listing.
- No `tools/call`, `prompts/get`, `resources/read`, stdio startup, or command execution.
- Query parameter values are removed from endpoint metadata before reports or baselines are built.
- Bounded request/response size, pagination, time, and artifact count.

These controls reduce exposure but do not make an untrusted endpoint safe. Metadata can still be deceptive, and the endpoint still observes the connecting IP and authorized list requests.

## Baseline Assumptions

Baselines help identify changed advertised contracts. They do not authenticate a server, verify source provenance, or prove runtime behavior. Updating a baseline is a security review action, not an automatic remediation.

## OWASP MCP Mapping

Findings map where applicable to OWASP MCP categories including secret exposure, scope creep, tool poisoning, command execution, and prompt injection through contextual payloads.

## Security Boundary

ArgusGate is not a sandbox, DLP system, identity provider, runtime firewall, or complete policy enforcement point. It provides static and metadata-level risk signals before use.
