# Threat Model

## Assets

- Developer and CI machines that store MCP configs.
- API tokens, SSH keys, cloud credentials, database credentials, and browser profiles.
- Internal services exposed through MCP tools.
- AI agent context and tool invocation results.

## Primary Adversaries

- A malicious MCP server author.
- A compromised MCP server.
- A dependency or configuration change that expands tool capability without review.
- An accidental committer of credentials into local config or fixtures.

## MVP Threats

- Tool poisoning through hidden or coercive tool descriptions.
- Secret exposure in config, headers, environment values, examples, tool metadata, or schemas.
- Tools with shell execution, broad file access, network/browser automation, database writes, credential access, Docker, Kubernetes, or host control.
- Sensitive paths such as `~/.ssh`, `/etc/shadow`, `.env`, `kubeconfig`, and cloud credential directories.
- SQL metadata that suggests write-capable or shell-capable database operations.
- Policy drift between approved tools/paths and actual metadata.

## Detector Heuristics

The v0.2.0 detectors are transparent static checks:

- Tool poisoning: suspicious instruction phrases, hidden markdown/HTML comments, suspicious encoded payloads, and invisible metadata characters.
- Secret exposure: bearer tokens, basic authorization values, URL userinfo credentials, key/value secret fields, JWT-like strings, connection strings, private-key-shaped blocks, and common ecosystem token shapes.
- Dangerous capability: shell execution, file read/write, network or browser automation, database writes, credential access, Docker, Kubernetes, cloud CLI, infrastructure-as-code, package manager, and host system operations.
- Sensitive path: references to SSH keys, `/etc/passwd`, `/etc/shadow`, `.env`, `kubeconfig`, cloud credential paths, token files, and browser profiles.
- SQL risk: static signals for SQL read access and write/schema/command-capable SQL operations.

These checks are not proof of exploitability. They are risk signals for review and CI gating.

## OWASP MCP Mapping

- MCP01: Token Mismanagement & Secret Exposure.
- MCP02: Privilege Escalation via Scope Creep.
- MCP03: Tool Poisoning.
- MCP05: Command Injection & Execution.
- MCP08: Lack of Audit and Telemetry, planned for future runtime/audit work.

## Assumptions

- Static metadata can reveal useful risk signals but cannot prove runtime safety.
- Tool annotations and descriptions are untrusted unless the server is trusted.
- Local fixture scanning must remain offline.
- Runtime enforcement requires a future proxy/gateway and is outside the MVP.

## Security Boundaries

ArgusGate is not a sandbox, firewall, identity provider, DLP system, or complete policy enforcement point in the MVP. It reports risk before use; it does not make unsafe tools safe.
