# Security Policy

ArgusGate is experimental security tooling. Static scanner findings are heuristic and may include false positives or false negatives.

## Reporting Security Issues

Please do not open a public issue for a suspected vulnerability in ArgusGate itself.

Until a dedicated private disclosure channel exists, contact the maintainers through the repository owner profile or open a public issue that requests a private security contact without including exploit details.

Include:

- affected version or commit;
- operating system and Go version if relevant;
- minimal reproduction steps;
- whether secrets, logs, reports, or fixture data were exposed;
- expected and actual behavior.

## Supported Versions

| Version | Support |
| --- | --- |
| `0.3.x` | Best-effort security fixes |
| `0.2.x` | Critical fixes only |
| `0.1.x` | Unsupported |

## Scanner Safety Scope

Local config and fixture scans must not execute MCP server commands, call tools, or connect to external services.

If you find behavior that violates this offline scanning model, treat it as security-sensitive.

The explicit `inspect` command may connect only to the user-selected HTTPS endpoint and may perform initialization and metadata list requests. Redirects, cross-origin requests, tool calls, prompt retrieval, resource reads, and command execution are outside its security contract.
