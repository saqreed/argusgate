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
| `0.2.x` | Best-effort security fixes |
| `0.1.x` | Unsupported |

## Scanner Safety Scope

The MVP scanner reads local config and fixture files. It must not execute MCP server commands, call tools, or connect to external services during local scans.

If you find behavior that violates this offline scanning model, treat it as security-sensitive.
