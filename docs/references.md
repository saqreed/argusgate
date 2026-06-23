# References

This document tracks external sources that influenced the MVP design.

## deep-research-report.md

Local source of truth for product goal, threat model, roadmap, competitor positioning, and the split between static scanner MVP and future gateway work.

Design influence: kept the first implementation CLI-first, offline, policy-driven, and explicitly deferred proxy, UI, database, RBAC, SaaS, and Kubernetes features.

## Official Model Context Protocol Specification

- Tools specification: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- Server concepts: https://modelcontextprotocol.io/docs/learn/server-concepts

Design influence: modeled tool metadata around `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations`, and `_meta`-style metadata. The docs also influenced the decision to treat tool annotations and descriptions as untrusted static input.

## OWASP MCP Top 10

- Project page: https://owasp.org/www-project-mcp-top-10/

Design influence: mapped findings to MCP01 secret exposure, MCP02 scope creep, MCP03 tool poisoning, MCP05 command injection/execution, and future MCP08 audit/telemetry work.

## Invariant Labs MCP-Scan And Tool Poisoning Research

- MCP-Scan documentation: https://explorer.invariantlabs.ai/docs/mcp-scan/
- Tool poisoning notification: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks

Design influence: confirmed that local config and tool-description scanning are useful early controls, and that hidden/coercive instructions in tool metadata should be treated as high-risk static signals. ArgusGate does not copy MCP-Scan code, issue names, or branding.

## MCPTox

- Paper page: https://arxiv.org/abs/2508.14925

Design influence: kept malicious examples focused on tool poisoning patterns and future red-team fixture expansion, without adding runtime benchmarking to the MVP.

## GitHub Actions And Release Automation

- GitHub CLI in workflows: https://docs.github.com/actions/using-workflows/using-github-cli-in-workflows
- GITHUB_TOKEN authentication and permissions: https://docs.github.com/actions/reference/authentication-in-a-workflow
- Workflow artifacts: https://docs.github.com/en/actions/tutorials/store-and-share-data

Design influence: implemented tag-driven release archives with the preinstalled GitHub CLI, scoped workflow permissions, artifact passing between jobs, and checksum publication without adding third-party release actions.
