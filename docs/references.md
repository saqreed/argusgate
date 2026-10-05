# References

This document records public sources that influenced ArgusGate design.

## Model Context Protocol

- Specification revision 2025-11-25: https://modelcontextprotocol.io/specification/2025-11-25
- Server overview: https://modelcontextprotocol.io/specification/2025-11-25/server
- Tools: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- Prompts: https://modelcontextprotocol.io/specification/2025-11-25/server/prompts
- Resources: https://modelcontextprotocol.io/specification/2025-11-25/server/resources
- Transports: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- Official Go SDK: https://github.com/modelcontextprotocol/go-sdk

Design influence: metadata models, Streamable HTTP inspection, protocol initialization, pagination, tool schema validation, and the decision to treat descriptions and annotations as untrusted input.

## MCP Security

- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- Invariant Labs tool-poisoning research: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- MCP-Scan documentation: https://explorer.invariantlabs.ai/docs/mcp-scan/

Design influence: tool-poisoning checks, secret/scope findings, stable rule mapping, and metadata review before trust. ArgusGate does not copy project code or branding.

## GitHub Actions And SARIF

- Composite actions: https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action
- Action metadata syntax: https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax
- Uploading SARIF: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file
- SARIF support: https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files

Design influence: typed composite-action inputs/outputs, `$GITHUB_OUTPUT`, SARIF 2.1.0 output, stable partial fingerprints, and documented Code Scanning integration.

## Go Security

- Go vulnerability management: https://go.dev/security/vuln/
- govulncheck: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck

Design influence: module verification, reachable-vulnerability checks, race-enabled tests, and release review.

- Go download index: https://go.dev/dl/?mode=json
- URL path-resolution advisory: https://pkg.go.dev/vuln/GO-2026-6218
- TLS handshake resource advisory: https://pkg.go.dev/vuln/GO-2026-6090
- ASN.1 recursion advisory: https://pkg.go.dev/vuln/GO-2026-5972
- IDNA advisory: https://pkg.go.dev/vuln/GO-2026-5026

Design influence: minimum Go 1.26.8 toolchain for supported patch releases and vulnerability checks bound to the same toolchain used to build release binaries, rather than an automatically substituted version.

## GitHub Release Publication

- GitHub CLI release creation: https://cli.github.com/manual/gh_release_create
- GitHub CLI release editing: https://cli.github.com/manual/gh_release_edit

Design influence: regular version tags clear the prerelease flag and become Latest, prerelease suffixes retain prerelease status, and publication requires an existing remote tag.
