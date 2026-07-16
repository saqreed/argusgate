# Contributing

ArgusGate is an early open-source MCP security scanner. Contributions should keep the v0.3 scope focused, testable, and honest.

## Development Setup

Requirements:

- Go 1.25.12 or newer.

Run:

```bash
go mod verify
go test ./...
go vet ./...
mkdir -p bin
go build -o ./bin/argusgate ./cmd/argusgate
```

## Contribution Guidelines

- Keep config and fixture scans offline.
- Keep live inspection explicit, HTTPS-only, metadata-only, bounded, and covered by transport security tests.
- Never add tool calls, prompt retrieval, resource reads, or MCP command execution to inspection paths.
- Treat baseline updates as explicit review actions.
- Add tests for detector, policy, parser, report, or CLI behavior changes.
- Do not add real secrets to tests, examples, docs, screenshots, or reports.
- Redact secret-like values before printing or writing reports.
- Keep README claims conservative: ArgusGate is heuristic static analysis, not a complete security boundary.
- Avoid web UI, database, auth/RBAC, proxy, Kubernetes, or SaaS work unless a maintainer explicitly accepts that scope.

## Pull Request Checklist

- `go test ./...` passes.
- `go vet ./...` passes.
- `go build -o ./bin/argusgate ./cmd/argusgate` passes.
- New examples use fake placeholders only.
- Docs are updated when CLI, report, policy, or detector behavior changes.
