# Contributing

ArgusGate is an early open-source MCP security scanner. Contributions should keep the v0.1 scope small, testable, and honest.

## Development Setup

Requirements:

- Go 1.24 or newer.

Run:

```bash
go test ./...
go vet ./...
mkdir -p bin
go build -o ./bin/argusgate ./cmd/argusgate
```

## Contribution Guidelines

- Keep scanner behavior offline unless live inspection is explicitly designed and reviewed.
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
