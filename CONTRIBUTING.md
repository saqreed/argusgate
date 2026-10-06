# Contributing

ArgusGate is an early open-source MCP security scanner. Contributions should keep the v0.3 scope focused, testable, and honest.

## Find A Task

Look for [good first issue](https://github.com/saqreed/argusgate/labels/good%20first%20issue) for bounded starter tasks and [help wanted](https://github.com/saqreed/argusgate/labels/help%20wanted) for broader work. Comment on an issue before a substantial change so the approach and scope can be agreed.

Use [Discussions](https://github.com/saqreed/argusgate/discussions) for questions and ideas. Follow [SECURITY.md](SECURITY.md) for suspected vulnerabilities; do not disclose exploit details in a public issue or PR.

## Development Setup

Requirements:

- Go 1.26.8 or newer.
- Git and a fork or local checkout of this repository.

From the repository root, run:

```bash
go mod verify
go test ./...
go vet ./...
mkdir -p bin
go build -o ./bin/argusgate ./cmd/argusgate
```

On Windows PowerShell, the equivalent build is:

```powershell
New-Item -ItemType Directory -Force bin | Out-Null
go build -o .\bin\argusgate.exe ./cmd/argusgate
```

Try an offline smoke test with the built binary:

```bash
./bin/argusgate fixtures scan --path examples/fixtures/safe-tools.yaml
```

Use `.\bin\argusgate.exe` on Windows. This safe fixture should exit `0`; intentionally risky fixtures may correctly exit `1`.

## Contribution Guidelines

- Keep config and fixture scans offline.
- Keep live inspection explicit, HTTPS-only, metadata-only, bounded, and covered by transport security tests.
- Never add tool calls, prompt retrieval, resource reads, or MCP command execution to inspection paths.
- Treat baseline updates as explicit review actions.
- Add tests for detector, policy, parser, report, or CLI behavior changes.
- Keep changes focused. For detector changes, include a risky case and a safe negative case where practical.
- Do not add real secrets to tests, examples, docs, screenshots, or reports.
- Use clearly fake placeholders such as `FAKE_TOKEN_DO_NOT_USE` and reserved example domains. Fixtures describe capabilities; they must not execute them.
- Redact secret-like values before printing or writing reports.
- Keep README claims conservative: ArgusGate is heuristic static analysis, not a complete security boundary.
- Avoid web UI, database, auth/RBAC, proxy, Kubernetes, or SaaS work unless a maintainer explicitly accepts that scope.
- Update CLI examples, schemas, policy documentation, or rule descriptions when their public contracts change. Check that commands and expected exit codes are real.
- Keep generated reports, binaries, and local research notes out of commits.

## Submitting A Change

Create a branch, add focused tests where appropriate, run the checks above, and open a PR linked to the relevant issue. Explain the behavior change, validation, documentation impact, and any security tradeoffs. Documentation-only changes do not need unrelated code or version bumps.

## Pull Request Checklist

- `go test ./...` passes.
- `go mod verify` passes.
- `go vet ./...` passes.
- `go build -o ./bin/argusgate ./cmd/argusgate` passes.
- New examples use fake placeholders only.
- Docs are updated when CLI, report, policy, or detector behavior changes.
