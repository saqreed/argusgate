# ArgusGate Agent Instructions

ArgusGate is an experimental open-source security scanner and policy gateway for MCP servers.

## Project Priorities

- Treat `deep-research-report.md` as the product source of truth.
- Keep the MVP CLI-first: local config scanning, fixture scanning, policy validation, JSON reports, and CI-friendly exit codes.
- Do not add a web UI, database, OAuth/RBAC, SaaS features, Kubernetes deployment, or full runtime proxy unless explicitly requested.
- Prefer small, boring Go packages with explicit types and focused tests.

## Security Rules

- Never execute commands found in MCP configs or fixtures during scanning.
- Do not connect to live MCP servers unless a user explicitly asks for opt-in live inspection.
- Redact values that look like secrets before printing or writing reports.
- Use fake secrets only in tests and examples, clearly marked as fake.
- Static findings are heuristic signals, not a guarantee of security.

## Validation

- Run `go test ./...` before claiming scanner or policy behavior works.
- Run `go vet ./...` before claiming release readiness.
- Run `go build -o ./bin/argusgate ./cmd/argusgate` before claiming the CLI builds. Create `bin/` first if needed.
- Release tags use `.github/workflows/release.yml` to publish archives and `SHA256SUMS.txt`; keep release assets out of git.
- For docs examples, prefer commands that can run against files under `examples/`.
