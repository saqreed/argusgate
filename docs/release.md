# Release Process

ArgusGate publishes prerelease builds from version tags such as `v0.3.0`.

## Assets

The release workflow builds Linux, macOS, and Windows archives for `amd64` and `arm64`. Each archive contains the binary, README, license, changelog, and JSON schemas. `SHA256SUMS.txt` covers every archive.

The root `action.yml` downloads these archives and refuses to run them unless the checksum matches.

## Maintainer Checklist

1. Update `argusgate/scanner.Version`.
2. Add the matching `CHANGELOG.md` section.
3. Confirm examples and documentation use the same release version.
4. Run:

   ```bash
   go mod verify
   go test -mod=readonly -count=1 ./...
   go vet -mod=readonly ./...
   go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
   go run github.com/securego/gosec/v2/cmd/gosec@v2.28.0 -quiet ./...
   go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 -no-color
   mkdir -p bin
   go build -mod=readonly -trimpath -o ./bin/argusgate ./cmd/argusgate
   ```

5. Verify:

   ```bash
   ./bin/argusgate --version
   ./bin/argusgate policy validate --policy examples/policies/v03-trust.yaml
   ./bin/argusgate baseline create --fixtures examples/fixtures/safe-tools.yaml --output argusgate-baseline.json
   ./bin/argusgate fixtures scan --path examples/fixtures/safe-tools.yaml --baseline argusgate-baseline.json
   ./bin/argusgate fixtures scan --path examples/fixtures/v03-metadata.yaml --policy examples/policies/v03-trust.yaml --report v03-report.json --sarif v03.sarif
   ```

6. Commit, merge, and create an annotated tag:

   ```bash
   git tag -a v0.3.0 -m "ArgusGate v0.3.0"
   git push origin main
   git push origin v0.3.0
   ```

The malicious v0.3 fixture command should exit `1`. Pushing the tag runs tests, checks version/changelog consistency, cross-compiles all archives, generates checksums, and publishes a GitHub prerelease.

## User Checksum Verification

Linux or macOS:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

Windows PowerShell:

```powershell
Get-FileHash .\argusgate_v0.3.0_windows_amd64.zip -Algorithm SHA256
```
