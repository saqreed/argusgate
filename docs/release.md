# Release Process

ArgusGate publishes prerelease builds from version tags such as `v0.1.5`.

## Release Assets

The release workflow builds compressed archives for:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

Each archive contains:

- the `argusgate` binary, or `argusgate.exe` on Windows;
- `README.md`;
- `LICENSE`;
- `CHANGELOG.md`.

The workflow also publishes `SHA256SUMS.txt` for release asset verification.

## Maintainer Flow

1. Update `argusgate/scanner.Version`.
2. Update `CHANGELOG.md`.
3. Run:

   ```bash
   go test ./...
   go vet ./...
   mkdir -p bin
   go build -o ./bin/argusgate ./cmd/argusgate
   ```

4. Commit the release changes.
5. Create and push an annotated tag:

   ```bash
   git tag -a v0.1.5 -m "ArgusGate v0.1.5"
   git push origin main
   git push origin v0.1.5
   ```

Pushing the tag starts `.github/workflows/release.yml`. The workflow runs tests, verifies that the tag matches `argusgate/scanner.Version`, checks that `CHANGELOG.md` has a matching section, cross-compiles release archives, verifies the Linux `amd64` binary version, generates checksums, and creates or updates a GitHub prerelease.

## User Verification

After downloading an archive and `SHA256SUMS.txt`, verify the checksum before running the binary.

Linux or macOS:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

Windows PowerShell:

```powershell
Get-FileHash .\argusgate_v0.1.5_windows_amd64.zip -Algorithm SHA256
```

Compare the PowerShell hash with the matching line in `SHA256SUMS.txt`.
