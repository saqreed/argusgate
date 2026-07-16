$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$version = $env:ARGUSGATE_VERSION.Trim()
if ([string]::IsNullOrWhiteSpace($version)) {
    $version = $env:ARGUSGATE_ACTION_REF.Trim()
}
if ($version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$') {
    throw "ArgusGate release version is required. Pin saqreed/argusgate@vX.Y.Z or set input version."
}

$platforms = @{
    "Linux"   = "linux"
    "macOS"   = "darwin"
    "Windows" = "windows"
}
$architectures = @{
    "X64"   = "amd64"
    "ARM64" = "arm64"
}
$goos = $platforms[$env:RUNNER_OS]
$goarch = $architectures[$env:RUNNER_ARCH]
if ([string]::IsNullOrWhiteSpace($goos) -or [string]::IsNullOrWhiteSpace($goarch)) {
    throw "Unsupported GitHub runner platform: $($env:RUNNER_OS)/$($env:RUNNER_ARCH)"
}

$extension = if ($goos -eq "windows") { "zip" } else { "tar.gz" }
$package = "argusgate_${version}_${goos}_${goarch}"
$asset = "${package}.${extension}"
$baseUrl = "https://github.com/saqreed/argusgate/releases/download/${version}"
$installRoot = Join-Path $env:RUNNER_TEMP "argusgate-action-$([guid]::NewGuid().ToString('N'))"
$archivePath = Join-Path $installRoot $asset
$checksumsPath = Join-Path $installRoot "SHA256SUMS.txt"

New-Item -ItemType Directory -Path $installRoot | Out-Null

Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile $archivePath
Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS.txt" -OutFile $checksumsPath

$expected = $null
foreach ($line in Get-Content -LiteralPath $checksumsPath) {
    if ($line -match '^([a-fA-F0-9]{64})\s+\*?(.+)$' -and $Matches[2].Trim() -eq $asset) {
        $expected = $Matches[1].ToLowerInvariant()
        break
    }
}
if ([string]::IsNullOrWhiteSpace($expected)) {
    throw "SHA256SUMS.txt does not contain an entry for $asset"
}
$actual = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) {
    throw "Checksum verification failed for $asset"
}

if ($extension -eq "zip") {
    Expand-Archive -LiteralPath $archivePath -DestinationPath $installRoot
} else {
    & tar -xzf $archivePath -C $installRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract $asset"
    }
}

$binaryName = if ($goos -eq "windows") { "argusgate.exe" } else { "argusgate" }
$binaryPath = Join-Path (Join-Path $installRoot $package) $binaryName
if (-not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
    throw "Release archive did not contain $binaryName"
}
if ($goos -ne "windows") {
    & chmod +x $binaryPath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to mark the ArgusGate binary executable"
    }
}

"binary=$binaryPath" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
