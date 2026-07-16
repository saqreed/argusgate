$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$sourceType = $env:ARGUSGATE_SOURCE_TYPE.Trim().ToLowerInvariant()
$source = $env:ARGUSGATE_SOURCE.Trim()
if ($sourceType -notin @("config", "fixtures", "url")) {
    throw "source-type must be config, fixtures, or url"
}
if ([string]::IsNullOrWhiteSpace($source)) {
    throw "source is required"
}
if (-not (Test-Path -LiteralPath $env:ARGUSGATE_BINARY -PathType Leaf)) {
    throw "ArgusGate binary was not installed"
}

$arguments = [System.Collections.Generic.List[string]]::new()
switch ($sourceType) {
    "config" {
        $arguments.Add("scan")
        $arguments.Add("--config")
        $arguments.Add($source)
    }
    "fixtures" {
        $arguments.Add("fixtures")
        $arguments.Add("scan")
        $arguments.Add("--path")
        $arguments.Add($source)
    }
    "url" {
        $arguments.Add("inspect")
        $arguments.Add("--url")
        $arguments.Add($source)
        if (-not [string]::IsNullOrWhiteSpace($env:ARGUSGATE_SERVER_ID)) {
            $arguments.Add("--server-id")
            $arguments.Add($env:ARGUSGATE_SERVER_ID)
        }
        if (-not [string]::IsNullOrWhiteSpace($env:ARGUSGATE_TIMEOUT)) {
            $arguments.Add("--timeout")
            $arguments.Add($env:ARGUSGATE_TIMEOUT)
        }
        if (-not [string]::IsNullOrWhiteSpace($env:ARGUSGATE_TOKEN_ENV)) {
            $arguments.Add("--token-env")
            $arguments.Add($env:ARGUSGATE_TOKEN_ENV)
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($env:ARGUSGATE_POLICY)) {
    $arguments.Add("--policy")
    $arguments.Add($env:ARGUSGATE_POLICY)
}
if (-not [string]::IsNullOrWhiteSpace($env:ARGUSGATE_BASELINE)) {
    $arguments.Add("--baseline")
    $arguments.Add($env:ARGUSGATE_BASELINE)
}
if (-not [string]::IsNullOrWhiteSpace($env:ARGUSGATE_FAIL_ON)) {
    $arguments.Add("--fail-on")
    $arguments.Add($env:ARGUSGATE_FAIL_ON)
}
if (-not [string]::IsNullOrWhiteSpace($env:ARGUSGATE_REPORT)) {
    $arguments.Add("--report")
    $arguments.Add($env:ARGUSGATE_REPORT)
}
if (-not [string]::IsNullOrWhiteSpace($env:ARGUSGATE_SARIF)) {
    $arguments.Add("--sarif")
    $arguments.Add($env:ARGUSGATE_SARIF)
}

& $env:ARGUSGATE_BINARY @arguments
$exitCode = $LASTEXITCODE
if ($null -eq $exitCode) {
    $exitCode = 2
}

"report=$($env:ARGUSGATE_REPORT)" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
"sarif=$($env:ARGUSGATE_SARIF)" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
"exit-code=$exitCode" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append

# The final composite step propagates the captured scanner decision after outputs exist.
exit 0
