# Run from a normal PowerShell terminal. No administrator session is needed.
$ErrorActionPreference = 'Stop'
$launcher = Get-Command py -ErrorAction SilentlyContinue
if ($launcher) {
    & $launcher.Source -3 -c 'import sys; assert sys.version_info >= (3, 10)' 2>$null
    if ($LASTEXITCODE -eq 0) {
        Push-Location -LiteralPath $PSScriptRoot
        try { & $launcher.Source -3 -m vps_proxy_setup @args; $setupExit = $LASTEXITCODE }
        finally { Pop-Location }
        exit $setupExit
    }
}
$launcher = Get-Command python -ErrorAction SilentlyContinue
if ($launcher) {
    & $launcher.Source -c 'import sys; assert sys.version_info >= (3, 10)' 2>$null
    if ($LASTEXITCODE -eq 0) {
        Push-Location -LiteralPath $PSScriptRoot
        try { & $launcher.Source -m vps_proxy_setup @args; $setupExit = $LASTEXITCODE }
        finally { Pop-Location }
        exit $setupExit
    }
}
Write-Error 'Python 3.10+ is required. Install Python from https://www.python.org/downloads/ and reopen PowerShell.'
exit 1
