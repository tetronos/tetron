# Installs tetron on Windows 10 or 11 (x86_64).
#
# Run from an elevated PowerShell ("Run as administrator"):
#   irm https://tetronos.github.io/tetron/install.ps1 | iex
# or, to pin a release, download this file and run:
#   .\install.ps1 -Version vX.Y.Z
# -BaseUrl downloads the zip and its .sha256 from another location (a
# mirror) instead of the GitHub release.
#
# What it does, in order:
#   1. Downloads tetron-x86_64-windows.zip and its .sha256 from the tetron
#      GitHub releases (the latest release, or the tag given with -Version).
#   2. Stops unless the zip's SHA-256 matches the published .sha256.
#   3. Extracts it to a new temporary folder and runs `tetron.exe install`
#      from there. That copies tetron.exe and wintun.dll into
#      %ProgramFiles%\tetron, registers and starts the `tetron` Windows
#      service (LocalSystem, automatic start), and activates the VPN.
#   4. Adds %ProgramFiles%\tetron to the machine PATH if it is not there yet,
#      so `tetron` works in new terminals.
#   5. Deletes the temporary folder.
#
# Nothing else on the system is changed. `tetron uninstall` removes the
# service and the program files and keeps %ProgramData%\tetron (the node's
# identity and networks).

param(
    [string]$Version = "latest",
    [string]$BaseUrl = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "tetronos/tetron"
$Asset = "tetron-x86_64-windows.zip"

# The service install needs an elevated (Administrator) session.
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an elevated PowerShell (right-click, Run as administrator)."
}

if ([Environment]::Is64BitOperatingSystem -eq $false) {
    throw "tetron for Windows needs a 64-bit (x86_64) Windows."
}

if ($BaseUrl -ne "") {
    $base = $BaseUrl.TrimEnd("/")
} elseif ($Version -eq "latest") {
    $base = "https://github.com/$Repo/releases/latest/download"
} else {
    $base = "https://github.com/$Repo/releases/download/$Version"
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("tetron-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # 1. Download the archive and its checksum.
    $zip = Join-Path $work $Asset
    $sum = "$zip.sha256"
    Write-Host "downloading $base/$Asset"
    Invoke-WebRequest -Uri "$base/$Asset" -OutFile $zip -UseBasicParsing
    Invoke-WebRequest -Uri "$base/$Asset.sha256" -OutFile $sum -UseBasicParsing

    # 2. Verify. The .sha256 file is "<hash>  <file name>".
    $expected = ((Get-Content $sum -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "checksum mismatch for $Asset (expected $expected, got $actual); nothing was installed"
    }
    Write-Host "checksum ok ($actual)"

    # 3. Extract and let tetron install itself as a service.
    $dir = Join-Path $work "tetron"
    Expand-Archive -Path $zip -DestinationPath $dir
    & (Join-Path $dir "tetron.exe") install
    if ($LASTEXITCODE -ne 0) { throw "tetron install failed (exit code $LASTEXITCODE)" }

    # 4. Put the install folder on the machine PATH for new terminals.
    $installDir = Join-Path $env:ProgramFiles "tetron"
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $entries = $machinePath -split ";" | Where-Object { $_ -ne "" }
    if ($entries -notcontains $installDir) {
        [Environment]::SetEnvironmentVariable("Path", (($entries + $installDir) -join ";"), "Machine")
        Write-Host "added $installDir to the machine PATH (open a new terminal to use it)"
    }

    Write-Host "tetron is installed. Next: tetron create, or tetron join <invite key>."
}
finally {
    # 5. Clean up the download.
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
