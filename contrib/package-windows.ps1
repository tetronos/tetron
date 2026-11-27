# Builds the Windows release archive tetron-x86_64-windows.zip (WIN-080/081).
#
# Usage, from the repository root on Windows, after `cargo build --release`:
#   pwsh contrib/package-windows.ps1 -Binary target\x86_64-pc-windows-msvc\release\tetron.exe
#
# The archive holds tetron.exe, wintun.dll (amd64), tetron's LICENSE and
# Wintun's own license. A .sha256 file is written beside it.

param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [string]$OutName = "tetron-x86_64-windows"
)

$ErrorActionPreference = "Stop"

# Wintun is redistributed as the official prebuilt, signed DLL, never built
# from source. One version is pinned, and the download must match this hash
# exactly or packaging stops.
$WintunVersion = "0.14.1"
$WintunSha256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$WintunUrl = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("tetron-package-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # Fetch and verify Wintun.
    $wintunZip = Join-Path $work "wintun.zip"
    Invoke-WebRequest -Uri $WintunUrl -OutFile $wintunZip -UseBasicParsing
    $actual = (Get-FileHash -Algorithm SHA256 $wintunZip).Hash.ToLowerInvariant()
    if ($actual -ne $WintunSha256) {
        throw "wintun-$WintunVersion.zip hash $actual does not match the pinned $WintunSha256"
    }
    Expand-Archive -Path $wintunZip -DestinationPath (Join-Path $work "wintun-src")

    # Lay out the archive contents.
    $stage = Join-Path $work $OutName
    New-Item -ItemType Directory -Path $stage | Out-Null
    Copy-Item $Binary (Join-Path $stage "tetron.exe")
    Copy-Item (Join-Path $work "wintun-src\wintun\bin\amd64\wintun.dll") $stage
    Copy-Item "LICENSE" (Join-Path $stage "LICENSE")
    Copy-Item (Join-Path $work "wintun-src\wintun\LICENSE.txt") (Join-Path $stage "WINTUN-LICENSE.txt")

    # The packaged binary must start.
    $version = & (Join-Path $stage "tetron.exe") --version
    if ($LASTEXITCODE -ne 0) { throw "packaged tetron.exe --version failed" }
    Write-Host "packaged $version with wintun $WintunVersion"

    # Archive and checksum, in the same "<hash>  <name>" form as the other
    # release assets.
    $zip = "$OutName.zip"
    if (Test-Path $zip) { Remove-Item $zip }
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
    $hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    Set-Content -Path "$zip.sha256" -Value "$hash  $zip" -NoNewline -Encoding ascii
    Write-Host "wrote $zip ($hash)"
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
