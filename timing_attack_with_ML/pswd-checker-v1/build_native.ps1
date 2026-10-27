$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$locator = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path -LiteralPath $locator)) { throw 'MSVC Build Tools with the C++ workload are required.' }
$installation = & $locator -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$installation) { throw 'No MSVC x64 C++ toolchain found.' }
$devShell = Join-Path $installation 'Common7\Tools\Launch-VsDevShell.ps1'
& $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation
& cl.exe /nologo /O2 /W4 /LD native_windows.c /Fe:native_windows.dll /link /INCREMENTAL:NO
if ($LASTEXITCODE -ne 0) { throw 'Native compilation failed.' }
