param([switch]$SelfCheck, [string]$UpstreamPath)
$ErrorActionPreference = 'Stop'
$repo = 'CyberfiTechh/CyberFi-Releases'
$certificateThumbprint = '2470547AF0CF456E06BF7065399591BBD7EC79ED'
$expected = @{
    '0.0.113' = 'c1f4e1f2e0b779e5fa808f288255e39b15d01a84cf3e84835e71960333e47deb'
    '0.0.114' = '3bcbe22f5f338cf0d8cb4d6747c69bd11ca347b649b4bc1c8bb48c4fe9ecdae2'
}
function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Receive-PublishedAsset([string]$Url, [string]$Destination) {
    Write-Host "[$([DateTime]::UtcNow.ToString('o'))] Downloading $([IO.Path]::GetFileName($Destination))"
    & curl.exe --fail --location --retry 2 --connect-timeout 20 --max-time 300 --output $Destination $Url
    Assert-True ($LASTEXITCODE -eq 0) "Bounded release download failed: $([IO.Path]::GetFileName($Destination)) (curl exit $LASTEXITCODE)"
    Write-Host "[$([DateTime]::UtcNow.ToString('o'))] Downloaded $((Get-Item -LiteralPath $Destination).Length) bytes"
}
function Assert-Owned([string]$Path, [string]$Root) {
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    Assert-True ($full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) "Path is outside the owned root: $full"
    $full
}
if ($SelfCheck) {
    Assert-True ($expected.Count -eq 2) 'Exactly two immutable versions required'
    foreach ($entry in $expected.GetEnumerator()) {
        Assert-True ($entry.Value -cmatch '^[a-f0-9]{64}$') 'Invalid pinned digest'
        Assert-True ($entry.Key -in @('0.0.113', '0.0.114')) 'Unexpected version'
    }
    Assert-True ($certificateThumbprint -cmatch '^[A-F0-9]{40}$') 'Invalid certificate pin'
    $null = Assert-Owned (Join-Path ([IO.Path]::GetTempPath()) 'owned/item') ([IO.Path]::GetTempPath())
    try { $null = Assert-Owned ([IO.Path]::GetTempPath()) (Join-Path ([IO.Path]::GetTempPath()) 'owned'); throw 'Guard accepted parent' }
    catch { Assert-True ($_.Exception.Message -like 'Path is outside*') 'Ownership guard failed' }
    'Acceptance harness self-check passed; no installers or network used.'
    return
}
Assert-True ($IsWindows -and $env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_ENVIRONMENT -eq 'github-hosted' -and
    $env:GITHUB_REPOSITORY -ceq $repo -and $env:GITHUB_REF -eq 'refs/heads/main') 'Only the disposable public Windows runner may install'
$root = Assert-Owned (Join-Path $env:RUNNER_TEMP 'cyberfi-windows-acceptance') $env:RUNNER_TEMP
Assert-True (-not (Test-Path -LiteralPath $root)) 'Acceptance root must start empty'
$evidence = Join-Path $root 'evidence'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$uninstallKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\f8156223-0df4-5c6f-b223-7004db2f68a2'
Assert-True (-not (Test-Path -LiteralPath $uninstallKey)) 'Existing CyberFi installation must never be replaced'
$installation = Assert-Owned (Join-Path $root 'installed') $root
$exe = Join-Path $installation 'CyberFi.exe'
$ownedHome = Assert-Owned (Join-Path $root 'home') $root
# NSIS relaunch has no user-data-dir argument; use its real default on the disposable runner.
$userData = Assert-Owned (Join-Path $env:APPDATA 'CyberFi') $env:APPDATA
Assert-True (-not (Test-Path -LiteralPath $userData)) 'Runner CyberFi profile must start empty'
$happy = Join-Path $ownedHome '.happy'
New-Item -ItemType Directory -Path $ownedHome, $userData, $happy -Force | Out-Null

function Assert-Signature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    Assert-True ($signature.SignerCertificate.Thumbprint -ceq $certificateThumbprint -and
        $signature.Status -in @('Valid', 'NotTrusted', 'UnknownError')) "Unexpected or invalid signature on $Path ($($signature.Status))"
    $signature
}
function Assert-Installed([string]$Version) {
    Assert-True (Test-Path -LiteralPath $exe) 'Installed executable missing'
    Assert-True ((Get-Item -LiteralPath $exe).VersionInfo.ProductVersion -eq "$Version.0") 'Installed PE version mismatch'
    Assert-True ((Assert-Signature $exe).Status -eq 'Valid') 'Installed app must have a valid trusted pinned signature before launch'
    $registry = Get-ItemProperty -LiteralPath $uninstallKey
    Assert-True ($registry.DisplayVersion -eq $Version -and $registry.UninstallString.Contains($installation)) 'Installer registry points elsewhere'
    [ordered]@{ version = $Version; executable = $exe; sha256 = (Get-FileHash $exe -Algorithm SHA256).Hash; registryVersion = $registry.DisplayVersion }
}
function Assert-Smoke([string]$Path) {
    Assert-True (Test-Path -LiteralPath $Path) "Packaged app did not write $Path"
    $report = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    Assert-True ($report.packaged -and $report.platform -eq 'win32' -and $report.arch -eq 'x64' -and
        $report.welcomeVisible -and $report.windowTitle -eq 'CyberFi' -and $report.screenshotWritten -and
        $report.hiddenMode -and -not $report.focusedWindow -and
        @($report.windows | Where-Object { $_.visible -or $_.focused }).Count -eq 0) 'Packaged hidden smoke failed'
}

$installers = @{}
foreach ($version in @('0.0.113', '0.0.114')) {
    $release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/tags/v$version" -Headers @{ Accept = 'application/vnd.github+json' } -TimeoutSec 30
    Assert-True (-not $release.draft -and $release.tag_name -ceq "v$version") 'Expected an actual published release'
    $release | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath (Join-Path $evidence "release-$version.json") -Encoding utf8
    $name = "CyberFi-$version-x64.exe"
    $asset = @($release.assets | Where-Object { $_.name -ceq $name })
    Assert-True ($asset.Count -eq 1 -and $asset[0].state -eq 'uploaded' -and
        $asset[0].digest -ceq "sha256:$($expected[$version])") 'Immutable installer asset mismatch'
    $path = Join-Path $root $name
    Receive-PublishedAsset "https://github.com/$repo/releases/download/v$version/$name" $path
    Assert-True ((Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $expected[$version]) 'Downloaded installer digest mismatch'
    foreach ($suffix in @('.sha256', '.update.json')) {
        $metadata = @($release.assets | Where-Object { $_.name -ceq "$name$suffix" })
        Assert-True ($metadata.Count -eq 1 -and $metadata[0].state -eq 'uploaded') 'Missing release verification asset'
        $sidecar = "$path$suffix"
        Receive-PublishedAsset "https://github.com/$repo/releases/download/v$version/$name$suffix" $sidecar
        Assert-True ("sha256:$((Get-FileHash $sidecar -Algorithm SHA256).Hash.ToLowerInvariant())" -ceq $metadata[0].digest) 'Verification asset digest mismatch'
    }
    Assert-True ((Get-Content "$path.sha256" -Raw).Split()[0] -ceq $expected[$version]) 'Published SHA256 sidecar mismatch'
    $manifest = Get-Content "$path.update.json" -Raw | ConvertFrom-Json
    Assert-True ($manifest.sha256 -ceq $expected[$version] -and $manifest.size -eq (Get-Item $path).Length) 'Manifest digest/size mismatch'
    $signature = Assert-Signature $path
    $publicKey = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($signature.SignerCertificate)
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes("$version`n$name`n$($manifest.sha256)`n$($manifest.size)`n")
        Assert-True ($publicKey.VerifyData($payload, [Convert]::FromBase64String($manifest.signature),
            [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)) 'Signed update manifest failed verification'
    } finally { $publicKey.Dispose() }
    # Trust only the pinned public local-signing certificate in this ephemeral runner.
    $cer = Join-Path $root 'pinned-signer.cer'
    [IO.File]::WriteAllBytes($cer, $signature.SignerCertificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    Import-Certificate -FilePath $cer -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
    Assert-True ((Get-AuthenticodeSignature $path).Status -eq 'Valid') 'Pinned Authenticode signature did not validate'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence "manifest-$version.json") -Encoding utf8
    $installers[$version] = $path
}

# No token is inherited by the installer or its automatically relaunched app.
foreach ($name in @((Get-ChildItem Env: | Where-Object { $_.Name -match 'TOKEN|SECRET|PASSWORD|CREDENTIAL' }).Name) + @('HAPPY_AGENT_SERVER_SOCKET_PATH')) {
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}
$env:HAPPY_DESKTOP_WINDOWS_HIDDEN = '1'
$env:HAPPY_HOME_DIR = $happy
$env:HOME = $ownedHome
$env:USERPROFILE = $ownedHome
$env:HAPPY_DESKTOP_SMOKE_REPORT = Join-Path $evidence 'fresh-113.json'
$env:HAPPY_DESKTOP_SMOKE_SCREENSHOT = Join-Path $evidence 'fresh-113.png'
$fresh = Start-Process -FilePath $installers['0.0.113'] -ArgumentList "/S /D=$installation" -WindowStyle Hidden -PassThru
Assert-True ($fresh.WaitForExit(180000) -and $fresh.ExitCode -eq 0) 'Fresh 113 installation failed'
$before = Assert-Installed '0.0.113'
@'
import assert from 'node:assert/strict';
import { gymElectronProcessRun } from './packages/happy-desktop-gym/sources/electron/launch.ts';
const result = await gymElectronProcessRun({ executablePath: process.env.ACCEPTANCE_EXE,
    args: [`--user-data-dir=${process.env.ACCEPTANCE_USER_DATA}`], env: process.env, timeout: 120000 });
assert.equal(result.exitCode, 0, result.output);
'@ | Set-Content -LiteralPath (Join-Path $UpstreamPath 'acceptance-smoke.mjs') -Encoding utf8
$env:ACCEPTANCE_EXE = $exe
$env:ACCEPTANCE_USER_DATA = $userData
Push-Location $UpstreamPath
try { & node --import tsx acceptance-smoke.mjs; Assert-True ($LASTEXITCODE -eq 0) 'Fresh 113 app launch failed' }
finally { Pop-Location }
Assert-Smoke $env:HAPPY_DESKTOP_SMOKE_REPORT

# Save actual initialized settings plus disabled catalogue entries and a profile marker.
$settings = Join-Path $userData 'desktop/config.json'
Assert-True (Test-Path -LiteralPath $settings) 'Fresh app did not initialize settings in owned profile'
$mcp = Join-Path $ownedHome 'happy/config/mcp.toml'
$skill = Join-Path $ownedHome '.agents/skills/acceptance-sentinel/SKILL.md'
New-Item -ItemType Directory -Path (Split-Path $mcp), (Split-Path $skill) -Force | Out-Null
"[mcp_servers.acceptance_sentinel]`nenabled = false`ncommand = 'node'`nargs = ['--version']`n" | Set-Content $mcp -Encoding utf8
"---`nname: acceptance-sentinel`ndescription: Installer preservation marker`n---`nPreserve this file.`n" | Set-Content $skill -Encoding utf8
$marker = Join-Path $userData 'acceptance-sentinel.txt'
'113 settings and catalogue belong to this disposable profile' | Set-Content $marker -Encoding utf8
$preserve = @($settings, $mcp, $skill, $marker)
$hashes = @{}
foreach ($path in $preserve) { $hashes[$path] = (Get-FileHash $path -Algorithm SHA256).Hash }
$hashes | ConvertTo-Json | Set-Content (Join-Path $evidence 'preserved-before.json') -Encoding utf8

$env:HAPPY_DESKTOP_SMOKE_REPORT = Join-Path $evidence 'automatic-relaunch-114.json'
$env:HAPPY_DESKTOP_SMOKE_SCREENSHOT = Join-Path $evidence 'automatic-relaunch-114.png'
$started = Get-Date
# These are the production updater's exact NSIS arguments; no manual 114 app launch follows.
$upgrade = Start-Process -FilePath $installers['0.0.114'] -ArgumentList '--updated /S --force-run' -WindowStyle Hidden -PassThru
Assert-True ($upgrade.WaitForExit(180000) -and $upgrade.ExitCode -eq 0) 'Silent 114 upgrade failed'
$deadline = (Get-Date).AddSeconds(120)
while (-not (Test-Path -LiteralPath $env:HAPPY_DESKTOP_SMOKE_REPORT) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
Assert-Smoke $env:HAPPY_DESKTOP_SMOKE_REPORT
do {
    $running = @(Get-Process -Name CyberFi -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $exe })
    if ($running.Count) { Start-Sleep -Milliseconds 250 }
} while ($running.Count -and (Get-Date) -lt $deadline)
Assert-True ($running.Count -eq 0) 'Automatically relaunched app did not finish its smoke and flush settings'
$after = Assert-Installed '0.0.114'
foreach ($path in $preserve) {
    Assert-True ((Get-FileHash $path -Algorithm SHA256).Hash -ceq $hashes[$path]) "Settings/catalogue changed during upgrade: $path"
}
Assert-True ((Get-Item $env:HAPPY_DESKTOP_SMOKE_REPORT).LastWriteTime -ge $started) 'Stale relaunch evidence'
[ordered]@{ status = 'PASS'; fresh = $before; upgraded = $after; automaticRelaunch = $true;
    hiddenWindowsVerified = $true; preservedFiles = $preserve; installerArguments = '--updated /S --force-run';
    applicationUpdaterDownloadUiTested = $false; note = 'Released installer path tested; app download/button/feed path is a separate test.'
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'result.json') -Encoding utf8
'Real released 113 install -> 114 silent upgrade and automatic hidden relaunch passed.'
