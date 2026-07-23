<#
Purpose: Collect current Windows service, Registry, HTTP.sys, socket, and Defender evidence.
Safety: Read-only collection after an authorized isolated run; does not launch or control the sample.
Inputs: -OutputDirectory PATH [-InstallerArtifactDirectory PATH] [-Force]
Outputs: Deterministic UTF-8 text files and SHA-256 manifest in OutputDirectory.
Author: James Banday
Date: 2026-07-22
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter()]
    [string]$InstallerArtifactDirectory,

    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'MSExchangeService'

function Write-EvidenceFile {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content
    )
    $Path = Join-Path -Path $OutputDirectory -ChildPath $Name
    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "Output exists; use -Force to replace it: $Path"
    }
    $Content | Set-Content -LiteralPath $Path -Encoding UTF8 -Force:$Force
}

function Invoke-ReadOnlyNative {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $Text = & netsh.exe @Arguments 2>&1 | Out-String
    return "Command: netsh.exe $($Arguments -join ' ')`r`nExitCode: $LASTEXITCODE`r`n$Text"
}

try {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    Write-EvidenceFile -Name 'network_adapter_state.txt' -Content (
        Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed |
            Format-List | Out-String
    )

    Write-EvidenceFile -Name 'msexchangeservice_state.txt' -Content (
        Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" |
            Select-Object Name, DisplayName, State, StartMode, StartName, ServiceType, PathName |
            Format-List | Out-String
    )

    $ServiceKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $EventSourceKey = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\$ServiceName"
    Write-EvidenceFile -Name 'msexchangeservice_registry.txt' -Content (
        if (Test-Path -LiteralPath $ServiceKey) {
            Get-ItemProperty -LiteralPath $ServiceKey | Format-List * | Out-String
        } else {
            "NOT FOUND: $ServiceKey"
        }
    )
    Write-EvidenceFile -Name 'msexchangeservice_eventlog_source.txt' -Content (
        if (Test-Path -LiteralPath $EventSourceKey) {
            Get-ItemProperty -LiteralPath $EventSourceKey | Format-List * | Out-String
        } else {
            "NOT FOUND: $EventSourceKey"
        }
    )

    $ZoneMapKey = 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
    Write-EvidenceFile -Name 'zonemap_registry_state.txt' -Content (
        if (Test-Path -LiteralPath $ZoneMapKey) {
            Get-ItemProperty -LiteralPath $ZoneMapKey |
                Select-Object AutoDetect, IntranetName, ProxyBypass, UNCAsIntranet |
                Format-List | Out-String
        } else {
            "NOT FOUND: $ZoneMapKey"
        }
    )

    Write-EvidenceFile -Name 'http_sys_service_state.txt' -Content (
        Invoke-ReadOnlyNative -Arguments @('http', 'show', 'servicestate', 'view=requestq', 'verbose=yes')
    )
    Write-EvidenceFile -Name 'http_sys_url_acls.txt' -Content (
        Invoke-ReadOnlyNative -Arguments @('http', 'show', 'urlacl')
    )
    Write-EvidenceFile -Name 'http_sys_ssl_bindings.txt' -Content (
        Invoke-ReadOnlyNative -Arguments @('http', 'show', 'sslcert')
    )
    Write-EvidenceFile -Name 'tcp_443_state.txt' -Content (
        Get-NetTCPConnection -LocalPort 443 -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
            Sort-Object LocalAddress, State |
            Format-Table -AutoSize | Out-String
    )

    Write-EvidenceFile -Name 'defender_threat_state.txt' -Content (
        if (Get-Command Get-MpThreat -ErrorAction SilentlyContinue) {
            Get-MpThreat | Format-List * | Out-String
        } else {
            'UNAVAILABLE: Get-MpThreat is not installed on this system.'
        }
    )
    Write-EvidenceFile -Name 'defender_detection_history.txt' -Content (
        if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
            Get-MpThreatDetection | Format-List * | Out-String
        } else {
            'UNAVAILABLE: Get-MpThreatDetection is not installed on this system.'
        }
    )

    if ($InstallerArtifactDirectory) {
        if (-not (Test-Path -LiteralPath $InstallerArtifactDirectory -PathType Container)) {
            throw "Installer artifact directory does not exist: $InstallerArtifactDirectory"
        }
        Write-EvidenceFile -Name 'installer_artifact_inventory.txt' -Content (
            Get-ChildItem -LiteralPath $InstallerArtifactDirectory -File |
                Where-Object { $_.Name -in @('InstallUtil.InstallLog', 'Microsoft.Exchange.Service.InstallLog', 'Microsoft.Exchange.Service.InstallState') } |
                Select-Object Name, Length, CreationTimeUtc, LastWriteTimeUtc,
                    @{Name = 'SHA256'; Expression = { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash } } |
                Format-Table -AutoSize | Out-String
        )
    }

    $ManifestPath = Join-Path $OutputDirectory 'collection_sha256_manifest.txt'
    if ((Test-Path -LiteralPath $ManifestPath) -and -not $Force) {
        throw "Output exists; use -Force to replace it: $ManifestPath"
    }
    Get-ChildItem -LiteralPath $OutputDirectory -File |
        Where-Object Name -ne 'collection_sha256_manifest.txt' |
        Sort-Object Name |
        ForEach-Object {
            $Hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$Hash  $($_.Name)"
        } | Set-Content -LiteralPath $ManifestPath -Encoding UTF8 -Force:$Force

    Write-Host "Evidence collected without executing the sample: $OutputDirectory"
    exit 0
} catch {
    Write-Error "Dynamic evidence collection failed: $($_.Exception.Message)"
    exit 1
}
