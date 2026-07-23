<#
Purpose: Verify that a supplied sample path, service, listener association, and active Defender threat are absent.
Safety: Read-only verification; does not delete files, stop services, restore snapshots, or execute the sample.
Inputs: -SamplePath PATH -OutputDirectory PATH [-Force]
Outputs: cleanup_verification.txt and cleanup_verification.json.
Author: James Banday
Date: 2026-07-22
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SamplePath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [Parameter()]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'MSExchangeService'

try {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $TextPath = Join-Path $OutputDirectory 'cleanup_verification.txt'
    $JsonPath = Join-Path $OutputDirectory 'cleanup_verification.json'
    foreach ($Path in @($TextPath, $JsonPath)) {
        if ((Test-Path -LiteralPath $Path) -and -not $Force) {
            throw "Output exists; use -Force to replace it: $Path"
        }
    }

    $SamplePresent = Test-Path -LiteralPath $SamplePath -PathType Leaf
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $ServicePresent = $null -ne $Service
    $ServiceRegistryPresent = Test-Path -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $HttpState = & netsh.exe http show servicestate view=requestq verbose=yes 2>&1 | Out-String
    $ListenerAssociationPresent = $HttpState -match [regex]::Escape($ServiceName)

    $ActiveThreats = @()
    if (Get-Command Get-MpThreat -ErrorAction SilentlyContinue) {
        $ActiveThreats = @(Get-MpThreat | Where-Object { $_.IsActive -eq $true })
    }
    $DarkNeuronActive = @($ActiveThreats | Where-Object {
        $_.ThreatName -eq 'Trojan:MSIL/DarkNeuron.B!dha'
    }).Count -gt 0

    $Passed = -not ($SamplePresent -or $ServicePresent -or $ServiceRegistryPresent -or $ListenerAssociationPresent -or $DarkNeuronActive)
    $Result = [ordered]@{
        checked_at_utc = (Get-Date).ToUniversalTime().ToString('o')
        sample_path = $SamplePath
        sample_present = $SamplePresent
        service_name = $ServiceName
        service_present = $ServicePresent
        service_registry_present = $ServiceRegistryPresent
        http_sys_service_association_present = $ListenerAssociationPresent
        defender_darkneuron_active = $DarkNeuronActive
        passed = $Passed
        note = 'Current-state verification only; historical evidence may remain after cleanup.'
    }

    ($Result.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) |
        Set-Content -LiteralPath $TextPath -Encoding UTF8 -Force:$Force
    $Result | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath $JsonPath -Encoding UTF8 -Force:$Force

    if (-not $Passed) {
        Write-Error "Cleanup verification failed. Review: $TextPath"
        exit 1
    }
    Write-Host "Cleanup verification passed: $TextPath"
    exit 0
} catch {
    Write-Error "Cleanup verification could not complete: $($_.Exception.Message)"
    exit 1
}
