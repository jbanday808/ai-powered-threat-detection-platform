# Turla Neuron Threat-Hunting Queries

## Query Safety

- All commands are read-only.
- No command executes the malware.
- No command starts, stops, installs, or removes the suspicious service.
- No command changes Registry values or network state.
- No request is sent to `/ews/exchange/`.
- Protocol terms below are search strings for existing telemetry, not generated messages.
- Replace placeholders only with authorized scope and time boundaries.

Field names are vendor-neutral examples. Map them to the local schema and record those mappings with the hunt.

## Exact File Hunt

```text
file.sha256 == "d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29"
AND host.id IN <HOST_SCOPE>
AND event.time BETWEEN <HUNT_START_TIME> AND <HUNT_END_TIME>
```

Collect path, signer, size, first/last seen, host role, and detection provenance. Treat an exact match outside an authorized laboratory or evidence repository as critical.

## Filename Hunt

```text
file.name == "Microsoft.Exchange.Service.exe"
OR process.name == "Microsoft.Exchange.Service.exe"
```

The filename is supporting evidence. Correlate it with hash, service, signer, path, and host role.

## Service Installation Hunt

```text
event.id == 7045
AND service.name == "MSExchangeService"
AND service.image_path CONTAINS "Microsoft.Exchange.Service.exe"
```

Optional supporting fields:

```text
service.display_name CONTAINS "Microsoft Exchange Service"
OR service.account == "LocalSystem"
OR service.start_type IN ("auto", "automatic", 2)
```

This corresponds to the existing [Sigma rule](../sigma/win_system_turla_neuron_service_install.yml). Event ID and field names may differ by parser.

## Exchange-Themed Service Hunt

```text
service.inventory
| WHERE service.name == "MSExchangeService"
   OR service.display_name CONTAINS "Microsoft Exchange"
| JOIN asset_inventory ON host.id
| WHERE asset.role != "approved_exchange_server"
| PROJECT host, service, image_path, signer, start_type, account, asset_role
```

Do not classify Exchange terminology as malicious before asset and software validation.

## Process Tree Hunt

```text
process.name == "Microsoft.Exchange.Service.exe"
AND (
  parent.name == "services.exe"
  OR child.name == "cmd.exe"
)
```

Higher-confidence correlation:

```text
process.name == "Microsoft.Exchange.Service.exe"
AND child.name == "cmd.exe"
AND (
  process.sha256 == "<KNOWN_SHA256>"
  OR service.name == "MSExchangeService"
)
```

`services.exe` starting a service is normal. The suspicious child shell, file identity, and service context provide the detection value.

## Service Registry Hunt

```text
registry.path == "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MSExchangeService"
AND (
  registry.value_name IN ("ImagePath", "Start", "Type", "ObjectName", "DisplayName")
  OR registry.data CONTAINS "Microsoft.Exchange.Service.exe"
)
```

Current-state PowerShell:

```powershell
$key = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSExchangeService'
if (Test-Path -LiteralPath $key) {
    Get-ItemProperty -LiteralPath $key |
        Select-Object ImagePath, Start, Type, ObjectName, DisplayName, Description
}
```

## Event Log Source Hunt

```text
registry.path == "HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\MSExchangeService"
```

Current-state PowerShell:

```powershell
$key = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\MSExchangeService'
if (Test-Path -LiteralPath $key) {
    Get-ItemProperty -LiteralPath $key
}
```

Source registration is medium-confidence unless correlated with the suspicious service or executable.

## HTTP.sys Listener Hunt

Vendor-neutral logic:

```text
http_sys.registered_url CONTAINS "/ews/exchange/"
AND (
  http_sys.service == "MSExchangeService"
  OR http_sys.process_image ENDSWITH "\\Microsoft.Exchange.Service.exe"
)
```

Read-only local inspection:

```powershell
netsh.exe http show servicestate view=requestq verbose=yes
Get-NetTCPConnection -State Listen -LocalPort 443 |
    Select-Object LocalAddress, LocalPort, State, OwningProcess
```

Review output; do not send a request. PID 4/System can own HTTP.sys sockets and is not the malware.

## Temporary Storage Hunt

Vendor-neutral logic:

```text
directory.path MATCHES "^C:\\\\Windows\\\\Temp\\\\\\{[0-9A-Fa-f-]{36}\\}$"
AND (
  creator.process_name == "Microsoft.Exchange.Service.exe"
  OR related.service == "MSExchangeService"
  OR child.file_name ENDSWITH ".TMP"
  OR child.content CONTAINS_ANY ("MSXEWS", "TVNYRVdT")
)
```

Read-only current-state PowerShell:

```powershell
Get-ChildItem -LiteralPath 'C:\Windows\Temp' -Directory -ErrorAction SilentlyContinue |
    Where-Object Name -Match '^\{[0-9A-Fa-f-]{36}\}$' |
    Select-Object FullName, CreationTimeUtc, LastWriteTimeUtc,
        @{Name='Owner';Expression={(Get-Acl -LiteralPath $_.FullName).Owner}}
```

Do not treat a GUID directory as malicious without creator, service, content, or timing correlation.

## Defender History Hunt

Vendor-neutral logic:

```text
antivirus.threat_name == "Trojan:MSIL/DarkNeuron.B!dha"
OR antivirus.threat_id == 2147724727
```

Read-only PowerShell:

```powershell
Get-MpThreat |
    Where-Object {
        $_.ThreatName -eq 'Trojan:MSIL/DarkNeuron.B!dha' -or
        $_.ThreatID -eq 2147724727
    } |
    Select-Object ThreatName, ThreatID, IsActive, DidThreatExecute, Resources

Get-MpThreatDetection |
    Where-Object ThreatID -eq 2147724727 |
    Select-Object ThreatID, ActionSuccess, ThreatStatusErrorCode, Resources, InitialDetectionTime
```

Interpret current and historical records separately.

## Installer Artifact Hunt

```text
file.name IN (
  "InstallUtil.InstallLog",
  "Microsoft.Exchange.Service.InstallLog",
  "Microsoft.Exchange.Service.InstallState"
)
AND (
  creator.process_name == "Microsoft.Exchange.Service.exe"
  OR related.service == "MSExchangeService"
  OR temporal_distance(service_installation) <= <CORRELATION_WINDOW>
)
```

These files also occur during legitimate .NET installation.

## ZoneMap Supporting Hunt

```text
process.name == "Microsoft.Exchange.Service.exe"
AND registry.path ENDSWITH "\\Internet Settings\\ZoneMap"
AND registry.value_name IN ("AutoDetect", "IntranetName", "ProxyBypass", "UNCAsIntranet")
```

Use this only to strengthen an existing finding. The Registry values alone are broad context.

## Protocol Artifact Hunt

Search existing endpoint strings, memory results, application logs, or decrypted proxy/reverse-proxy telemetry:

```text
artifact CONTAINS_AT_LEAST 2 OF (
  "cid",
  "cadataKey",
  "cadata",
  "cadataSig"
)
AND artifact CONTAINS_ANY (
  "f2949bab-240a-46ca-a455-6f504367ba7d",
  "8d963325-01b8-4671-8e82-d0904275ab06"
)
```

The common field `cid` is weak alone. No on-wire payload was captured, and this query does not create or transmit one.

## YARA File Hunt

Use the existing [YARA rule](../yara/turla_neuron_v2.yar) through an approved file-scanning platform:

```text
rule.name IN ("Turla_Neuron_Exact", "Turla_Neuron_Behavior")
AND host.id IN <HOST_SCOPE>
```

Record whether the match came from the exact or behavioral rule, the scanned path, file hash, scan time, and authorization context. YARA scans file content and does not execute it.

## Multi-Indicator Correlation

```text
GROUP evidence BY host.id WITHIN <CORRELATION_WINDOW>
SCORE:
  exact_sha256 = 100
  active_defender_darkneuron = 80
  service_name = 40
  filename = 40
  ews_queue_non_exchange_host = 40
  service_launches_cmd = 30
  known_guid = 25
  multiple_protocol_fields = 25
  local_system = 10
  automatic_startup = 10
  event_log_source = 10
  installer_artifacts = 10
  authorized_lab = -100
  verified_legitimate_exchange = -80
  historical_inactive_only = -40
```

Return the score, every contributing factor, data-source coverage, and missing telemetry. Do not return a final disposition without analyst validation.

## Read-Only Host Triage Summary

The following commands collect current state and do not modify the endpoint:

```powershell
Get-CimInstance Win32_Service -Filter "Name='MSExchangeService'" |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName

Get-ItemProperty -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSExchangeService' `
    -ErrorAction SilentlyContinue

netsh.exe http show servicestate view=requestq verbose=yes

Get-MpThreat | Where-Object {
    $_.ThreatName -eq 'Trojan:MSIL/DarkNeuron.B!dha' -or
    $_.ThreatID -eq 2147724727
}
```

Preserve output and hashes through the approved evidence process before containment.

## Recording Results

Use [turla_neuron_hunt_tracker.csv](turla_neuron_hunt_tracker.csv). Do not replace blank result fields with assumptions. Record:

- Actual host/time scope
- Data sources queried
- Query version
- Coverage gaps
- Count of returned records
- Analyst-validated findings
- False-positive explanation
- Outcome and escalation reference

## Query Limitations

- No production queries were executed for this package.
- No Sysmon schema or event results are assumed.
- No packet capture or Suricata alert exists.
- HTTPS fields may require endpoint, TLS-inspection, or reverse-proxy visibility.
- Current-state commands cannot reconstruct deleted historical artifacts.
- Platform field mappings must be tested locally.
