# Turla Neuron / DarkNeuron Dynamic Analysis

## Analysis Overview

Dynamic analysis observes what a suspicious program does while it runs in a controlled environment. During this test, Turla Neuron installed itself as a Windows service, created persistence-related artifacts, opened a local HTTPS listener, and created a computer-specific storage directory.

| Field | Value |
|---|---|
| Incident ID | MAL-2026-0721-NEURON |
| Sample | Microsoft.Exchange.Service.exe |
| SHA-256 | d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29 |
| Execution argument | `-install` |
| Environment | Isolated Windows VM |
| Network state | Disabled |
| Monitoring | Noriben, Procmon, PowerShell, HTTP.sys and Registry inspection |
| Analysis date | 2026-07-22 |
| Analyst | James Banday |

The analysis classification is controlled dynamic malware analysis. Detailed tool-specific findings remain in the [Noriben package](../noriben/turla_neuron_noriben_analysis.md), [dnSpy package](../dnspy/turla_neuron_dnspy_analysis.md), and [static-analysis package](../static/turla_neuron_static_analysis.md).

## Scope and Safety Controls

A VMware snapshot was created before execution, and the Windows network adapter was disabled. The disposable analysis VM had no unrestricted Internet access and contained no production credentials, systems, or data. Administrative PowerShell, Noriben, and Procmon were used for controlled observation. A harmless Noriben baseline was completed before the sample was intentionally run. Evidence was collected before cleanup or snapshot restoration, after which Microsoft Defender and direct service and file checks were used to verify cleanup.

## Pre-Execution Validation

Before execution, the sample SHA-256 matched the known value, the network adapter was disabled, and `MSExchangeService` was absent. Noriben's harmless baseline created `probe.txt`, demonstrated that Procmon launched correctly, and recorded no network traffic. The Procmon binaries were recorded as having valid Microsoft signatures. These baseline facts are supporting laboratory context; the raw pre-execution service query, signature output, and adapter-state export were not retained as separate repository files.

Baseline activity is not attributed to the malware. Normal events from Windows, Splunk Universal Forwarder, Azure Monitor Agent, Explorer, Python/Noriben, Procmon, and the baseline `cmd.exe` may appear in processed monitoring output.

## Controlled Execution

The analyzed command was:

```text
C:\Malware\TurlaNeuron\Microsoft.Exchange.Service.exe -install
```

The execution was intentional and occurred only inside the isolated VM while the network remained disabled. The `-install` argument invoked the program's .NET service installer. No attacker sent commands during the test. `C:\Malware\TurlaNeuron\` was the laboratory location and is not a universal IOC. The available evidence does not support a precise capture duration, so none is asserted here.

## Process and Service Activity

The program installed `MSExchangeService`, used the display name `Microsoft Exchange Service`, and started the service immediately. It was observed running with automatic startup as `LocalSystem`, using the `WIN32_OWN_PROCESS` service type. The executable path in this VM was `C:\Malware\TurlaNeuron\Microsoft.Exchange.Service.exe`; another affected host could use a different directory. Windows Service Control Manager activity is normally hosted by `services.exe`.

In plain language, the malware registered itself as a highly privileged Windows background service and started running immediately. Process IDs are temporary laboratory evidence and must not be treated as universal IOCs.

## Installer Activity

The processed Noriben timeline and installer evidence record:

- `InstallUtil.InstallLog`
- `Microsoft.Exchange.Service.InstallLog`
- `Microsoft.Exchange.Service.InstallState`
- `Installing service MSExchangeService`
- `Service MSExchangeService has been successfully installed`
- `Creating EventLog source MSExchangeService in log Application`
- `Committing assembly`

These are normal-looking .NET installation records created while the malicious service was being registered. The filenames can also occur during legitimate .NET service installation, so they require correlation with the service name, executable, and other evidence.

## Service Registry Persistence

Windows Registry evidence confirms:

```text
HKLM\SYSTEM\CurrentControlSet\Services\MSExchangeService
```

| Value | Observed data | Meaning |
|---|---|---|
| Type | 16 | Dedicated service process (`WIN32_OWN_PROCESS`) |
| Start | 2 | Automatic startup |
| ErrorControl | 1 | Normal service-start error handling |
| ImagePath | `C:\Malware\TurlaNeuron\Microsoft.Exchange.Service.exe` | Laboratory executable location |
| DisplayName | Microsoft Exchange Service | Exchange-themed masquerading |
| ObjectName | LocalSystem | Highly privileged service account |
| DelayedAutoStart | 0 | Normal automatic rather than delayed startup |

This persistence was observed dynamically and confirmed by a Windows Registry artifact. The Exchange-themed name and description gave the service a legitimate appearance, but the exact laboratory path is environmental.

## Event Log Source Registration

The installer created:

```text
HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\MSExchangeService
```

The configured `EventMessageFile` was:

```text
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll
```

In plain language, the installer registered a source that could be used to write messages into the Windows Application log. The source registration is confirmed; no matching `MSExchangeService` Application events were found, so the evidence does not show that the malware actually wrote Event Log messages.

## HTTP.sys Listener

HTTP.sys service-state output confirmed the runtime registration:

```text
HTTPS://*:443/EWS/EXCHANGE/
```

The request queue was active, was associated with `MSExchangeService` and `Microsoft.Exchange.Service.exe`, contained one registered URL, and had one attached process. Its counters showed zero arrived requests and zero rejected requests.

In plain language, the malware opened a hidden local web address and waited for specially formatted instructions. Because the test system was disconnected from the network, no requests arrived.

HTTP.sys managed the kernel listener, so port 443 could appear under PID 4/System even though the request queue was attached to the Turla Neuron service. PID 4 is not the malware process and is not an IOC. No inbound request, successful C2 communication, external C2 IP or domain, SSL certificate binding for `0.0.0.0:443`, or Neuron-specific persistent URL ACL was observed. Runtime queue registration is different from a persistent URL reservation.

## Host-Specific Storage Directory

Direct inspection found:

```text
C:\Windows\Temp\{433532c3-7ccc-4378-8462-ffd9d5838324}
```

The directory was created at approximately 2026-07-22 09:43:46 in the laboratory. The service ran as `LocalSystem`, whose temporary directory was under `C:\Windows\Temp`, and the folder name was derived from the host MachineGuid. It was empty when inspected; no task or response files were observed.

The general hunting pattern is:

```text
C:\Windows\Temp\{GUID}
```

The exact laboratory MachineGuid is environmental and must not be promoted as a universal IOC.

## ZoneMap Registry Activity

The monitored installer activity wrote values under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap
```

| Value | Data |
|---|---:|
| AutoDetect | 0 |
| IntranetName | 1 |
| ProxyBypass | 1 |
| UNCAsIntranet | 1 |

These settings affect how Windows classifies local and network locations. They can also be configured legitimately and are supporting behavior, not high-confidence standalone IOCs. Because no pre-execution Registry export was retained, the evidence establishes that the executable wrote the values but cannot prove whether it changed them from different data or rewrote existing values.

## Noriben Timeline Findings

The filtered Noriben timeline associates `Microsoft.Exchange.Service.exe` with `InstallUtil.InstallLog`, `Microsoft.Exchange.Service.InstallLog`, `Microsoft.Exchange.Service.InstallState`, and the four ZoneMap values. This processed timeline supports the installation sequence but does not replace a usable raw Procmon capture. Further source and background-noise details are in the [Noriben dynamic-analysis package](../noriben/turla_neuron_noriben_analysis.md).

## Network Activity

The network adapter was disabled. The processed Noriben account records no external network traffic or unique remote hosts, while separate HTTP.sys evidence confirms only a local listening capability. No external destination was contacted, no remote instruction was received, and no C2 IP address, C2 domain, data transfer, or exfiltration was observed. An active local listener and external communication are separate findings.

## Raw Procmon Evidence Limitation

The retained malware-run PML was reported as approximately 976 bytes. Re-export produced an approximately 124-byte CSV containing zero events. It was therefore not usable as primary event evidence.

The retained PML appeared empty, truncated, or overwritten. The exact failure mechanism could not be proven from the remaining evidence. Conclusions instead rely on processed Noriben output, the timeline, installer evidence, Registry and HTTP.sys observations, service queries, screenshots, Defender records, and direct observations. The unusable PML is not described as successful raw evidence preservation.

## Defender Detection and Remediation

Microsoft Defender classified the file as `Trojan:MSIL/DarkNeuron.B!dha`, Threat ID `2147724727`. Defender records show `ActionSuccess=True` and `ThreatStatusErrorCode=0`; the Windows copy was quarantined or removed, while historical threat records remained visible.

In plain language, Defender successfully isolated the file. The retained history shows where and when detection occurred but does not mean the malware remained active. Random Defender quarantine names and `C:\$Recycle.Bin` locations are temporary security-product artifacts, not Turla Neuron IOCs.

## Cleanup Verification

After remediation, `Test-Path` returned `False` for the sample, `MSExchangeService` was absent, and Defender reported `IsActive=False`. A final targeted scan showed no currently affected resources.

The `DidThreatExecute=False` field belongs to the restored or cleaned Defender record. It does not contradict the earlier intentional execution in the isolated snapshot. The post-cleanup system no longer contained the active service or sample, while historical Defender records remained available as evidence.

## Static-to-Dynamic Correlation

| Static finding | Dynamic evidence | Status |
|---|---|---|
| Built-in service installer | Installer log and service artifacts | confirmed_dynamically |
| Immediate service start | Running service and active HTTP.sys queue | confirmed_dynamically |
| `MSExchangeService` | Installer, Registry, and HTTP.sys evidence | confirmed_dynamically |
| Microsoft Exchange Service display name | Service Registry export | confirmed_dynamically |
| Automatic startup | `Start=2` | confirmed_dynamically |
| LocalSystem account | `ObjectName=LocalSystem` | confirmed_dynamically |
| `/ews/exchange/` listener | Active HTTP.sys queue | confirmed_dynamically |
| MachineGuid-based storage | Empty host-specific directory | confirmed_dynamically |
| Installer artifacts | Noriben timeline and installer log | confirmed_dynamically |
| Event Log source | Application source Registry key | confirmed_dynamically |
| ZoneMap writes | Filtered Noriben timeline | supporting_evidence |
| Hidden command-shell capability | dnSpy code only; no remote command received | confirmed_statically_only |
| File read/write capability | dnSpy code only | not_exercised |
| Encrypted Registry configuration | dnSpy code only | confirmed_statically_only |

## Detection Engineering Value

### Sigma

The dynamic findings support monitoring Windows System Event ID 7045 for `ServiceName=MSExchangeService` with an `ImagePath` containing `Microsoft.Exchange.Service.exe`. `LocalSystem` and automatic startup are useful supporting context. The repository rule is [win_system_turla_neuron_service_install.yml](../../detections/sigma/win_system_turla_neuron_service_install.yml).

### Splunk and Sysmon

Recommended correlations include service installation, creation of the service Registry key, `Microsoft.Exchange.Service.exe` launched through service management, `cmd.exe` spawned by an unexpected service, new automatic LocalSystem services in uncommon paths, ZoneMap writes by the same executable, and Event Log source creation. These are investigation recommendations, not claims that every data source was validated in this run.

### Network and HTTP.sys

Hunt for `/ews/exchange/` on non-Exchange hosts, new HTTP.sys request queues on port 443, unexpected workstation or server HTTPS listeners, and request fields `cid`, `cadataKey`, `cadata`, and `cadataSig` where visibility allows. Port 443 alone is too broad.

### YARA

The runtime evidence supports the significance of `MSExchangeService`, `Microsoft.Exchange.Service.exe`, `/ews/exchange/`, embedded GUIDs, and command-channel strings in the [YARA rule](../../detections/yara/turla_neuron_v2.yar). YARA scanning identifies file content and does not execute the sample.

## MITRE ATT&CK Mapping

| Technique | ID | Dynamic evidence | Classification |
|---|---|---|---|
| Windows Service | T1543.003 | Service installation and automatic LocalSystem persistence | observed_dynamically |
| Modify Registry | T1112 | Service, Event Log source, and ZoneMap Registry artifacts | observed_dynamically |
| Web Protocols | T1071.001 | Active local HTTPS listener; no inbound traffic | observed_dynamically |
| Windows Command Shell | T1059.003 | Command execution exists in decompiled code only | capability_only |
| Encrypted Channel | T1573 | Encrypted protocol logic exists in decompiled code only | corroborated_by_static_analysis |
| Ingress Tool Transfer | T1105 | File-write capability exists in decompiled code only | capability_only |
| Deobfuscate/Decode Files or Information | T1140 | Decoding and decryption logic exists in decompiled code only | corroborated_by_static_analysis |

Capability-only techniques are not presented as attacker actions observed during the run.

## Key Findings

- The sample successfully installed and started `MSExchangeService`.
- The service ran as `LocalSystem` and was configured for automatic startup.
- The Exchange-themed display name and description supported masquerading.
- An active HTTP.sys listener registered `/ews/exchange/`.
- A MachineGuid-based storage directory was created and remained empty.
- ZoneMap writes, installer artifacts, and an Event Log source were recorded.
- No external communication or attacker request was observed.
- The retained raw PML was unusable, but processed and direct evidence remained.
- Defender remediated the sample, and final checks found no active service or threat.

## Not Observed

The controlled run did not observe:

- External C2 connection
- External C2 IP address
- External C2 domain
- Inbound attacker request
- Remote attacker command execution
- File upload command
- File download command
- Data exfiltration
- Lateral movement
- Production-system impact

## Evidence Limitations

- No usable raw malware-run PML remained.
- No external attacker requests or C2 infrastructure were observed.
- No remote command execution or file-transfer command was exercised.
- No data exfiltration occurred.
- The host-specific directory was empty.
- No hidden encrypted malware configuration was confirmed dynamically.
- The ZoneMap pre-execution baseline was unavailable.
- Process IDs, the MachineGuid, paths, and timestamps are laboratory-specific.
- Dynamic findings apply to this controlled run and may not represent every capability.
- No separate network or Sysmon evidence package was present in the repository.

## Screenshot Evidence

### Evidence: Pre-execution VMware snapshot

![VMware snapshot created before dynamic analysis](../../screenshots/Pre-Noriben_Turla_Neuron_Snapshot.png)

**Plain-language explanation:** The snapshot provided a restore point so the disposable Windows VM could be returned to a clean state after the test.

**Technical finding:** A snapshot named for the pre-Noriben state is visible before controlled execution.

**Evidence limitation:** The image documents the safety control; it does not show malware activity.

### Evidence: ZoneMap Registry writes

![ZoneMap Registry modifications](../../screenshots/TurlaNeuron_22_Dynamic_ZoneMap_Registry_Modifications.png)

**Plain-language explanation:** The installer wrote Windows settings that affect how local and network locations are classified.

**Technical finding:** `AutoDetect=0`, `IntranetName=1`, `ProxyBypass=1`, and `UNCAsIntranet=1` are shown under the ZoneMap key.

**Evidence limitation:** No pre-execution Registry export proves whether the values changed or were rewritten, and the values can be legitimate.

### Evidence: Filtered Noriben activity

![Filtered Noriben timeline activity](../../screenshots/TurlaNeuron_23_Noriben_Filtered_Timeline_Activity.png)

**Plain-language explanation:** The timeline records setup files and Windows settings touched by the installer.

**Technical finding:** Filtered events associate `Microsoft.Exchange.Service.exe` with installer logs, InstallState, and ZoneMap values.

**Evidence limitation:** This is filtered Noriben timeline evidence, not a complete raw Procmon capture.

### Evidence: Host-specific storage directory

![MachineGuid-based LocalSystem storage directory](../../screenshots/TurlaNeuron_24_Dynamic_HostSpecific_SYSTEM_Storage_Directory.png)

**Plain-language explanation:** The service created a computer-specific folder that could differ on every Windows host.

**Technical finding:** The LocalSystem path under `C:\Windows\Temp` used the laboratory MachineGuid and was empty when inspected.

**Evidence limitation:** The exact GUID is environmental; use `C:\Windows\Temp\{GUID}` for hunting.

### Evidence: Active HTTP.sys request queue

![HTTP.sys EWS Exchange URL registration](../../screenshots/TurlaNeuron_25_Dynamic_HTTPsys_EWS_Exchange_URL_Registration.png)

**Plain-language explanation:** The service opened a local web-listening location and waited, but no instructions arrived.

**Technical finding:** An active queue attached to `MSExchangeService` registered `HTTPS://*:443/EWS/EXCHANGE/` with one process and zero arrived or rejected requests.

**Evidence limitation:** No inbound request, external communication, SSL binding, or Neuron-specific persistent URL ACL was observed.

### Evidence: Successful service installation

![Installer log confirming service installation](../../screenshots/TurlaNeuron_26_Dynamic_Installer_Log_Service_Success.png)

**Plain-language explanation:** The installer successfully registered the program to run as a Windows background service.

**Technical finding:** The log records installation of `MSExchangeService`, Event Log source creation, successful installation, and assembly commit.

**Evidence limitation:** The displayed `C:\Malware\TurlaNeuron\` assembly path is laboratory-specific.

### Evidence: Application Event Log source

![MSExchangeService Event Log source](../../screenshots/TurlaNeuron_27_Dynamic_MSExchangeService_EventLog_Source.png)

**Plain-language explanation:** The installer registered a name that could be used to write Application log messages.

**Technical finding:** The `MSExchangeService` source points to the .NET Framework `EventLogMessages.dll`.

**Evidence limitation:** No matching Application messages from this source were found.

### Evidence: Service Registry persistence

![Service Registry persistence](../../screenshots/TurlaNeuron_28_Dynamic_Service_Registry_Persistence.png)

**Plain-language explanation:** Windows was configured to start the fake Exchange service automatically with high privileges.

**Technical finding:** The Registry shows `Type=16`, `Start=2`, `ObjectName=LocalSystem`, the Exchange display name, the executable ImagePath, and `DelayedAutoStart=0`.

**Evidence limitation:** The ImagePath shown is specific to the analysis VM.

### Evidence: Defender quarantine

![Defender quarantine notification](../../screenshots/TurlaNeuron_29_Defender_DarkNeuron_Quarantined_RecycleBin.png)

**Plain-language explanation:** Defender isolated the malicious file so it could no longer run normally.

**Technical finding:** Defender identifies `Trojan:MSIL/DarkNeuron.B!dha` with status `Quarantined`.

**Evidence limitation:** The randomized Recycle Bin filename is a Defender-managed temporary artifact, not a malware IOC.

### Evidence: Defender remediation history

![Defender detection and remediation history](../../screenshots/TurlaNeuron_30_Defender_DarkNeuron_Detection_and_Remediation_History.png)

**Plain-language explanation:** Defender retained a history of the times it found and successfully handled the file.

**Technical finding:** Records show `ActionSuccess=True`, `ThreatStatusErrorCode=0`, and Threat ID `2147724727`.

**Evidence limitation:** Historical entries do not mean the malware remained active, and laboratory paths or SIDs are not universal IOCs.

### Evidence: Inactive cleanup state

![Inactive cleanup verification](../../screenshots/TurlaNeuron_31_Defender_DarkNeuron_Inactive_Cleanup_Verification.png)

**Plain-language explanation:** The file and service were no longer present, and Defender no longer considered the threat active.

**Technical finding:** The image shows `Sample present: False`, no `MSExchangeService` output, and `IsActive: False`.

**Evidence limitation:** `DidThreatExecute=False` describes the cleaned Defender record and does not negate controlled execution in the earlier snapshot.

### Evidence: Final Defender scan

![Final Defender scan](../../screenshots/TurlaNeuron_32_Defender_Final_Scan_Threat_Inactive.png)

**Plain-language explanation:** A final scan found no active malware copy in the former analysis directory.

**Technical finding:** The targeted scan shows `IsActive=False`, `DidThreatExecute=False`, and no currently affected resources.

**Evidence limitation:** Defender historical records remained available and were not claimed to have been erased.
