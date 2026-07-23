# Turla Neuron / DarkNeuron Noriben Dynamic Analysis

## Analysis Overview

Noriben records what programs create, change, or access while they run. During this test, it was used to observe how Turla Neuron installed itself as a Windows service and modified the analysis computer.

| Field | Value |
|---|---|
| Sample | `Microsoft.Exchange.Service.exe` |
| SHA-256 | `d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29` |
| Noriben version | 2.0.4 |
| Execution argument | `-install` |
| Network state | Disabled |
| Environment | Isolated Windows VM |
| Analysis classification | Controlled dynamic analysis |

The repository does not retain raw Noriben text, CSV, timeline, log, or PML files. The directly usable Noriben evidence is a screenshot of a filtered timeline. This package therefore separates that timeline from installer logs, Registry exports, HTTP.sys output, direct PowerShell observations, and supplied baseline/PML handling context.

## Scope and Safety Controls

- A VMware snapshot was created before controlled execution.
- The VMware network adapter was disabled.
- No unrestricted Internet connection was available.
- No production credentials or shared production data were used.
- The sample was intentionally executed only inside the isolated VM.
- Evidence was collected before cleanup.
- The service was later removed through snapshot restoration or cleanup.
- Microsoft Defender quarantined or removed the sample.
- Final Defender checks showed the threat inactive and the service absent.
- No production systems were involved.

## Noriben Baseline Validation

**Classification: supporting_context**

The harmless baseline command was:

```text
C:\Windows\System32\cmd.exe /c echo NoribenBaseline>C:\Malware\TurlaNeuron\Dynamic-Analysis\Baseline-Validation\probe.txt
```

The baseline ran for approximately 15–17 seconds. The recorded outcome was:

- Noriben launched Procmon successfully.
- The baseline `cmd.exe` created `probe.txt`.
- Noriben generated text, CSV, timeline, log, and PML artifacts.
- No network traffic was recorded.

Background activity included Splunk Universal Forwarder, Azure Monitor Agent health-monitor, Explorer, Windows servicing, service-host, Python/Noriben, and Procmon activity. These events represent normal laboratory or monitoring noise and are not attributed to Turla Neuron.

**Plain-language explanation:** The baseline test proved the monitoring tool worked before the malware was run. It also showed which normal background events might appear during any capture.

**Evidence limitation:** The baseline raw files are not present in the repository. These facts are preserved as baseline context rather than independently revalidated raw events.

## Controlled Malware Execution

The analyzed command was:

```text
C:\Malware\TurlaNeuron\Microsoft.Exchange.Service.exe -install
```

The execution was intentional, occurred in the isolated snapshot, and took place while the network adapter remained disabled. No attacker interacted with the VM. The exact malware-run capture duration is not retained in a usable repository artifact, so it is recorded as unknown rather than inferred.

The laboratory directory is evidence of this test only and is not a universal IOC.

## Process Activity

**Classification: confirmed_by_noriben and supporting_context**

- The filtered timeline attributes installer-related file and Registry activity to `Microsoft.Exchange.Service.exe`.
- The `-install` command identifies the initial process as the installer invocation.
- Direct service and installer evidence confirms that Windows subsequently installed and started `MSExchangeService`.
- A normal service launch would be managed by the Service Control Manager and `services.exe`, but the missing raw Noriben process tree prevents reconstruction of the complete parent/child sequence from Noriben alone.

The installer process and the running service process are different execution contexts. Temporary process IDs seen in laboratory output are not stable and are not promoted as IOCs.

## File Activity

The filtered Noriben timeline shows `Microsoft.Exchange.Service.exe` associated with:

| File artifact | Classification | Interpretation |
|---|---|---|
| `InstallUtil.InstallLog` | confirmed_by_noriben | General .NET installer log activity |
| `Microsoft.Exchange.Service.InstallLog` | confirmed_by_noriben | Log named for the analyzed assembly |
| `Microsoft.Exchange.Service.InstallState` | confirmed_by_noriben | Installer state used to support rollback or uninstall |

`InstallLog` records .NET installation activity, while `InstallState` stores installer state. These names may also occur during legitimate .NET service installation and are not high-confidence standalone IOCs.

Noriben output files from the original capture are not present under `results/noriben`; they are described in the evidence inventory as absent rather than fabricated.

## Registry Activity

### ZoneMap writes

**Classification: confirmed_by_noriben**

The filtered timeline and Registry screenshot show activity under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap
```

| Value | Observed data |
|---|---:|
| `AutoDetect` | 0 |
| `IntranetName` | 1 |
| `ProxyBypass` | 1 |
| `UNCAsIntranet` | 1 |

**Plain-language explanation:** The installer wrote settings that influence how Windows classifies local and network locations.

These values can be legitimate and are supporting evidence only. Without a pre-execution Registry export, the analysis cannot prove whether the values were newly changed or rewritten with their existing values. Detection should correlate the writes with `Microsoft.Exchange.Service.exe` and the service installation.

### Service Registry evidence

**Classification: confirmed_by_other_dynamic_evidence**

A separate Registry export confirms:

```text
HKLM\SYSTEM\CurrentControlSet\Services\MSExchangeService
```

This source records the service ImagePath, automatic startup, `LocalSystem` account, and dedicated-process type. The filtered Noriben screenshot does not prove that Noriben alone captured every service Registry field.

## Service Installation Artifacts

The timeline and direct Windows evidence correlate as follows:

| Field or event | Value | Evidence source | Classification |
|---|---|---|---|
| Service name | `MSExchangeService` | Installer log and Registry export | confirmed_by_direct_observation |
| Display name | `Microsoft Exchange Service` | Service Registry export | confirmed_by_other_dynamic_evidence |
| Executable | `Microsoft.Exchange.Service.exe` | Noriben timeline, installer log, and Registry export | confirmed_by_noriben |
| Startup type | Automatic (`Start = 2`) | Service Registry export | confirmed_by_other_dynamic_evidence |
| Account | `LocalSystem` | Service Registry export | confirmed_by_other_dynamic_evidence |
| Service type | `WIN32_OWN_PROCESS` (`Type = 16`) | Service Registry export | confirmed_by_other_dynamic_evidence |
| Event Log source | `MSExchangeService` | Installer log and Event Log source Registry export | confirmed_by_direct_observation |
| Installer commit | Successful | Installer log | confirmed_by_direct_observation |

No separate retained PowerShell service-query text file exists in the repository; the service details above come from the preserved screenshots and report.

**Plain-language explanation:** The program registered itself as a highly privileged background service that could start automatically whenever Windows started.

## HTTP.sys and Network Findings

The network adapter was disabled, and the run summary recorded no external network traffic or unique remote host. No external C2 IP address or domain was identified.

Separate HTTP.sys evidence confirms runtime registration of:

```text
HTTPS://*:443/EWS/EXCHANGE/
```

The request queue was active and attached to the service process, but zero requests arrived and zero were rejected. No successful command-and-control communication was observed.

**Plain-language explanation:** The malware opened a local listening address, but the isolated computer did not receive instructions from outside.

Noriben’s lack of external network traffic does not contradict an active local HTTP.sys listener. A listener capability and a completed external communication are different findings.

## Host-Specific Storage

**Classification: confirmed_by_direct_observation**

The observed directory was:

```text
C:\Windows\Temp\{433532c3-7ccc-4378-8462-ffd9d5838324}
```

- The exact folder name was based on the laboratory host `MachineGuid`.
- The service ran as `LocalSystem`.
- `LocalSystem` used `C:\Windows\Temp` as its temporary directory.
- The folder was empty when inspected.
- No task or response files were observed.

The exact MachineGuid is environmental and is not a universal IOC. Use this generalized hunting pattern:

```text
C:\Windows\Temp\{GUID}
```

## Noriben Timeline Analysis

**Classification: confirmed_by_noriben**

The filtered timeline screenshot shows `Microsoft.Exchange.Service.exe` associated with:

- `InstallUtil.InstallLog`
- `Microsoft.Exchange.Service.InstallLog`
- `Microsoft.Exchange.Service.InstallState`
- `ZoneMap` Registry writes

The timeline is useful for chronological and attribution review, but it is a filtered spreadsheet view and does not replace the full raw event capture. Repeated installer-log rows in the screenshot are summarized once per artifact in the event CSV unless repetition changes the analytical conclusion.

## Raw Procmon PML Limitation

**Classification: evidence_limitation**

The retained malware-run PML measured 976 bytes. A later re-export produced a 124-byte CSV containing zero events. It was therefore not usable as primary event evidence.

> The retained PML appeared empty, truncated, or overwritten during later handling. Its exact failure mechanism could not be proven from the remaining evidence.

The PML must not be described as preserving successful raw events. No PML or derived CSV is currently stored in this repository.

Evidence that remained usable or was represented by preserved screenshots included:

- The filtered Noriben timeline.
- Installer logs.
- Registry exports.
- HTTP.sys output.
- Direct PowerShell observations.
- Screenshots.
- The correlated incident report.

Noriben text, CSV, timeline CSV, and log formats were reportedly generated during collection, but their raw files are absent from the repository and cannot be treated as presently available primary evidence.

## Background Noise and False Positives

| Process or artifact | Why it appeared | Malware-related? | Analyst action |
|---|---|---|---|
| `splunkd.exe` | Splunk Universal Forwarder activity | No | Exclude expected forwarding activity unless correlated with suspicious behavior |
| `AMAExtHealthMonitor.exe` | Azure Monitor Agent health monitoring | No | Treat as expected monitoring activity |
| `Explorer.exe` | Windows shell and routine Registry access | No | Establish user and shell baseline |
| `TrustedInstaller.exe` | Windows servicing | No | Correlate with maintenance state |
| `svchost.exe` | Normal Windows service hosting | No | Investigate only anomalous service context |
| Python/Noriben | Analysis-tool orchestration | No | Exclude known capture-tool activity |
| `Procmon64.exe` | Process Monitor collection | No | Exclude known sensor activity |
| Baseline `cmd.exe` | Harmless probe creation | No | Keep separate from malware-run shell behavior |

Analysts must distinguish the malware’s activity from the operating system, telemetry agents, and tools used to collect evidence.

## Static-to-Dynamic Correlation

| Static dnSpy finding | Noriben or dynamic evidence | Status |
|---|---|---|
| Service installation code | Installer log confirms successful `MSExchangeService` installation | confirmed_dynamically |
| Automatic service start | Service Registry and runtime artifacts | confirmed_dynamically |
| Installer logs | Filtered timeline shows three installer artifacts | confirmed_dynamically |
| ZoneMap writes | Filtered timeline and Registry screenshot | supporting_evidence |
| MachineGuid-based storage | Braced directory observed under `C:\Windows\Temp` | confirmed_dynamically |
| HTTP.sys listener | Active `/ews/exchange/` request queue | confirmed_dynamically |
| Command-shell capability | No service-spawned attacker command observed | not_exercised |
| File-transfer capability | No transfer command observed | not_exercised |
| Encrypted configuration | No hidden configuration value confirmed | confirmed_statically_only |

Noriben did not establish remote command execution.

## Detection Engineering Value

### Sigma

The service evidence supports correlation of:

- Windows System Event ID 7045.
- `ServiceName = MSExchangeService`.
- `ImagePath` containing `Microsoft.Exchange.Service.exe`.
- Automatic startup and `LocalSystem` as supporting fields.

### Splunk

Recommended correlations include:

- Service installation.
- Creation or access of installer artifacts.
- ZoneMap writes by `Microsoft.Exchange.Service.exe`.
- Services installed from uncommon paths.
- `cmd.exe` spawned by a suspicious service process.

These searches are recommendations; this package does not claim they were validated in Splunk.

### YARA

Noriben does not replace content scanning. The runtime service and listener findings explain why static strings such as `MSExchangeService` and `/ews/exchange/` are useful in the repository YARA rule.

### Threat Hunting

1. Search for `MSExchangeService`.
2. Identify its ImagePath.
3. Confirm startup type and account.
4. Review command-shell child processes.
5. Review HTTP.sys listeners.
6. Search for `/ews/exchange/`.
7. Review ZoneMap writes by the same executable.
8. Check for MachineGuid-based temporary directories.

Only the service, listener, ZoneMap, installer, and storage findings were confirmed in this case. The remaining steps are investigative pivots.

## Key Findings

- The monitoring baseline succeeded according to the preserved baseline context.
- The sample installed itself as `MSExchangeService`.
- Installer-related files were created or accessed.
- ZoneMap values were written.
- The service became persistent and ran as `LocalSystem`.
- A MachineGuid-based storage folder was created and was empty when inspected.
- An HTTP.sys listener was registered.
- No external communications were observed.
- The retained raw PML was unusable.
- The filtered timeline, screenshots, installer logs, Registry exports, HTTP.sys state, and direct observations remained usable.

## Evidence Limitations

- No usable raw malware-run PML remained.
- No raw Noriben report, CSV, timeline CSV, or log is stored in the repository.
- No attacker requests were received.
- No external C2 infrastructure was identified.
- No file-transfer command was exercised and no data exfiltration was observed.
- No hidden Registry configuration was confirmed dynamically.
- The pre-execution ZoneMap baseline was unavailable.
- Process IDs and timestamps are laboratory-specific.
- The analysis path and exact MachineGuid are not universal IOCs.

## Screenshot Evidence

| Screenshot | Evidence source | What it supports | Limitation |
|---|---|---|---|
| ![ZoneMap Registry modifications](../../screenshots/TurlaNeuron_22_Dynamic_ZoneMap_Registry_Modifications.png) | Registry Editor and filtered timeline correlation | Observed ZoneMap values | Does not prove prior values differed |
| ![Filtered Noriben timeline activity](../../screenshots/TurlaNeuron_23_Noriben_Filtered_Timeline_Activity.png) | Filtered Noriben timeline | Installer files and ZoneMap writes attributed to the executable | Not the full raw Procmon capture |
| ![Host-specific LocalSystem storage directory](../../screenshots/TurlaNeuron_24_Dynamic_HostSpecific_SYSTEM_Storage_Directory.png) | Direct PowerShell file observation | MachineGuid-based directory and creation time | Not captured by Noriben alone; exact GUID is environmental |
| ![HTTP.sys EWS listener registration](../../screenshots/TurlaNeuron_25_Dynamic_HTTPsys_EWS_Exchange_URL_Registration.png) | Direct HTTP.sys state output | Active local listener with zero requests | Does not prove external C2 |
| ![Successful service installer log](../../screenshots/TurlaNeuron_26_Dynamic_Installer_Log_Service_Success.png) | Installer log | Successful service installation, Event Log source, and commit | Direct installer evidence rather than Noriben alone |
| ![MSExchangeService Event Log source](../../screenshots/TurlaNeuron_27_Dynamic_MSExchangeService_EventLog_Source.png) | Registry export | Application Event Log source registration | Does not prove events were written |
| ![MSExchangeService Registry persistence](../../screenshots/TurlaNeuron_28_Dynamic_Service_Registry_Persistence.png) | Service Registry export | Automatic LocalSystem service configuration | Direct Windows evidence rather than Noriben alone |
