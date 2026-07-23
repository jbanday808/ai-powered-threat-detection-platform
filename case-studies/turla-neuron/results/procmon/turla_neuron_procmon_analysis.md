# Turla Neuron / DarkNeuron Procmon Analysis

## Overview

Process Monitor records detailed file, Registry, process, and network-related activity on Windows. Noriben used Process Monitor to capture events and convert them into a more readable report.

| Field | Value |
|---|---|
| Sample | Microsoft.Exchange.Service.exe |
| SHA-256 | d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29 |
| Procmon executable | Procmon64.exe |
| Collection wrapper | Noriben 2.0.4 |
| Environment | Isolated Windows VM |
| Network state | Disabled |
| Analysis date | 2026-07-22 |

This package distinguishes the successfully validated baseline, processed Noriben evidence, separate Windows artifacts, and the unusable malware-run PML. It does not reconstruct or invent missing raw events.

## Scope and Safety

A VMware snapshot was created before execution. The Windows network adapter was disabled, so the disposable VM had no unrestricted Internet access. No production systems, credentials, or data were involved. The sample was intentionally executed under monitoring, evidence was collected before cleanup, and Microsoft Defender later quarantined or removed the Windows copy.

## Tool Verification

Laboratory verification recorded valid Microsoft Authenticode signatures for `Procmon.exe` and `Procmon64.exe`. Noriben selected `Procmon64.exe`, the Process Monitor EULA was accepted, and capture succeeded during the harmless baseline. The signature and EULA command output is not retained separately, so these points are preserved handling context rather than independently revalidated source files.

## Baseline Capture

The harmless command was:

```text
C:\Windows\System32\cmd.exe /c echo NoribenBaseline>C:\Malware\TurlaNeuron\Dynamic-Analysis\Baseline-Validation\probe.txt
```

The baseline recorded `cmd.exe` creating `probe.txt`. Its reported usable PML was approximately 1.2 MB, and Noriben generated usable text, CSV, timeline, and log files. No network traffic was recorded. The baseline also contained expected Splunk Universal Forwarder, Azure Monitor Agent, Windows Explorer, and servicing activity.

In plain language, this proved that Procmon and Noriben worked before the malware run and helped distinguish routine computer activity from activity associated with the sample. The baseline files themselves are no longer present in the repository, so their size and contents are preserved as laboratory context rather than independently revalidated raw evidence.

## Malware-Run Capture

The analyzed command was:

```text
C:\Malware\TurlaNeuron\Microsoft.Exchange.Service.exe -install
```

It was intentionally executed in the isolated VM; it must not be executed as part of reviewing this package. Procmon was launched through Noriben. Processed Noriben evidence retained installer-related activity, but the final raw PML did not preserve usable events. The Windows path is laboratory-specific and is not a universal IOC.

## Process Activity

The available sources distinguish four activity types:

- `Microsoft.Exchange.Service.exe` performed the controlled installer activity.
- The installed service subsequently operated through normal Windows service management involving `services.exe`.
- `Procmon64.exe` and `python.exe` were monitoring-tool processes used by Procmon and Noriben.
- Windows and monitoring background processes were unrelated noise.

No raw malware-run process event stream survived in the PML. Process IDs are temporary laboratory values and are not IOCs.

## File Activity

The filtered Noriben timeline associated `Microsoft.Exchange.Service.exe` with:

- `InstallUtil.InstallLog`
- `Microsoft.Exchange.Service.InstallLog`
- `Microsoft.Exchange.Service.InstallState`

These artifacts support the .NET service-installation sequence. They are not malicious by themselves because legitimate .NET service installers can create similar files. This finding comes from processed Noriben evidence, not from a recovered raw PML event.

## Registry Activity

The processed timeline associated `Microsoft.Exchange.Service.exe` with writes under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap
```

The displayed values were `ProxyBypass`, `IntranetName`, `UNCAsIntranet`, and `AutoDetect`. These writes are supporting behavior and require correlation with the executable and service installation. No pre-execution Registry baseline was preserved, so the evidence does not prove that the data was different before execution. The unusable raw PML did not independently preserve these events.

## Processed Noriben Timeline

![Filtered Noriben timeline activity](../../screenshots/TurlaNeuron_23_Noriben_Filtered_Timeline_Activity.png)

**Plain-language explanation:** The filtered timeline preserves a readable summary of files and Registry settings associated with the installer even though the underlying raw capture could not later be recovered.

**Technical finding:** It attributes installer-log, InstallState, and ZoneMap activity to `Microsoft.Exchange.Service.exe`.

**Evidence limitation:** This is processed output. It is not a substitute for the missing raw Procmon event stream and does not provide full event properties, stacks, or independently recoverable timing.

## Raw PML Failure Analysis

The retained handling record identifies:

| Property | Result |
|---|---|
| Filename | `Noriben_22_Jul_26__09_43_979200.pml` |
| Size | 976 bytes |
| SHA-256 | A29B4908C3C5C79F265FD37A56A7186572ADCFA541EBDB89EFDB751CBA66FD84 |
| Procmon re-export exit code | 0 |
| Re-exported CSV size | Approximately 124 bytes |
| Exported events | 0 |
| Procmon GUI | No events displayed |
| Usability | `corrupted_or_unusable` |

A successful command exit code only means Procmon completed the export request. It does not prove that the source PML contained events.

The retained malware-run PML appeared empty, truncated, or overwritten. The exact failure mechanism could not be determined from the remaining evidence. Possible explanations include capture termination before events were saved, later overwrite, truncation, an empty backing file, or an evidence-preservation mistake. These are possibilities, not confirmed causes.

## Evidence Recovery Attempts

The recorded recovery workflow:

1. Opened the original PML in Procmon.
2. Created a working copy for inspection.
3. Attempted command-line CSV export.
4. Inspected the file in the Procmon GUI.
5. Counted the exported rows.
6. Calculated and recorded the PML SHA-256.
7. Verified that zero events were recoverable.

No successful event recovery is claimed. The PML and re-exported CSV are absent from the repository, so the recorded PML hash cannot be recalculated here.

## Evidence Still Available

Usable alternatives include the Noriben analysis, event summary, findings JSON, filtered timeline screenshot, installer evidence, Registry observations, HTTP.sys service-state output, service queries, Defender records, the incident report, and dnSpy static analysis. Raw Noriben text, CSV, timeline CSV, log, baseline PML, malware-run PML, and the PML re-export CSV are not present as source files.

Analysts should cite the precise source: the filtered timeline for processed Procmon/Noriben activity, installer and Registry screenshots for Windows artifacts, the [dynamic-analysis package](../dynamic/turla_neuron_dynamic_analysis.md) for runtime correlation, and the [dnSpy package](../dnspy/turla_neuron_dnspy_analysis.md) for code capabilities.

## Static and Dynamic Correlation

| Finding | Procmon/Noriben evidence | Other evidence | Status |
|---|---|---|---|
| Installer-log creation | Filtered Noriben timeline | Installer success screenshot | processed_procmon_evidence |
| InstallState creation | Filtered Noriben timeline | Installer sequence | processed_procmon_evidence |
| ZoneMap Registry writes | Filtered Noriben timeline | Direct Registry screenshot | processed_procmon_evidence |
| `MSExchangeService` installation | Processed installation context | Installer log and service Registry | confirmed_by_other_dynamic_evidence |
| Automatic startup | No recoverable raw event | `Start=2` Registry evidence | confirmed_by_other_dynamic_evidence |
| HTTP.sys listener | No recoverable raw event | HTTP.sys service-state output | confirmed_by_other_dynamic_evidence |
| MachineGuid storage directory | No recoverable raw event | Direct filesystem inspection | confirmed_by_other_dynamic_evidence |
| Command execution capability | No remote shell event observed | dnSpy code | confirmed_statically_only / not_exercised |

## Background Noise

| Process | Expected activity | Malware-related? |
|---|---|---|
| `splunkd.exe` | Splunk Universal Forwarder monitoring | No |
| `AMAExtHealthMonitor.exe` | Azure Monitor Agent health activity | No |
| `Explorer.exe` | Windows shell and routine Registry activity | No |
| `TrustedInstaller.exe` | Windows servicing | No |
| `svchost.exe` | Normal Windows service hosting | No |
| `python.exe` | Noriben wrapper execution | No |
| `Procmon64.exe` | Evidence collection | No |
| Baseline `cmd.exe` | Harmless `probe.txt` creation | No |

These processes must not be classified as Turla Neuron merely because they appeared during monitoring.

## Detection Engineering Value

Procmon-style telemetry can support detection of service installation, service Registry creation, installer-log creation, ZoneMap writes, suspicious process trees, `cmd.exe` spawned by a service process, and file writes under unusual temporary directories. Correlation is important because several individual operations can be legitimate.

The raw malware-run PML was unavailable for direct rule testing. Detection recommendations therefore derive from processed Noriben evidence, separately preserved Windows artifacts, and static analysis rather than replay of a raw Procmon stream.

## Lessons Learned

- Hash the PML immediately after collection.
- Copy raw evidence to a protected evidence directory before opening it.
- Keep baseline and malware captures in separate directories.
- Make the raw PML read-only after capture.
- Export CSV and XML immediately after stopping Procmon.
- Record event counts before cleanup.
- Preserve evidence outside the snapshot before reverting.
- Do not reuse a Procmon output path.
- Validate PML size before trusting it.
- Keep processed Noriben output alongside the raw capture.

## Key Findings

- Procmon was successfully validated during the harmless baseline.
- The processed Noriben timeline retained useful malware-installation activity.
- The 976-byte malware-run PML contained no recoverable events.
- The PML could not serve as primary evidence.
- Processed Noriben and separate Windows evidence remained available.
- No external traffic was observed.

## Evidence Limitations

- No usable malware-run PML is present.
- Zero events were exportable.
- No raw process, file, Registry, stack-trace, or complete event-level timing stream survived.
- No attacker request was received.
- No external C2 infrastructure was identified.
- No attacker command execution or data exfiltration was observed.
- Process IDs and laboratory paths are environmental.
- Baseline and malware-run raw artifacts are absent from the repository.

## Evidence References

- [Noriben analysis](../noriben/turla_neuron_noriben_analysis.md)
- [Noriben event summary](../noriben/turla_neuron_noriben_event_summary.csv)
- [Noriben findings](../noriben/turla_neuron_noriben_findings.json)
- [Dynamic analysis](../dynamic/turla_neuron_dynamic_analysis.md)
- [Static analysis](../static/turla_neuron_static_analysis.md)
- [dnSpy analysis](../dnspy/turla_neuron_dnspy_analysis.md)
- [Incident report](../../reports/incident-report.md)
- [ZoneMap screenshot](../../screenshots/TurlaNeuron_22_Dynamic_ZoneMap_Registry_Modifications.png)
- [Filtered Noriben timeline screenshot](../../screenshots/TurlaNeuron_23_Noriben_Filtered_Timeline_Activity.png)
- [Installer success screenshot](../../screenshots/TurlaNeuron_26_Dynamic_Installer_Log_Service_Success.png)
- [Service Registry screenshot](../../screenshots/TurlaNeuron_28_Dynamic_Service_Registry_Persistence.png)
