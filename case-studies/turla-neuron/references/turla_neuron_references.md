# Turla Neuron / DarkNeuron Analysis References

## Overview

This document lists the training material, public threat reporting, malware-analysis tools, detection-engineering standards, and sample-intelligence sources used during the Turla Neuron analysis. Public references provide supporting context and do not independently prove that every documented behavior occurred during the controlled laboratory run.

## Reference Categories

### 1. Primary Training and Analysis References

#### REF-001 — Hack The Box Academy — Malware Analysis Module

- **Organization:** Hack The Box Academy
- **URL:** [REF-001]
- **Purpose in this analysis:** Supported malware reverse engineering, detection engineering, and the analysis workflow.
- **Accessed:** 2026-07-22

#### REF-002 — Hack The Box Academy — Incident Reporting / Analysis Reference

- **Organization:** Hack The Box Academy
- **URL:** [REF-002]
- **Purpose in this analysis:** Supported the incident-report structure and clear communication of analysis findings.
- **Accessed:** 2026-07-22

Together, these references informed the reverse-engineering process, reporting approach, detection-development workflow, and organization of evidence. They are training resources rather than direct evidence about what happened in the isolated VM.

### 2. Public Turla Threat Reporting

#### REF-003 — UK National Cyber Security Centre — Turla Malware Publication

- **Organization:** UK National Cyber Security Centre
- **URL:** [REF-003]
- **Purpose in this analysis:** Public background about Turla-associated malware and tradecraft.
- **Accessed:** 2026-07-22

#### REF-004 — UK National Cyber Security Centre — Turla Group Malware Alert

- **Organization:** UK National Cyber Security Centre
- **URL:** [REF-004]
- **Purpose in this analysis:** Public context about Turla-associated malware and tradecraft.
- **Accessed:** 2026-07-22

The NCSC publications support contextual comparison with publicly reported Turla activity. They do not independently prove who created, deployed, or operated the analyzed file.

### 3. Sample Intelligence

#### REF-005 — VirusTotal sample page

- **Organization:** VirusTotal
- **URL:** [REF-005]
- **Filename:** `Microsoft.Exchange.Service.exe`
- **SHA-256:** `d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29`
- **Purpose in this analysis:** Public multi-engine detection and file-metadata context.
- **Accessed:** 2026-07-22

Vendor detections and public scan metadata support sample identification and reputation assessment. They do not prove that every capability identified by a vendor or the static analysis executed during the laboratory run.

### 4. Malware-Analysis Tool Documentation

#### REF-006 — Noriben project

- **Organization:** Noriben
- **URL:** [REF-006]
- **Purpose in this analysis:** Documents the tool used to summarize process, file, and Registry activity from the controlled run.
- **Accessed:** 2026-07-22

#### REF-007 — Microsoft Sysinternals Process Monitor

- **Organization:** Microsoft
- **URL:** [REF-007]
- **Purpose in this analysis:** Documents the underlying event-capture technology used by the Noriben workflow.
- **Accessed:** 2026-07-22

#### REF-008 — Microsoft Defender PowerShell `Get-MpThreat`

- **Organization:** Microsoft
- **URL:** [REF-008]
- **Purpose in this analysis:** Supports interpretation of the Defender threat-status review after remediation.
- **Accessed:** 2026-07-22

#### REF-009 — Microsoft Defender PowerShell `Get-MpThreatDetection`

- **Organization:** Microsoft
- **URL:** [REF-009]
- **Purpose in this analysis:** Supports interpretation of detailed Defender detection and remediation history.
- **Accessed:** 2026-07-22

Tool documentation explains how evidence was collected or interpreted; it is not itself evidence that malware behavior occurred.

### 5. Detection Engineering References

#### REF-010 — Sigma documentation

- **Organization:** SigmaHQ
- **URL:** [REF-010]
- **Purpose in this analysis:** Provides the detection-rule standard used for the Windows service-installation rule.
- **Accessed:** 2026-07-22

The repository contains a YARA rule, but recursive reference discovery found no external YARA documentation URL. No Splunk or Suricata documentation URL is referenced by this case study, so none was added.

### 6. MITRE ATT&CK References

| Technique | ID | URL | Analysis classification | Evidence summary |
|---|---|---|---|---|
| Windows Service | T1543.003 | [REF-011] | Observed dynamically | `MSExchangeService` was installed with automatic startup and `LocalSystem` execution |
| Windows Command Shell | T1059.003 | [REF-012] | Confirmed statically | Decompiled code creates hidden `cmd.exe` and captures output; no attacker command was observed |
| Modify Registry | T1112 | [REF-013] | Observed dynamically | Service, Event Log source, and ZoneMap Registry activity was captured during the controlled run |
| Web Protocols | T1071.001 | [REF-014] | Capability only | The HTTPS listener and request parser are present, but no inbound request or successful C2 session was observed |
| Ingress Tool Transfer | T1105 | [REF-015] | Capability only | Decompiled code implements file read/write transfer functions; no external transfer was observed |
| Deobfuscate/Decode Files or Information | T1140 | [REF-016] | Confirmed statically | Decompiled code performs Base64 conversion and encrypted-data decoding |

ATT&CK supplies standardized names for describing behavior and capability. Capability-only mappings are not claims of dynamically observed attacker activity.

### 7. Additional Repository References

Recursive discovery found these external URLs already embedded in the case-study files:

- **REF-001:** Present in the incident report, IOC package, YARA metadata, and Sigma references.
- **REF-003:** Present in the incident report, IOC package, YARA metadata, and Sigma references.
- **REF-004:** Present in the incident report, IOC package, YARA metadata, and Sigma references.

They are already represented in the primary and public-reporting categories, so they are not duplicated as additional reference records. A wildcard HTTPS EWS listener prefix was also discovered, but it is embedded malware configuration—not an external source—and was excluded from this package.

No other external URL was found in reverse-engineering notes, results files, or the compiled YARA artifact. Binary matching output from the compiled rule was not treated as reference metadata.

## Reference Usage Notes

- Public attribution should be described cautiously.
- Tool documentation supports methodology rather than attribution.
- VirusTotal supports sample-identification and multi-engine context.
- Hack The Box material supports the analysis and reporting workflow.
- MITRE ATT&CK provides standardized technique names.
- References do not replace direct laboratory evidence.
- Temporary Defender quarantine paths and laboratory-specific values are neither external references nor general IOCs.

## Complete Reference Table

| ID | Category | Title | Organization | URL | Purpose | Accessed |
|---|---|---|---|---|---|---|
| REF-001 | Training | Hack The Box Academy — Malware Analysis Module | Hack The Box Academy | [REF-001] | Reverse engineering, detection engineering, and analysis workflow | 2026-07-22 |
| REF-002 | Training | Hack The Box Academy — Incident Reporting / Analysis Reference | Hack The Box Academy | [REF-002] | Incident-report structure and communication | 2026-07-22 |
| REF-003 | Public threat reporting | UK National Cyber Security Centre — Turla Malware Publication | UK National Cyber Security Centre | [REF-003] | Public Turla-associated malware and tradecraft context | 2026-07-22 |
| REF-004 | Public threat reporting | UK National Cyber Security Centre — Turla Group Malware Alert | UK National Cyber Security Centre | [REF-004] | Public Turla-associated malware and tradecraft context | 2026-07-22 |
| REF-005 | Sample intelligence | VirusTotal Sample Page — Microsoft.Exchange.Service.exe | VirusTotal | [REF-005] | Multi-engine detection and file metadata | 2026-07-22 |
| REF-006 | Tool documentation | Noriben Project | Noriben | [REF-006] | Summarized process, file, and Registry activity | 2026-07-22 |
| REF-007 | Tool documentation | Microsoft Sysinternals Process Monitor | Microsoft | [REF-007] | Underlying event-capture technology | 2026-07-22 |
| REF-008 | Tool documentation | Microsoft Defender PowerShell — Get-MpThreat | Microsoft | [REF-008] | Defender threat-status review | 2026-07-22 |
| REF-009 | Tool documentation | Microsoft Defender PowerShell — Get-MpThreatDetection | Microsoft | [REF-009] | Detailed Defender detection history | 2026-07-22 |
| REF-010 | Detection engineering | Sigma Documentation | SigmaHQ | [REF-010] | Sigma rule standard | 2026-07-22 |
| REF-011 | MITRE ATT&CK | Windows Service | MITRE | [REF-011] | Service-persistence classification | 2026-07-22 |
| REF-012 | MITRE ATT&CK | Windows Command Shell | MITRE | [REF-012] | Command-shell capability classification | 2026-07-22 |
| REF-013 | MITRE ATT&CK | Modify Registry | MITRE | [REF-013] | Registry-modification classification | 2026-07-22 |
| REF-014 | MITRE ATT&CK | Web Protocols | MITRE | [REF-014] | HTTPS listener capability classification | 2026-07-22 |
| REF-015 | MITRE ATT&CK | Ingress Tool Transfer | MITRE | [REF-015] | File-transfer capability classification | 2026-07-22 |
| REF-016 | MITRE ATT&CK | Deobfuscate/Decode Files or Information | MITRE | [REF-016] | Base64 and encrypted-data decoding classification | 2026-07-22 |

[REF-001]: https://academy.hackthebox.com/app/module/234/section/2514
[REF-002]: https://academy.hackthebox.com/app/module/238/section/2584
[REF-003]: https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB
[REF-004]: https://www.ncsc.gov.uk/alerts/turla-group-malware
[REF-005]: https://www.virustotal.com/gui/file/d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29
[REF-006]: https://github.com/Rurik/Noriben
[REF-007]: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
[REF-008]: https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreat
[REF-009]: https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection
[REF-010]: https://sigmahq.io/docs/
[REF-011]: https://attack.mitre.org/techniques/T1543/003/
[REF-012]: https://attack.mitre.org/techniques/T1059/003/
[REF-013]: https://attack.mitre.org/techniques/T1112/
[REF-014]: https://attack.mitre.org/techniques/T1071/001/
[REF-015]: https://attack.mitre.org/techniques/T1105/
[REF-016]: https://attack.mitre.org/techniques/T1140/
