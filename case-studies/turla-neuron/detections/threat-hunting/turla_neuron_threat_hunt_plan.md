# Turla Neuron Threat Hunt Plan

## Executive Summary

This hunt searches for a malicious program that hides behind a Microsoft Exchange-style service name. The strongest warning appears when several clues occur together, such as the known file hash, the suspicious service, automatic high-privilege startup, and an unusual web listener.

No production hunt was executed as part of creating this package. The plan is an evidence-based template for authorized enterprise hunting.

## Hunt Objective

Identify Windows systems showing file, service, process, Registry, HTTP.sys, storage, or security-product evidence associated with Turla Neuron, and distinguish active compromise from historical, legitimate, laboratory, false-positive, or insufficient-telemetry outcomes.

## Scope

Recommended scope:

- Windows workstations and servers in `<HOST_SCOPE>`
- Systems that are not authorized malware laboratories
- Systems that are not approved Microsoft Exchange servers
- Historical telemetry between `<HUNT_START_TIME>` and `<HUNT_END_TIME>`
- Current endpoint, file, service, Registry, listener, and Defender state

Organizations should document exclusions, retention limits, asset coverage, and legal authorization before running queries.

## Assumptions

- Telemetry availability and field names vary.
- Event ID 7045 fields may differ between platforms and parsers.
- EDR process and Registry telemetry may be required for deeper hunts.
- HTTP.sys request-queue state is not always centrally collected.
- HTTPS contents may be unavailable without endpoint or decrypted visibility.
- Historical Defender records can remain after successful cleanup.
- A missing result can reflect missing telemetry rather than absence of activity.

## Primary Hunt Hypotheses

### HUNT-001 — Exact Sample Present

**Hypothesis:** A host contains a file whose SHA-256 matches the analyzed sample.

**Evidence:** Exact SHA-256, filename, path, signer, first-seen and last-seen time.  
**Priority:** Critical.  
**False-positive expectation:** Extremely low, except authorized malware laboratories or evidence repositories.

### HUNT-002 — Turla Neuron Service Persistence

**Hypothesis:** A Windows system installed `MSExchangeService` using `Microsoft.Exchange.Service.exe`.

Review Event ID 7045, current service inventory, service Registry data, executable path, startup type, and account.  
**Priority:** High.

### HUNT-003 — Exchange-Themed Service on Non-Exchange Host

**Hypothesis:** A non-Exchange system contains an unexpected service using Microsoft Exchange terminology.

Review service name, display name, description, asset role, executable signature, and installation history.  
**Priority:** High when correlated with the filename or hash.

### HUNT-004 — Suspicious Service Process Tree

**Hypothesis:** `Microsoft.Exchange.Service.exe` is launched by `services.exe` or launches `cmd.exe`.

Review parent/child processes, command line, service account, process hash, and host role.  
**Priority:** High.

`services.exe` starting a legitimate service is normal. Require correlation with the suspicious filename, hash, service, or shell child.

### HUNT-005 — HTTP.sys EWS Listener

**Hypothesis:** A non-Exchange host registers `/ews/exchange/` through HTTP.sys or links port 443 to the suspicious service.

Review request queues, registered URL, associated service, process image, TCP listener, and asset role.  
**Priority:** High when the queue belongs to `MSExchangeService`.

PID 4/System alone is not suspicious.

### HUNT-006 — Service Registry Persistence

**Hypothesis:** `HKLM\SYSTEM\CurrentControlSet\Services\MSExchangeService` exists.

Review `ImagePath`, `Start`, `Type`, `ObjectName`, `DisplayName`, description, and available creation/modification time.  
**Priority:** High.

### HUNT-007 — Event Log Source Registration

**Hypothesis:** `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\MSExchangeService` exists.

**Priority:** Medium alone; high when correlated with the service executable. Registration does not prove that the malware wrote events.

### HUNT-008 — MachineGuid-Based Temporary Storage

**Hypothesis:** A suspicious service created `C:\Windows\Temp\{GUID}`.

Review directory creation, owner, creator, contents, associated service, and timestamps.  
**Priority:** Medium.

GUID-named temporary folders are common and are not malicious by themselves.

### HUNT-009 — Protocol Artifacts

**Hypothesis:** Endpoint, memory, proxy, reverse-proxy, decrypted HTTPS, or application logs contain multiple Turla Neuron protocol artifacts.

Search for `cid`, `cadataKey`, `cadata`, `cadataSig`, `f2949bab-240a-46ca-a455-6f504367ba7d`, and `8d963325-01b8-4671-8e82-d0904275ab06`.  
**Priority:** High when multiple fields and a known GUID appear together.

No on-wire request was captured in the laboratory.

### HUNT-010 — Defender DarkNeuron Detection

**Hypothesis:** Defender history contains `Trojan:MSIL/DarkNeuron.B!dha` or Threat ID `2147724727`.

Review `IsActive`, `ActionSuccess`, remediation time, resources, source, and current file/service state.  
**Priority:** High when active; medium when historical and remediated.

### HUNT-011 — Installer Artifacts

**Hypothesis:** The suspicious executable created `InstallUtil.InstallLog`, `Microsoft.Exchange.Service.InstallLog`, or `Microsoft.Exchange.Service.InstallState`.

**Priority:** Medium. These files can be legitimate and require process, service, hash, or timing correlation.

### HUNT-012 — Supporting ZoneMap Activity

**Hypothesis:** `Microsoft.Exchange.Service.exe` wrote `AutoDetect`, `IntranetName`, `ProxyBypass`, or `UNCAsIntranet` under ZoneMap.

**Priority:** Low or medium as supporting evidence. These values are not malicious by themselves, and the laboratory had no pre-execution Registry baseline.

## Hunt Prioritization

| Priority | Hunt condition | Recommended analyst action |
|---|---|---|
| Critical | Exact SHA-256 on a non-laboratory system; active Defender detection with suspicious service | Preserve evidence and escalate immediately |
| High | Service plus suspicious executable; service plus EWS queue; suspicious service launches shell; multiple protocol fields plus GUID | Validate asset role and correlate endpoint evidence |
| Medium | Event Log source, installer artifacts, GUID directory, historical Defender record | Enrich and correlate with stronger indicators |
| Low | Port 443, LocalSystem, ZoneMap values, or Exchange terminology alone | Do not escalate without additional evidence |

## Hunt Workflow

1. Define host and time scope.
2. Confirm telemetry coverage.
3. Search exact indicators.
4. Search service persistence.
5. Review asset role.
6. Review process trees.
7. Review Registry artifacts.
8. Review HTTP.sys and listener state.
9. Review Defender history.
10. Correlate indicators by host and time.
11. Validate false positives.
12. Escalate credible findings.
13. Record telemetry gaps.
14. Update detections.

## Correlation Model

| Factor | Score |
|---|---:|
| Exact SHA-256 | +100 |
| Active DarkNeuron Defender detection | +80 |
| `MSExchangeService` | +40 |
| `Microsoft.Exchange.Service.exe` | +40 |
| `/ews/exchange/` queue on non-Exchange host | +40 |
| Suspicious service launches `cmd.exe` | +30 |
| Known GUID | +25 |
| Multiple protocol fields | +25 |
| LocalSystem | +10 |
| Automatic startup | +10 |
| Event Log source | +10 |
| Installer artifacts | +10 |
| Authorized malware-analysis system | −100 |
| Verified legitimate Exchange host and approved signed executable | −80 |
| Historical inactive detection only | −40 |

Suggested interpretation:

- 100 or more: Critical
- 70–99: High
- 40–69: Medium
- 20–39: Low
- Below 20: Informational

Record every factor used. Organizations should tune values and thresholds for their assets, telemetry, and false-positive history.

## Analyst Validation Checklist

- Is the host an approved malware-analysis system?
- Is it a legitimate Exchange server?
- Does the SHA-256 match?
- Is the executable digitally signed?
- Is its path expected?
- Does the service configuration match an approved application?
- Is the service active?
- Did it launch a command shell?
- Is the HTTP.sys queue associated with the service?
- Are Defender records active or historical?
- Are multiple indicators present on the same host and time window?
- Is supporting evidence preserved?

## Escalation Criteria

Escalate when:

- The exact hash appears outside an authorized laboratory.
- The suspicious service and filename match.
- The suspicious service launches `cmd.exe`.
- `/ews/exchange/` is associated with the service on a non-Exchange host.
- An active Defender DarkNeuron detection remains.
- Multiple protocol indicators appear together.
- Persistence and command execution occur on the same host.

## False-Positive Analysis

Consider:

- Authorized malware-analysis laboratories
- Security-research evidence repositories
- Approved internal applications using similar service names
- Legitimate Exchange systems and management components
- Normal .NET installer artifacts
- Legitimate ZoneMap administration or Group Policy
- Normal GUID-named temporary directories
- Historical remediated Defender records
- Approved port-443 listeners

## Recommended Response

For credible findings:

1. Preserve alert and endpoint evidence.
2. Verify the file hash.
3. Isolate the endpoint after analyst approval.
4. Review the service and process tree.
5. Collect HTTP.sys and Registry evidence.
6. Quarantine the file after evidence preservation and approval.
7. Remove confirmed malicious persistence after approval.
8. Run an endpoint scan.
9. Search related systems.
10. Verify cleanup.

This plan contains no command that executes the malware or interacts with its listener.

## Evidence Limitations

- No production hunt was executed.
- No Sysmon events were collected.
- No packet capture containing malware traffic exists.
- No external C2 IP address or domain was identified.
- No attacker request, remote command, file transfer, exfiltration, or lateral movement was observed.
- The raw malware-run Procmon PML was unusable.
- Some hunts require telemetry unavailable in the laboratory.

## References

- [Threat-hunting queries](turla_neuron_hunt_queries.md)
- [Machine-readable hypotheses](turla_neuron_hunt_hypotheses.yml)
- [Sigma rule](../sigma/win_system_turla_neuron_service_install.yml)
- [YARA rule](../yara/turla_neuron_v2.yar)
- [IOC package](../../iocs/turla_neuron_iocs.md)
- [Dynamic analysis](../../results/dynamic/turla_neuron_dynamic_analysis.md)
- [Network analysis](../../results/network/turla_neuron_network_analysis.md)
