# Turla Neuron MITRE ATT&CK Mapping

## Executive Summary

The strongest confirmed ATT&CK mappings for this sample involve Windows-service persistence, service masquerading, Registry activity, a local web listener, encoded and encrypted communication processing, and command-shell capability.

Service persistence and the Exchange-themed service identity were supported statically and dynamically. The local HTTP.sys listener was also observed at runtime. No external C2 communication occurred. Command execution and file-transfer behavior were found in code but were not exercised by an attacker.

| Case field | Value |
|---|---|
| Incident ID | `MAL-2026-0721-NEURON` |
| Sample | `Microsoft.Exchange.Service.exe` |
| SHA-256 | `d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29` |
| Family / alias | Turla Neuron / DarkNeuron |
| Service | `MSExchangeService` |
| Listener | `https://*:443/ews/exchange/` |
| Analysis date | 2026-07-22 |

## Mapping Methodology

- Static evidence identifies an implemented capability; it does not prove execution.
- Dynamic evidence identifies behavior supported by preserved runtime artifacts.
- Group-level reporting supplies broader historical context and is kept separate.
- Candidate mappings are not counted or presented as confirmed.
- Every mapping uses an official MITRE technique URL.
- Every sample mapping cites one or more local evidence files.
- ATT&CK 19 tactic names are used, including the current `Stealth` and `Defense Impairment` terminology where applicable.

The evidence priority is direct dynamic evidence, decompiled code, static metadata, detections and IOCs, official MITRE pages, government reporting, major threat-intelligence publications, and supporting methodology.

## Sample-Specific Mapping

| Tactic | Technique | ID | Evidence classification | Confidence | Sample evidence | Dynamic status | Detection coverage | MITRE URL |
|---|---|---|---|---|---|---|---|---|
| Persistence / Privilege Escalation | Create or Modify System Process: Windows Service | T1543.003 | `statically_and_dynamically_confirmed` | high | `-install`, `MSExchangeService`, installer log, service key | Installed, started, automatic, LocalSystem | Sigma, YARA, SOAR, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1543/003/) |
| Stealth | Masquerading: Masquerade Task or Service | T1036.004 | `statically_and_dynamically_confirmed` | high | Exchange-themed service name, display name, description, and executable | Service identity present at runtime | YARA, SOAR, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1036/004/) |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `capability_only` | high | CommandScript Type 0 uses `cmd.exe /c` and captures output/error | Not exercised through an attacker request | YARA, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1059/003/) |
| Defense Impairment / Persistence | Modify Registry | T1112 | `statically_and_dynamically_confirmed` | high | Encrypted REG_BINARY configuration code; service/Event Log keys; ZoneMap writes | Service and ZoneMap Registry activity observed; hidden configuration not observed | Sigma context, SOAR, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1112/) |
| Discovery | Query Registry | T1012 | `confirmed_statically` | high | Recursive HKCU\SOFTWARE search, subkey/value enumeration, binary reads | Hidden configuration search not confirmed dynamically | YARA context, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1012/) |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | `statically_and_dynamically_confirmed` | high | HTTPS prefix, request handler, `/ews/exchange/`, HTTP.sys queue | Local listener observed; zero requests; no external session | YARA, SOAR, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1071/001/) |
| Command and Control | Encrypted Channel: Symmetric Cryptography | T1573.001 | `confirmed_statically` | high | RC4-style `EncryptScript` for command and response processing | No encrypted attacker session captured | YARA, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1573/001/) |
| Command and Control | Encrypted Channel: Asymmetric Cryptography | T1573.002 | `confirmed_statically` | high | Embedded RSA public key, 1024-bit RSA, exponent 65537, OAEP | No RSA session captured; no private key recovered | YARA context, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1573/002/) |
| Command and Control | Data Encoding: Standard Encoding | T1132.001 | `confirmed_statically` | high | Base64 request decoding, response encoding, and file-content encoding | No encoded request observed on wire | YARA, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1132/001/) |
| Stealth | Deobfuscate/Decode Files or Information | T1140 | `confirmed_statically` | high | Base64 decoding, RC4-style decryption, UTF-8 and JSON decoding before dispatch | No attacker payload was received | YARA, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1140/) |
| Command and Control | Ingress Tool Transfer | T1105 | `capability_only` | medium | Type 1 writes decoded bytes; Type 2 reads and encodes bytes; remote request design | No network file transfer observed | YARA context, threat hunting | [MITRE](https://attack.mitre.org/techniques/T1105/) |

### Technique Notes

#### T1543.003 — Windows Service

The `-install` branch, decompiled installer, `MSExchangeService` creation, automatic startup, LocalSystem account, service Registry key, and successful installer log directly support the mapping. Static and runtime evidence agree.

#### T1036.004 — Masquerade Task or Service

The service name `MSExchangeService`, display name `Microsoft Exchange Service`, Exchange-themed description, and malicious executable create a legitimate-looking service identity. The same identity was present in runtime service artifacts.

#### T1059.003 — Windows Command Shell

CommandScript Type 0 launches `cmd.exe` with `/c`, disables shell execution, redirects standard output and error, and reads both streams. This is a high-confidence code capability, but no attacker delivered a command during the isolated run.

#### T1112 — Modify Registry

This mapping covers several distinct purposes: service persistence keys, Event Log source registration, ZoneMap writes, and code capable of encrypted `REG_BINARY` configuration writes. The first three have dynamic support; the hidden configuration write does not.

#### T1012 — Query Registry

The code recursively searches `HKCU\SOFTWARE`, enumerates values, reads byte arrays, decrypts candidate data, and attempts JSON decoding. This was not confirmed as a runtime action.

#### T1071.001 — Web Protocols

The sample registers `https://*:443/ews/exchange/`, and HTTP.sys showed an active queue associated with the malware service. This proves a local web-protocol listener, not an external C2 destination or successful session.

#### T1573.001 and T1573.002 — Encrypted Channel

RC4-style symmetric processing and RSA public-key/OAEP processing are both present in code. No request, key exchange, TLS session, or encrypted attacker traffic was captured.

#### T1132.001 and T1140 — Encoding and Decoding

The request workflow decodes Base64 before processing encrypted JSON, and responses/file content can be Base64 encoded. The decode/decrypt pipeline fits T1140 because encoded or protected information is transformed into usable instructions or data before handling.

#### T1105 — Ingress Tool Transfer

The remote command protocol includes file-write and file-read operations, but no network transfer occurred. T1105 is therefore capability-only and is never presented as dynamically observed.

### File-Deletion Decision

`Storage.KillOldThread` calls `Storage.KillOld`, but the preserved repository evidence does not show the deletion implementation or an observed deletion. T1070.004 is therefore not included as a confirmed mapping.

## Candidate Techniques

| Tactic | Technique | ID | Classification | Confidence | Why it is only a candidate | MITRE URL |
|---|---|---|---|---|---|---|
| Collection | Data from Local System | T1005 | `candidate_mapping` | medium | Type 2 can read local file bytes, but no collection objective or runtime use was demonstrated. | [MITRE](https://attack.mitre.org/techniques/T1005/) |
| Collection | Data Staged: Local Data Staging | T1074.001 | `candidate_mapping` | low | A host-specific storage directory was created, but it was empty and no staging behavior was observed. | [MITRE](https://attack.mitre.org/techniques/T1074/001/) |

Candidate mappings are deliberately excluded from the confirmed mapping count.

## Techniques Explicitly Not Observed

| Technique or activity | Status | Reason |
|---|---|---|
| External C2 connection | `not_observed` | Adapter disabled; Noriben network sections empty; HTTP.sys requests arrived = 0 |
| Exfiltration over C2 | `not_observed` | No external session or transferred data |
| Lateral movement | `not_observed` | No supporting process, network, or authentication evidence |
| Credential theft | `not_observed` | No sample or runtime evidence supporting credential access |
| Process injection | `not_observed` | No sample or runtime evidence supporting injection |
| Spearphishing | `not_observed` | No delivery evidence in this controlled sample analysis |
| Successful attacker command | `not_observed` | Command capability exists in code; no inbound request arrived |
| Network-delivered file transfer | `not_observed` | File operations exist in code; no inbound/outbound transfer occurred |

Broader G0010 reporting is not used to assign these techniques to this sample.

## Static-to-Dynamic Coverage Matrix

| ATT&CK ID | Static evidence | Dynamic evidence | Detection available | Final status |
|---|---|---|---|---|
| T1543.003 | Installer and AfterInstall code | Installer log, service key, running state | Sigma, YARA, SOAR, hunt | statically and dynamically confirmed |
| T1036.004 | Service identity and description | Same identity in service artifacts | YARA, SOAR, hunt | statically and dynamically confirmed |
| T1059.003 | Type 0 shell dispatcher | None | YARA strings, hunt | capability only |
| T1112 | Config write code | Service/Event Log/ZoneMap Registry activity | Sigma context, SOAR, hunt | statically and dynamically confirmed |
| T1012 | Config search code | None | hunt | confirmed statically |
| T1071.001 | HTTPS prefix and handler | Active HTTP.sys queue; zero requests | YARA, SOAR, hunt | statically and dynamically confirmed |
| T1573.001 | RC4-style routine | None | YARA context, hunt | confirmed statically |
| T1573.002 | RSA public-key/OAEP routine | None | YARA context, hunt | confirmed statically |
| T1132.001 | Base64 processing | None on wire | YARA, hunt | confirmed statically |
| T1140 | Decode/decrypt workflow | None from attacker | YARA, hunt | confirmed statically |
| T1105 | File read/write command types | None | YARA context, hunt | capability only |

Local evidence: [dnSpy](../results/dnspy/turla_neuron_dnspy_analysis.md), [static](../results/static/turla_neuron_static_analysis.md), [dynamic](../results/dynamic/turla_neuron_dynamic_analysis.md), [network](../results/network/turla_neuron_network_analysis.md), [Noriben](../results/noriben/turla_neuron_noriben_analysis.md), and [Procmon](../results/procmon/turla_neuron_procmon_analysis.md).

Defensive content: [Sigma](../detections/sigma/win_system_turla_neuron_service_install.yml), [YARA](../detections/yara/turla_neuron_v2.yar), [SOAR](../detections/soar/README.md), and [threat hunting](../detections/threat-hunting/README.md).

## Detection Coverage

| ATT&CK ID | YARA | Sigma | SOAR | Threat hunting | Evidence gap |
|---|---|---|---|---|---|
| T1543.003 | Embedded service/file artifacts | Event ID 7045 service install | Service and endpoint investigation | Service, Registry, hash correlation | No production validation |
| T1036.004 | Exchange-themed strings | Context in service alert | Verify legitimate Exchange role | Non-Exchange host comparison | Naming alone can be legitimate |
| T1059.003 | Shell/function strings | Not covered by current service rule | Collect process tree before action | Service-to-`cmd.exe` search | No runtime shell event |
| T1112 | Registry-related content context | Service key indirectly | Query service/Event Log/ZoneMap state | Registry telemetry searches | Raw malware-run PML unusable |
| T1012 | Static code context | Not covered | Read-only Registry enrichment | EDR/Registry search | No dynamic query event |
| T1071.001 | URI, GUID, request fields | Not covered | Query HTTP.sys state | Queue, listener, URI correlation | No request or PCAP |
| T1573.001 | RC4-related strings/functions | Not covered | Preserve relevant artifacts | Endpoint/memory/static correlation | No encrypted session |
| T1573.002 | RSA-related context | Not covered | Preserve relevant artifacts | Endpoint/memory/static correlation | No RSA session/private key |
| T1132.001 | Base64/request artifacts | Not covered | Preserve relevant artifacts | Multiple-field correlation | No on-wire payload |
| T1140 | Decode/decrypt functions | Not covered | Preserve file and memory evidence | Static/EDR correlation | No attacker payload |
| T1105 | File-operation strings/functions | Not covered | Collect file/process evidence | File-operation plus listener hunt | No transfer occurred |

YARA identifies the file and embedded artifacts; it does not directly detect ATT&CK behavior in event logs. Sigma identifies a specific service-installation event pattern. SOAR coordinates safe investigation and approval gates. Threat hunting correlates multiple host and protocol clues.

## ATT&CK Tactic Summary

- **Execution:** Windows Command Shell exists as capability-only.
- **Persistence / Privilege Escalation:** Windows Service is directly confirmed.
- **Stealth:** Exchange service masquerading and decoding behavior are supported.
- **Defense Impairment:** Registry modification is supported; the current ATT&CK 19 tactic name is used.
- **Discovery:** Registry querying is statically confirmed.
- **Command and Control:** Web protocols, encryption, standard encoding, and transfer capability are present, but no external C2 session occurred.
- **Collection:** T1005 and T1074.001 remain candidates, not confirmed.
- **Indicator Removal:** No confirmed sample mapping is assigned because deletion behavior was not sufficiently preserved.

## Broader Turla Group Context — MITRE G0010

The following section is public threat-intelligence context from the live MITRE G0010 Enterprise layer retrieved on 2026-07-22. It is not evidence that this sample implements every technique.

- Group: Turla (`G0010`)
- MITRE group page version: 5.1
- MITRE group page last modified: 2026-01-20
- Official layer versions: layer 4.5, ATT&CK 19, Navigator 5.3.2
- Mapping status: complete against the 68 unique techniques in the official downloadable G0010 layer at retrieval time

| Tactic | Technique | ID | Evidence classification | Confidence | Official technique URL | MITRE G0010 evidence |
|---|---|---|---|---|---|---|
| Stealth / Privilege Escalation | Create Process with Token | T1134.002 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1134/002/) | [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors can impersonate or steal process tokens before executing commands.(Citation: ESET Turla PowerShell May 2019) |
| Discovery | Local Account | T1087.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1087/001/) | [Turla](https://attack.mitre.org/groups/G0010) has used net user to enumerate local accounts on the system.(Citation: ESET ComRAT May 2020)(Citation: ESET Crutch December 2020) |
| Discovery | Domain Account | T1087.002 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1087/002/) | [Turla](https://attack.mitre.org/groups/G0010) has used net user /domain to enumerate domain accounts.(Citation: ESET ComRAT May 2020) |
| Resource Development | Web Services | T1583.006 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1583/006/) | [Turla](https://attack.mitre.org/groups/G0010) has created web accounts including Dropbox and GitHub for C2 and document exfiltration.(Citation: ESET Crutch December 2020) |
| Command and Control | Web Protocols | T1071.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1071/001/) | [Turla](https://attack.mitre.org/groups/G0010) has used HTTP and HTTPS for C2 communications.(Citation: ESET Turla Mosquito Jan 2018)(Citation: ESET Turla Mosquito May 2018) |
| Command and Control | Mail Protocols | T1071.003 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1071/003/) | [Turla](https://attack.mitre.org/groups/G0010) has used multiple backdoors which communicate with a C2 server via email attachments.(Citation: Crowdstrike GTR2020 Mar 2020) |
| Collection | Archive via Utility | T1560.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1560/001/) | [Turla](https://attack.mitre.org/groups/G0010) has encrypted files stolen from connected USB drives into a RAR file before exfiltration.(Citation: Symantec Waterbug Jun 2019) |
| Persistence / Privilege Escalation | Registry Run Keys / Startup Folder | T1547.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1547/001/) | A [Turla](https://attack.mitre.org/groups/G0010) Javascript backdoor added a local_update_check value under the Registry key HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run to establish persistence. Additionally, a [Turla](https://attack.mitre.org/groups/G0010) custom executable containing Metasploit shellcode is saved to the Startup folder to gain persistence.(Citation: ESET Turla Mosquito Jan 2018)(Citation: ESET Turla Mosquito May 2018)(Citation: ESET Turla Lunar toolset May 2024) |
| Persistence / Privilege Escalation | Winlogon Helper DLL | T1547.004 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1547/004/) | [Turla](https://attack.mitre.org/groups/G0010) established persistence by adding a Shell value under the Registry key HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon.(Citation: ESET Turla Mosquito Jan 2018) |
| Credential Access | Brute Force | T1110 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1110/) | [Turla](https://attack.mitre.org/groups/G0010) may attempt to connect to systems within a victim's network using net use commands and a predefined list or collection of passwords.(Citation: Kaspersky Turla) |
| Execution | PowerShell | T1059.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1059/001/) | [Turla](https://attack.mitre.org/groups/G0010) has used PowerShell to execute commands/scripts, in some cases via a custom executable or code from [Empire](https://attack.mitre.org/software/S0363)'s PSInject.(Citation: ESET Turla Mosquito May 2018)(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019) [Turla](https://attack.mitre.org/groups/G0010) has also used PowerShell scripts to load and execute malware in memory. |
| Execution | Windows Command Shell | T1059.003 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1059/003/) | [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors have used cmd.exe to execute commands.(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019) |
| Execution | Visual Basic | T1059.005 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1059/005/) | [Turla](https://attack.mitre.org/groups/G0010) has used VBS scripts throughout its operations.(Citation: Symantec Waterbug Jun 2019) |
| Execution | Python | T1059.006 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1059/006/) | [Turla](https://attack.mitre.org/groups/G0010) has used IronPython scripts as part of the [IronNetInjector](https://attack.mitre.org/software/S0581) toolchain to drop payloads.(Citation: Unit 42 IronNetInjector February 2021 ) |
| Execution | JavaScript | T1059.007 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1059/007/) | [Turla](https://attack.mitre.org/groups/G0010) has used various JavaScript-based backdoors.(Citation: ESET Turla Mosquito Jan 2018) |
| Resource Development | Virtual Private Server | T1584.003 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1584/003/) | [Turla](https://attack.mitre.org/groups/G0010) has used the VPS infrastructure of compromised Iranian threat actors.(Citation: NSA NCSC Turla OilRig) |
| Resource Development | Server | T1584.004 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1584/004/) | [Turla](https://attack.mitre.org/groups/G0010) has used compromised servers as infrastructure.(Citation: Recorded Future Turla Infra 2020)(Citation: Accenture HyperStack October 2020)(Citation: Talos TinyTurla September 2021) |
| Resource Development | Web Services | T1584.006 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1584/006/) | [Turla](https://attack.mitre.org/groups/G0010) has frequently used compromised WordPress sites for C2 infrastructure.(Citation: Recorded Future Turla Infra 2020) |
| Credential Access | Windows Credential Manager | T1555.004 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1555/004/) | [Turla](https://attack.mitre.org/groups/G0010) has gathered credentials from the Windows Credential Manager tool.(Citation: Symantec Waterbug Jun 2019) |
| Collection | Databases | T1213.006 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1213/006/) | [Turla](https://attack.mitre.org/groups/G0010) has used a custom .NET tool to collect documents from an organization's internal central database.(Citation: ESET ComRAT May 2020) |
| Collection | Data from Local System | T1005 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1005/) | [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors can upload files from victim machines.(Citation: ESET Turla PowerShell May 2019) |
| Collection | Data from Removable Media | T1025 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1025/) | [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors can collect files from USB thumb drives.(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019) |
| Stealth | Deobfuscate/Decode Files or Information | T1140 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1140/) | [Turla](https://attack.mitre.org/groups/G0010) has used a custom decryption routine, which pulls key and salt values from other artifacts such as a WMI filter or [PowerShell Profile](https://attack.mitre.org/techniques/T1546/013), to decode encrypted PowerShell payloads.(Citation: ESET Turla PowerShell May 2019) |
| Resource Development | Malware | T1587.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1587/001/) | [Turla](https://attack.mitre.org/groups/G0010) has developed its own unique malware for use in operations.(Citation: Recorded Future Turla Infra 2020) |
| Defense Impairment | Disable or Modify Tools | T1685 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1685/) | [Turla](https://attack.mitre.org/groups/G0010) has used a AMSI bypass, which patches the in-memory amsi.dll, in PowerShell scripts to bypass Windows antimalware products.(Citation: ESET Turla PowerShell May 2019) |
| Initial Access | Drive-by Compromise | T1189 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1189/) | [Turla](https://attack.mitre.org/groups/G0010) has infected victims using watering holes.(Citation: ESET ComRAT May 2020)(Citation: Secureworks IRON HUNTER Profile) |
| Privilege Escalation / Persistence | Windows Management Instrumentation Event Subscription | T1546.003 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1546/003/) | [Turla](https://attack.mitre.org/groups/G0010) has used WMI event filters and consumers to establish persistence.(Citation: ESET Turla PowerShell May 2019) |
| Privilege Escalation / Persistence | PowerShell Profile | T1546.013 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1546/013/) | [Turla](https://attack.mitre.org/groups/G0010) has used PowerShell profiles to maintain persistence on an infected machine.(Citation: ESET Turla PowerShell May 2019) |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1567/002/) | [Turla](https://attack.mitre.org/groups/G0010) has used WebDAV to upload stolen USB files to a cloud drive.(Citation: Symantec Waterbug Jun 2019) [Turla](https://attack.mitre.org/groups/G0010) has also exfiltrated stolen files to OneDrive and 4shared.(Citation: ESET ComRAT May 2020) |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1068/) | [Turla](https://attack.mitre.org/groups/G0010) has exploited vulnerabilities in the VBoxDrv.sys driver to obtain kernel mode privileges.(Citation: Unit42 AcidBox June 2020) |
| Discovery | File and Directory Discovery | T1083 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1083/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover files in specific locations on the hard disk %TEMP% directory, the current user's desktop, the Program Files directory, and Recent.(Citation: Kaspersky Turla)(Citation: ESET ComRAT May 2020) [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors have also searched for files matching the lPH*.dll pattern.(Citation: ESET Turla PowerShell May 2019) |
| Discovery | Group Policy Discovery | T1615 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1615/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover Group Policy details using the gpresult command.(Citation: ESET ComRAT May 2020) |
| Stealth | File/Path Exclusions | T1564.012 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1564/012/) | [Turla](https://attack.mitre.org/groups/G0010) has placed [LunarWeb](https://attack.mitre.org/software/S1141) install files into directories that are excluded from scanning.(Citation: ESET Turla Lunar toolset May 2024) |
| Command and Control | Ingress Tool Transfer | T1105 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1105/) | [Turla](https://attack.mitre.org/groups/G0010) has used shellcode to download Meterpreter after compromising a victim.(Citation: ESET Turla Mosquito May 2018) |
| Lateral Movement | Lateral Tool Transfer | T1570 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1570/) | [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors can be used to transfer files to/from victim machines on the local network.(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019) |
| Stealth | Match Legitimate Resource Name or Location | T1036.005 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1036/005/) | [Turla](https://attack.mitre.org/groups/G0010) has named components of [LunarWeb](https://attack.mitre.org/software/S1141) to mimic Zabbix agent logs.(Citation: ESET Turla Lunar toolset May 2024) |
| Defense Impairment / Persistence | Modify Registry | T1112 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1112/) | [Turla](https://attack.mitre.org/groups/G0010) has modified Registry values to store payloads.(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019) |
| Execution | Native API | T1106 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1106/) | [Turla](https://attack.mitre.org/groups/G0010) and its RPC backdoors have used APIs calls for various tasks related to subverting AMSI and accessing then executing commands through RPC and/or named pipes.(Citation: ESET Turla PowerShell May 2019) |
| Stealth | Indicator Removal from Tools | T1027.005 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1027/005/) | Based on comparison of [Gazer](https://attack.mitre.org/software/S0168) versions, [Turla](https://attack.mitre.org/groups/G0010) made an effort to obfuscate strings in the malware that could be used as IoCs, including the mutex name and named pipe.(Citation: ESET Gazer Aug 2017) |
| Stealth | Command Obfuscation | T1027.010 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1027/010/) | [Turla](https://attack.mitre.org/groups/G0010) has used encryption (including salted 3DES via [PowerSploit](https://attack.mitre.org/software/S0194)'s Out-EncryptedScript.ps1), random variable names, and base64 encoding to obfuscate PowerShell commands and payloads.(Citation: ESET Turla PowerShell May 2019) |
| Stealth | Fileless Storage | T1027.011 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1027/011/) | [Turla](https://attack.mitre.org/groups/G0010) has used the Registry to store encrypted and encoded payloads.(Citation: ESET Turla PowerShell May 2019)(Citation: Symantec Waterbug Jun 2019) |
| Resource Development | Malware | T1588.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1588/001/) | [Turla](https://attack.mitre.org/groups/G0010) has used malware obtained after compromising other threat actors, such as [OilRig](https://attack.mitre.org/groups/G0049).(Citation: NSA NCSC Turla OilRig)(Citation: Recorded Future Turla Infra 2020) |
| Resource Development | Tool | T1588.002 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1588/002/) | [Turla](https://attack.mitre.org/groups/G0010) has obtained and customized publicly-available tools like [Mimikatz](https://attack.mitre.org/software/S0002).(Citation: Symantec Waterbug Jun 2019) |
| Discovery | Password Policy Discovery | T1201 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1201/) | [Turla](https://attack.mitre.org/groups/G0010) has used net accounts and net accounts /domain to acquire password policy information.(Citation: ESET ComRAT May 2020) |
| Discovery | Peripheral Device Discovery | T1120 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1120/) | [Turla](https://attack.mitre.org/groups/G0010) has used fsutil fsinfo drives to list connected drives.(Citation: ESET ComRAT May 2020) |
| Discovery | Local Groups | T1069.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1069/001/) | [Turla](https://attack.mitre.org/groups/G0010) has used net localgroup and net localgroup Administrators to enumerate group information, including members of the local administrators group.(Citation: ESET ComRAT May 2020) |
| Discovery | Domain Groups | T1069.002 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1069/002/) | [Turla](https://attack.mitre.org/groups/G0010) has used net group "Domain Admins" /domain to identify domain administrators.(Citation: ESET ComRAT May 2020) |
| Initial Access | Spearphishing Link | T1566.002 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1566/002/) | [Turla](https://attack.mitre.org/groups/G0010) attempted to trick targets into clicking on a link featuring a seemingly legitimate domain from Adobe.com to download their malware and gain initial access.(Citation: ESET Turla Mosquito Jan 2018) |
| Discovery | Process Discovery | T1057 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1057/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover running processes using the tasklist /v command.(Citation: Kaspersky Turla) [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors have also enumerated processes associated with specific open ports or named pipes.(Citation: ESET Turla PowerShell May 2019) |
| Stealth / Privilege Escalation | Process Injection | T1055 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1055/) | [Turla](https://attack.mitre.org/groups/G0010) has also used [PowerSploit](https://attack.mitre.org/software/S0194)'s Invoke-ReflectivePEInjection.ps1 to reflectively load a PowerShell payload into a random process on the victim system.(Citation: ESET Turla PowerShell May 2019) |
| Stealth / Privilege Escalation | Dynamic-link Library Injection | T1055.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1055/001/) | [Turla](https://attack.mitre.org/groups/G0010) has used Metasploit to perform reflective DLL injection in order to escalate privileges.(Citation: ESET Turla Mosquito May 2018)(Citation: Github Rapid7 Meterpreter Elevate) |
| Command and Control | Proxy | T1090 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1090/) | [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors have included local UPnP RPC proxies.(Citation: ESET Turla PowerShell May 2019) |
| Command and Control | Internal Proxy | T1090.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1090/001/) | [Turla](https://attack.mitre.org/groups/G0010) has compromised internal network systems to act as a proxy to forward traffic to C2.(Citation: Talos TinyTurla September 2021) |
| Discovery | Query Registry | T1012 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1012/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover information in the Windows Registry with the reg query command.(Citation: Kaspersky Turla) [Turla](https://attack.mitre.org/groups/G0010) has also retrieved PowerShell payloads hidden in Registry keys as well as checking keys associated with null session named pipes .(Citation: ESET Turla PowerShell May 2019) |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1021/002/) | [Turla](https://attack.mitre.org/groups/G0010) used net use commands to connect to lateral systems within a network.(Citation: Kaspersky Turla) |
| Discovery | Remote System Discovery | T1018 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1018/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover remote systems on a local network using the net view and net view /DOMAIN commands. [Turla](https://attack.mitre.org/groups/G0010) has also used net group "Domain Computers" /domain, net group "Domain Controllers" /domain, and net group "Exchange Servers" /domain to enumerate domain computers, including the organization's DC and Exchange Server.(Citation: Kaspersky Turla)(Citation: ESET ComRAT May 2020) |
| Discovery | Security Software Discovery | T1518.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1518/001/) | [Turla](https://attack.mitre.org/groups/G0010) has obtained information on security software, including security logging information that may indicate whether their malware has been detected.(Citation: ESET ComRAT May 2020) |
| Defense Impairment | Code Signing Policy Modification | T1553.006 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1553/006/) | [Turla](https://attack.mitre.org/groups/G0010) has modified variables in kernel memory to turn off Driver Signature Enforcement after exploiting vulnerabilities that obtained kernel mode privileges.(Citation: Unit42 AcidBox June 2020)(Citation: GitHub Turla Driver Loader) |
| Discovery | System Information Discovery | T1082 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1082/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover operating system configuration details using the systeminfo and set commands.(Citation: Kaspersky Turla)(Citation: ESET ComRAT May 2020) |
| Discovery | System Network Configuration Discovery | T1016 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1016/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover network configuration details using the arp -a, nbtstat -n, net config, ipconfig /all, and route commands, as well as [NBTscan](https://attack.mitre.org/software/S0590).(Citation: Kaspersky Turla)(Citation: Symantec Waterbug Jun 2019)(Citation: ESET ComRAT May 2020) [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors have also retrieved registered RPC interface information from process memory.(Citation: ESET Turla PowerShell May 2019) |
| Discovery | Internet Connection Discovery | T1016.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1016/001/) | [Turla](https://attack.mitre.org/groups/G0010) has used tracert to check internet connectivity.(Citation: ESET ComRAT May 2020) |
| Discovery | System Network Connections Discovery | T1049 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1049/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover active local network connections using the netstat -an, net use, net file, and net session commands.(Citation: Kaspersky Turla)(Citation: ESET ComRAT May 2020) [Turla](https://attack.mitre.org/groups/G0010) RPC backdoors have also enumerated the IPv4 TCP connection table via the GetTcpTable2 API call.(Citation: ESET Turla PowerShell May 2019) |
| Discovery | System Service Discovery | T1007 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1007/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover running services and associated processes using the tasklist /svc command.(Citation: Kaspersky Turla) |
| Discovery | System Time Discovery | T1124 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1124/) | [Turla](https://attack.mitre.org/groups/G0010) surveys a system upon check-in to discover the system time by using the net time command.(Citation: Kaspersky Turla) |
| Execution | Malicious Link | T1204.001 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1204/001/) | [Turla](https://attack.mitre.org/groups/G0010) has used spearphishing via a link to get users to download and run their malware.(Citation: ESET Turla Mosquito Jan 2018) |
| Stealth / Persistence / Privilege Escalation / Initial Access | Local Accounts | T1078.003 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1078/003/) | [Turla](https://attack.mitre.org/groups/G0010) has abused local accounts that have the same password across the victim’s network.(Citation: ESET Crutch December 2020) |
| Command and Control | Web Service | T1102 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1102/) | [Turla](https://attack.mitre.org/groups/G0010) has used legitimate web services including Pastebin, Dropbox, and GitHub for C2 communications.(Citation: Accenture HyperStack October 2020)(Citation: ESET Crutch December 2020) |
| Command and Control | Bidirectional Communication | T1102.002 | `group_level_context` | high | [MITRE](https://attack.mitre.org/techniques/T1102/002/) | A [Turla](https://attack.mitre.org/groups/G0010) JavaScript backdoor has used Google Apps Script as its C2 server.(Citation: ESET Turla Mosquito Jan 2018)(Citation: ESET Turla Mosquito May 2018) |

The [group Navigator layer](turla_group_context_navigator_layer.json) contains only those official G0010 techniques. Sample techniques were not merged into it.

## Evidence Limitations

- Decompiled output is not original source code.
- No attacker request or complete protocol session was captured.
- No external C2 IP address or domain was identified.
- The local wildcard listener is not a remote destination.
- Port 443 and the `LocalSystem` account are broad Windows context and are not malicious by themselves.
- PID 4/System is the HTTP.sys kernel socket owner, not the malware process.
- The exact laboratory MachineGuid is environmental and is not a sample-wide or group-wide IOC.
- No private RSA key was recovered.
- Command execution and file transfer were not attacker-exercised.
- The retained malware-run Procmon PML was unusable.
- The host-specific directory was empty.
- Candidate mappings require more evidence.
- Group reporting describes G0010 broadly and does not prove behavior by this binary.
- Public activity reporting concerns Kazuar, ApolloShadow, and STOCKSTAY—not analysis of this Neuron sample.
