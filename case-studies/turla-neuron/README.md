# Turla Neuron / DarkNeuron Malware Analysis

> Static analysis, .NET reverse engineering, controlled dynamic analysis, detection engineering, threat hunting, and defensive response automation.

- **Analysis:** Complete
- **Environment:** Isolated laboratory
- **Production impact:** None confirmed
- **Severity:** High
- **Platform:** Windows / .NET

## Overview

This case study examines a malicious Windows program known as Turla Neuron or DarkNeuron. The program disguises itself as a Microsoft Exchange-related background service. Its code allows it to start automatically, wait for encrypted instructions, run operating-system commands, manage files, and store protected configuration information.

The work was performed for defensive research and education in isolated virtual machines. Its goal was to understand the malware, preserve evidence, and create practical detections and response guidance. No real organization or production environment was investigated.

| Case detail | Value |
|---|---|
| Project | Turla Neuron / DarkNeuron Malware Analysis |
| Incident ID | MAL-2026-0721-NEURON |
| Analyst | James Banday |
| Analysis date | 2026-07-22 |
| Status | Analysis Complete — No Production Impact Confirmed |
| Severity | High (P2) |
| Sample | `Microsoft.Exchange.Service.exe` |
| SHA-256 | `d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29` |
| Defender detection | `Trojan:MSIL/DarkNeuron.B!dha` |
| Defender Threat ID | `2147724727` |
| Service | `MSExchangeService` |
| Display name | `Microsoft Exchange Service` |
| Service account | `LocalSystem` |
| Startup type | Automatic |
| Local listener | `https://*:443/ews/exchange/` |
| URI path | `/ews/exchange/` |

A file hash such as SHA-256 is a digital fingerprint. It identifies this exact analyzed file; it does not identify every possible version of the malware.

## What Is Turla?

Turla is the name commonly used in public cybersecurity reporting for a sophisticated cyber-espionage group associated with long-running operations. Different organizations may track overlapping activity under names such as Secret Blizzard, Snake, Waterbug, or Venomous Bear.

Public reporting provides useful background context, but it does not independently prove who developed, operated, or deployed this exact file. The analyzed sample is identified as Turla Neuron or DarkNeuron in the available evidence, and its behavior is consistent with public Turla-related reporting. Group-level history must not be confused with behavior directly observed in this sample.

## What Is Turla Neuron?

Turla Neuron is a malicious Windows .NET program that installs itself as a service. A Windows service is a program that runs quietly in the background, often without a visible window. Persistence means a program is configured to return after Windows restarts. A listener is a local address where a program waits for incoming messages.

The analyzed program:

- Uses Microsoft Exchange terminology to appear legitimate.
- Installs as `MSExchangeService`, displayed as `Microsoft Exchange Service`.
- Is configured to start automatically with Windows.
- Runs using the highly privileged `LocalSystem` account.
- Opens a local HTTPS listener at `https://*:443/ews/exchange/`.
- Expects specially formatted, encoded, and encrypted instructions.
- Contains code for command execution, file reading, file writing, configuration management, and host-specific storage.

The code proves that these capabilities exist. The controlled run separately confirmed service installation, automatic persistence, LocalSystem execution, listener registration, installer artifacts, and creation of a computer-specific storage directory. It did **not** observe an attacker request, remote command, or file transfer.

## Why It Matters

On a real system, these capabilities would create significant risk:

- A legitimate-looking service name can help the program avoid casual notice.
- `LocalSystem` gives the service extensive Windows privileges.
- Automatic startup provides persistence, meaning the malware can return after a restart.
- A listener is a local address where the malware waits for instructions.
- Command execution could allow operating-system actions.
- File operations could allow data to be written or read.
- Encryption makes instructions and settings harder to inspect.

The isolated analysis confirmed how the program establishes a foothold and waits. It did not demonstrate an attacker successfully using those capabilities.

## Turla Neuron Execution Flow

![Turla Neuron execution-flow diagram showing service installation, automatic startup, listener creation, command capability, and persistence](screenshots/TurlaNeuron_Diagram.png)

> **Figure 1 — Simplified Turla Neuron execution flow.** The diagram explains how the malware installs a fake Microsoft Exchange service, starts automatically, opens a local listener, and waits for instructions. During this isolated test, no attacker connected to the listener and no external command was received.

In simple terms:

1. The executable uses its built-in installer to create `MSExchangeService`.
2. Windows configures the fake Exchange service to start automatically as `LocalSystem`.
3. The service opens the local listener `https://*:443/ews/exchange/`.
4. It waits for specially formatted, encoded, and encrypted messages.
5. Its code can dispatch operating-system commands, file operations, or configuration work.
6. It maintains a computer-specific temporary storage directory.
7. During this test, no outside instruction arrived and none of those remote capabilities was exercised.

For the method-level reconstruction and Mermaid diagram, see the [integrated reverse-engineering analysis](results/reverse-engineering/turla_neuron_reverse_engineering.md) and [technical execution flow](results/reverse-engineering/turla_neuron_execution_flow.md).

## Key Findings

| Finding | Plain-language meaning | Evidence status |
|---|---|---|
| Exact SHA-256 established | The analyzed file has a reliable digital fingerprint. | Confirmed statically |
| Defender classified the file as DarkNeuron | Microsoft Defender recognized the Windows copy as `Trojan:MSIL/DarkNeuron.B!dha`. | Confirmed dynamically |
| `MSExchangeService` / `Microsoft Exchange Service` | The malware used an Exchange-themed background-service identity. | Confirmed statically and dynamically |
| Automatic startup as `LocalSystem` | Windows was configured to start it with high privileges after reboot. | Confirmed dynamically |
| `Microsoft.Exchange.Service.exe` ImagePath | The service pointed to the analyzed executable; its laboratory directory is not universal. | Confirmed dynamically |
| `https://*:443/ews/exchange/` | The service opened a local Exchange-themed address and waited. | Confirmed statically and dynamically |
| Active HTTP.sys queue; zero requests | Windows linked the listener queue to the service, but nothing contacted it. | Confirmed dynamically |
| Hidden `cmd.exe` execution and output capture | The code can run commands and collect normal/error output. | Capability only; not remotely exercised |
| Encoded file write/read | The code can write decoded bytes and return encoded file contents. | Capability only; not dynamically exercised |
| Encrypted Registry configuration | The code can search for and write encrypted settings under a user Registry area. | Confirmed statically; exact hidden configuration not observed |
| `C:\Windows\Temp\{GUID}` storage pattern | The service created a computer-specific temporary directory. | Confirmed statically and dynamically; directory was empty |
| Defender remediation and cleanup | The Windows copy was quarantined or removed, the sample and service were absent, and Defender reported the threat inactive. | Cleanup verified |

## Laboratory Safety

The sample was intentionally handled only in controlled virtual machines:

- A VMware snapshot was created before execution.
- The Windows VM network adapter was disabled.
- `Get-NetAdapter` recorded the adapter as disabled with a link speed of 0 bps.
- No bridged or NAT network was attached during execution.
- No unrestricted Internet access was provided.
- No production systems, accounts, credentials, or information were involved.
- No simulated C2 service or inbound request was used.
- No attacker connected to the listener and no remote command was received.
- No external C2 IP address or domain was identified.
- Evidence was collected before cleanup or snapshot restoration.
- Defender later quarantined or removed the Windows copy.
- Cleanup verification found the sample and `MSExchangeService` absent.
- Defender reported the threat as inactive.
- The malware executable is not stored in this repository.

The local listener could still be registered because disabling an adapter does not remove Windows' local networking stack. Its existence does not prove that external communication occurred.

## Static Findings vs. Observed Behavior

This distinction is central to the case:

| Evidence type | What it establishes | Examples |
|---|---|---|
| Static analysis | Code or data exists in the file without running it. | Command types, file operations, encryption, hidden configuration |
| Dynamic analysis | An artifact shows behavior occurred during the controlled run. | Service installation, Registry persistence, HTTP.sys queue, storage directory |
| Capability only | Code supports an action, but the run did not exercise it. | Remote command execution, upload/download, configuration commands |
| Not observed | Available evidence did not show the event. | Attacker request, external C2, exfiltration, lateral movement |

## Defensive Content

### File Detection with YARA

[YARA](detections/yara/turla_neuron_v2.yar) identifies suspicious files. This case includes:

- `Turla_Neuron_Exact`: matches the exact SHA-256.
- `Turla_Neuron_Behavior`: matches a combination of distinctive embedded service, listener, GUID, protocol, and function artifacts.

YARA scans a file as data; it does not execute it.

### Log Detection with Sigma

[Sigma](detections/sigma/win_system_turla_neuron_service_install.yml) identifies suspicious activity in security logs. The rule alerts on Windows System Event ID 7045 when `MSExchangeService` is installed with an ImagePath containing `Microsoft.Exchange.Service.exe`.

The alert is behavioral evidence and does not prove attribution by itself.

### Response Automation with SOAR

[SOAR](detections/soar/README.md)—Security Orchestration, Automation, and Response—coordinates incident-response steps. The vendor-neutral playbook performs read-only enrichment automatically and requires explicit approval before containment or permanent remediation.

It never contacts the malware listener, treats port 443 or PID 4/System as malicious by themselves, or deletes evidence automatically.

### Indicators of Compromise

The [IOC package](iocs/turla_neuron_iocs.md) provides Markdown, CSV, and JSON formats. It separates strong indicators, such as the exact hash and distinctive service, from broad supporting context such as LocalSystem or port 443.

No external C2 IP address or domain is included because none was identified.

### Threat Hunting

The [vendor-neutral threat-hunting package](detections/threat-hunting/README.md) provides twelve hypotheses, safe query patterns, a transparent correlation model, and a blank hunt tracker. It helps defenders search enterprise Windows telemetry without claiming that a production hunt was already performed.

No completed Suricata rule is included. Organizations may develop and validate network IDS content in the future when representative packet evidence or appropriately decrypted test telemetry is available.

## Analysis and Evidence Packages

| Area | What it contains | Start here |
|---|---|---|
| Incident report | Full narrative, evidence sequence, remediation, and screenshot index | [Incident report](reports/incident-report.md) |
| Static analysis | File identity, metadata, embedded artifacts, and YARA summary | [Static analysis](results/static/turla_neuron_static_analysis.md) |
| dnSpy analysis | Decompiled .NET functions, commands, protocol, Registry, cryptography, and storage | [dnSpy analysis](results/dnspy/turla_neuron_dnspy_analysis.md) |
| Reverse engineering | Integrated system architecture, maps, and execution flow | [Reverse-engineering analysis](results/reverse-engineering/turla_neuron_reverse_engineering.md) |
| Dynamic analysis | Consolidated behavior observed in the isolated VM | [Dynamic analysis](results/dynamic/turla_neuron_dynamic_analysis.md) |
| Noriben | Processed installer, file, and Registry timeline evidence | [Noriben analysis](results/noriben/turla_neuron_noriben_analysis.md) |
| Procmon | Baseline validation and explanation of the unusable malware-run PML | [Procmon analysis](results/procmon/turla_neuron_procmon_analysis.md) |
| Network | Static protocol design, local socket/HTTP.sys evidence, and no-traffic findings | [Network analysis](results/network/turla_neuron_network_analysis.md) |
| MITRE ATT&CK | Sample-specific mapping, separate G0010 group context, Navigator layers, and public activity assessment | [ATT&CK package](mitre-attack/README.md) |
| Screenshots | Visual evidence from identification through cleanup | [Screenshot inventory](results/static/turla_neuron_screenshot_inventory.txt) |
| References | Training, public reporting, tools, detection standards, and ATT&CK sources | [References](references/turla_neuron_references.md) |
| Scripts | Safe defensive collection and validation utilities | [Scripts guide](scripts/README.md) |

Each structured package includes validation output. CSV and JSON files are provided where useful for SOC, DFIR, detection-engineering, or automation workflows.

## Repository Map

```text
turla-neuron/
├── README.md                  # This landing page
├── detections/
│   ├── sigma/                 # Windows service-installation log rule
│   ├── yara/                  # Exact and behavioral file rules
│   ├── soar/                  # Vendor-neutral response automation
│   └── threat-hunting/        # Vendor-neutral hypotheses and queries
├── iocs/                      # IOC package in Markdown, CSV, and JSON
├── mitre-attack/              # Sample mapping and separate Turla G0010 context
│   ├── README.md
│   ├── turla_neuron_attack_mapping.md
│   ├── turla_neuron_attack_mapping.csv
│   ├── turla_neuron_attack_mapping.json
│   ├── turla_neuron_sample_navigator_layer.json
│   ├── turla_group_context_navigator_layer.json
│   ├── turla_history_and_current_activity.md
│   ├── turla_attack_reference_matrix.md
│   └── turla_attack_validation.txt
├── references/                # Centralized source references
├── reports/                   # Complete incident report
├── results/
│   ├── static/                # Overall non-execution analysis
│   ├── dnspy/                 # Detailed .NET decompilation findings
│   ├── reverse-engineering/   # Integrated architecture and flow
│   ├── dynamic/               # Consolidated observed behavior
│   ├── noriben/               # Processed Noriben evidence
│   ├── procmon/               # Procmon evidence and limitations
│   └── network/               # Listener and no-traffic analysis
├── screenshots/               # Original visual evidence
└── scripts/                   # Safe defensive utilities
```

## What Was Not Observed

The controlled run did **not** observe:

- An inbound attacker request
- An outbound connection to external infrastructure
- A confirmed C2 IP address
- A confirmed C2 domain
- Malware-attributed DNS activity
- A successful TLS or command session
- An attacker-delivered command
- A file upload or download command
- Data exfiltration
- Lateral movement
- Production-system impact

The listener prefix `https://*:443/ews/exchange/` is a local wildcard address, not a remote destination.

## Evidence Limitations

- No packet capture was collected.
- The retained malware-run Procmon PML was only 976 bytes and had zero recoverable events.
- Conclusions therefore use processed Noriben evidence and separately preserved Windows artifacts.
- No complete request/response protocol session was captured.
- No private RSA key was recovered.
- The hidden encrypted Registry configuration location was not dynamically identified.
- The host-specific storage directory was empty when inspected.
- Laboratory paths, process IDs, timestamps, and the exact MachineGuid are environmental—not universal indicators.

## Safe Navigation

- Start with this README, then use the incident report for the full narrative.
- Use `results/static/` and `results/dnspy/` for capabilities found without execution.
- Use `results/dynamic/`, `results/noriben/`, and `results/network/` for observed behavior.
- Read each package's validation file before reusing structured data.
- Do not interpret screenshot numbering as a complete timeline.
- Do not treat broad values such as port 443, PID 4, LocalSystem, or ZoneMap settings as malicious alone.
- Do not copy a malware sample into this repository.
- Do not run the sample or contact the listener.
- Review [scripts/README.md](scripts/README.md) before using any defensive utility.

## Plain-Language Glossary

| Term | Meaning |
|---|---|
| Windows service | A program that can run quietly in the background. |
| Persistence | A configuration that helps a program return after restart. |
| Listener | A local address where a program waits for incoming communication. |
| HTTP.sys | The Windows kernel component that manages HTTP/HTTPS listening sockets and queues. |
| File hash | A digital fingerprint for identifying an exact file. |
| Registry | A Windows database that stores operating-system and application settings. |
| YARA | A way to identify files using hashes and distinctive content. |
| Sigma | A portable format for identifying suspicious activity in security logs. |
| SOAR | A workflow that coordinates security tools and response steps. |
| IOC | An Indicator of Compromise—a clue used during investigation. |
| Static analysis | Studying a file without running it. |
| Dynamic analysis | Observing a program in a controlled environment while it runs. |

## References and Attribution

The centralized [reference package](references/turla_neuron_references.md) documents the training material, public threat reporting, tools, sample-intelligence context, detection standards, and MITRE ATT&CK techniques used by this case.

The dedicated [MITRE ATT&CK package](mitre-attack/README.md) maps the analyzed sample and, separately, the broader Turla G0010 group context. It prevents public group reporting from being mistaken for behavior directly supported by this binary.

Key public context includes:

- [UK NCSC Turla malware publication](https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB)
- [UK NCSC Turla group malware alert](https://www.ncsc.gov.uk/alerts/turla-group-malware)
- [MITRE ATT&CK: Windows Service](https://attack.mitre.org/techniques/T1543/003/)

Public references support background and terminology. The laboratory artifacts remain the primary evidence for conclusions about this sample.
