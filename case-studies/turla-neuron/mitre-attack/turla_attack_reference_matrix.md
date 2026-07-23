# Turla ATT&CK Reference Matrix

This matrix separates official ATT&CK definitions, group-level intelligence, supporting public reporting, methodology, and internal sample evidence. External reporting never replaces direct laboratory evidence for sample conclusions.

| Reference ID | Source | Publication date | Scope | ATT&CK IDs supported | Sample or group context | URL | Notes |
|---|---|---|---|---|---|---|---|
| EXT-001 | MITRE ATT&CK — Turla G0010 | Created 2017-05-31; modified 2026-01-20 | Official group record and current technique set | G0010 and 68 group techniques | group | https://attack.mitre.org/groups/G0010/ | Version 5.1; retrieved 2026-07-22 |
| EXT-002 | MITRE ATT&CK — Groups methodology | Current page retrieved 2026-07-22 | How ATT&CK groups and associated names are represented | G0010 context | group | https://attack.mitre.org/groups/index.html | Explains that group reporting is sourced public context |
| EXT-003 | MITRE ATT&CK Navigator | Current site retrieved 2026-07-22 | Layer visualization | All mapped IDs | sample and group | https://mitre-attack.github.io/attack-navigator/ | Official layer uses layer 4.5 / ATT&CK 19 / Navigator 5.3.2 |
| EXT-004 | MITRE — Windows Service | Current definition retrieved 2026-07-22 | Technique definition | T1543.003 | sample | https://attack.mitre.org/techniques/T1543/003/ | Service persistence and privilege context |
| EXT-005 | MITRE — Masquerade Task or Service | Current definition retrieved 2026-07-22 | Technique definition | T1036.004 | sample | https://attack.mitre.org/techniques/T1036/004/ | Exchange-themed service identity |
| EXT-006 | MITRE — Windows Command Shell | Current definition retrieved 2026-07-22 | Technique definition | T1059.003 | sample | https://attack.mitre.org/techniques/T1059/003/ | Capability only |
| EXT-007 | MITRE — Modify Registry | Current definition retrieved 2026-07-22 | Technique definition | T1112 | sample | https://attack.mitre.org/techniques/T1112/ | Static configuration plus dynamic Registry activity |
| EXT-008 | MITRE — Query Registry | Current definition retrieved 2026-07-22 | Technique definition | T1012 | sample | https://attack.mitre.org/techniques/T1012/ | Static configuration search |
| EXT-009 | MITRE — Web Protocols | Current definition retrieved 2026-07-22 | Technique definition | T1071.001 | sample | https://attack.mitre.org/techniques/T1071/001/ | Local listener; no external session |
| EXT-010 | MITRE — Symmetric Cryptography | Current definition retrieved 2026-07-22 | Technique definition | T1573.001 | sample | https://attack.mitre.org/techniques/T1573/001/ | RC4-style capability |
| EXT-011 | MITRE — Asymmetric Cryptography | Current definition retrieved 2026-07-22 | Technique definition | T1573.002 | sample | https://attack.mitre.org/techniques/T1573/002/ | RSA public-key capability |
| EXT-012 | MITRE — Standard Encoding | Current definition retrieved 2026-07-22 | Technique definition | T1132.001 | sample | https://attack.mitre.org/techniques/T1132/001/ | Base64 processing |
| EXT-013 | MITRE — Deobfuscate/Decode Files or Information | Current definition retrieved 2026-07-22 | Technique definition | T1140 | sample | https://attack.mitre.org/techniques/T1140/ | Decode/decrypt before use |
| EXT-014 | MITRE — Ingress Tool Transfer | Current definition retrieved 2026-07-22 | Technique definition | T1105 | sample | https://attack.mitre.org/techniques/T1105/ | Capability only; no transfer observed |
| EXT-015 | MITRE — Data from Local System | Current definition retrieved 2026-07-22 | Candidate definition | T1005 | candidate | https://attack.mitre.org/techniques/T1005/ | File-read capability does not prove collection |
| EXT-016 | MITRE — Local Data Staging | Current definition retrieved 2026-07-22 | Candidate definition | T1074.001 | candidate | https://attack.mitre.org/techniques/T1074/001/ | Empty storage directory does not prove staging |
| EXT-017 | Microsoft — Kazuar: Anatomy of a nation-state botnet | 2026-05-14 | Recent actor/tooling activity | Group context only | group | https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/ | Kazuar is not the analyzed sample |
| EXT-018 | Microsoft — Frozen in transit / ApolloShadow | 2025-07-31 | Recent Secret Blizzard campaign | Group context only | group | https://www.microsoft.com/en-us/security/blog/2025/07/31/frozen-in-transit-secret-blizzards-aitm-campaign-against-diplomats/ | ApolloShadow is not the analyzed sample |
| EXT-019 | Google Threat Intelligence — STOCKSTAY Another Day | 2026-06-25 | Latest public activity-status evidence | Group context only | group | https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering | STOCKSTAY is not the analyzed sample |
| EXT-020 | UK NCSC — Turla malware publication | Public document; date not invented | Government threat reporting | Group context only | group | https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB | Background and attribution context |
| EXT-021 | UK NCSC — Turla group malware alert | Public page; date not invented | Government threat reporting | Group context only | group | https://www.ncsc.gov.uk/alerts/turla-group-malware | Background and tradecraft context |
| EXT-022 | UK NCSC — Turla group update | 2019-10-21 | Neuron public context | Group context only | group | https://www.ncsc.gov.uk/news/turla-group-behind-cyber-attack | Does not prove this binary’s operator |
| EXT-023 | Hack The Box Academy — Malware Analysis | Accessed 2026-07-22 | Methodology and training | None directly | methodology | https://academy.hackthebox.com/app/module/234/section/2514 | Supports workflow, not sample evidence |
| EXT-024 | Hack The Box Academy — Incident Reporting | Accessed 2026-07-22 | Reporting methodology | None directly | methodology | https://academy.hackthebox.com/app/module/238/section/2584 | Supports report structure |
| EXT-025 | MITRE ATT&CK — LightNeuron | Current page retrieved 2026-07-22 | Naming-separation context | S0395 | group/software context | https://attack.mitre.org/software/S0395/ | Not treated as the same malware as Turla Neuron/DarkNeuron |
| INT-001 | dnSpy analysis | 2026-07-22 | Decompiled sample logic | T1543.003, T1036.004, T1059.003, T1112, T1012, T1071.001, T1573.001, T1573.002, T1132.001, T1140, T1105 | sample | ../results/dnspy/turla_neuron_dnspy_analysis.md | Primary static evidence |
| INT-002 | Static analysis | 2026-07-22 | File identity and static capability | All sample static mappings | sample | ../results/static/turla_neuron_static_analysis.md | Corroborates decompilation and YARA |
| INT-003 | Dynamic analysis | 2026-07-22 | Consolidated runtime findings | T1543.003, T1036.004, T1112, T1071.001 | sample | ../results/dynamic/turla_neuron_dynamic_analysis.md | Primary dynamic evidence |
| INT-004 | Network analysis | 2026-07-22 | Listener and no-traffic findings | T1071.001; limitations for T1573 and T1132.001 | sample | ../results/network/turla_neuron_network_analysis.md | Zero requests; no external C2 |
| INT-005 | Noriben analysis | 2026-07-22 | Processed file/Registry timeline | T1112, T1543.003 support | sample | ../results/noriben/turla_neuron_noriben_analysis.md | Raw PML limitation retained |
| INT-006 | Procmon analysis | 2026-07-22 | Baseline and raw-PML limitation | Evidence limitation | sample | ../results/procmon/turla_neuron_procmon_analysis.md | Malware-run PML unusable |
| INT-007 | Reverse-engineering integration | 2026-07-22 | Complete reconstructed workflow | All sample mappings/candidates | sample | ../results/reverse-engineering/turla_neuron_reverse_engineering.md | Correlates static and dynamic evidence |
| INT-008 | Sigma service rule | 2026-07-22 | Event-log detection | T1543.003 | sample detection | ../detections/sigma/win_system_turla_neuron_service_install.yml | Detects service installation, not attribution alone |
| INT-009 | YARA rules | 2026-07-22 | Exact and behavioral file detection | Supports multiple sample artifacts | sample detection | ../detections/yara/turla_neuron_v2.yar | File/content detection, not event behavior |
| INT-010 | IOC package | 2026-07-22 | Structured indicators | Supports mapped artifacts | sample detection | ../iocs/turla_neuron_iocs.md | Separates exact from broad indicators |
| INT-011 | Threat-hunting package | 2026-07-22 | Hunt hypotheses and correlation | T1543.003, T1036.004, T1059.003, T1112, T1071.001 | detection recommendation | ../detections/threat-hunting/README.md | No production hunt executed |
| INT-012 | SOAR workflow | 2026-07-22 | Approval-gated response | Defensive coverage context | detection recommendation | ../detections/soar/README.md | Read-only enrichment first |
| INT-013 | Incident report | 2026-07-22 | Case narrative and screenshot evidence | Dynamic mappings and limitations | sample | ../reports/incident-report.md | Primary consolidated report |

## Official G0010 Technique Definitions

These rows make every group-level mapping traceable to its official technique definition. The association itself comes from MITRE G0010.

| Reference ID | Technique | ID | Scope | URL | Group source |
|---|---|---|---|---|---|
| GRP-001 | Create Process with Token | T1134.002 | group | https://attack.mitre.org/techniques/T1134/002/ | https://attack.mitre.org/groups/G0010/ |
| GRP-002 | Local Account | T1087.001 | group | https://attack.mitre.org/techniques/T1087/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-003 | Domain Account | T1087.002 | group | https://attack.mitre.org/techniques/T1087/002/ | https://attack.mitre.org/groups/G0010/ |
| GRP-004 | Web Services | T1583.006 | group | https://attack.mitre.org/techniques/T1583/006/ | https://attack.mitre.org/groups/G0010/ |
| GRP-005 | Web Protocols | T1071.001 | group | https://attack.mitre.org/techniques/T1071/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-006 | Mail Protocols | T1071.003 | group | https://attack.mitre.org/techniques/T1071/003/ | https://attack.mitre.org/groups/G0010/ |
| GRP-007 | Archive via Utility | T1560.001 | group | https://attack.mitre.org/techniques/T1560/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-008 | Registry Run Keys / Startup Folder | T1547.001 | group | https://attack.mitre.org/techniques/T1547/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-009 | Winlogon Helper DLL | T1547.004 | group | https://attack.mitre.org/techniques/T1547/004/ | https://attack.mitre.org/groups/G0010/ |
| GRP-010 | Brute Force | T1110 | group | https://attack.mitre.org/techniques/T1110/ | https://attack.mitre.org/groups/G0010/ |
| GRP-011 | PowerShell | T1059.001 | group | https://attack.mitre.org/techniques/T1059/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-012 | Windows Command Shell | T1059.003 | group | https://attack.mitre.org/techniques/T1059/003/ | https://attack.mitre.org/groups/G0010/ |
| GRP-013 | Visual Basic | T1059.005 | group | https://attack.mitre.org/techniques/T1059/005/ | https://attack.mitre.org/groups/G0010/ |
| GRP-014 | Python | T1059.006 | group | https://attack.mitre.org/techniques/T1059/006/ | https://attack.mitre.org/groups/G0010/ |
| GRP-015 | JavaScript | T1059.007 | group | https://attack.mitre.org/techniques/T1059/007/ | https://attack.mitre.org/groups/G0010/ |
| GRP-016 | Virtual Private Server | T1584.003 | group | https://attack.mitre.org/techniques/T1584/003/ | https://attack.mitre.org/groups/G0010/ |
| GRP-017 | Server | T1584.004 | group | https://attack.mitre.org/techniques/T1584/004/ | https://attack.mitre.org/groups/G0010/ |
| GRP-018 | Web Services | T1584.006 | group | https://attack.mitre.org/techniques/T1584/006/ | https://attack.mitre.org/groups/G0010/ |
| GRP-019 | Windows Credential Manager | T1555.004 | group | https://attack.mitre.org/techniques/T1555/004/ | https://attack.mitre.org/groups/G0010/ |
| GRP-020 | Databases | T1213.006 | group | https://attack.mitre.org/techniques/T1213/006/ | https://attack.mitre.org/groups/G0010/ |
| GRP-021 | Data from Local System | T1005 | group | https://attack.mitre.org/techniques/T1005/ | https://attack.mitre.org/groups/G0010/ |
| GRP-022 | Data from Removable Media | T1025 | group | https://attack.mitre.org/techniques/T1025/ | https://attack.mitre.org/groups/G0010/ |
| GRP-023 | Deobfuscate/Decode Files or Information | T1140 | group | https://attack.mitre.org/techniques/T1140/ | https://attack.mitre.org/groups/G0010/ |
| GRP-024 | Malware | T1587.001 | group | https://attack.mitre.org/techniques/T1587/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-025 | Disable or Modify Tools | T1685 | group | https://attack.mitre.org/techniques/T1685/ | https://attack.mitre.org/groups/G0010/ |
| GRP-026 | Drive-by Compromise | T1189 | group | https://attack.mitre.org/techniques/T1189/ | https://attack.mitre.org/groups/G0010/ |
| GRP-027 | Windows Management Instrumentation Event Subscription | T1546.003 | group | https://attack.mitre.org/techniques/T1546/003/ | https://attack.mitre.org/groups/G0010/ |
| GRP-028 | PowerShell Profile | T1546.013 | group | https://attack.mitre.org/techniques/T1546/013/ | https://attack.mitre.org/groups/G0010/ |
| GRP-029 | Exfiltration to Cloud Storage | T1567.002 | group | https://attack.mitre.org/techniques/T1567/002/ | https://attack.mitre.org/groups/G0010/ |
| GRP-030 | Exploitation for Privilege Escalation | T1068 | group | https://attack.mitre.org/techniques/T1068/ | https://attack.mitre.org/groups/G0010/ |
| GRP-031 | File and Directory Discovery | T1083 | group | https://attack.mitre.org/techniques/T1083/ | https://attack.mitre.org/groups/G0010/ |
| GRP-032 | Group Policy Discovery | T1615 | group | https://attack.mitre.org/techniques/T1615/ | https://attack.mitre.org/groups/G0010/ |
| GRP-033 | File/Path Exclusions | T1564.012 | group | https://attack.mitre.org/techniques/T1564/012/ | https://attack.mitre.org/groups/G0010/ |
| GRP-034 | Ingress Tool Transfer | T1105 | group | https://attack.mitre.org/techniques/T1105/ | https://attack.mitre.org/groups/G0010/ |
| GRP-035 | Lateral Tool Transfer | T1570 | group | https://attack.mitre.org/techniques/T1570/ | https://attack.mitre.org/groups/G0010/ |
| GRP-036 | Match Legitimate Resource Name or Location | T1036.005 | group | https://attack.mitre.org/techniques/T1036/005/ | https://attack.mitre.org/groups/G0010/ |
| GRP-037 | Modify Registry | T1112 | group | https://attack.mitre.org/techniques/T1112/ | https://attack.mitre.org/groups/G0010/ |
| GRP-038 | Native API | T1106 | group | https://attack.mitre.org/techniques/T1106/ | https://attack.mitre.org/groups/G0010/ |
| GRP-039 | Indicator Removal from Tools | T1027.005 | group | https://attack.mitre.org/techniques/T1027/005/ | https://attack.mitre.org/groups/G0010/ |
| GRP-040 | Command Obfuscation | T1027.010 | group | https://attack.mitre.org/techniques/T1027/010/ | https://attack.mitre.org/groups/G0010/ |
| GRP-041 | Fileless Storage | T1027.011 | group | https://attack.mitre.org/techniques/T1027/011/ | https://attack.mitre.org/groups/G0010/ |
| GRP-042 | Malware | T1588.001 | group | https://attack.mitre.org/techniques/T1588/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-043 | Tool | T1588.002 | group | https://attack.mitre.org/techniques/T1588/002/ | https://attack.mitre.org/groups/G0010/ |
| GRP-044 | Password Policy Discovery | T1201 | group | https://attack.mitre.org/techniques/T1201/ | https://attack.mitre.org/groups/G0010/ |
| GRP-045 | Peripheral Device Discovery | T1120 | group | https://attack.mitre.org/techniques/T1120/ | https://attack.mitre.org/groups/G0010/ |
| GRP-046 | Local Groups | T1069.001 | group | https://attack.mitre.org/techniques/T1069/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-047 | Domain Groups | T1069.002 | group | https://attack.mitre.org/techniques/T1069/002/ | https://attack.mitre.org/groups/G0010/ |
| GRP-048 | Spearphishing Link | T1566.002 | group | https://attack.mitre.org/techniques/T1566/002/ | https://attack.mitre.org/groups/G0010/ |
| GRP-049 | Process Discovery | T1057 | group | https://attack.mitre.org/techniques/T1057/ | https://attack.mitre.org/groups/G0010/ |
| GRP-050 | Process Injection | T1055 | group | https://attack.mitre.org/techniques/T1055/ | https://attack.mitre.org/groups/G0010/ |
| GRP-051 | Dynamic-link Library Injection | T1055.001 | group | https://attack.mitre.org/techniques/T1055/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-052 | Proxy | T1090 | group | https://attack.mitre.org/techniques/T1090/ | https://attack.mitre.org/groups/G0010/ |
| GRP-053 | Internal Proxy | T1090.001 | group | https://attack.mitre.org/techniques/T1090/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-054 | Query Registry | T1012 | group | https://attack.mitre.org/techniques/T1012/ | https://attack.mitre.org/groups/G0010/ |
| GRP-055 | SMB/Windows Admin Shares | T1021.002 | group | https://attack.mitre.org/techniques/T1021/002/ | https://attack.mitre.org/groups/G0010/ |
| GRP-056 | Remote System Discovery | T1018 | group | https://attack.mitre.org/techniques/T1018/ | https://attack.mitre.org/groups/G0010/ |
| GRP-057 | Security Software Discovery | T1518.001 | group | https://attack.mitre.org/techniques/T1518/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-058 | Code Signing Policy Modification | T1553.006 | group | https://attack.mitre.org/techniques/T1553/006/ | https://attack.mitre.org/groups/G0010/ |
| GRP-059 | System Information Discovery | T1082 | group | https://attack.mitre.org/techniques/T1082/ | https://attack.mitre.org/groups/G0010/ |
| GRP-060 | System Network Configuration Discovery | T1016 | group | https://attack.mitre.org/techniques/T1016/ | https://attack.mitre.org/groups/G0010/ |
| GRP-061 | Internet Connection Discovery | T1016.001 | group | https://attack.mitre.org/techniques/T1016/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-062 | System Network Connections Discovery | T1049 | group | https://attack.mitre.org/techniques/T1049/ | https://attack.mitre.org/groups/G0010/ |
| GRP-063 | System Service Discovery | T1007 | group | https://attack.mitre.org/techniques/T1007/ | https://attack.mitre.org/groups/G0010/ |
| GRP-064 | System Time Discovery | T1124 | group | https://attack.mitre.org/techniques/T1124/ | https://attack.mitre.org/groups/G0010/ |
| GRP-065 | Malicious Link | T1204.001 | group | https://attack.mitre.org/techniques/T1204/001/ | https://attack.mitre.org/groups/G0010/ |
| GRP-066 | Local Accounts | T1078.003 | group | https://attack.mitre.org/techniques/T1078/003/ | https://attack.mitre.org/groups/G0010/ |
| GRP-067 | Web Service | T1102 | group | https://attack.mitre.org/techniques/T1102/ | https://attack.mitre.org/groups/G0010/ |
| GRP-068 | Bidirectional Communication | T1102.002 | group | https://attack.mitre.org/techniques/T1102/002/ | https://attack.mitre.org/groups/G0010/ |

## MITRE G0010 Layer Association References

The official downloadable G0010 layer supplies comments linking techniques to these group and software records. They are preserved as MITRE’s association context, not treated as direct evidence from this sample.

| Reference ID | MITRE object | URL | Role |
|---|---|---|---|
| ASSOC-001 | Turla G0010 | https://attack.mitre.org/groups/G0010/ | Primary group record |
| ASSOC-002 | G0049 | https://attack.mitre.org/groups/G0049/ | Group/campaign association cited in official layer comments |
| ASSOC-003 | S0002 | https://attack.mitre.org/software/S0002/ | Software association cited in official layer comments |
| ASSOC-004 | S0168 | https://attack.mitre.org/software/S0168/ | Software association cited in official layer comments |
| ASSOC-005 | S0194 | https://attack.mitre.org/software/S0194/ | Software association cited in official layer comments |
| ASSOC-006 | S0363 | https://attack.mitre.org/software/S0363/ | Software association cited in official layer comments |
| ASSOC-007 | S0581 | https://attack.mitre.org/software/S0581/ | Software association cited in official layer comments |
| ASSOC-008 | S0590 | https://attack.mitre.org/software/S0590/ | Software association cited in official layer comments |
| ASSOC-009 | S1141 | https://attack.mitre.org/software/S1141/ | Software association cited in official layer comments |
| ASSOC-010 | PowerShell Profile | https://attack.mitre.org/techniques/T1546/013/ | Technique cross-reference cited in official layer comments |

## Coverage Rules

Every sample mapping in this package has an official MITRE definition and at least one `INT-*` evidence reference. Group rows come only from MITRE G0010 and link to their official technique pages. Microsoft, Google, NCSC, and HTB sources supply context or methodology; none substitutes for an ATT&CK definition or direct sample evidence.
