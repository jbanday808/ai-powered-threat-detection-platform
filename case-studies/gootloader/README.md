# GootLoader JavaScript Malware Investigation

# Executive Summary

This case study documents the analysis of a GootLoader JavaScript malware sample inside an isolated malware analysis lab.

The sample used for analysis was named `Legal_Case_Documents_2026.js`.

The investigation reviewed static file content, controlled execution behavior, Microsoft Defender logs, and custom YARA detection results.

Static analysis showed obfuscated JavaScript and hidden string reconstruction. Dynamic analysis showed `wscript.exe` execution, Windows DLL loading, registry queries, file activity, and a quick process exit.

No child processes, network domains, or IP addresses were observed during the lab run.

No live malware, payloads, ZIP files, or unsafe instructions are included in this repository.

# Quick Facts

| Category | Finding |
| --- | --- |
| Malware Family | GootLoader |
| File Type | JavaScript |
| Sample Name | `Legal_Case_Documents_2026.js` |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` |
| Execution Process | `wscript.exe` |
| Child Processes Observed | None |
| Network Domains Observed | None |
| Network IPs Observed | None |
| Defender Logs Reviewed | Yes |
| YARA Detection | Custom rule matched the sample |

# Why This Project Matters

GootLoader is commonly associated with fake document lures and script-based execution.

This project shows how an analyst can safely study a suspicious JavaScript file, document what happened in a lab, and create defensive detection content without sharing harmful files.

### Simple Summary

This project explains how a suspicious JavaScript file was checked safely and turned into useful security findings.

# Investigation Dashboard

| Category | Status |
| --- | --- |
| Malware Family Identification | Complete |
| Isolated Lab Analysis | Complete |
| Static Analysis | Complete |
| Dynamic Analysis | Complete |
| Microsoft Defender Review | Complete |
| IOC Development | Complete |
| YARA Detection | Complete |
| Sigma Detection | Complete |
| Splunk Threat Hunting | Complete |
| MITRE ATT&CK Mapping | Complete |
| Incident Report | Complete |
| Final Documentation | Complete |

# Project Navigation

## Reports

* [Executive Summary](reports/executive-summary.md)
* [Threat Intelligence Report](reports/threat-intelligence-report.md)
* [Incident Report](reports/incident-report.md)
* [MITRE ATT&CK Mapping](reports/mitre-attack.md)
* [Static Analysis Summary](reports/static-analysis.md)
* [Dynamic Analysis Summary](reports/dynamic-analysis.md)
* [Splunk Threat Hunting Report](reports/splunk-threat-hunting.md)
* [Sigma Analysis](reports/sigma-analysis.md)
* [YARA Analysis](reports/yara-analysis.md)
* [Investigation Timeline](reports/timeline.md)
* [Lessons Learned](reports/lessons-learned.md)

## Detection Content

* [Custom GootLoader YARA Rule](rules/yara/gootloader_custom.yar)
* [GootLoader Sigma Rule](rules/sigma/gootloader-javascript-execution.yml)
* [GootLoader Suricata Rule](rules/suricata/gootloader.rules)

## Indicators of Compromise

* [GootLoader IOC List](iocs/gootloader-iocs.csv)

## Evidence

* [Pre-Execution VM Snapshot](screenshots/GootLoader_01_VMware_PreExecution_Snapshot.png)
* [MalwareBazaar Details](screenshots/GootLoader_02_MalwareBazaar_Details.png)
* [VirusTotal Details](screenshots/GootLoader_03_VirusTotal_Details.png.png)
* [Injected JavaScript Function](screenshots/GootLoader_05_Injected_stop_Function.png)
* [Obfuscated String Variables](screenshots/GootLoader_10_Obfuscated_String_Variables.png)
* [Process Execution and Exit](screenshots/GootLoader_11_Process_Execution_and_Exit.png)
* [Microsoft Defender Event Log](screenshots/GootLoader_12_Microsoft_Defender_Event_Log.png)
* [YARA Rule Match](screenshots/GootLoader_13_YARA_Rule_Match.png)
* [Static Execution Diagram](screenshots/GootLoader_Static_Execution_Diagram.png)
* [Dynamic Execution Diagram](screenshots/GootLoader_Dynamic_Execution_Diagram.png)

## References

* [Investigation References](references/README.md)
* [Safety Notes](references/SAFETY.md)

# Investigation Timeline

| Phase | Activity |
| --- | --- |
| Phase 1 | Prepare isolated lab |
| Phase 2 | Review malware intelligence sources |
| Phase 3 | Capture pre-execution evidence |
| Phase 4 | Perform static JavaScript review |
| Phase 5 | Identify obfuscation and string reconstruction |
| Phase 6 | Run controlled dynamic analysis |
| Phase 7 | Review `wscript.exe` behavior |
| Phase 8 | Review Microsoft Defender logs |
| Phase 9 | Develop and test YARA detection |
| Phase 10 | Map findings to MITRE ATT&CK |
| Phase 11 | Document final results |

### Simple Summary

The investigation started with a safe lab setup, then reviewed the file, observed controlled behavior, created detections, and documented the results.

# Project Overview

GootLoader is a malware family that often uses JavaScript files to start infection activity.

This project analyzed a GootLoader JavaScript sample in an isolated lab. The investigation focused on what could be safely observed and documented without sharing malware or instructions that could help misuse it.

### Simple Summary

This project studied a harmful JavaScript file in a safe lab and turned the findings into defensive documentation.

# Investigation Objectives

* Safely analyze a GootLoader JavaScript sample in an isolated lab.
* Review the file without publishing live malware.
* Identify obfuscated JavaScript patterns.
* Document hidden string reconstruction.
* Observe controlled execution through `wscript.exe`.
* Review Windows activity such as DLL loading, registry queries, and file activity.
* Review Microsoft Defender logs.
* Create and validate a custom YARA rule.
* Record useful indicators of compromise.
* Map findings to MITRE ATT&CK.
* Present results in a clear portfolio format.

# Skills Demonstrated

## Malware Analysis

* Static JavaScript review
* Dynamic behavior review
* Obfuscation analysis
* Lab evidence collection

## Threat Hunting

* IOC development
* Process behavior review
* Microsoft Defender log review
* Splunk investigation workflow

## Detection Engineering

* YARA rule development
* Sigma rule development
* MITRE ATT&CK mapping
* Defensive documentation

## Incident Response

* Timeline writing
* Evidence handling
* Analyst reporting
* Safety-focused malware documentation

# Tools Used

| Tool | Purpose |
| --- | --- |
| VMware | Isolated lab environment and snapshot control |
| MalwareBazaar | Malware intelligence and sample metadata review |
| VirusTotal | External detection and reputation review |
| JavaScript static review tools | Obfuscation and string review |
| Process Monitor | Process, file, registry, and DLL activity review |
| Microsoft Defender | Security event and detection log review |
| YARA | Custom malware detection rule validation |
| Sigma | Detection logic development |
| Splunk | Threat hunting query development |
| MITRE ATT&CK | Mapping observed behavior to known techniques |

# Project Highlights

* Confirmed the sample as GootLoader.
* Analyzed a JavaScript file named `Legal_Case_Documents_2026.js`.
* Documented the SHA-256 hash for tracking and detection.
* Found obfuscated JavaScript and hidden string reconstruction.
* Observed execution through `wscript.exe`.
* Observed Windows DLL loading, registry queries, file activity, and quick process exit.
* Confirmed that no child processes were observed.
* Confirmed that no domains or IP addresses were observed.
* Reviewed Microsoft Defender logs.
* Validated a custom YARA rule against the sample.

# Investigation Evidence

| Evidence | Description |
| --- | --- |
| [Pre-Execution VM Snapshot](screenshots/GootLoader_01_VMware_PreExecution_Snapshot.png) | Shows the lab state before controlled analysis. |
| [MalwareBazaar Details](screenshots/GootLoader_02_MalwareBazaar_Details.png) | Shows malware intelligence metadata. |
| [VirusTotal Details](screenshots/GootLoader_03_VirusTotal_Details.png.png) | Shows external reputation and detection context. |
| [Injected JavaScript Function](screenshots/GootLoader_05_Injected_stop_Function.png) | Shows suspicious JavaScript content found during review. |
| [Obfuscated String Variables](screenshots/GootLoader_10_Obfuscated_String_Variables.png) | Shows hidden string reconstruction indicators. |
| [Process Execution and Exit](screenshots/GootLoader_11_Process_Execution_and_Exit.png) | Shows `wscript.exe` execution and quick exit behavior. |
| [Microsoft Defender Event Log](screenshots/GootLoader_12_Microsoft_Defender_Event_Log.png) | Shows Defender log review evidence. |
| [YARA Rule Match](screenshots/GootLoader_13_YARA_Rule_Match.png) | Shows the custom YARA rule detecting the sample. |
| [Static Execution Diagram](screenshots/GootLoader_Static_Execution_Diagram.png) | Summarizes static analysis findings. |
| [Dynamic Execution Diagram](screenshots/GootLoader_Dynamic_Execution_Diagram.png) | Summarizes dynamic analysis findings. |

# Key Findings

## JavaScript Obfuscation

Static analysis showed obfuscated JavaScript and hidden string reconstruction.

Simple explanation:

The file tried to make its real behavior harder to read.

## Script Execution

Dynamic analysis showed the sample executed through `wscript.exe`.

Simple explanation:

Windows Script Host was used to run the JavaScript file.

## Windows Activity

Dynamic analysis showed Windows DLL loading, registry queries, file activity, and quick process exit.

Simple explanation:

The script interacted with normal Windows components, checked system areas, touched files, and then stopped quickly.

## No Child Processes Observed

No child processes were observed during the lab run.

Simple explanation:

The analysis did not show the script launching another program.

## No Network Indicators Observed

No network domains or IP addresses were observed during the lab run.

Simple explanation:

The analysis did not capture a network destination to report.

## Defender and YARA Validation

Microsoft Defender logs were reviewed, and a custom YARA rule successfully detected the sample.

Simple explanation:

Security logs and a custom detection rule helped confirm and document the finding.

# IOC Summary

| Type | Value |
| --- | --- |
| Malware Family | GootLoader |
| File Name | `Legal_Case_Documents_2026.js` |
| File Type | JavaScript |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` |
| Execution Process | `wscript.exe` |
| Domains | None observed |
| IP Addresses | None observed |

The complete indicator list is available in [`iocs/gootloader-iocs.csv`](iocs/gootloader-iocs.csv).

# MITRE ATT&CK Highlights

| Tactic | Technique | ID | Simple Meaning |
| --- | --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | The malware used JavaScript execution. |
| Defense Evasion | Obfuscated Files or Information | T1027 | The malware hid parts of its code to make analysis harder. |

# Analyst Conclusion

The GootLoader investigation confirmed that the analyzed sample was a JavaScript malware file executed through `wscript.exe` in an isolated lab.

Static analysis found obfuscated JavaScript and hidden string reconstruction. Dynamic analysis showed Windows DLL loading, registry queries, file activity, and a quick process exit.

No child processes, domains, or IP addresses were observed during the analysis window. Microsoft Defender logs were reviewed, and a custom YARA rule successfully detected the sample.

This case study provides a safe, defensive record of the investigation without publishing live malware or unsafe instructions.

# Summary

This project demonstrates practical malware analysis and threat hunting skills through the safe investigation of a GootLoader JavaScript sample.

Key competencies demonstrated include:

* Malware Analysis
* JavaScript Static Analysis
* Dynamic Behavior Review
* Microsoft Defender Investigation
* IOC Development
* YARA Rule Development
* Sigma Detection Logic
* MITRE ATT&CK Mapping
* Splunk Threat Hunting
* Incident Response Documentation

### Simple Summary

This project shows how a security analyst can safely investigate a harmful JavaScript file, document the evidence, and create detections for defenders.

# Safety Notice

* Defensive cybersecurity research only.
* No malware samples included.
* No payloads included.
* No executable files included.
* No ZIP archives included.
* No credentials included.
* No sensitive data included.
* No unsafe malware execution instructions included.

# Author

James Banday

Threat Hunter | Cyber Intrusion Analyst | Cloud Security | Kubernetes | DevSecOps | Incident Response

This case study demonstrates practical malware analysis, threat hunting, IOC development, Microsoft Defender investigation, detection engineering, MITRE ATT&CK mapping, YARA rule development, and incident response documentation used to investigate and document GootLoader JavaScript malware within a controlled malware analysis lab environment.

## GitHub Repository

https://github.com/jbanday808/ai-eks-threat-hunting-platform/tree/main

## LinkedIn Profile

https://www.linkedin.com/in/james-allen-morta-banday-62a391128/
