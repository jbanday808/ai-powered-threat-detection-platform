# Lumma Stealer Credential Theft Investigation

# Executive Summary

This case study documents the investigation of a Lumma Stealer malware sample inside a controlled and isolated malware analysis lab.

The goal of the investigation was to identify what the malware does, collect indicators of compromise, perform reverse engineering, map the behavior to MITRE ATT&CK, and create detection content that security teams can use to find similar threats.

The investigation confirmed behavior consistent with credential theft malware, including browser password targeting, password decryption functions, system discovery, process discovery, and privilege-related activity.

Reverse engineering was performed using IDA Pro to review strings, functions, and malware capabilities without exposing active malware in the repository.

No live malware, executables, archives, or payloads are included in this repository.

# Recruiter Quick Facts

| Category | Details |
|----------|---------|
| Project Type | Malware Investigation & Threat Hunting Case Study |
| Malware Family | Lumma Stealer / SalatStealer |
| Investigation Status | Complete |
| Primary Objective | Investigate credential theft malware and develop reusable detection content |
| Lab Environment | Isolated Malware Analysis Lab |
| Primary Skills | Malware Analysis, Reverse Engineering, Threat Hunting, Detection Engineering, Incident Response |
| Detection Content | Custom YARA Rule, IOC Development, Splunk Threat Hunting Queries |
| Framework | MITRE ATT&CK |
| Analysis Types | Static Analysis, Dynamic Analysis, Reverse Engineering |
| Outcome | Successfully analyzed malware behavior, validated detections, mapped ATT&CK techniques, documented findings, and developed reusable detection content. |

### Why This Project Matters

This case study demonstrates the complete workflow used by a Cyber Intrusion Analyst to investigate malware, identify attacker behavior, develop detections, document findings, and communicate results to both technical and non-technical audiences.

# Investigation Dashboard

| Category                   | Status        |
| -------------------------- | ------------- |
| Malware Family             | Lumma Stealer |
| Investigation Status       | Complete      |
| Static Analysis            | Complete      |
| Dynamic Analysis           | Complete      |
| Reverse Engineering        | Complete      |
| MITRE ATT&CK Mapping       | Complete      |
| IOC Development            | Complete      |
| YARA Detection             | Complete      |
| Splunk Threat Hunting      | Complete      |
| Incident Report            | Complete      |
| Threat Intelligence Report | Complete      |
| Defender Validation        | Complete      |

# Project Navigation

## Reports

* [Threat Intelligence Report](reports/threat-intelligence-report.md)
* [Incident Report](reports/incident-report.md)
* [MITRE ATT&CK Mapping](reports/mitre-attack.md)
* [Splunk Threat Hunting Report](reports/splunk-threat-hunting.md)
* [Static Analysis Summary](reports/static-analysis.md)
* [Dynamic Analysis Summary](reports/dynamic-analysis.md)
* [Lessons Learned](reports/lessons-learned.md)

## Detection Content

* [Custom Lumma Stealer YARA Rule](rules/yara/lumma_custom.yar)

## Indicators of Compromise

* [Lumma Stealer IOC List](iocs/lumma-iocs.csv)

## Evidence

* [Screenshot Evidence Guide](screenshots/README.md)
* [Investigation Screenshots](screenshots/)

## References

* [Investigation References](references/README.md)

# Investigation Timeline

| Phase    | Activity                    |
| -------- | --------------------------- |
| Phase 1  | Malware Intelligence Review |
| Phase 2  | Static Analysis             |
| Phase 3  | Reverse Engineering         |
| Phase 4  | Dynamic Analysis            |
| Phase 5  | Credential Theft Review     |
| Phase 6  | MITRE ATT&CK Mapping        |
| Phase 7  | IOC Development             |
| Phase 8  | YARA Detection Development  |
| Phase 9  | Splunk Threat Hunting       |
| Phase 10 | Incident Documentation      |
| Phase 11 | Final Assessment            |

### Simple Summary

This timeline shows how the malware was investigated from initial identification through reverse engineering, detection development, threat hunting, and final reporting.

# Project Overview

Lumma Stealer is an information-stealing malware family designed to collect sensitive data from infected systems.

This project demonstrates how a Cyber Intrusion Analyst can safely investigate malware, perform reverse engineering, document findings, create reusable detections, and explain technical results in a clear way.

### Simple Summary

This project shows how an analyst studies malware, identifies what it is designed to steal, validates detections, and creates defensive content to help find similar threats.

# Investigation Objectives

* Safely analyze the malware sample in a controlled lab.
* Identify credential theft behavior.
* Perform reverse engineering using IDA Pro.
* Identify malware strings, functions, and credential theft indicators.
* Document static and dynamic analysis findings.
* Validate Microsoft Defender detections.
* Develop Indicators of Compromise.
* Map findings to MITRE ATT&CK.
* Create YARA and Splunk detection content.
* Present findings in a professional portfolio format.

# Skills Demonstrated

## Malware Analysis

* Static Analysis
* Dynamic Analysis
* Reverse Engineering
* Credential Theft Analysis

## Reverse Engineering

* IDA Pro Analysis
* Malware String Review
* Function Name Review
* Credential Theft Function Identification
* Browser Credential Collection Review
* DPAPI-Related Function Review
* Privilege-Related Function Review

### Simple Summary

Reverse engineering helped identify what the malware was designed to do by reviewing its internal strings and functions.

## Threat Hunting

* IOC Development
* Splunk Investigations
* Detection Validation

## Incident Response

* Investigation Documentation
* Evidence Collection
* Containment Recommendations

## Detection Engineering

* YARA Rule Development
* MITRE ATT&CK Mapping
* Threat Intelligence Enrichment

# Tools Used

| Tool               | Purpose                                               |
| ------------------ | ----------------------------------------------------- |
| MalwareBazaar      | Malware intelligence and sample details               |
| IDA Pro            | Reverse engineering, string review, and malware function analysis |
| Noriben            | Dynamic behavior monitoring                           |
| Process Monitor    | Process and file activity review                      |
| Microsoft Defender | Detection, quarantine, and removal validation         |
| YARA               | Malware detection rule development                    |
| Splunk             | Threat hunting query development                      |
| MITRE ATT&CK       | Mapping malware behavior to known attacker techniques |

# Technologies Used

| Category | Technologies |
|----------|--------------|
| SIEM | Splunk Enterprise |
| Malware Analysis | IDA Pro, Noriben, Process Monitor |
| Detection Engineering | YARA |
| Threat Intelligence | MalwareBazaar, VirusTotal |
| Endpoint Security | Microsoft Defender |
| Threat Hunting | Splunk SPL |
| Frameworks | MITRE ATT&CK |
| Operating Systems | Windows 11, Kali Linux |
| Documentation | Markdown, GitHub |

### Skills Applied

- Malware Analysis
- Reverse Engineering
- Threat Hunting
- Detection Engineering
- Incident Response
- IOC Development
- MITRE ATT&CK Mapping
- Microsoft Defender Investigation
- Splunk Threat Hunting
- Technical Documentation

# Key Findings

## Reverse Engineering Findings

Evidence:

* `main.getChromeLogins`
* `main.GetChromiumMasterKeys`
* `main.loginPBE.Decrypt`
* `main.DPAPI`
* `main.enablePrivilege`
* `main.findLsassProcess`
* `main.impersonateSystem`

Simple explanation:

Reverse engineering showed that the malware contained functions related to browser credential theft, password decryption, system discovery, and privilege-related activity.

Non-technical explanation:

This means the malware was designed to search for valuable information, especially saved browser passwords, and attempt to access protected data on the computer.

## Browser Credential Collection

Evidence:

* `main.getChromeLogins`
* `main.getEdgeLogins`
* `main.GetChromiumMasterKeys`

Simple explanation:

Reverse engineering identified functions that target saved browser credentials from Chrome and Edge.

## Password Decryption

Evidence:

* `main.loginPBE.Decrypt`
* `main.DPAPI`

Simple explanation:

Reverse engineering identified functions that may help the malware unlock protected password data stored on the computer.

## Process and System Discovery

Evidence:

* `main.findLsassProcess`
* `main.NtQuerySystemHandles`

Simple explanation:

The malware looks at running processes and system information to better understand the infected computer.

## Privilege-Related Activity

Evidence:

* `main.enablePrivilege`
* `main.getSystemToken`
* `main.impersonateSystem`

Simple explanation:

The malware contains functions that may help it request higher access on the system.

## Defender Detection and Remediation

Microsoft Defender detected, blocked, quarantined, and removed the malware sample.

Simple explanation:

The security tool identified the file as malicious and stopped it from continuing to run.

# IOC Summary

**Summary:** These indicators show that the sample was designed to collect browser credentials, decrypt protected password data, inspect the system, and attempt to gain higher privileges.

The complete indicator list is available in [`iocs/lumma-iocs.csv`](iocs/lumma-iocs.csv).

# MITRE ATT&CK Highlights

| Tactic            | Technique                         | ID        | Simple Meaning                               |
| ----------------- | --------------------------------- | --------- | -------------------------------------------- |
| Execution         | Command and Scripting Interpreter | T1059     | Malware ran on the system                    |
| Discovery         | Process Discovery                 | T1057     | Malware looked for running processes         |
| Discovery         | System Information Discovery      | T1082     | Malware collected system details             |
| Credential Access | Credentials from Password Stores  | T1555     | Malware targeted saved passwords             |
| Credential Access | Credentials from Web Browsers     | T1555.003 | Malware targeted Chrome and Edge credentials |
| Credential Access | Unsecured Credentials             | T1552     | Malware attempted to decrypt password data   |
| Collection        | Data from Local System            | T1005     | Malware collected local system data          |
| Defense Evasion   | Access Token Manipulation         | T1134     | Malware attempted higher-level access        |
| Defense Evasion   | Abuse Elevation Control Mechanism | T1548     | Malware attempted privilege escalation       |

# Analyst Conclusion

The Lumma Stealer investigation confirmed the malware family, validated file and network indicators, documented credential theft functionality, and produced reusable detection and threat hunting content.

Static analysis and reverse engineering identified browser credential collection functions, password decryption capabilities, Chromium master key access routines, process discovery functions, and privilege-related functionality.

Dynamic analysis using Noriben, Process Monitor, and Microsoft Defender validated malware execution activity and provided evidence of detection, quarantine, blocking, and remediation actions.

Threat intelligence sources including MalwareBazaar, Microsoft Defender, and reverse engineering findings strengthened confidence in the final assessment. A custom YARA rule was also created for future local validation.

This case study demonstrates practical Cyber Intrusion Analyst and Threat Hunter skills, including malware analysis, reverse engineering, IOC enrichment, detection engineering, MITRE ATT&CK mapping, Splunk investigation workflows, and incident response documentation.

# Summary

This project demonstrates practical Cyber Intrusion Analyst and Threat Hunter skills through the investigation of a credential theft malware sample.

Key competencies demonstrated include:

* Malware Analysis
* Reverse Engineering
* Threat Hunting
* Incident Response
* IOC Development
* MITRE ATT&CK Mapping
* Detection Engineering
* Microsoft Defender Investigations
* Splunk Threat Hunting
* Technical Documentation

### Simple Summary

This project shows the complete workflow used by security analysts to investigate malware, perform reverse engineering, validate detections, document findings, and develop defensive security content.

# Safety Notice

* Defensive cybersecurity research only.
* No malware samples included.
* No executable files included.
* No ZIP archives included.
* No credentials included.
* No sensitive data included.
* No malware execution instructions included.

# Author

James Banday

Threat Hunter | Cyber Intrusion Analyst | Cloud Security | Kubernetes | DevSecOps | Incident Response

This case study demonstrates practical malware analysis, reverse engineering, threat hunting, IOC enrichment, Microsoft Defender investigation, Splunk threat hunting workflows, detection engineering, MITRE ATT&CK mapping, and incident response documentation used to investigate and document Lumma Stealer credential theft activity within a controlled malware analysis lab environment.

## GitHub Repository

https://github.com/jbanday808/ai-eks-threat-hunting-platform/tree/main

## LinkedIn Profile

https://www.linkedin.com/in/james-allen-morta-banday-62a391128/
