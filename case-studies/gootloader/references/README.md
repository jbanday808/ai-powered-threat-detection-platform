# References

## Overview

This folder contains the references and research sources used throughout the GootLoader malware analysis case study.

The original malware sample is intentionally excluded from the repository for safety and responsible malware handling.

---

## Sample Information

| Property | Value |
| --- | --- |
| Malware Family | GootLoader |
| File Type | JavaScript |
| Analysis Filename | `Legal_Case_Documents_2026.js` |
| Original Filename | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879.js` |
| MD5 | `95238ad5a91d721c6e8fdf4c36187798` |
| SHA-1 | `7b468a279606b62b0abe1a3e14aa16f0c9e6b93d` |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` |
| File Size | `281.67 KB` |
| Malware Source | MalwareBazaar |
| Analysis Environment | Isolated Windows Malware Analysis VM |

---

## Why the Malware Sample Is Not Included

The original malware sample is intentionally excluded from this public repository.

Sharing live malware is not appropriate for a public GitHub repository. This project focuses on defensive cybersecurity research.

All screenshots, reports, detection rules, and analysis were produced from the original sample inside an isolated malware analysis lab.

---

## Research Sources

| Source | Purpose |
| --- | --- |
| MalwareBazaar | Obtained the malware sample |
| VirusTotal | Verified file hashes and malware reputation |
| MITRE ATT&CK | Mapped observed adversary techniques |
| Microsoft Sysinternals Process Monitor | Captured runtime process activity |
| Microsoft Defender | Reviewed security events and detections |
| CyberChef | Assisted with JavaScript deobfuscation |
| YARA | Created and validated custom detection rules |
| Sigma | Developed SIEM detection rules |
| Suricata | Developed network detection example |
| Splunk | Created threat hunting searches |

---

## Repository Contents

| Component | Description |
| --- | --- |
| README.md | Project overview |
| Static Analysis | JavaScript code analysis |
| Dynamic Analysis | Runtime behavior analysis |
| Executive Summary | High-level investigation summary |
| Threat Intelligence Report | Malware research findings |
| Incident Report | Investigation summary |
| Timeline | Analysis workflow |
| MITRE ATT&CK Mapping | Observed techniques |
| YARA Rule | File-based detection |
| Sigma Rule | SIEM detection |
| Suricata Rule | Example network detection |
| Splunk Threat Hunting | SPL hunting queries |
| Screenshots | Evidence collected during analysis |

---

## Confirmed Indicators

| Indicator | Value |
| --- | --- |
| Malware Family | GootLoader |
| File Type | JavaScript |
| Execution Process | `wscript.exe` |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` |
| Network Domains | None observed |
| IP Addresses | None observed |
| Child Processes | Not observed |
| Persistence | Not observed |

---

## Important Note

This investigation documents the behavior observed from one GootLoader sample analyzed in a controlled lab environment.

Different GootLoader variants may exhibit additional behavior that was not observed during this investigation.

---

## References

* [MalwareBazaar](https://bazaar.abuse.ch/)
* [VirusTotal](https://www.virustotal.com/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [Microsoft Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
* [Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender/)
* [CyberChef](https://gchq.github.io/CyberChef/)
* [YARA Documentation](https://yara.readthedocs.io/)
* [Sigma Documentation](https://sigmahq.io/)
* [Suricata Documentation](https://docs.suricata.io/)
* [Splunk Documentation](https://docs.splunk.com/)
