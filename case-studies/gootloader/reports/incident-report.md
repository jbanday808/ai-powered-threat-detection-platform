# Incident Report – GootLoader

## Executive Summary

This report documents a controlled malware analysis investigation of a GootLoader JavaScript sample inside an isolated lab.

The sample executed through Windows Script Host, showed limited local activity, and exited quickly.

No child processes, persistence, network indicators, or second-stage execution were observed during the lab investigation.

---

## Incident Overview

| Field | Details |
| --- | --- |
| Incident Type | Malware Analysis Case Study |
| Malware Family | GootLoader |
| File Type | JavaScript |
| Sample Name | `Legal_Case_Documents_2026.js` |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` |
| Environment | Isolated Malware Analysis Lab |
| Status | Analysis Complete |

---

## Scope

This was a controlled lab investigation, not a real enterprise compromise.

The investigation focused on confirmed behavior observed during safe analysis.

Scope included:

* Static analysis
* Dynamic analysis
* IOC review
* Microsoft Defender log review
* MITRE ATT&CK mapping
* YARA and Sigma detection development

---

## Detection Summary

| Detection Area | Result |
| --- | --- |
| MalwareBazaar | Sample identified |
| VirusTotal | File reputation reviewed |
| YARA | Custom rule matched sample |
| Sigma | Suspicious JavaScript execution rule created |
| Microsoft Defender | No confirmed detection for this execution |
| Network IOCs | None observed |

---

## Observed Activity

| Activity | Observation |
| --- | --- |
| Script execution | Observed through `wscript.exe` |
| DLL loading | Observed |
| Registry queries | Observed |
| File activity | Observed |
| Process exit | Observed |
| Child processes | Not observed |
| Persistence | Not observed |
| Network traffic | No domains or IPs observed |

---

## Timeline of Events

| Phase | Event |
| --- | --- |
| 1 | Sample obtained from MalwareBazaar |
| 2 | Hash and file details verified using VirusTotal |
| 3 | Static JavaScript analysis performed |
| 4 | Obfuscated functions and variables identified |
| 5 | Sample executed in isolated Windows VM |
| 6 | Process Monitor captured `wscript.exe` activity |
| 7 | Microsoft Defender logs reviewed |
| 8 | Custom YARA rule created and validated |
| 9 | MITRE ATT&CK mapping completed |
| 10 | Findings documented |

---

## Impact Assessment

Because this investigation was performed in an isolated lab, no production systems were affected.

No data loss, credential theft, lateral movement, persistence, or network-based indicators were observed.

| Impact Area | Result |
| --- | --- |
| Production systems affected | No |
| Data loss | Not observed |
| Credential theft | Not observed |
| Lateral movement | Not observed |
| Persistence | Not observed |
| Network-based IOCs | None observed |

---

## Root Cause

This was not a real user infection.

For this case study, the root cause was controlled execution of a known malware sample for defensive research.

---

## Containment Actions

* Used an isolated malware analysis VM.
* Took a VMware snapshot before execution.
* Avoided storing live malware in the public repository.
* Reviewed Microsoft Defender logs.
* Documented findings and detections.

---

## Eradication and Recovery

Since this was a lab environment, recovery would consist of reverting to the clean VMware snapshot.

Analysis artifacts could also be removed if needed.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

---

## Indicators of Compromise

| Type | Value |
| --- | --- |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` |
| SHA-1 | `7b468a279606b62b0abe1a3e14aa16f0c9e6b93d` |
| MD5 | `95238ad5a91d721c6e8fdf4c36187798` |
| File Name | `Legal_Case_Documents_2026.js` |
| Process | `wscript.exe` |
| Domains | None observed |
| IP Addresses | None observed |

---

## Recommendations

* Monitor suspicious JavaScript execution through `wscript.exe` and `cscript.exe`.
* Alert on JavaScript launched from user folders, Downloads, Temp, or malware staging folders.
* Use YARA to scan suspicious JavaScript files.
* Review Microsoft Defender and endpoint logs for script execution.
* Block or restrict Windows Script Host where not required.
* Train users to avoid opening unexpected document-themed script files.

---

## Analyst Conclusion

The investigation confirmed an obfuscated GootLoader JavaScript sample and documented its static and limited dynamic behavior.

The sample executed through `wscript.exe`, performed limited local activity, and exited quickly in the isolated lab.

No network IOCs, persistence, child processes, or second-stage payload execution were observed.

The investigation still produced valuable defensive content, including YARA and Sigma rules.

---

## References

* [MalwareBazaar](https://bazaar.abuse.ch/)
* [VirusTotal](https://www.virustotal.com/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [Microsoft Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
* [Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender/)
* [YARA Documentation](https://yara.readthedocs.io/)
* [Sigma Documentation](https://sigmahq.io/)
