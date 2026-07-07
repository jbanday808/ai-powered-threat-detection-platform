# GootLoader Investigation Timeline

## Overview

This timeline summarizes the complete GootLoader malware investigation from collecting the sample through documenting the final findings.

Each phase builds on the previous one to understand the malware safely and develop detection content.

---

## Investigation Timeline

| Phase | Activity | Purpose | Status |
| --- | --- | --- | --- |
| Phase 1 | Threat Intelligence | Collected malware intelligence from MalwareBazaar and VirusTotal | Complete |
| Phase 2 | Sample Verification | Verified SHA-256, SHA-1, and MD5 hashes | Complete |
| Phase 3 | Static Analysis | Reviewed obfuscated JavaScript and identified suspicious functions | Complete |
| Phase 4 | Dynamic Analysis | Observed runtime behavior inside an isolated Windows VM | Complete |
| Phase 5 | IOC Development | Collected static and dynamic indicators of compromise | Complete |
| Phase 6 | MITRE ATT&CK Mapping | Mapped observed behavior to ATT&CK techniques | Complete |
| Phase 7 | Detection Engineering | Developed and validated a custom YARA rule | Complete |
| Phase 8 | Documentation | Documented findings and created the case study | Complete |

---

## Phase 1 – Threat Intelligence

The malware sample was obtained from MalwareBazaar for defensive analysis in an isolated lab.

VirusTotal was used to review external detection context and verify sample details. These sources helped confirm the malware family and file hashes.

![MalwareBazaar Details](../screenshots/GootLoader_02_MalwareBazaar_Details.png)

![VirusTotal Details](../screenshots/GootLoader_03_VirusTotal_Details.png.png)

---

## Phase 2 – Sample Verification

The SHA-256, SHA-1, and MD5 hashes were verified before analysis.

Hash verification helped confirm file integrity and ensured the investigation focused on the correct sample.

| Verification | Result |
| --- | --- |
| SHA-256 | Verified |
| SHA-1 | Verified |
| MD5 | Verified |

---

## Phase 3 – Static Analysis

The JavaScript was reviewed safely without executing it.

Static analysis identified obfuscated code, injected functions, hidden string reconstruction, and suspicious variables.

![Injected stop Function](../screenshots/GootLoader_05_Injected_stop_Function.png)

![Legitimate jQuery Code](../screenshots/GootLoader_06_Legitimate_jQuery_Code.png)

![returned Function Analysis](../screenshots/GootLoader_07_returned_Function_Analysis.png)

![el Function Analysis](../screenshots/GootLoader_08_el_Function_Analysis.png)

![adjusted and fxNow Functions](../screenshots/GootLoader_09_adjusted_and_fxNow_Functions.png)

![Obfuscated String Variables](../screenshots/GootLoader_10_Obfuscated_String_Variables.png)

![Static Execution Diagram](../screenshots/GootLoader_Static_Execution_Diagram.png)

---

## Phase 4 – Dynamic Analysis

The JavaScript sample was executed in an isolated Windows VM.

The analysis observed Windows Script Host execution, registry activity, file activity, and quick process exit.

Microsoft Defender logs were reviewed. Payload execution and persistence were not confirmed.

![Pre-Execution VMware Snapshot](../screenshots/GootLoader_01_VMware_PreExecution_Snapshot.png)

![Process Execution and Exit](../screenshots/GootLoader_11_Process_Execution_and_Exit.png)

![Microsoft Defender Event Log](../screenshots/GootLoader_12_Microsoft_Defender_Event_Log.png)

![Dynamic Execution Diagram](../screenshots/GootLoader_Dynamic_Execution_Diagram.png)

---

## Phase 5 – IOC Development

Indicators were collected throughout the investigation.

These indicators support future search, detection, and reporting.

| IOC Type | Observation |
| --- | --- |
| SHA-256 | Collected |
| SHA-1 | Collected |
| MD5 | Collected |
| Process | `wscript.exe` |
| JavaScript File | `Legal_Case_Documents_2026.js` |
| Domains | None observed |
| IP Addresses | None observed |

---

## Phase 6 – MITRE ATT&CK Mapping

| Technique | ID | Purpose |
| --- | --- | --- |
| Command and Scripting Interpreter: JavaScript | T1059.007 | JavaScript execution |
| Obfuscated Files or Information | T1027 | Hidden malicious code |

MITRE ATT&CK mapping helps defenders understand attacker techniques and improve detection.

---

## Phase 7 – Detection Engineering

A custom YARA rule was developed using static indicators from the analysis.

The rule was successfully validated against the original GootLoader malware sample.

![YARA Rule Match](../screenshots/GootLoader_13_YARA_Rule_Match.png)

---

## Phase 8 – Documentation

The investigation was documented through reports, screenshots, diagrams, IOC documentation, MITRE ATT&CK mapping, and detection rules.

The result is a reusable cybersecurity portfolio project focused on defensive malware analysis.

---

## Timeline Summary

| Completed Activity | Status |
| --- | --- |
| Threat Intelligence | Complete |
| Hash Verification | Complete |
| Static Analysis | Complete |
| Dynamic Analysis | Complete |
| IOC Development | Complete |
| MITRE ATT&CK Mapping | Complete |
| YARA Detection | Complete |
| Documentation | Complete |

---

## Lessons Learned

* Malware should always be analyzed in an isolated environment.
* Static analysis helps identify suspicious code before execution.
* Dynamic analysis confirms runtime behavior.
* Not all malware fully executes in a laboratory environment.
* Detection rules improve future malware identification.

---

## Analyst Conclusion

The investigation followed a structured malware analysis workflow from initial identification through static analysis, controlled dynamic analysis, IOC collection, MITRE ATT&CK mapping, detection engineering, and documentation.

The completed timeline demonstrates a repeatable investigation process suitable for enterprise security operations and incident response.

---

## References

* [MalwareBazaar](https://bazaar.abuse.ch/)
* [VirusTotal](https://www.virustotal.com/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [Microsoft Sysinternals](https://learn.microsoft.com/sysinternals/)
* [Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender/)
* [YARA Documentation](https://yara.readthedocs.io/)
