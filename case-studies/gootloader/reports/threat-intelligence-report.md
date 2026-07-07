# Threat Intelligence Report – GootLoader

## Executive Summary

This report summarizes the threat intelligence gathered for a GootLoader JavaScript malware sample.

MalwareBazaar and VirusTotal were used to verify the sample, review reputation details, and support the investigation.

No domains or IP addresses were identified during OSINT review or dynamic analysis for this specific sample.

---

## Threat Overview

GootLoader is a JavaScript-based malware loader.

It is commonly used to trick users into opening a fake document or script that can lead to additional malware being downloaded.

This investigation focused only on the confirmed behavior observed in the lab.

---

## Intelligence Sources

| Source | Purpose |
| --- | --- |
| MalwareBazaar | Sample source and malware intelligence |
| VirusTotal | File reputation, hashes, and detection review |
| Static Analysis | JavaScript code review and obfuscation analysis |
| Dynamic Analysis | Runtime behavior review in an isolated VM |
| Microsoft Defender Logs | Security event review |

---

## Malware Sample Details

| Field | Value |
| --- | --- |
| Malware Family | GootLoader |
| File Type | JavaScript |
| Analysis File Name | `Legal_Case_Documents_2026.js` |
| Original File Name | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879.js` |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` |
| SHA-1 | `7b468a279606b62b0abe1a3e14aa16f0c9e6b93d` |
| MD5 | `95238ad5a91d721c6e8fdf4c36187798` |
| Source | MalwareBazaar |

---

## MalwareBazaar Findings

The sample was obtained from MalwareBazaar for defensive analysis.

MalwareBazaar provided the original sample details and associated the sample with GootLoader.

The SHA-256 hash was used to track and verify the sample during the investigation.

![MalwareBazaar Details](../screenshots/GootLoader_02_MalwareBazaar_Details.png)

---

## VirusTotal Findings

VirusTotal was used to review file reputation.

VirusTotal confirmed file metadata and hash values. These results supported the malware classification.

![VirusTotal Details](../screenshots/GootLoader_03_VirusTotal_Details.png.png)

---

## OSINT Findings

No confirmed domains, IP addresses, or URLs were identified during OSINT review for this specific sample.

| IOC Type | Result |
| --- | --- |
| Domains | None identified |
| IP Addresses | None identified |
| URLs | None identified |
| File Hashes | Identified |
| File Name | Identified |

---

## Static Intelligence Findings

Static analysis showed that the sample contained obfuscated JavaScript.

Legitimate-looking jQuery code was present. Suspicious injected functions, hidden strings, and runtime reconstruction patterns were also observed.

| Finding | Meaning |
| --- | --- |
| Obfuscated JavaScript | Malware logic was hidden |
| Injected Functions | Suspicious code was added into legitimate-looking script |
| String Reconstruction | Hidden values may be rebuilt during runtime |
| jQuery Code | Legitimate-looking code may help disguise the malware |

---

## Dynamic Intelligence Findings

Dynamic analysis confirmed limited runtime behavior in an isolated Windows VM.

The sample executed through `wscript.exe`, loaded Windows DLLs, queried the registry, performed file activity, and exited quickly.

No child processes, domains, or IP addresses were observed.

| Behavior | Result |
| --- | --- |
| `wscript.exe` execution | Observed |
| DLL loading | Observed |
| Registry activity | Observed |
| File activity | Observed |
| Child processes | Not observed |
| Network IOCs | None observed |

---

## Microsoft Defender Findings

Microsoft Defender logs were reviewed.

Historical Defender detection events were present on the VM. No confirmed Defender malware detection was recorded for this specific GootLoader execution.

![Microsoft Defender Event Log](../screenshots/GootLoader_12_Microsoft_Defender_Event_Log.png)

---

## Indicators of Compromise

| Type | Value | Status |
| --- | --- | --- |
| SHA-256 | `53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879` | Confirmed |
| SHA-1 | `7b468a279606b62b0abe1a3e14aa16f0c9e6b93d` | Confirmed |
| MD5 | `95238ad5a91d721c6e8fdf4c36187798` | Confirmed |
| File Name | `Legal_Case_Documents_2026.js` | Confirmed |
| Process | `wscript.exe` | Observed |
| Domains | None observed | Not observed |
| IP Addresses | None observed | Not observed |
| URLs | None observed | Not observed |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Simple Meaning |
| --- | --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | JavaScript was executed by Windows Script Host |
| Defense Evasion | Obfuscated Files or Information | T1027 | Malware hid its logic using obfuscated code |

---

## Risk Summary

GootLoader is risky because it can act as an entry point for additional malware.

Even though this sample did not show second-stage behavior in the isolated lab, its obfuscation and Windows Script Host execution make it suspicious and worth detecting.

---

## Analyst Assessment

Threat intelligence confirmed the sample identity and supported the classification as GootLoader.

No domains or IP addresses were found during this investigation. The strongest confirmed IOCs are file hashes, filename, and execution behavior.

This report does not claim network communication, persistence, or payload download.

---

## Recommendations

* Monitor for suspicious JavaScript execution through `wscript.exe`.
* Alert on unexpected script execution from user-accessible folders.
* Use YARA rules to detect similar obfuscated JavaScript files.
* Review Defender and endpoint logs for script-based execution.
* Treat unknown JavaScript files from downloaded archives as high risk.

---

## Conclusion

The threat intelligence review confirmed the sample identity, documented file-based IOCs, and supported detection development.

The lack of domains or IPs does not reduce the value of the analysis because host-based and file-based indicators were still identified.

---

## References

* [MalwareBazaar](https://bazaar.abuse.ch/)
* [VirusTotal](https://www.virustotal.com/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender/)
* [YARA Documentation](https://yara.readthedocs.io/)
