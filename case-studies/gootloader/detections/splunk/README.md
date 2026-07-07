# Splunk Detection

## Overview

This folder documents Splunk threat hunting detections for the GootLoader case study.

The detections focus on suspicious JavaScript execution through Windows Script Host.

---

## Detection Objective

The Splunk hunts are designed to help analysts find:

* `wscript.exe` execution
* `cscript.exe` execution
* JavaScript file execution
* Document-themed JavaScript filenames
* Known GootLoader sample hashes
* Microsoft Defender malware events

---

## Confirmed Behavior Used

| Behavior | Status |
| --- | --- |
| JavaScript execution | Confirmed |
| `wscript.exe` execution | Confirmed |
| Registry queries | Confirmed |
| File activity | Confirmed |
| Process exit | Confirmed |
| Child processes | Not observed |
| Domains | Not observed |
| IP Addresses | Not observed |
| Persistence | Not observed |

---

## Detection Coverage

| Hunt Area | Purpose |
| --- | --- |
| Windows Script Host | Find suspicious `wscript.exe` or `cscript.exe` activity |
| JavaScript Files | Identify `.js` or `.jse` script execution |
| Document-Themed Names | Detect possible lure-style filenames |
| User Folders | Find scripts launched from risky locations |
| File Hashes | Search for known sample hashes |
| Defender Logs | Review malware detection events |

---

## Related Splunk Hunts

| Hunt | Description |
| --- | --- |
| JavaScript Execution Through Windows Script Host | Finds `.js` execution using `wscript.exe` or `cscript.exe` |
| Document-Themed JavaScript Filename | Finds suspicious filenames using terms like Legal, Case, Document, or Documents |
| Script Execution From User Folders | Finds scripts launched from Downloads, Desktop, Temp, AppData, or user paths |
| Known GootLoader Sample Hash | Searches for the known MD5, SHA-1, and SHA-256 values |
| Microsoft Defender Detection Review | Reviews Defender detection and remediation events |
| GootLoader Analysis Filename | Searches for `Legal_Case_Documents_2026.js` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

---

## Tuning Recommendations

* Allowlist trusted administrative scripts.
* Allowlist known software deployment scripts.
* Prioritize scripts from Downloads, Desktop, Temp, and AppData.
* Review parent process and command line.
* Correlate with Defender alerts.
* Correlate with YARA matches.
* Correlate with Sigma detections.
* Review endpoint telemetry for process lifetime and file activity.

---

## Limitations

These Splunk hunts focus on host-based behavior.

No network domains were observed. No IP addresses were observed.

No persistence or child processes were observed.

Some legitimate scripts may trigger results, and field names may vary by Splunk environment.

---

## Related Detection Content

| Detection | Location |
| --- | --- |
| Splunk Threat Hunting Report | `reports/splunk-threat-hunting.md` |
| Sigma Rule | `rules/sigma/gootloader-javascript-execution.yml` |
| YARA Rule | `rules/yara/gootloader_custom.yar` |
| Suricata Rule | `rules/suricata/gootloader.rules` |

---

## Analyst Assessment

The Splunk hunts focus on the strongest confirmed behavior from the investigation: JavaScript execution through Windows Script Host.

Because no network indicators were observed, the hunts focus on host-based activity, filenames, hashes, and Defender logs.

These searches should be tuned for each environment before production use.

---

## Conclusion

Splunk provides useful visibility into suspicious script execution and can help analysts investigate GootLoader-style behavior.

These hunts should be used with endpoint telemetry, Microsoft Defender logs, YARA results, and Sigma detections for stronger coverage.

---

## References

* [Splunk Documentation](https://docs.splunk.com/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [Microsoft Defender Operational Logs](https://learn.microsoft.com/microsoft-365/security/defender/)
* [Sysmon Event ID 1](https://learn.microsoft.com/sysinternals/downloads/sysmon)
* [Windows Security Event ID 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
* [YARA Analysis Report](../../reports/yara-analysis.md)
* [Sigma Analysis Report](../../reports/sigma-analysis.md)
