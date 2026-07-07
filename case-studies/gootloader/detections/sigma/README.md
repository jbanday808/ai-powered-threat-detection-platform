# Sigma Detection

## Overview

Sigma is a vendor-neutral rule format used to detect suspicious activity across different SIEM platforms.

This detection focuses on behavior observed during the GootLoader investigation.

---

## Detection Objective

The Sigma rule is designed to identify suspicious JavaScript execution through Windows Script Host.

The rule looks for:

* `wscript.exe` execution
* `cscript.exe` execution
* JavaScript `.js` files
* Document-themed JavaScript filenames
* Suspicious command-line execution

---

## Detection Logic

| Detection | Purpose |
| --- | --- |
| `wscript.exe` | Detect Windows Script Host execution |
| `cscript.exe` | Detect command-line script execution |
| `.js` extension | Identify JavaScript execution |
| Document-themed filename | Identify social engineering lures |
| Command line | Capture script execution details |

---

## Confirmed Behavior Used

| Behavior | Status |
| --- | --- |
| JavaScript execution | Confirmed |
| Windows Script Host (`wscript.exe`) | Confirmed |
| Registry queries | Confirmed |
| File activity | Confirmed |
| Process exit | Confirmed |
| Child processes | Not observed |
| Persistence | Not observed |
| Domains | Not observed |
| IP Addresses | Not observed |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

---

## Detection Coverage

This Sigma rule helps identify:

* Suspicious JavaScript execution
* Windows Script Host abuse
* Document-themed malware lures
* Suspicious script execution within enterprise environments

---

## False Positives

Possible false positives include:

* Administrative JavaScript scripts
* Enterprise logon scripts
* Software deployment scripts
* Internal automation
* Legitimate IT maintenance scripts

---

## Tuning Recommendations

* Allowlist trusted administrative scripts.
* Prioritize JavaScript launched from Downloads, Desktop, Temp, and AppData.
* Review parent process relationships.
* Review command-line arguments.
* Correlate with Defender alerts.
* Correlate with EDR telemetry.
* Correlate with YARA matches.
* Correlate with Splunk threat hunting searches.

---

## Limitations

The Sigma rule detects host behavior only.

No network domains were observed. No IP addresses were observed.

No persistence or child processes were observed.

Additional GootLoader variants may exhibit different behavior.

---

## Related Detection Content

| Detection | Location |
| --- | --- |
| Sigma Rule | `rules/sigma/gootloader-javascript-execution.yml` |
| YARA Rule | `rules/yara/gootloader_custom.yar` |
| Suricata Rule | `rules/suricata/gootloader.rules` |
| Splunk Hunts | `reports/splunk-threat-hunting.md` |

---

## Analyst Assessment

The Sigma rule focuses on the confirmed execution behavior observed during the investigation.

It provides defenders with a portable detection that can be converted to multiple SIEM platforms.

The rule should be reviewed with endpoint context, command-line details, and known-good script activity.

---

## Conclusion

Sigma provides an effective method for detecting suspicious JavaScript execution associated with GootLoader-style malware.

This rule should be used together with YARA, Splunk, Suricata, Microsoft Defender, and endpoint telemetry for stronger detection coverage.

---

## References

* [Sigma Documentation](https://sigmahq.io/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [Microsoft Windows Script Host](https://learn.microsoft.com/windows-server/administration/windows-commands/wscript)
* [Microsoft Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
* [Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender/)
