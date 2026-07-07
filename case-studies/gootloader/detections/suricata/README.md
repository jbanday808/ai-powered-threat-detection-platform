# Suricata Detection

## Overview

This folder documents the Suricata detection content for the GootLoader case study.

Suricata is a network detection tool used to identify suspicious traffic patterns.

---

## Detection Objective

The Suricata rule is a low-confidence research rule because no confirmed network IOCs were observed during this investigation.

The rule is intended to demonstrate how a defender might look for suspicious JavaScript file delivery over HTTP.

---

## Confirmed Behavior Used

| Behavior | Status |
| --- | --- |
| JavaScript file type | Confirmed |
| Obfuscated JavaScript | Confirmed |
| `wscript.exe` execution | Confirmed |
| Domains | Not observed |
| IP Addresses | Not observed |
| URLs | Not observed |
| Confirmed C2 traffic | Not observed |
| Payload download | Not observed |

---

## Detection Coverage

| Detection Area | Purpose |
| --- | --- |
| HTTP traffic | Monitor possible JavaScript file delivery |
| `.js` file extension | Identify JavaScript files transferred over HTTP |
| Document-themed filenames | Look for lure-style filenames |
| GootLoader-style delivery | Support research-based network detection |

---

## Important Limitation

This Suricata rule is not based on confirmed domains, IP addresses, URLs, or C2 traffic.

It is included as a defensive research example only.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

---

## False Positives

Possible false positives include:

* Legitimate JavaScript downloads
* Web applications serving `.js` files
* Internal web portals
* Software installers
* Browser-based application scripts

---

## Tuning Recommendations

* Do not alert on all JavaScript downloads by default.
* Combine this rule with host-based evidence.
* Correlate with `wscript.exe` or `cscript.exe` execution.
* Correlate with YARA detections.
* Correlate with suspicious filenames.
* Add environment-specific allowlists.
* Use this rule as supporting context, not a standalone high-confidence alert.

---

## Related Detection Content

| Detection | Location |
| --- | --- |
| Suricata Rule | `rules/suricata/gootloader.rules` |
| YARA Rule | `rules/yara/gootloader_custom.yar` |
| Sigma Rule | `rules/sigma/gootloader-javascript-execution.yml` |
| Splunk Hunts | `reports/splunk-threat-hunting.md` |

---

## Analyst Assessment

The strongest detections for this case are host-based YARA, Sigma, and Splunk detections because no network IOCs were observed.

The Suricata rule provides additional research value but should be treated as low confidence unless correlated with endpoint evidence.

---

## Conclusion

Suricata can support network visibility, but this specific GootLoader investigation did not produce confirmed network indicators.

The Suricata content is included as a defensive research example and should be tuned before operational use.

---

## References

* [Suricata Documentation](https://docs.suricata.io/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [MalwareBazaar](https://bazaar.abuse.ch/)
* [VirusTotal](https://www.virustotal.com/)
* [YARA Analysis Report](../../reports/yara-analysis.md)
* [Sigma Analysis Report](../../reports/sigma-analysis.md)
* [Splunk Threat Hunting Report](../../reports/splunk-threat-hunting.md)
