# YARA Detection

## Overview

This folder documents the YARA detection content for the GootLoader case study.

YARA is used to detect suspicious files based on strings, patterns, and static indicators.

---

## Detection Objective

The YARA rule is designed to detect GootLoader-style obfuscated JavaScript using static indicators identified during analysis.

The rule focuses on:

* Obfuscated JavaScript
* Suspicious injected functions
* Runtime string reconstruction patterns
* JavaScript and jQuery-related indicators

---

## Confirmed Static Indicators Used

| Indicator Type | Indicator |
| --- | --- |
| JavaScript Object | `window.document` |
| jQuery Indicator | `jQuery.acceptData` |
| jQuery Indicator | `jQuery.expr.match.needsContext` |
| Suspicious Function | `function stop` |
| Suspicious Function | `function returned` |
| Suspicious Function | `function adjusted` |
| Suspicious Function | `function fxNow` |
| Suspicious Function | `function el` |
| Obfuscated Variable | `hooks` |
| Obfuscated Variable | `whitespace` |
| Obfuscated Variable | `isSuccess` |
| Obfuscated Variable | `preferredDoc` |
| Obfuscated Variable | `preservedScriptAttributes` |
| Runtime Pattern | `createCache()` |
| Runtime Pattern | `pixelPositionVal` |
| Runtime Pattern | `rbracket` |
| Runtime Pattern | `callbackName` |

---

## Detection Logic

| Logic Area | Purpose |
| --- | --- |
| File size check | Limits detection to smaller JavaScript-like files |
| Static strings | Matches known code indicators from the sample |
| Suspicious functions | Detects injected GootLoader-style logic |
| Runtime reconstruction patterns | Detects code used to rebuild hidden strings |
| Threshold match | Requires multiple indicators before alerting |

---

## Validation Result

The custom YARA rule successfully matched the analyzed GootLoader sample.

Validation result:

```bash
GootLoader_Combined_Static_IOC /home/james/Malware-Analysis/GootLoader/Sample/Legal_Case_Documents_2026.js
```

| Validation Item | Result |
| --- | --- |
| Rule Name | `GootLoader_Combined_Static_IOC` |
| Sample Name | `Legal_Case_Documents_2026.js` |
| Malware Family | GootLoader |
| Detection Result | Match observed |
| Confidence | High |

---

## Confirmed Behavior Used

| Behavior | Status |
| --- | --- |
| JavaScript file type | Confirmed |
| Obfuscated JavaScript | Confirmed |
| Suspicious functions | Confirmed |
| Runtime string reconstruction patterns | Confirmed |
| YARA rule match | Confirmed |
| Domains | Not observed |
| IP Addresses | Not observed |
| URLs | Not observed |
| Persistence | Not observed |
| Child processes | Not observed |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 |
| Defense Evasion | Obfuscated Files or Information | T1027 |

---

## Detection Coverage

This YARA rule helps identify suspicious JavaScript files that share static indicators with the analyzed sample.

It is useful for file triage, malware analysis workflows, and defensive scanning.

The rule does not rely on domains, IP addresses, URLs, payload names, persistence artifacts, or child process behavior.

---

## False Positives

Possible false positives include JavaScript files that contain similar jQuery code and matching variable or function names.

The rule requires multiple indicators before matching, which helps reduce false positives.

Additional testing against benign JavaScript files is recommended before production use.

---

## Tuning Recommendations

* Test the rule against benign JavaScript files.
* Test the rule against additional GootLoader samples if available.
* Use the rule with file hash checks and endpoint telemetry.
* Correlate YARA matches with `wscript.exe` or `cscript.exe` execution.
* Correlate YARA matches with Sigma and Splunk detections.
* Review matched files manually before taking response action.

---

## Limitations

This rule was validated against the analyzed GootLoader JavaScript sample.

It may not detect every GootLoader variant.

No network indicators, payloads, persistence mechanisms, or child processes were included because they were not observed.

---

## Related Detection Content

| Detection | Location |
| --- | --- |
| YARA Rule | `rules/gootloader_custom.yar` |
| YARA Analysis Report | `reports/yara-analysis.md` |
| Sigma Rule | `rules/sigma/gootloader-javascript-execution.yml` |
| Splunk Hunts | `reports/splunk-threat-hunting.md` |
| Suricata Rule | `rules/suricata/gootloader.rules` |

---

## Analyst Assessment

The YARA rule provides the strongest file-based detection for this case study.

It uses confirmed static indicators from the analyzed GootLoader JavaScript sample and successfully matched the original analysis file.

The rule should be treated as focused detection content for this sample and tested further before broad enterprise deployment.

---

## Conclusion

YARA provides an effective way to detect suspicious obfuscated JavaScript files without executing them.

For this GootLoader investigation, the YARA rule converted confirmed static analysis findings into reusable defensive detection content.

---

## References

* [YARA Documentation](https://yara.readthedocs.io/)
* [MITRE ATT&CK](https://attack.mitre.org/)
* [MalwareBazaar](https://bazaar.abuse.ch/)
* [VirusTotal](https://www.virustotal.com/)
* [Static Analysis Report](../../reports/static-analysis.md)
* [YARA Analysis Report](../../reports/yara-analysis.md)
