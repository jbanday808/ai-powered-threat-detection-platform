# Sigma Analysis – GootLoader

## Executive Summary

A Sigma rule was created to detect suspicious JavaScript execution related to the GootLoader investigation.

The rule focuses on Windows Script Host execution using `wscript.exe` and JavaScript files.

The detection is based only on confirmed behavior observed during the investigation.

---

## What is Sigma?

Sigma is a rule format security teams use to describe suspicious activity in logs.

It helps analysts write one detection rule that can be converted for different security tools.

Sigma is useful for sharing defensive detections across teams and platforms.

---

## Detection Objective

The goal of the Sigma rule is to detect suspicious JavaScript execution through Windows Script Host.

The rule is designed to:

* Detect `wscript.exe`
* Detect `.js` script execution
* Support investigation of suspicious JavaScript files
* Help identify activity similar to the observed GootLoader execution

---

## Confirmed Behavior Used for Detection

| Confirmed Behavior | Evidence |
| --- | --- |
| JavaScript file executed | `Legal_Case_Documents_2026.js` |
| Windows Script Host used | `wscript.exe` |
| Process activity observed | Process Monitor |
| Registry queries observed | Process Monitor |
| Child processes observed | None |
| Network IOCs observed | None |

---

## Sigma Rule

```yaml
title: Suspicious JavaScript Execution Using Windows Script Host
id: 7f9c4e2a-8d7b-4fd6-9d6f-gootloader-js-wscript
status: experimental
description: Detects suspicious JavaScript execution using Windows Script Host based on observed GootLoader execution behavior.
author: James Banday
date: 2026-07-05
references:
  - https://attack.mitre.org/techniques/T1059/007/
tags:
  - attack.execution
  - attack.t1059.007
logsource:
  product: windows
  category: process_creation
detection:
  selection_wscript:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
  selection_js:
    CommandLine|contains:
      - '.js'
      - '.jse'
  condition: selection_wscript and selection_js
fields:
  - UtcTime
  - Image
  - CommandLine
  - ParentImage
  - ParentCommandLine
  - User
  - CurrentDirectory
falsepositives:
  - Legitimate administrative scripts
  - Software installation scripts
  - Enterprise logon scripts
level: medium
```

---

## Rule Logic

| Rule Section | Purpose |
| --- | --- |
| `selection_wscript` | Looks for Windows Script Host processes. |
| `selection_js` | Looks for JavaScript file execution in the command line. |
| `condition` | Requires both Windows Script Host and JavaScript indicators. |
| `fields` | Lists useful log fields for analyst review. |
| `falsepositives` | Documents common benign script activity. |

### Simple Summary

The rule looks for JavaScript files being run by Windows Script Host.

This matches the confirmed GootLoader execution pattern from the lab.

---

## Detection Scope

| Scope Area | Status |
| --- | --- |
| `wscript.exe` execution | Covered |
| `.js` script execution | Covered |
| Registry queries | Context only |
| File activity | Context only |
| Child processes | Not observed |
| Network IOCs | Not observed |
| Persistence | Not observed |
| PowerShell activity | Not observed |

The rule does not include domains, IP addresses, URLs, payload names, child processes, persistence, or PowerShell activity.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection Relevance |
| --- | --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | Detects JavaScript execution through Windows Script Host. |

---

## Analyst Workflow

When this rule alerts, analysts should review the process and command-line context.

Useful review points include:

* Was the script expected?
* Where did the JavaScript file run from?
* Which user launched the process?
* Was the parent process suspicious?
* Did endpoint logs show related registry or file activity?

This workflow is defensive and does not require running the suspicious file.

---

## False Positive Considerations

Some organizations use scripts for legitimate administration, installation, or logon activity.

This rule is set to `medium` because `wscript.exe` and JavaScript execution can be legitimate in some environments.

Analysts should compare alerts against approved script locations and known administrative workflows.

---

## Key Findings

* The observed GootLoader sample executed through `wscript.exe`.
* The observed script file was `Legal_Case_Documents_2026.js`.
* A Sigma rule was created to detect similar Windows Script Host JavaScript execution.
* No child processes, network IOCs, persistence, payloads, or PowerShell activity were included because they were not observed.

---

## Analyst Assessment

The Sigma rule provides a practical log-based detection for suspicious JavaScript execution through Windows Script Host.

The rule is intentionally focused on confirmed behavior from this investigation.

Additional tuning may be needed in enterprise environments that use legitimate JavaScript automation.

---

## References

* [SigmaHQ Documentation](https://sigmahq.io/)
* [MITRE ATT&CK – Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
* [Microsoft Sysinternals Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
* [Microsoft Defender](https://learn.microsoft.com/microsoft-365/security/defender/)
