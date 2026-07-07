# Splunk Threat Hunting – GootLoader

## Executive Summary

This report provides Splunk threat hunting searches based on the observed GootLoader behavior from this investigation.

Confirmed behavior included JavaScript execution through `wscript.exe`, registry queries, file activity, and quick process exit.

No domains, IP addresses, URLs, persistence, child processes, or second-stage payload activity were observed during this investigation.

---

## What is Splunk Threat Hunting?

Splunk threat hunting uses security logs to search for suspicious activity that may not have triggered an alert.

It helps analysts review endpoint, process, file, and security events for behavior that may need investigation.

---

## Hunting Objectives

* Search for JavaScript execution through Windows Script Host.
* Identify suspicious `wscript.exe` or `cscript.exe` activity.
* Hunt for document-themed JavaScript filenames.
* Review suspicious script execution from user-accessible folders.
* Search for known file hashes from this sample.
* Review Microsoft Defender malware detection events.
* Support investigation of GootLoader-style behavior.

---

## Confirmed Behavior Used for Hunts

| Confirmed Behavior | Evidence |
| --- | --- |
| JavaScript execution | `Legal_Case_Documents_2026.js` |
| Windows Script Host | `wscript.exe` |
| File type | JavaScript |
| Registry activity | Observed in Process Monitor |
| File activity | Observed in Process Monitor |
| Process exit | Observed in Process Monitor |
| Child processes | Not observed |
| Network IOCs | None observed |
| Persistence | Not observed |

---

## Recommended Data Sources

| Data Source | Purpose |
| --- | --- |
| Sysmon Event ID 1 | Process creation hunting |
| Windows Security Event ID 4688 | Process creation hunting |
| Microsoft Defender Operational Logs | Malware detection and remediation review |
| Endpoint Detection and Response Logs | Process, file, and registry activity review |
| File Integrity or EDR File Logs | File hash and file path searches |

Field names may vary by Splunk deployment.

Analysts may need to adjust fields such as `Image`, `CommandLine`, `ParentImage`, `ProcessId`, `file_hash`, or `EventCode`.

---

## Hunt 1 – JavaScript Execution Through Windows Script Host

```spl
index=* (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Security")
(EventCode=1 OR EventCode=4688)
(Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR New_Process_Name="*\\wscript.exe" OR New_Process_Name="*\\cscript.exe")
(CommandLine="*.js*" OR CommandLine="*.jse*" OR Process_Command_Line="*.js*" OR Process_Command_Line="*.jse*")
| table _time host user Image New_Process_Name CommandLine Process_Command_Line ParentImage ParentCommandLine ProcessId
| sort - _time
```

Simple explanation: This search finds JavaScript files launched by Windows Script Host.

---

## Hunt 2 – Suspicious Document-Themed JavaScript Filename

```spl
index=* (EventCode=1 OR EventCode=4688)
(Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR New_Process_Name="*\\wscript.exe" OR New_Process_Name="*\\cscript.exe")
(CommandLine="*.js*" OR Process_Command_Line="*.js*" OR CommandLine="*.jse*" OR Process_Command_Line="*.jse*")
(CommandLine="*Legal*" OR CommandLine="*Case*" OR CommandLine="*Document*" OR CommandLine="*Documents*" OR Process_Command_Line="*Legal*" OR Process_Command_Line="*Case*" OR Process_Command_Line="*Document*" OR Process_Command_Line="*Documents*")
| table _time host user Image New_Process_Name CommandLine Process_Command_Line ParentImage ParentCommandLine
| sort - _time
```

Simple explanation: This search looks for document-themed JavaScript names similar to the analyzed sample name.

---

## Hunt 3 – Script Execution From User or Temporary Folders

```spl
index=* (EventCode=1 OR EventCode=4688)
(Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR New_Process_Name="*\\wscript.exe" OR New_Process_Name="*\\cscript.exe")
(CommandLine="*.js*" OR Process_Command_Line="*.js*" OR CommandLine="*.jse*" OR Process_Command_Line="*.jse*")
(CommandLine="*\\Users\\*" OR CommandLine="*\\Downloads\\*" OR CommandLine="*\\Desktop\\*" OR CommandLine="*\\Temp\\*" OR CommandLine="*\\AppData\\*" OR Process_Command_Line="*\\Users\\*" OR Process_Command_Line="*\\Downloads\\*" OR Process_Command_Line="*\\Desktop\\*" OR Process_Command_Line="*\\Temp\\*" OR Process_Command_Line="*\\AppData\\*")
| table _time host user Image New_Process_Name CommandLine Process_Command_Line ParentImage ParentCommandLine CurrentDirectory
| sort - _time
```

Simple explanation: This search finds scripts running from locations commonly used by users and downloaded files.

---

## Hunt 4 – Known GootLoader Sample Hash

```spl
index=*
("53f8a46c948c968fe753a5f723bdf99d3b3d141dc3dec3d8e36480975c7ce879"
OR "7b468a279606b62b0abe1a3e14aa16f0c9e6b93d"
OR "95238ad5a91d721c6e8fdf4c36187798")
| table _time host source sourcetype user file_name file_path file_hash Hashes signature Message
| sort - _time
```

Simple explanation: This search looks for the confirmed SHA-256, SHA-1, or MD5 hash values from the analyzed sample.

---

## Hunt 5 – Microsoft Defender Malware Detection Review

```spl
index=* sourcetype="WinEventLog:Microsoft-Windows-Windows Defender/Operational"
(EventCode=1116 OR EventCode=1117 OR EventCode=1118 OR EventCode=1119)
| table _time host EventCode Message
| sort - _time
```

Simple explanation: This search reviews Microsoft Defender malware detection and remediation events.

---

## Hunt 6 – GootLoader Analysis Filename

```spl
index=*
"Legal_Case_Documents_2026.js"
| table _time host source sourcetype user Message CommandLine Process_Command_Line file_name file_path
| sort - _time
```

Simple explanation: This search looks for the analysis filename used during this case study.

---

## Hunt 7 – Windows Script Host With Short Runtime Indicators

```spl
index=* (EventCode=1 OR EventCode=4688)
(Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR New_Process_Name="*\\wscript.exe" OR New_Process_Name="*\\cscript.exe")
(CommandLine="*.js*" OR Process_Command_Line="*.js*")
| table _time host user Image New_Process_Name CommandLine Process_Command_Line ParentImage ParentCommandLine ProcessId
| sort - _time
```

Simple explanation: This search lists Windows Script Host JavaScript executions for manual review and timeline correlation.

---

## Hunt Result Summary

| Hunt | Purpose | Expected Result |
| --- | --- | --- |
| Hunt 1 | Find JavaScript execution through Windows Script Host | Detect suspicious script execution |
| Hunt 2 | Find document-themed JavaScript filenames | Identify possible lure-style filenames |
| Hunt 3 | Find scripts running from user folders | Identify risky script locations |
| Hunt 4 | Search known hashes | Find known GootLoader sample indicators |
| Hunt 5 | Review Defender detections | Find Defender malware events |
| Hunt 6 | Search analysis filename | Find sample-specific activity |
| Hunt 7 | Review Windows Script Host activity | Support manual investigation |

---

## Tuning Guidance

* Add allowlists for known administrative scripts.
* Add allowlists for trusted software deployment paths.
* Prioritize scripts launched from Downloads, Desktop, Temp, and AppData.
* Review parent process and command line.
* Correlate process activity with Defender, EDR, and file hash data.
* Treat unexpected JavaScript execution as suspicious.

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Simple Meaning |
| --- | --- | --- | --- |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | JavaScript ran through Windows Script Host |
| Defense Evasion | Obfuscated Files or Information | T1027 | Malware hid its real logic using obfuscation |

---

## Limitations

* These hunts focus on observed host-based behavior.
* No network domains, IP addresses, or URLs were observed.
* No PowerShell, `cmd.exe`, persistence, or child processes were observed.
* Some legitimate administrative scripts may trigger these hunts.
* The known hash hunt only detects this specific sample.

---

## Analyst Assessment

The most useful hunts focus on suspicious JavaScript execution through `wscript.exe` or `cscript.exe`.

Document-themed script names, user-folder execution paths, and known file hashes provide strong review points for this case study.

These hunts should be tuned with local allowlists and reviewed alongside Defender, EDR, and file hash data.

---

## Recommended Next Steps

* Test searches against Sysmon process creation logs.
* Add environment-specific allowlists.
* Correlate script execution with Defender events.
* Correlate suspicious script execution with YARA results.
* Expand searches if future samples reveal domains, IPs, URLs, or second-stage behavior.

---

## Conclusion

These Splunk hunts support detection and investigation of GootLoader-style JavaScript execution.

The searches focus on confirmed behavior from this investigation and avoid unobserved activity such as network indicators, persistence, child processes, or second-stage payload execution.

---

## References

* [Splunk Documentation](https://docs.splunk.com/)
* [MITRE ATT&CK T1059.007](https://attack.mitre.org/techniques/T1059/007/)
* [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
* [Microsoft Defender Operational Logs](https://learn.microsoft.com/microsoft-365/security/defender/)
* [Sysmon Event ID 1](https://learn.microsoft.com/sysinternals/downloads/sysmon)
* [Windows Security Event ID 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)
* [YARA Analysis Report](yara-analysis.md)
