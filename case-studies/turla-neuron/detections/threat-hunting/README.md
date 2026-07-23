# Turla Neuron Threat Hunting

## Overview

Threat hunting is the proactive search for signs of malicious activity that may not have generated an alert. This package helps analysts search Windows systems for the distinctive file, service, Registry, process, listener, and protocol clues associated with Turla Neuron.

No production hunt was run while creating this package. The files provide hypotheses, safe query patterns, tracking fields, and evidence-based escalation guidance—not completed findings.

## What This Hunt Looks For

- The known malware file and exact SHA-256
- A fake Microsoft Exchange service
- Automatic `LocalSystem` persistence
- A hidden local HTTPS listener
- Unexpected command-shell activity from the suspicious service
- Service and Event Log Registry artifacts
- Host-specific temporary storage
- Microsoft Defender DarkNeuron records
- Multiple related indicators appearing on the same computer and close in time

## Important Safety and Accuracy Notes

- Port 443 is not malicious by itself.
- `LocalSystem` is not malicious by itself.
- PID 4/System is not the malware; HTTP.sys uses it for kernel socket ownership.
- Microsoft Exchange terminology is not automatically malicious.
- The exact laboratory MachineGuid is not a universal IOC.
- Defender quarantine filenames are temporary and should not be hunted as family-wide IOCs.
- `C:\Malware\TurlaNeuron\` is a laboratory path, not a production IOC.
- Static capability does not prove that an attacker exercised it.
- No external C2 IP address or domain was identified.
- Queries are read-only and must not contact `/ews/exchange/`.

## Hunting Package Contents

| File | Purpose | Audience |
|---|---|---|
| `README.md` | Package orientation, safety, order, and data sources | All readers |
| `turla_neuron_threat_hunt_plan.md` | Objectives, hypotheses, scoring, validation, and escalation | Hunt leads, responders |
| `turla_neuron_hunt_hypotheses.yml` | Machine-readable hypotheses and correlation model | Detection engineers, automation |
| `turla_neuron_hunt_queries.md` | Vendor-neutral and read-only query patterns | SOC analysts, threat hunters |
| `turla_neuron_hunt_tracker.csv` | Blank tracker with no invented findings | Hunt coordinators |
| `turla_neuron_hunt_mapping.json` | Indicator, evidence, ATT&CK, and detection mappings | Engineers, analysts |
| `turla_neuron_threat_hunting_validation.txt` | Structural, link, and safety checks | Reviewers |

## Recommended Hunt Order

1. Exact hash search
2. Filename search
3. Service-installation search
4. Service Registry search
5. Process-tree search
6. HTTP.sys and listener search
7. Temporary-storage search
8. Defender-history search
9. Multi-indicator correlation
10. Analyst validation and escalation

Start with high-confidence indicators, then widen the search. Broad clues should support—not replace—stronger evidence.

## Expected Outcomes

- `confirmed_active_compromise`
- `probable_compromise`
- `historical_remediated_detection`
- `authorized_lab_activity`
- `legitimate_exchange_activity`
- `false_positive`
- `insufficient_telemetry`
- `no_evidence_found`

`no_evidence_found` means the searched telemetry contained no matching evidence; it does not prove that activity never occurred. Record coverage and retention gaps.

## Data Sources

Useful sources include:

- Windows System Event Log
- Windows Registry telemetry
- EDR process telemetry
- Service inventory
- Microsoft Defender history
- HTTP.sys service state
- TCP listener inventory
- File inventory and hashes
- YARA scan results
- Asset inventory or CMDB
- DNS, proxy, and firewall records when available
- TLS inspection or reverse-proxy logs when available

This laboratory case did not collect Sysmon events or representative packet-capture evidence. The retained malware-run Procmon PML was unusable, so related hunts depend on enterprise telemetry rather than replay of a validated raw capture.

## Related Detection and Response Content

- [Sigma service-installation rule](../sigma/win_system_turla_neuron_service_install.yml)
- [YARA exact and behavioral rules](../yara/turla_neuron_v2.yar)
- [SOAR response package](../soar/README.md)
- [IOC package](../../iocs/turla_neuron_iocs.md)
- [Incident report](../../reports/incident-report.md)

## Deployment Notes

Replace `<HUNT_START_TIME>`, `<HUNT_END_TIME>`, `<HOST_SCOPE>`, and other placeholders with authorized organizational scope. Adapt field names to the local SIEM, EDR, data lake, Registry platform, and CMDB. Preserve query versions, coverage notes, analyst decisions, and source provenance with every hunt.
