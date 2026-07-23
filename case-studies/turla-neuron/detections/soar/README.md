# Turla Neuron SOAR Automation

## Overview

This SOAR workflow helps a security team respond consistently when Turla Neuron-related activity is detected. It gathers evidence automatically, measures the risk, alerts an analyst, and requests approval before taking disruptive actions such as isolating a computer or removing a service.

The package is vendor-neutral and contains no credentials, connector endpoints, executable remediation commands, malware interaction, or C2 protocol generation.

## What SOAR Means

Security Orchestration, Automation, and Response connects security tools and guides repetitive incident-response steps. It reduces manual work but still requires human approval for actions that could affect a computer or business service.

## Workflow Goals

- Confirm whether the alert is credible.
- Preserve evidence before disruptive action.
- Determine whether the host is a legitimate Exchange server or authorized laboratory.
- Identify service persistence and executable provenance.
- Review the local HTTPS listener without sending it traffic.
- Calculate severity from correlated evidence.
- Contain the endpoint only after approval.
- Remediate confirmed malicious artifacts only after separate approval.
- Verify cleanup and distinguish active from historical Defender records.
- Document decisions, evidence, actions, and outcomes.

## Supported Detection Inputs

| Input | Existing evidence or detection |
|---|---|
| Sigma-compatible service-installation alert | [Turla Neuron service-installation Sigma rule](../sigma/win_system_turla_neuron_service_install.yml) |
| YARA exact-hash match | `Turla_Neuron_Exact` in the [YARA rule](../yara/turla_neuron_v2.yar) |
| YARA behavioral match | `Turla_Neuron_Behavior` in the same YARA rule |
| Microsoft Defender detection | `Trojan:MSIL/DarkNeuron.B!dha`, Threat ID `2147724727` |
| EDR process or service alert | Organization-provided alert and endpoint metadata |
| HTTP.sys/local-listener telemetry | Local queue and socket evidence |
| Analyst-submitted IOC match | [Turla Neuron IOC package](../../iocs/turla_neuron_iocs.md) |

## Automated Actions

| Action | Automatic? | Modifies endpoint? | Approval required? |
|---|---:|---:|---:|
| Normalize alert fields and indicators | Yes | No | No |
| Create/update case and preserve alert | Yes | No | No |
| Query asset role and authorized activity | Yes | No | No |
| Calculate hashes and query approved reputation sources | Yes | No | No |
| Query endpoint, process, service, and Registry state | Yes | No | No |
| Query HTTP.sys and socket state without probing | Yes | No | No |
| Query Defender current and historical state | Yes | No | No |
| Collect metadata and generate evidence manifest | Yes | No | No |
| Calculate severity and recommendations | Yes | No | No |
| Notify analysts | Yes | No | No |
| Isolate endpoint | No | Yes | Containment approval |
| Block exact hash or properly scoped filename | No | Yes | Containment approval |
| Stop/disable service or suspend process | No | Yes | Containment approval |
| Quarantine file or add temporary firewall restriction | No | Yes | Containment approval |
| Delete confirmed malware or remove persistence | No | Yes | Remediation approval |
| Remove confirmed service keys, source, or storage | No | Yes | Remediation approval |
| Restore snapshot or reimage host | No | Yes | Remediation approval |
| Verify cleanup | Yes | No | No |
| Close case with disposition | No | No | Analyst decision |

## Safety Controls

- Read-only enrichment and evidence preservation occur first.
- Containment and remediation use separate recorded approval gates.
- Evidence is preserved before permanent deletion.
- The asset is checked for legitimate Exchange-server status.
- No step contacts `/ews/exchange/` or generates its protocol fields.
- Port 443 and PID 4/System are context, not malware indicators.
- An Exchange-themed name alone never authorizes service removal.
- Historical Defender records are not treated as active infection by themselves.
- Connector failures and unavailable evidence are recorded rather than silently ignored.

## Expected Integrations

Organizations map the generic operations to approved integrations:

- SIEM
- EDR
- Antivirus
- Threat-intelligence platform
- Ticketing or case management
- Email or chat notification
- Asset inventory or CMDB
- Identity provider
- Firewall
- Evidence repository

A product can be used as an optional implementation, but this package does not depend on vendor-specific connector names.

## Workflow Outcomes

- `true_positive_active`
- `true_positive_contained`
- `true_positive_remediated`
- `historical_detection_only`
- `authorized_lab_activity`
- `legitimate_exchange_service`
- `false_positive`
- `insufficient_evidence`

## Files

- `turla_neuron_soar_playbook.yml`: machine-readable vendor-neutral workflow and approval gates
- `turla_neuron_soar_workflow.md`: human-readable logic, decisions, and evidence handling
- `turla_neuron_soar_mapping.json`: alert normalization, indicators, action levels, and outcomes
- `turla_neuron_soar_validation.txt`: structural and safety validation

## Deployment Notes

Platform-specific connector names, credentials, field mappings, evidence repositories, notification destinations, approval mechanisms, rollback procedures, and authorization policies must be configured by the deploying organization. Use test mode first and require named approvers for every endpoint-changing action.

The playbook is a response design, not an executable connector bundle. It intentionally omits real hostnames, API endpoints, tokens, tenant identifiers, accounts, and deletion commands.

## Evidence Boundaries

- `https://*:443/ews/exchange/` is a local wildcard listener prefix, not a remote C2 destination.
- No external C2 IP address or domain was identified.
- No attacker request, file transfer, data exfiltration, or lateral movement was observed.
- The exact SHA-256 is strong sample evidence; the filename, Exchange name, LocalSystem, PID 4, and port 443 require correlation.
- Authorized laboratory activity and legitimate Exchange services must be dispositioned without automated disruption.
