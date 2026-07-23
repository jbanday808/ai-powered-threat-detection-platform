# Turla Neuron MITRE ATT&CK Mapping

## Overview

MITRE ATT&CK is a shared dictionary that security teams use to describe how cyber attackers operate. Instead of referring only to a malware name, ATT&CK organizes behavior into techniques such as creating a Windows service, running commands, modifying the Registry, or using encrypted communication.

This package applies that vocabulary to direct laboratory evidence from `Microsoft.Exchange.Service.exe`, then separately records public context for the broader Turla group.

## What This Package Contains

- A sample-specific technique mapping based on local static and dynamic evidence
- A matrix showing which behaviors were observed dynamically and which exist only as code capabilities
- A distinct public group-level mapping for MITRE ATT&CK group G0010
- Separate ATT&CK Navigator layers for the sample and the group
- A source-based Turla history and dated public-activity assessment
- Detection coverage and an evidence/reference matrix
- Machine-readable CSV and JSON plus a validation report

## Important Distinction

The sample mapping describes what was found in `Microsoft.Exchange.Service.exe`. The group mapping describes techniques publicly associated with the broader Turla organization. These are related sources of context, but they are not interchangeable.

A group-level technique does not prove that this Neuron sample implements it. A sample capability does not prove that Turla used it during a real intrusion. No production system was involved in this controlled case.

## Evidence Labels

| Label | Plain-language meaning |
|---|---|
| `observed_dynamically` | A preserved laboratory artifact shows the behavior occurred during execution. |
| `confirmed_statically` | Decompiled code or embedded data shows the capability exists, but execution is not implied. |
| `statically_and_dynamically_confirmed` | Code and runtime evidence independently support the same behavior. |
| `capability_only` | The code can perform the action, but the controlled run did not exercise it. |
| `candidate_mapping` | The mapping is plausible but the available evidence does not support treating it as confirmed. |
| `group_level_context` | Official MITRE reporting associates the technique with G0010; this is not sample evidence. |
| `detection_recommendation` | A defensive use of the mapped behavior, not proof that it occurred. |
| `not_observed` | Available evidence did not show the activity during the controlled run. |
| `evidence_limitation` | Missing or incomplete evidence prevents a stronger conclusion. |

Confidence is recorded as `high`, `medium`, or `low`. High means direct evidence strongly supports the mapping; medium requires interpretation or correlation; low is tentative and requires analyst review.

## Activity-Status Notice

Public reporting through June 25, 2026 describes Turla as active. This does not prove that the analyzed Neuron sample is still being deployed, nor does it prove that any production system in this case was targeted.

Public reporting status:  
Publicly reported as active

Status as of:  
2026-06-25

Latest supporting source:  
Google Threat Intelligence Group — STOCKSTAY Another Day

Public threat-intelligence reporting published through June 25, 2026 describes Turla as remaining active and continuing to develop and deploy espionage-focused malware.

## Files

| File | Purpose | Intended audience |
|---|---|---|
| [README.md](README.md) | Package orientation and evidence labels | All readers |
| [turla_neuron_attack_mapping.md](turla_neuron_attack_mapping.md) | Human-readable sample and group mapping | SOC, DFIR, detection engineering |
| [turla_neuron_attack_mapping.csv](turla_neuron_attack_mapping.csv) | Tabular mappings for analysis and import | Analysts and automation |
| [turla_neuron_attack_mapping.json](turla_neuron_attack_mapping.json) | Structured mappings, coverage, status, and sources | Automation and engineering |
| [turla_neuron_sample_navigator_layer.json](turla_neuron_sample_navigator_layer.json) | Sample-specific ATT&CK Navigator layer | Detection engineering |
| [turla_group_context_navigator_layer.json](turla_group_context_navigator_layer.json) | Official G0010 group-context layer | Threat intelligence |
| [turla_history_and_current_activity.md](turla_history_and_current_activity.md) | Source-based history and dated public status | Managers and threat intelligence |
| [turla_attack_reference_matrix.md](turla_attack_reference_matrix.md) | External definitions and internal evidence references | Reviewers and auditors |
| [turla_attack_validation.txt](turla_attack_validation.txt) | Parsing, consistency, link, and claim checks | Reviewers and maintainers |

## Key Sources

- [MITRE ATT&CK Turla group G0010](https://attack.mitre.org/groups/G0010/)
- [MITRE ATT&CK group methodology](https://attack.mitre.org/groups/index.html)
- [Microsoft — Kazuar: Anatomy of a nation-state botnet](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/)
- [Google Threat Intelligence — STOCKSTAY Another Day](https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering)
- [UK NCSC — Turla malware publication](https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB)
- [Internal reverse-engineering analysis](../results/reverse-engineering/turla_neuron_reverse_engineering.md)
- [Internal dynamic analysis](../results/dynamic/turla_neuron_dynamic_analysis.md)
