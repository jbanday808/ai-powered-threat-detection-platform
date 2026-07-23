# Turla Threat-Actor History and Public Activity Status

## Plain-Language Overview

Turla is a name used by security researchers for a long-running cyber-espionage organization. Different security companies use different names for overlapping activity, which is why the same actor may appear under several labels.

This document summarizes public reporting. It does not replace evidence from the analyzed `Microsoft.Exchange.Service.exe` sample and does not establish that this binary is currently deployed.

## MITRE ATT&CK Identification

| Field | Value |
|---|---|
| Group name | Turla |
| ATT&CK ID | G0010 |
| MITRE page | [https://attack.mitre.org/groups/G0010/](https://attack.mitre.org/groups/G0010/) |
| Associated names | IRON HUNTER; Group 88; Waterbug; WhiteBear; Snake; Krypton; Venomous Bear; Secret Blizzard; BELUGASTURGEON |
| MITRE page version | 5.1 |
| MITRE page last modified | 2026-01-20 |
| Retrieved | 2026-07-22 |

MITRE records associated names to help analysts understand reported overlaps. The names are not necessarily exact one-to-one equivalents across every vendor, campaign, or period.

## History Timeline

| Date | Event | Source | Confidence | Relevance to this case |
|---|---|---|---|---|
| At least 2004 | MITRE and later public reporting describe Turla operations dating to at least 2004. | [MITRE G0010](https://attack.mitre.org/groups/G0010/) | high | Establishes long-running group context only. |
| 2014 and later | MITRE records Turla targeting and the public software record describes LightNeuron targeting Exchange servers since at least 2014. | [MITRE G0010](https://attack.mitre.org/groups/G0010/), [MITRE S0395](https://attack.mitre.org/software/S0395/) | high | Explains Exchange-related historical context; it does not equate LightNeuron with this sample. |
| 2017-05-31 | MITRE created the G0010 group entry. | [MITRE G0010](https://attack.mitre.org/groups/G0010/) | high | Establishes the ATT&CK record’s provenance. |
| 2019-10-21 | UK NCSC published reporting that discussed Turla’s use of Neuron and related tooling. | [NCSC update](https://www.ncsc.gov.uk/news/turla-group-behind-cyber-attack) | high | Supports public Neuron/Turla context, not this laboratory binary’s operator identity. |
| Since at least 2024 | Microsoft later reported a Secret Blizzard adversary-in-the-middle campaign that had been ongoing since at least 2024. | [Microsoft ApolloShadow report](https://www.microsoft.com/en-us/security/blog/2025/07/31/frozen-in-transit-secret-blizzards-aitm-campaign-against-diplomats/) | high | Recent group-level campaign context; unrelated malware must not be conflated with Neuron. |
| 2025-07-31 | Microsoft published details of diplomatic targeting and ApolloShadow deployment by Secret Blizzard. | [Microsoft ApolloShadow report](https://www.microsoft.com/en-us/security/blog/2025/07/31/frozen-in-transit-secret-blizzards-aitm-campaign-against-diplomats/) | high | Demonstrates then-recent actor-level activity, not behavior by this sample. |
| 2026-05-14 | Microsoft reported that Kazuar had remained under constant development and continued evolving for espionage-focused operations. | [Microsoft Kazuar report](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/) | high | Supports continued development at actor/tooling level; Kazuar is not this sample. |
| 2026-06-25 | Google Threat Intelligence published “STOCKSTAY Another Day,” describing Turla as active and STOCKSTAY as continually developed and deployed since at least December 2022. | [Google STOCKSTAY report](https://cloud.google.com/blog/topics/threat-intelligence/stockstay-turla-intelligence-gathering) | high | Latest activity-status evidence; STOCKSTAY is not this sample. |

The timeline intentionally omits milestones for which the selected sources do not provide sufficient support.

## Current Public Activity Assessment

Assessment:  
Publicly reported as active

Assessment date:  
2026-06-25

Assessment confidence:  
High based on recent public reporting

Public reporting status:  
Publicly reported as active

Status as of:  
2026-06-25

Latest supporting source:  
Google Threat Intelligence Group — STOCKSTAY Another Day

Public threat-intelligence reporting published through June 25, 2026 describes Turla as remaining active and continuing to develop and deploy espionage-focused malware.

Google Threat Intelligence described Turla as active and continuing to evolve its delivery methods while documenting STOCKSTAY. Microsoft’s May 14, 2026 Kazuar analysis described that malware as under constant development and continuing to evolve in support of espionage operations.

These reports support a time-bounded actor-level assessment. They do not prove that the analyzed Neuron sample remains deployed. The status is not inferred from the MITRE page’s modification date.

## Known Names and Overlaps

| Name | Tracking organization or context | Relationship | Source |
|---|---|---|---|
| Turla | MITRE ATT&CK primary group name | Primary G0010 name | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| IRON HUNTER | MITRE-listed associated group | Reported overlap; not asserted as exact equivalence | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| Group 88 | MITRE-listed associated group | Reported overlap; not asserted as exact equivalence | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| Waterbug | MITRE-listed associated group | Reported overlap; not asserted as exact equivalence | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| WhiteBear | MITRE-listed associated group | Reported overlap; not asserted as exact equivalence | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| Snake | MITRE-listed associated group name and implant context | Overlapping public usage; not exact in every source | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| Krypton | MITRE-listed associated group | Reported overlap; not asserted as exact equivalence | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| Venomous Bear | MITRE-listed associated group | Reported overlap; not asserted as exact equivalence | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| Secret Blizzard | Microsoft tracking name listed by MITRE | Strong public overlap with Turla reporting; scope may vary by source | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |
| BELUGASTURGEON | MITRE-listed associated group | Reported overlap; not asserted as exact equivalence | [MITRE G0010](https://attack.mitre.org/groups/G0010/) |

## Targeting History

Official MITRE and recent major reporting describe targeting or interest involving government, diplomatic organizations and embassies, defense and military organizations, education and research, and other sectors relevant to espionage. Those are public actor-level patterns, not victim findings from this case.

No production victim, organization, account, or infrastructure is claimed in this laboratory analysis.

## Attribution

Public government and commercial reporting has attributed or linked Turla and overlapping Secret Blizzard activity to Russia’s Federal Security Service.

This case study does not independently prove who developed or operated `Microsoft.Exchange.Service.exe`. Attribution is supporting context, while the sample-specific mapping relies on direct local evidence.

## Relationship to the Analyzed Sample

- Local evidence identifies the sample as Turla Neuron or DarkNeuron.
- The sample uses Exchange-themed service masquerading and a local HTTPS listener.
- Sample-specific ATT&CK mappings come from decompilation and controlled runtime artifacts.
- G0010 reporting supplies group context only.
- Kazuar, ApolloShadow, and STOCKSTAY are separately reported malware or campaigns and are not this Neuron binary.
- The public activity assessment does not assert that this exact sample is currently deployed.

## LightNeuron Naming Warning

MITRE lists LightNeuron as software S0395.

The analyzed Neuron sample and MITRE’s LightNeuron software entry share Turla and Exchange-related context, but this case study does not treat them as the same malware family without direct supporting evidence.

“Turla Neuron,” “DarkNeuron,” and “LightNeuron” are therefore not used interchangeably in this package.

## Assessment Limitations

- Public group names and overlaps can change as reporting evolves.
- MITRE’s group technique list represents sourced public reporting, not every possible Turla behavior.
- The latest public reports concern different tooling from this sample.
- No operator identity was established through laboratory evidence.
- The assessment is time-bounded to public reporting through 2026-06-25.

