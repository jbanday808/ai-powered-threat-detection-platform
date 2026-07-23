# Turla Neuron / DarkNeuron Indicators of Compromise

**Incident ID:** MAL-2026-0721-NEURON  
**Author:** James Banday  
**Date created:** 2026-07-22  
**Active indicators:** 39  
**Excluded laboratory artifacts:** 15

## Overview

Indicators of Compromise are clues that help security teams search for a malicious file or its activity. Some clues are very specific, such as a file hash, while others require supporting context.

This package covers the analyzed Turla Neuron sample, also known as DarkNeuron. It distinguishes exact file identifiers and distinctive family-associated artifacts from broad behaviors that may also occur on legitimate systems.

## Confidence Levels

- **High:** Strongly identifies the analyzed sample or highly distinctive malware artifact.
- **Medium:** Useful when combined with related indicators.
- **Low:** Broad or potentially legitimate behavior requiring investigation.

## File Indicators

| Type | Value | Confidence | Evidence | Recommended Use |
|---|---|---|---|---|
| Filename | `Microsoft.Exchange.Service.exe` | High | Static metadata and dynamic service evidence | Hunt with service or hash context; a filename can be changed |
| MD5 | `0f12268221e27406351a6313f902b498` | High | VirusTotal metadata | Exact sample matching; prefer SHA-256 where available |
| SHA-1 | `b0bdbc81a0e367330007b7e593d8ddabf92ca7afd` | High | VirusTotal metadata | Exact sample matching; prefer SHA-256 where available |
| SHA-256 | `d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29` | High | YARA exact rule and VirusTotal metadata | Preferred high-confidence exact sample match |

## Service Indicators

| Indicator | Value | Confidence | Evidence | Recommended Use |
|---|---|---|---|---|
| Service name | `MSExchangeService` | High | Installer log and service Registry evidence | Alert on installation and correlate with executable name |
| Display name | `Microsoft Exchange Service` | Medium | Decompiler and service Registry evidence | Correlate with service name and image path |
| Executable-name pattern | `*\Microsoft.Exchange.Service.exe` | High | Service Registry and Sigma evidence | Match service image paths without requiring a directory |
| Service account | `LocalSystem` | Low | Service Registry evidence | Supporting privilege context only; common for legitimate services |
| Startup type | `Automatic` | Low | Service Registry `Start = 2` | Supporting persistence context only; common by itself |
| Service type | `WIN32_OWN_PROCESS` | Low | Service Registry `Type = 16` | Supporting dedicated-process context only |
| Description | `Host service for the Microsoft Exchange Server management provider. If this service is stopped or disabled, Microsoft Exchange cannot be managed.` | Medium | Decompiler and service Registry evidence | Search descriptions with the distinctive service and image fields |

The account, startup type, and service type are useful supporting context but are not unique or malicious by themselves.

## Registry Indicators

| Indicator | Value | Confidence | Evidence | Recommended Use |
|---|---|---|---|---|
| Service key | `HKLM\SYSTEM\CurrentControlSet\Services\MSExchangeService` | High | Dynamic service Registry evidence | Hunt for the exact persistence key |
| Event Log source key | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\MSExchangeService` | Medium | Dynamic Event Log source evidence | Correlate with service installation; registration does not prove messages were written |
| ImagePath data | Contains `Microsoft.Exchange.Service.exe` | High | Dynamic service Registry evidence | Match independently of the laboratory directory |
| DisplayName data | `Microsoft Exchange Service` | Medium | Dynamic service Registry evidence | Correlate with service name and ImagePath |
| ObjectName data | `LocalSystem` | Low | Dynamic service Registry evidence | Privilege context only |
| Start data | `2` | Low | Dynamic service Registry evidence | Automatic-start context only |
| Type data | `16` | Low | Dynamic service Registry evidence | Dedicated-service context only |

### Supporting ZoneMap Behavior

| Indicator | Value | Confidence | Evidence | Recommended Use |
|---|---|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\AutoDetect` | `0` | Low | Dynamic Registry and filtered Noriben evidence | Correlate with installer and service evidence |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\IntranetName` | `1` | Low | Dynamic Registry and filtered Noriben evidence | Correlate with installer and service evidence |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProxyBypass` | `1` | Low | Dynamic Registry and filtered Noriben evidence | Correlate with installer and service evidence |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet` | `1` | Low | Dynamic Registry and filtered Noriben evidence | Correlate with installer and service evidence |

These values were written during the monitored run, but each may be configured legitimately and is not a high-confidence standalone IOC.

## Network and Protocol Indicators

| Indicator | Value | Confidence | Evidence | Recommended Use |
|---|---|---|---|---|
| HTTP listener prefix | `HTTPS://*:443/EWS/EXCHANGE/` | High | Decompiled configuration and dynamic HTTP.sys state | Hunt local HTTP.sys registrations with the service |
| URI path | `/ews/exchange/` | High | YARA and dynamic HTTP.sys evidence | Case-insensitive matching with service context |
| Port | `443` | Low | Dynamic HTTP.sys evidence | Never alert on the port alone |
| Request parameter | `cid` | Medium | Decompiled request parser | Correlate with the URI and other request fields |
| Request parameter | `cadataKey` | High | YARA and decompiler evidence | Hunt with the URI and related parameters |
| Request parameter | `cadata` | Medium | Decompiled request parser | Use only with related fields; the word is broad alone |
| Request parameter | `cadataSig` | High | YARA and decompiler evidence | Hunt with the URI and related parameters |
| Validation GUID | `f2949bab-240a-46ca-a455-6f504367ba7d` | High | YARA and decompiler evidence | Search files or requests with related artifacts |
| Fallback encryption GUID | `8d963325-01b8-4671-8e82-d0904275ab06` | High | YARA and decompiler evidence | Search files or decoded requests with related artifacts |

The wildcard URL is an embedded local listener prefix, not a remote destination. No external C2 IP or domain was confirmed, and no inbound request was observed in the isolated run. Port 443 alone is not useful as an IOC.

## Storage and Task Indicators

| Indicator | Value | Confidence | Evidence | Recommended Use |
|---|---|---|---|---|
| Storage-directory pattern | `C:\Windows\Temp\{GUID}` | Medium | Decompiled path logic and dynamic directory evidence | Hunt for braced Temp directories created by the service |
| Task marker | `MSXEWS` | Medium | Reverse-engineering evidence | Search static content or task data with related indicators |
| Base64 marker | `TVNYRVdT` | Medium | Reverse-engineering evidence | Search encoded content with related indicators |

The directory name is derived from the host’s `MachineGuid`; its exact value changes between computers and must not be treated as universal.

## Installer Artifacts

| Indicator | Value | Confidence | Evidence | Recommended Use |
|---|---|---|---|---|
| Installer log | `InstallUtil.InstallLog` | Low | Filtered Noriben timeline | Pivot around suspicious .NET service installation |
| Installer log | `Microsoft.Exchange.Service.InstallLog` | Medium | Filtered Noriben timeline | Hunt near service creation time |
| Installer state | `Microsoft.Exchange.Service.InstallState` | Medium | Filtered Noriben timeline | Hunt near service creation time |

These filenames support investigation of service installation but may also occur during legitimate .NET installation activity.

## Microsoft Defender Classification

| Indicator | Value | Confidence | Evidence | Recommended Use |
|---|---|---|---|---|
| Detection name | `Trojan:MSIL/DarkNeuron.B!dha` | Medium | Defender remediation evidence | Pivot in Defender history |
| Threat ID | `2147724727` | Medium | Defender remediation evidence | Pivot in Defender telemetry |

These are Microsoft Defender identification and investigation context, not portable malware-content indicators.

## Recommended Correlations

The strongest alert combines several independent clues:

- Windows System Event ID 7045.
- `ServiceName = MSExchangeService`.
- `ImagePath` containing `Microsoft.Exchange.Service.exe`.
- `LocalSystem` execution and automatic startup as supporting context.
- HTTP.sys registration for `/ews/exchange/`.
- An unexpected `cmd.exe` child process from the service, based on source-code-confirmed capability.
- A matching file hash, preferably SHA-256.

A hash match identifies this sample directly. For behavior-based hunting, require the distinctive service or listener artifact before adding broad context such as `LocalSystem`, automatic startup, port 443, or ZoneMap settings.

## Indicators Not Confirmed

- No confirmed C2 IP address.
- No confirmed C2 domain.
- No observed attacker request.
- No confirmed external data transfer or exfiltration destination.
- No production host indicators.

## Excluded Laboratory Artifacts

| Excluded artifact | Why it must not be deployed as a production IOC |
|---|---|
| `C:\Malware\TurlaNeuron\` | Analyst-chosen laboratory sample directory |
| `C:\Users\james\` | Analyst-specific profile path |
| `433532c3-7ccc-4378-8462-ffd9d5838324` | Exact MachineGuid of the laboratory VM; use only the `{GUID}` path pattern |
| `1632, 6812, 960, PID 4` | Temporary runtime identifiers; PID 4 is also the normal Windows System process |
| Analyst username `james` | Laboratory identity, not malware-controlled data |
| Laboratory user SID | Host- and account-specific identity |
| `Pre-Noriben Turla Neuron` | Analyst-created VMware snapshot recovery label |
| `2026-07-22 laboratory timestamps` | Analysis times describe the controlled run only |
| Random Defender quarantine filenames | Temporary Defender-managed names |
| `C:\$Recycle.Bin` paths | Generic containment location, not malware content |
| `RZ18ZGP.exe` | Random temporary quarantine name |
| Port 443 by itself | Common HTTPS port used widely by legitimate software |
| ZoneMap values by themselves | Common administrative settings that need service and process context |
| Temporary Noriben filenames | Monitoring-tool artifacts from this analysis |
| `Local Kali sample path` | Analyst filesystem location, not a production artifact |

## References

- https://academy.hackthebox.com/app/module/234/section/2514
- https://academy.hackthebox.com/app/module/238/section/2584
- https://www.ncsc.gov.uk/file/2691/download?token=RzXWTuAB
- https://www.ncsc.gov.uk/alerts/turla-group-malware
