# Turla Neuron / DarkNeuron Reverse-Engineering Analysis

## Executive Technical Summary

Turla Neuron is a malicious Windows program that disguises itself as a Microsoft Exchange service. It can start automatically, open a hidden HTTPS listener, accept specially formatted encrypted instructions, run system commands, transfer files, and store encrypted settings.

The malware was analyzed in an isolated laboratory. Static analysis revealed these capabilities; dynamic analysis confirmed service installation and persistence, local HTTP.sys listener registration, and host-specific storage creation. No attacker connected, no external C2 infrastructure was identified, and no file-transfer or remote-command request was exercised.

| Area | Reconstructed behavior | Final classification |
|---|---|---|
| Entry | Install, uninstall, or service execution branches | confirmed_statically |
| Persistence | Exchange-themed automatic LocalSystem service | statically_confirmed_and_dynamically_observed |
| Listener | Local `/ews/exchange/` HTTPS request queue | statically_confirmed_and_dynamically_observed |
| Protocol | Four decoded/encrypted request fields | confirmed_statically |
| Commands | Shell, file, and configuration types 0–6 | capability_only / not_exercised |
| Configuration | Encrypted JSON in HKCU Registry values | confirmed_statically |
| Storage | MachineGuid-associated temporary directory | statically_confirmed_and_dynamically_observed |
| External C2 | No request, session, IP, or domain | not_observed |

## Analysis Scope

The sample is a managed .NET assembly examined through dnSpyEx 6.6.0 and correlated with static, dynamic, Noriben, Procmon, network, detection, and incident evidence. Decompiled C#-like output may differ from original source. No original project, debug symbols, private RSA key, external attacker interaction, complete protocol session, or usable raw malware-run Procmon PML was available.

## High-Level Malware Architecture

| Component | Primary responsibility | Evidence classification |
|---|---|---|
| `neuron_service.Program` | Argument dispatch and service entry | confirmed_statically |
| `neuron_service.ProjectInstaller` | Service configuration and immediate start | statically_confirmed_and_dynamically_observed |
| `neuron_service.MSExchangeService` | Service lifecycle, listener, and storage thread | statically_confirmed_and_dynamically_observed |
| `WebServer` / `WebServerUtils` | Listener runtime and request handling | statically_confirmed_and_dynamically_observed |
| `CommandScript` | Numeric command dispatcher | capability_only |
| `Config` | Encrypted Registry configuration | confirmed_statically |
| `Crypt` | RC4-style and RSA-related processing | confirmed_statically |
| `Storage` | Host-specific storage and cleanup loop | confirmed_statically |
| `Utils` | Host-derived key associated with MachineGuid | inferred_from_multiple_artifacts |

Only components with responsibilities supported by the structured repository evidence are included.

## Stage 1 — Program Entry

`Program.Main(string[] args)` sends `-install` to `ManagedInstallerClass.InstallHelper`, sends `-uninstall` through the installer using `/u`, and otherwise instantiates `MSExchangeService` for `ServiceBase.Run`.

In plain language, the file contains built-in options to install or remove itself as a Windows service. When started normally, it runs as that service. The install branch was exercised in the laboratory; uninstall and argument-free startup were reconstructed statically.

## Stage 2 — Service Installation and Masquerading

`ProjectInstaller.InitializeComponent` configures:

- Service name: `MSExchangeService`
- Display name: `Microsoft Exchange Service`
- Exchange-themed description
- Automatic startup
- Dedicated service process

`serviceInstaller1_AfterInstall` creates a `ServiceController` and immediately starts the service. Dynamic Registry and installer evidence confirms `Start=2`, `Type=16`, `ObjectName=LocalSystem`, the Exchange display name, and the sample ImagePath. The Exchange branding could reduce casual suspicion on systems where an administrator expects Microsoft software.

## Stage 3 — Service Startup

`MSExchangeService.OnStart`:

1. Creates a `WebServer`.
2. Assigns `WebServerUtils.SendResponse`.
3. Registers `https://*:443/ews/exchange/`.
4. Creates the storage-maintenance thread.
5. Starts `Storage.KillOldThread`.
6. Runs the web listener.

`OnStop` calls `WebServer.Stop()` and aborts the storage thread. The HTTPS prefix is a local wildcard listener, not a remote destination.

## Stage 4 — HTTP.sys Listener

Static configuration and runtime HTTP.sys state align:

- Local port: 443
- URI: `/ews/exchange/`
- Queue: Active
- Service: `MSExchangeService`
- Image: `Microsoft.Exchange.Service.exe`
- Requests arrived: 0
- Requests rejected: 0

The malware registered the URL, HTTP.sys owned the kernel socket, socket tools showed PID 4/System, and HTTP.sys mapped the application queue back to the malware service. PID 4 is not the malware. No request reached the queue, no successful TLS session was observed, and no external communication was confirmed.

## Stage 5 — Request Parsing

`WebServerUtils.SendResponse` retrieves the query string, reads the input stream, splits request-body content, extracts key-value pairs, URL-decodes values, and falls back to query-string data when parsing fails. It recognizes `cid`, `cadataKey`, `cadata`, and `cadataSig`.

The service therefore expects special fields rather than ordinary browsing traffic. No captured request demonstrates these fields on the wire.

## Stage 6 — Request Validation

The embedded validation GUID is:

```text
f2949bab-240a-46ca-a455-6f504367ba7d
```

An expected `cid` selects key-related processing; unsupported input can lead to randomized encrypted-looking output where supported by the decompiled workflow. This identifier reduces accidental interaction but must not be treated as authentication equivalent to a secure credential.

## Stage 7 — Key and Session Processing

`cadataKey` undergoes Base64 decoding, UTF-8 conversion, JSON decoding, and server/session configuration processing. RSA-related public-key encryption is present as supporting context. No `cadataKey` request, attacker-side exchange, or complete live handshake was captured.

## Stage 8 — Encrypted Command Processing

For `cadata`, the code Base64-decodes data, invokes RC4-style `EncryptScript`, uses the fallback GUID `8d963325-01b8-4671-8e82-d0904275ab06` where supported, converts UTF-8, decodes JSON, and dispatches command or storage work.

`cadataSig` uses session-key processing, constructs `CommandScript`, serializes results to JSON, applies RC4-style encryption, and Base64-encodes output. These are statically confirmed protocol behaviors, not observed network traffic.

## Stage 9 — Command Dispatcher

| Type | Operation | Input | Output | Classification |
|---:|---|---|---|---|
| 0 | Run `cmd.exe /c` with redirected stdout/stderr | Command text | Captured output and errors | capability_only |
| 1 | `WriteAllBytes` | Base64-decoded data | Operation result | capability_only |
| 2 | `ReadAllBytes` | File path | Base64 file content | capability_only |
| 3 | Return selected instruction data | Instruction selection | Selected data | confirmed_statically |
| 4 | `GetConfigAsString` | Configuration request | Configuration string | confirmed_statically |
| 5 | `AddConfigAsString` | Configuration data | Operation result | confirmed_statically |
| 6 | `DelConfigAsString` | Configuration selector | Operation result | confirmed_statically |

Type 0 uses `UseShellExecute=false`, a temporary working directory, and reads both output streams to completion. No attacker-delivered command was observed. Types 1–6 were not dynamically exercised.

## Stage 10 — Registry Configuration

`Config.FindConfig` opens `HKCU\SOFTWARE`, recursively visits subkeys, enumerates value names, reads byte arrays, decrypts them through `EncryptScript` using `Utils.GetKey`, and decodes UTF-8 JSON. Supported fields include `Connect`, `URL`, `LastStart`, `FirstStart`, `Interval`, `SubKey`, and `ValueName`.

`Config.WriteConfig` opens the selected subkey for writing, serializes configuration as JSON, encrypts it, writes `REG_BINARY`, and returns success or failure.

In plain language, the malware can hide encrypted settings in an ordinary user Registry area. The exact hidden key/value was not found dynamically. The observed ZoneMap writes are separate installer behavior and do not prove this configuration path executed.

## Stage 11 — Cryptography

### RC4-Style EncryptScript

`EncryptScript` uses 256-entry key and permutation arrays, a key-scheduling phase, pseudo-random generation, and XOR. The same symmetric transformation encrypts or decrypts when supplied with the correct key.

### RSA Processing

Repository evidence supports `RSACryptoServiceProvider`, a 1024-bit public key, exponent 65537, OAEP, and Base64 output as reverse-engineering context. Only a public key was recovered; no private key was present, so RSA-encrypted content could not be decrypted from the sample alone.

### Host-Derived Key

`Utils.GetKey()` is associated with Windows MachineGuid. Host-derived data differs between systems, so the laboratory GUID is not a family-wide IOC.

## Stage 12 — Storage and Task Processing

`Storage.GetPathName` uses the system temporary directory and a host-derived key. Under LocalSystem, dynamic evidence showed:

```text
C:\Windows\Temp\{MachineGuid}
```

The generalized hunt pattern is `C:\Windows\Temp\{GUID}`. Supported artifacts include task marker `MSXEWS`, Base64 marker `TVNYRVdT`, and `.TMP` output. The indexed evidence does not directly establish duplicate-task avoidance, detailed task headers, minimum-size rules, or seven-day retention, so those are not promoted.

## Stage 13 — Storage Cleanup

`Storage.KillOldThread` calls `Storage.KillOld`, sleeps 300000 milliseconds (five minutes), and repeats indefinitely.

The host-specific directory was created dynamically but was empty when inspected. No task/response file or cleanup action was observed. The cleanup loop is confirmed statically only.

## Stage 14 — Dynamic Confirmation

| Reconstructed behavior | Static evidence | Dynamic evidence | Final classification |
|---|---|---|---|
| Service installation | Installer code | Installer log and service artifacts | statically_confirmed_and_dynamically_observed |
| Immediate service start | AfterInstall handler | Running listener/service | statically_confirmed_and_dynamically_observed |
| Automatic persistence | Installer configuration | `Start=2` Registry value | statically_confirmed_and_dynamically_observed |
| LocalSystem execution | Account not hardcoded in visible installer view | `ObjectName=LocalSystem` | observed_dynamically |
| Exchange masquerading | Names and description | Service Registry | statically_confirmed_and_dynamically_observed |
| HTTP.sys listener | `OnStart` prefix | Active request queue | statically_confirmed_and_dynamically_observed |
| Host-specific directory | `GetPathName` | Empty MachineGuid directory | statically_confirmed_and_dynamically_observed |
| Installer logs | Installer flow | InstallLog/InstallState | observed_dynamically |
| Event Log source | Installer behavior | Application source key | observed_dynamically |
| ZoneMap writes | Not used as proof of core config | Noriben timeline/Registry view | observed_dynamically |
| Command execution | Type 0 code | None | capability_only |
| File read/write | Types 1–2 code | None | capability_only |
| Hidden Registry configuration | `Config` code | None | confirmed_statically |
| Storage polling | `KillOldThread` code | No cleanup action | confirmed_statically / not_exercised |
| External C2 communication | Listener/protocol capability | Zero requests and no traffic | not_observed |

## Protocol Summary

| Field | Purpose | Processing | Observed on wire? |
|---|---|---|---|
| `cid` | Validation selector | Parse, URL-decode, compare GUID | No |
| `cadataKey` | Key/session data | Base64, UTF-8, JSON, key processing | No |
| `cadata` | Encrypted command/storage data | Base64, RC4-style processing, JSON | No |
| `cadataSig` | Session command data | Session key, CommandScript, encrypted response | No |

No PCAP contained these fields, and no live request or response was captured. Protocol conclusions come from decompiled code.

## Execution Flow Summary

1. The executable receives an argument.
2. `-install` invokes the .NET installer.
3. The installer creates `MSExchangeService`.
4. The service starts automatically as LocalSystem.
5. `OnStart` registers `/ews/exchange/`.
6. HTTP.sys manages the port-443 listener.
7. The service waits for specially formatted requests.
8. Request fields are decoded and decrypted.
9. Commands are dispatched by numeric type.
10. Results are serialized, encrypted, and encoded.
11. Host-specific storage is checked periodically.
12. The service remains persistent until stopped or removed.

See the separate [execution-flow diagram](turla_neuron_execution_flow.md).

## Detection Engineering Value

### YARA

High-value artifacts include `MSExchangeService`, `/ews/exchange/`, both GUIDs, `cadataKey`, `cadataSig`, `ExecCMD`, `KillOldThread`, `EncryptScript`, `MSXEWS`, and `TVNYRVdT`. See the [YARA rule](../../detections/yara/turla_neuron_v2.yar).

### Sigma

Correlate System Event ID 7045, `ServiceName=MSExchangeService`, an ImagePath containing `Microsoft.Exchange.Service.exe`, LocalSystem, and automatic startup. See the [Sigma rule](../../detections/sigma/win_system_turla_neuron_service_install.yml).

### Splunk and EDR

Correlate service installation, service launch, `cmd.exe` spawned by the service, Registry persistence, HTTP.sys queues, ZoneMap writes, and the host-specific temporary directory.

### Network Detection

Investigate `/ews/exchange/` on non-Exchange systems, the four request fields, the GUIDs, and unexpected HTTP.sys listeners. HTTPS inspection, endpoint telemetry, or reverse-proxy logs may be required to observe fields.

## MITRE ATT&CK Mapping

| Technique | ID | Evidence | Classification |
|---|---|---|---|
| Windows Service | T1543.003 | Installer and persistence | Observed dynamically |
| Windows Command Shell | T1059.003 | Type 0 dispatcher | Capability only |
| Modify Registry | T1112 | Config code and observed service/ZoneMap writes | Confirmed statically and observed dynamically |
| Web Protocols | T1071.001 | HTTPS listener and handler | Observed dynamically |
| Encrypted Channel | T1573 | RC4/RSA-related processing | Confirmed statically |
| Data Encoding | T1132.001 | Base64 request/response handling | Confirmed statically |
| Ingress Tool Transfer | T1105 | File write/read command types | Capability only |
| Deobfuscate/Decode Files or Information | T1140 | Base64 and encrypted-data decoding | Confirmed statically |

## Analyst Conclusions

Turla Neuron persists as an Exchange-themed Windows service and uses HTTP.sys for a local HTTPS request queue. Its request handler recognizes four fields, applies validation, encoding, and encryption, and dispatches shell, file, or configuration operations. It can search and write encrypted Registry configuration and derive a host-specific temporary path.

Dynamic evidence confirms the installer, automatic LocalSystem persistence, active listener, and empty host-specific directory. It does not show external interaction, command execution, file transfer, hidden configuration, or cleanup activity.

## Evidence Limitations

- Decompiled code is not original source, and no debug symbols were available.
- No attacker request or complete protocol session was captured.
- No C2 IP or domain was identified.
- No private RSA key was recovered.
- No command or file-transfer request was exercised.
- The hidden configuration location was not dynamically identified.
- The malware-run PML was unusable.
- The host storage directory was empty.
- Some names may reflect decompiler output.
- Laboratory paths, process IDs, timestamps, and MachineGuid are environmental.

## Evidence References

- [dnSpy analysis](../dnspy/turla_neuron_dnspy_analysis.md)
- [Static analysis](../static/turla_neuron_static_analysis.md)
- [Dynamic analysis](../dynamic/turla_neuron_dynamic_analysis.md)
- [Network analysis](../network/turla_neuron_network_analysis.md)
- [Noriben analysis](../noriben/turla_neuron_noriben_analysis.md)
- [Procmon analysis](../procmon/turla_neuron_procmon_analysis.md)
- [IOC package](../../iocs/turla_neuron_iocs.md)
- [Incident report](../../reports/incident-report.md)
- [Service installer screenshot](../../screenshots/TurlaNeuron_05_dnSpy_Service_Installer_Configuration.png)
- [Request validation screenshot](../../screenshots/TurlaNeuron_10_dnSpy_SendResponse_Request_Validation.png)
- [Command execution screenshot](../../screenshots/TurlaNeuron_12_dnSpy_CommandScript_Type0_Command_Execution.png)
- [Registry configuration screenshot](../../screenshots/TurlaNeuron_16_dnSpy_Config_Registry_Search_and_Decryption.png)
- [RC4-style routine screenshot](../../screenshots/TurlaNeuron_19_dnSpy_RC4_EncryptScript_Implementation.png)
- [HTTP.sys listener screenshot](../../screenshots/TurlaNeuron_25_Dynamic_HTTPsys_EWS_Exchange_URL_Registration.png)
- [Service persistence screenshot](../../screenshots/TurlaNeuron_28_Dynamic_Service_Registry_Persistence.png)
