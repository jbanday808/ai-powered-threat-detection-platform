# Turla Neuron / DarkNeuron dnSpy Reverse-Engineering Analysis

## Analysis Overview

dnSpy was used to read the internal .NET code of the malware without relying only on its filename or antivirus label. This revealed how the program installs itself, waits for instructions, runs commands, handles files, stores configuration, and protects data with encryption.

| Field | Value |
|---|---|
| Sample filename | `Microsoft.Exchange.Service.exe` |
| SHA-256 | `d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29` |
| Malware family | Turla Neuron / DarkNeuron |
| Microsoft Defender detection | `Trojan:MSIL/DarkNeuron.B!dha` |
| Analysis tool | dnSpyEx 6.6.0 |
| Analysis date | 2026-07-22 |
| Analyst | James Banday |
| Analysis classification | Static reverse engineering |

## Scope and Limitations

- The executable was decompiled as a .NET assembly.
- Decompiled C# may differ slightly from the original source code because names and control flow are reconstructed from compiled instructions.
- Dynamic execution evidence is documented separately in the incident report and screenshots.
- A static capability proves that code exists; it does not prove that an attacker exercised it.
- No private RSA key was recovered.
- No external C2 IP address or domain was confirmed.
- No malware executable is stored in this results directory.

The labels used below are:

- **Confirmed statically:** The relevant code or embedded value is visible in decompiler evidence.
- **Confirmed dynamically:** A separate runtime artifact confirms the behavior occurred during the isolated run.
- **Capability present but not exercised:** Code exists, but the runtime evidence does not show it being used.
- **Supporting context:** Useful interpretation that is not, by itself, direct proof of execution.
- **Evidence limitation:** A boundary on what the available evidence can establish.

## Assembly and Entry Point

**Classification: Confirmed statically**

| Item | Value |
|---|---|
| Namespace | `neuron_service` |
| Primary class | `Program` |
| Method | `Main(string[] args)` |

`Main` implements three paths:

- `-install` passes the executing assembly location to `ManagedInstallerClass.InstallHelper`.
- `-uninstall` invokes `InstallHelper` with `/u` and the executing assembly location.
- With no recognized argument, it creates `MSExchangeService` and starts it through `ServiceBase.Run`.

**Plain-language explanation:** The program can install or remove itself as a Windows service. When run normally, it starts the hidden service component.

**Evidence limitation:** This code defines available entry paths. The screenshot is not a runtime command-line record.

## Service Installer

### `ProjectInstaller.InitializeComponent`

**Classification: Confirmed statically**

| Property | Value |
|---|---|
| ServiceName | `MSExchangeService` |
| DisplayName | `Microsoft Exchange Service` |
| Description | `Host service for the Microsoft Exchange Server management provider. If this service is stopped or disabled, Microsoft Exchange cannot be managed.` |
| Installer credentials | Username and password are `null`; no hardcoded credentials are visible |

The service was configured to resemble a legitimate Microsoft Exchange component.

**Plain-language explanation:** The malware uses a believable Microsoft Exchange name so that the service may look legitimate to an administrator.

### `ProjectInstaller.serviceInstaller1_AfterInstall`

**Classification: Confirmed statically**

The post-install handler:

- Creates a `ServiceController` for `MSExchangeService`.
- Calls `Start()` to start the newly installed service immediately.

**Dynamic correlation:** The installer log and service Registry evidence separately confirm that `MSExchangeService` was installed during the controlled run.

## Service Runtime

### `MSExchangeService.OnStart`

**Classification: Confirmed statically**

The method:

- Creates a `WebServer` instance.
- Uses `WebServerUtils.SendResponse` as the request handler.
- Registers `https://*:443/ews/exchange/`.
- Creates and starts a thread for `Storage.KillOldThread`.
- Calls the web server’s `Run()` method.

**Plain-language explanation:** When Windows starts the service, the malware opens a hidden web address and waits for instructions.

**Dynamic correlation:** HTTP.sys state separately confirms an active request queue for `HTTPS://*:443/EWS/EXCHANGE/`. Its counters showed no inbound requests.

### `MSExchangeService.OnStop`

**Classification: Confirmed statically**

The method:

- Calls `WebServer.Stop()`.
- Calls `Abort()` on the storage thread.

No graceful cleanup behavior beyond those calls is inferred.

## Request Parsing and Validation

### `WebServerUtils.SendResponse`

**Classification: Confirmed statically**

The method:

- Reads the request query string.
- Attempts to read the POST body through a `StreamReader`.
- Splits body data into key-value pairs.
- URL-decodes values.
- Iterates through the resulting keys.

The validation identifier is:

```text
cid = f2949bab-240a-46ca-a455-6f504367ba7d
```

Recognized request fields include:

- `cid`
- `cadataKey`
- `cadata`
- `cadataSig`

**Plain-language explanation:** The malware expects specially formatted messages. It checks hidden identifiers before processing instructions.

**Evidence limitation:** The code proves the parser and validation values exist. No accepted external attacker request was observed.

## Encrypted Command Channel

**Classification: Confirmed statically; protocol capability not exercised**

### `cadataKey`

The code Base64-decodes supplied content, converts it from UTF-8, parses JSON, and associates the result with key-exchange or encrypted-session processing.

### `cadata`

The code:

- Base64-decodes the value.
- Passes the data to `EncryptScript`.
- Uses fallback GUID `8d963325-01b8-4671-8e82-d0904275ab06`.
- Parses the decrypted content as JSON.
- Uses the decoded object for storage or command requests.

### `cadataSig`

The code associates this field with session-key processing, creates `CommandScript` objects, serializes results as JSON, encrypts the result, and Base64-encodes the response.

**Evidence limitation:** No successful external command request was observed dynamically. These are statically confirmed protocol capabilities, not evidence of an active C2 session.

## Command Processing

The `CommandScript` implementation dispatches numeric command types. The screenshots show shell execution, output capture, file operations, and configuration calls.

| Command type | Capability | Static evidence | Dynamic status |
|---:|---|---|---|
| 0 | Launches `cmd.exe` with `/c`; sets `UseShellExecute = false`; hides the window; redirects standard output and error; uses a temporary working directory; reads both output streams | Process configuration and stream-reading code | Confirmed statically; remote command execution not observed |
| 1 | Base64-decodes supplied data and writes bytes to a file | `FromBase64String` and `WriteAllBytes` | Capability present but not exercised |
| 2 | Reads bytes from a file and Base64-encodes the contents | `ReadAllBytes` and `ToBase64String` | Capability present but not exercised |
| 3 | Returns or passes through selected instruction data | Command-dispatch branch | Confirmed statically; not exercised dynamically |
| 4 | Calls `GetConfigAsString` | Configuration-dispatch branch | Confirmed statically; not exercised dynamically |
| 5 | Calls `AddConfigAsString` | Configuration-dispatch branch | Confirmed statically; not exercised dynamically |
| 6 | Calls `DelConfigAsString` | Configuration-dispatch branch | Confirmed statically; not exercised dynamically |

**Plain-language explanation:** The code could run hidden Windows commands, collect their output, move file content in or out, and manage settings. The isolated run did not record an attacker using these command types.

## Registry Configuration

### `Config.FindConfig`

**Classification: Confirmed statically**

The method:

- Opens `HKCU\SOFTWARE`.
- Recursively enumerates subkeys.
- Enumerates Registry value names.
- Reads values as byte arrays.
- Calls `Crypt.EncryptScript` with `Utils.GetKey()`.
- Converts the decrypted bytes from UTF-8.
- Decodes the result as JSON configuration.

Identified configuration fields include:

- `Connect`
- `URL`
- `LastStart`
- `FirstStart`
- `Interval`
- `SubKey`
- `ValueName`

**Plain-language explanation:** The malware can hide encrypted settings inside the current user’s Registry and search for them later.

### `Config.WriteConfig`

**Classification: Confirmed statically**

The method:

- Opens `HKCU\SOFTWARE\<SubKey>` for writing.
- Serializes the configuration as JSON.
- Encrypts the data with `EncryptScript` and `Utils.GetKey()`.
- Writes it using `RegistryValueKind.Binary` (`REG_BINARY`).
- Returns success or failure.

**Evidence limitation:** The hidden malware configuration was not confirmed dynamically. The evidence establishes the read/write capability, not that a specific encrypted configuration value existed during the run.

## Cryptography

### RC4-Style `EncryptScript`

**Classification: Confirmed statically**

The visible method uses:

- Two 256-entry arrays.
- A key-scheduling loop.
- Pseudo-random byte generation.
- XOR of each input byte with the generated stream.
- One symmetric routine that can support both encryption and decryption.

**Plain-language explanation:** The malware scrambles instructions and stored settings so they are difficult to read without the correct key.

### RSA `Encryption`

**Classification: Supporting context**

The decompiled cryptography component identifies:

- `RSACryptoServiceProvider`.
- A 1024-bit RSA key.
- Public exponent 65537.
- An embedded public key.
- OAEP encryption enabled.
- Base64 output.

Only a public key was present. No private key was recovered, so the sample alone did not provide the material needed to decrypt RSA-encrypted data.

**Evidence limitation:** The indexed screenshot visibly shows the `Crypt.Encryption` methods in the class tree but displays the `EncryptScript` body, not the detailed RSA method body. RSA properties are retained as supporting reverse-engineering context rather than promoted to dynamically observed behavior.

## Storage and Task Processing

### `Storage.KillOldThread`

**Classification: Confirmed statically**

The method repeats indefinitely:

1. Calls `Storage.KillOld(null)`.
2. Sleeps for `300000` milliseconds.

`300000` milliseconds equals five minutes.

### `Storage.GetPathName`

**Classification: Confirmed statically**

The method:

- Reads the system temporary-directory environment variable.
- Creates a directory named from `Utils.GetKey()`.
- Returns the same braced directory path.
- Uses a key associated with the host `MachineGuid`.

When the service ran as `LocalSystem`, dynamic evidence placed the directory under:

```text
C:\Windows\Temp\{MachineGuid}
```

The exact laboratory MachineGuid is environmental and must not be treated as a universal IOC. The dynamically observed directory was empty when inspected.

### Task Artifacts

**Classification: Supporting context**

Repository reverse-engineering artifacts identify:

- Task marker: `MSXEWS`
- Base64 marker: `TVNYRVdT`
- Task-output extension: `.TMP`
- Cleanup of older files through `KillOld`

The five-minute cleanup invocation is directly visible. Seven-day retention and duplicate-task avoidance are not documented as findings because the indexed evidence does not directly establish those details.

## Static-to-Dynamic Correlation

| Static finding | Dynamic confirmation | Status |
|---|---|---|
| `MSExchangeService` installer | Installer log records successful installation | Confirmed dynamically |
| Immediate service start | Service persistence and runtime artifacts followed installation | Confirmed dynamically |
| `LocalSystem` service execution | Service Registry `ObjectName = LocalSystem` | Confirmed dynamically |
| `Microsoft.Exchange.Service.exe` ImagePath | Service Registry captured the executable path | Confirmed dynamically |
| HTTP.sys `/ews/exchange/` registration | Active HTTP.sys request queue and URL captured | Confirmed dynamically |
| MachineGuid-based storage directory | Braced directory observed under `C:\Windows\Temp` | Confirmed dynamically |
| Event Log source creation | `MSExchangeService` Application source key observed | Confirmed dynamically |
| ZoneMap Registry writes | Filtered Noriben and Registry evidence | Supporting evidence |
| Installer-log creation | `InstallUtil.InstallLog`, `.InstallLog`, and `.InstallState` activity | Confirmed dynamically |
| Command execution capability | No attacker command captured | Not exercised |
| File-transfer capability | No transfer captured | Not exercised |
| Encrypted Registry configuration | No hidden configuration value confirmed | Confirmed statically only |

## Detection Engineering Value

### YARA

The decompiler findings support static matching on:

- `MSExchangeService`
- `/ews/exchange/`
- `f2949bab-240a-46ca-a455-6f504367ba7d`
- `8d963325-01b8-4671-8e82-d0904275ab06`
- `cadataKey`
- `cadataSig`
- `ExecCMD`
- `KillOldThread`

The repository YARA rule uses a combination of these strings rather than treating a broad string as sufficient by itself.

### Sigma

The service findings support a Windows System service-installation rule using:

- Event ID 7045.
- `ServiceName = MSExchangeService`.
- `ImagePath` containing `Microsoft.Exchange.Service.exe`.
- `LocalSystem` and automatic startup as optional supporting context.

### Splunk and Sysmon

Recommended, but not validated here, searches include:

- `Microsoft.Exchange.Service.exe` running as a service.
- `cmd.exe` launched by the service process.
- Registry creation under the service key.
- HTTP.sys listener registration.
- Unexpected Exchange-themed services on non-Exchange systems.

### Network Detection

Recommended investigation pivots include:

- `/ews/exchange/` on systems not running Microsoft Exchange.
- The combined request fields `cid`, `cadataKey`, `cadata`, and `cadataSig`.
- Unexpected port-443 listeners tied to the suspicious service.

These are detection recommendations. No network signature or SIEM query is claimed as validated by this package.

## MITRE ATT&CK Mapping

| Technique | ID | Static evidence | Classification |
|---|---|---|---|
| Windows Service | T1543.003 | Installer, service entry point, post-install start, and runtime class | Confirmed dynamically |
| Windows Command Shell | T1059.003 | Hidden `cmd.exe /c` with output and error capture | Confirmed statically |
| Modify Registry | T1112 | Encrypted configuration search/write code | Confirmed statically |
| Web Protocols | T1071.001 | HTTPS listener and structured request fields | Capability only |
| Data Encoding | T1132.001 | Base64 request, response, and file-content conversion | Confirmed statically |
| Encrypted Channel | T1573 | RC4-style and RSA-related protocol processing | Capability only |
| Ingress Tool Transfer | T1105 | File write/read command types | Capability only |
| Deobfuscate/Decode Files or Information | T1140 | Base64 decoding, decryption, and JSON decoding | Confirmed statically |

The Windows service behavior was dynamically confirmed by separate runtime evidence. The remaining classifications describe code capability unless explicitly stated otherwise.

## Key Findings

- Turla Neuron uses a Windows service named `MSExchangeService` and Exchange-themed metadata for persistence and masquerading.
- Service startup creates an HTTPS listener at `/ews/exchange/` and a five-minute storage-cleanup thread.
- `SendResponse` implements structured request parsing and checks embedded identifiers.
- Command types provide hidden shell execution, output capture, file operations, and configuration management.
- Registry configuration can be recursively located, decrypted, updated, and stored as binary data.
- `EncryptScript` implements an RC4-style symmetric transform.
- Storage paths are derived from a host-specific key and therefore differ across systems.
- Dynamic evidence confirms the service, listener, Event Log source, installer artifacts, and host-specific directory—but not attacker commands, file transfer, or hidden configuration use.

## Evidence Limitations

- Decompiled code is not the original source.
- The raw Procmon PML was not usable as primary evidence; the report relies on filtered Noriben output and captured artifacts.
- No attacker sent commands during the isolated run.
- No external C2 infrastructure was identified.
- File-transfer and configuration commands were not dynamically exercised.
- No confirmed data exfiltration occurred.
- The analysis used a laboratory path that is not a universal IOC.
- No private RSA key was recovered.

## Screenshot Evidence Index

Every existing dnSpy screenshot numbered 05 through 21 is indexed below.

| Screenshot | Function or behavior | Classification |
|---|---|---|
| ![Program entry point with install and uninstall handling](../../screenshots/TurlaNeuron_05_dnSpy_Service_Installer_Configuration.png) | `Program.Main`: install, uninstall, and service execution | Confirmed statically |
| ![AfterInstall starts MSExchangeService](../../screenshots/TurlaNeuron_06_dnSpy_AfterInstall_Automatic_Service_Start.png) | `serviceInstaller1_AfterInstall`: immediate service start | Confirmed statically |
| ![ProjectInstaller Exchange-themed service settings](../../screenshots/TurlaNeuron_07_dnSpy_Service_Installer_Configuration.png) | `InitializeComponent`: service name, display name, and description | Confirmed statically |
| ![OnStart creates HTTPS listener and storage thread](../../screenshots/TurlaNeuron_08_dnSpy_Service_OnStart_HTTPS_Listener.png) | `MSExchangeService.OnStart` | Confirmed statically |
| ![OnStop stops server and aborts thread](../../screenshots/TurlaNeuron_09_dnSpy_Service_OnStop.png) | `MSExchangeService.OnStop` | Confirmed statically |
| ![SendResponse request parsing and cid validation](../../screenshots/TurlaNeuron_10_dnSpy_SendResponse_Request_Validation.png) | `WebServerUtils.SendResponse`: parsing and validation | Confirmed statically |
| ![cadata encrypted command-channel processing](../../screenshots/TurlaNeuron_11_dnSpy_Cadata_RC4_Remote_Storage_Command_Channel.png) | `cadata` decode, decrypt, JSON parse, and dispatch | Confirmed statically |
| ![Command type zero creates hidden cmd process](../../screenshots/TurlaNeuron_12_dnSpy_CommandScript_Type0_Command_Execution.png) | Command type 0 shell execution | Capability present but not exercised |
| ![Command output and error redirection](../../screenshots/TurlaNeuron_13_dnSpy_CommandScript_Type0_Execution_and_Output_Capture.png) | Standard output and error capture | Capability present but not exercised |
| ![File write read and Base64 operations](../../screenshots/TurlaNeuron_14_dnSpy_CommandScript_Types1_2_File_Transfer.png) | Command types 1 and 2 file operations | Capability present but not exercised |
| ![Configuration command operations](../../screenshots/TurlaNeuron_15_dnSpy_CommandScript_Configuration_Operations.png) | Command types 4–6 configuration functions | Capability present but not exercised |
| ![Recursive Registry search and decryption](../../screenshots/TurlaNeuron_16_dnSpy_Config_Registry_Search_and_Decryption.png) | `Config.FindConfig` search and decode | Confirmed statically |
| ![Configuration field accessors and value tracking](../../screenshots/TurlaNeuron_17_dnSpy_Config_Fields_SubKey_ValueName.png) | Configuration fields, `SubKey`, and `ValueName` | Confirmed statically |
| ![Encrypted binary Registry write](../../screenshots/TurlaNeuron_18_dnSpy_Config_Encrypted_Registry_Write.png) | `Config.WriteConfig` | Confirmed statically |
| ![RC4-style EncryptScript implementation](../../screenshots/TurlaNeuron_19_dnSpy_RC4_EncryptScript_Implementation.png) | `Crypt.EncryptScript` and cryptography component | Confirmed statically |
| ![Five-minute KillOldThread loop](../../screenshots/TurlaNeuron_20_dnSpy_Storage_Five_Minute_Polling.png) | `Storage.KillOldThread` | Confirmed statically |
| ![Host-specific temporary storage path](../../screenshots/TurlaNeuron_21_dnSpy_Host_Specific_Storage_Path.png) | `Storage.GetPathName` | Confirmed statically |
