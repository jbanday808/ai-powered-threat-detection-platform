# Turla Neuron / DarkNeuron Network Analysis

## Analysis Overview

Network analysis examines how malware communicates or waits for communication. During this isolated test, Turla Neuron opened a local HTTPS listening address, but the computer’s network adapter was disabled, so no outside system could contact it.

| Field | Value |
|---|---|
| Incident ID | MAL-2026-0721-NEURON |
| Sample | Microsoft.Exchange.Service.exe |
| SHA-256 | d1d7a96fcadc137e80ad866c838502713db9cdfe59939342b8e3beacf9c7fe29 |
| Service | MSExchangeService |
| Listener | `https://*:443/ews/exchange/` |
| Network adapter | Disabled |
| External traffic | Not observed |
| Packet capture | Not available |
| Analysis date | 2026-07-22 |
| Analyst | James Banday |

This package distinguishes embedded listener configuration, local socket state, HTTP.sys request-queue registration, and actual communications. Only the first three were supported; no inbound request, outbound connection, or successful command-and-control session occurred.

## Scope and Safety Controls

A VMware snapshot was created before execution. The Windows adapter was disabled, with no NAT or bridged access and no unrestricted Internet connection. No production system or network was involved. FakeNet, INetSim, DNS simulation, C2 emulation, and inbound test requests were not used. Evidence was collected through local Windows inspection, processed Noriben output, and static decompilation.

## Network State Before Execution

The retained laboratory account records `Ethernet0` as `Disabled` with a link speed of `0 bps`. `MSExchangeService` was absent before execution, and the VM was prepared for offline analysis.

A disabled physical or virtual adapter does not remove the local TCP/IP stack. Windows can still register a wildcard listener and maintain a local HTTP.sys request queue even when external systems cannot reach it.

## Static Listener Configuration

dnSpy evidence shows that `MSExchangeService.OnStart` created a `WebServer`, registered:

```text
https://*:443/ews/exchange/
```

and used `WebServerUtils.SendResponse` as its request handler. A separate background storage thread was also started. `MSExchangeService.OnStop` stopped the web server and aborted the storage thread.

In plain language, the malware was designed to open a hidden web address on the infected computer and wait for specially formatted instructions.

The wildcard `*` is a local host binding, not an attacker IP, domain, or remote C2 URL. Port 443 is common and is not malicious by itself. Code configured to listen, a socket observed listening, a registered HTTP.sys queue, and an actual remote exchange are different evidence states.

## Dynamic Socket Observation

The preserved analysis records these socket views:

| Tool view | Local endpoint | State | Owning process |
|---|---|---|---:|
| `Get-NetTCPConnection` | `[::]:443` | Listen | 4 |
| `netstat` | `0.0.0.0:443` | LISTENING | 4 |
| `netstat` | `[::]:443` | LISTENING | 4 |

Windows reported the listener under PID 4 because HTTP.sys handles HTTP and HTTPS sockets in the Windows kernel. PID 4/System is not Turla Neuron, must not be used as a malware IOC, and was not a child or injected malware process. The HTTP.sys request queue—not PID alone—associated the listener with the service. All process IDs are temporary laboratory values.

## HTTP.sys Request Queue

HTTP.sys evidence shows:

- Request queue state: Active
- Active processes attached: 1
- Associated and tagged service: `MSExchangeService`
- Process image: `C:\Malware\TurlaNeuron\Microsoft.Exchange.Service.exe`
- Registered URLs: 1
- Registered URL: `HTTPS://*:443/EWS/EXCHANGE/`
- Requests arrived: 0
- Requests rejected: 0
- Cache hits: 0

The Windows networking system therefore confirmed that the service was waiting at the Exchange-themed endpoint. No request reached it during the test. URL capitalization in HTTP.sys output does not change the meaning of the path. The executable path is specific to this laboratory and is not a universal network indicator.

## HTTP.sys, PID 4, and the Malware Process

The attribution chain is:

1. `Microsoft.Exchange.Service.exe` registered an HTTPS prefix.
2. HTTP.sys created or managed the kernel listening socket.
3. Socket tools attributed port 443 to PID 4/System.
4. HTTP.sys service-state output linked the application request queue to `Microsoft.Exchange.Service.exe` and `MSExchangeService`.
5. PID 4 owned the socket infrastructure, while the malware service owned the registered application queue.

This explains the apparently conflicting process attribution without misclassifying the Windows kernel process as malware.

## SSL Certificate Binding

The recorded command was:

```text
netsh http show sslcert ipport=0.0.0.0:443
```

The system reported that it could not find the specified SSL certificate binding. No binding was therefore observed for `0.0.0.0:443`. Depending on HTTP.sys configuration, that could prevent a complete TLS handshake even though the listener prefix and queue were registered.

This result is interpreted cautiously: all possible certificate binding forms were not exhaustively checked, and no successful encrypted communication is claimed.

## URL ACL Review

Existing HTTP.sys URL reservations were reviewed. No persistent Turla Neuron-specific reservation for `https://*:443/ews/exchange/` was observed. Other legitimate Windows reservations, including unrelated use of port 443, were not attributed to Turla Neuron.

A runtime listener registration is not the same as a permanent URL ACL reservation. The observed active queue proves runtime registration only.

## Noriben Network Findings

The processed Noriben report recorded empty `Network Traffic` and `Unique Hosts` sections. No external traffic or unique remote host was identified. This was expected with the adapter disabled and does not contradict the active local HTTP.sys listener.

## Requests and Connections

| Activity | Result | Evidence classification |
|---|---|---|
| Local HTTPS listener created | Observed | observed_local_listener |
| HTTP.sys request queue active | Observed | confirmed_by_http_sys |
| Inbound request | Not observed | not_observed |
| Outbound TCP connection | Not observed | not_observed |
| DNS query related to Turla Neuron | Not observed | not_observed |
| External C2 IP | Not identified | not_observed |
| External C2 domain | Not identified | not_observed |
| TLS session | Not observed | not_observed |
| HTTP request body | Not captured | evidence_limitation |
| HTTP response body | Not captured | evidence_limitation |
| Command execution from network request | Not observed | not_observed |
| File transfer over network | Not observed | not_observed |
| Data exfiltration | Not observed | not_observed |

## Packet-Capture Availability

No PCAP, PCAPNG, or ETL packet capture was found. The VM was deliberately kept offline. Network conclusions are based on local socket state, HTTP.sys request-queue output, Noriben’s empty network section, and static code analysis. No packet count, capture duration, interface, or payload statistic is asserted.

## Protocol Reconstruction

Static code supports the following expected request elements:

- URI path: `/ews/exchange/`
- `cid`
- `cadataKey`
- `cadata`
- `cadataSig`
- Validation GUID: `f2949bab-240a-46ca-a455-6f504367ba7d`
- Fallback encryption GUID: `8d963325-01b8-4671-8e82-d0904275ab06`

The request handler parses query strings and request bodies, URL-decodes values, Base64-decodes data, processes JSON, applies RC4-style processing, performs RSA-related key handling, and returns encrypted and encoded responses.

These fields and operations were found in decompiled code. They were not observed in network traffic. No request payload, response payload, or protocol session was collected, so the exact on-wire exchange cannot be fully reconstructed from this run. No live command, exploit, or tasking request was generated.

## Network Indicators

| Indicator | Type | Confidence | Scope | Notes |
|---|---|---|---|---|
| `/ews/exchange/` | URI path | High with host correlation | Family-associated | Investigate on non-Exchange hosts |
| `https://*:443/ews/exchange/` | Local listener prefix | High | Host behavior | Wildcard prefix is not a remote address |
| `cid` | Request field | Medium | Protocol support | Too broad alone |
| `cadataKey` | Request field | Medium | Protocol support | Correlate with other fields |
| `cadata` | Request field | Medium | Protocol support | Too broad alone |
| `cadataSig` | Request field | Medium | Protocol support | Correlate with other fields |
| `f2949bab-240a-46ca-a455-6f504367ba7d` | Validation GUID | High | Embedded identifier | Distinctive when combined with the listener |
| `8d963325-01b8-4671-8e82-d0904275ab06` | Encryption fallback GUID | High | Embedded identifier | Distinctive static artifact |

No C2 IP address or domain is available. The wildcard listener is not a remote address, the laboratory executable path is not a universal network indicator, and port 443 alone is excluded as overly broad.

## Detection Engineering Recommendations

### Host-Based Detection

- Detect unexpected HTTP.sys request queues.
- Detect `/ews/exchange/` registrations on non-Exchange systems.
- Correlate port-443 listeners with recent service creation.
- Alert on `MSExchangeService` using `Microsoft.Exchange.Service.exe`.
- Identify Exchange-themed services on systems that are not Exchange servers.

### Network IDS or Suricata

Where decrypted traffic or reverse-proxy logs are available, defensive logic could require `/ews/exchange/` plus at least two of `cid`, `cadataKey`, `cadata`, and `cadataSig`, or the known validation GUID.

HTTPS normally encrypts URI and body data after the TLS handshake. A network IDS cannot reliably see these fields without TLS inspection, endpoint telemetry, reverse-proxy logging, or another decrypted source. Matching only port 443 is too broad, and `/ews/exchange/` could overlap with legitimate Exchange activity. Correlation with service and host context is strongly recommended. No Suricata rule is presented as validated because no suitable packet or capture exists.

### Splunk and SIEM Hunting

Search for HTTP.sys URL-registration telemetry, port-443 listeners on non-web servers, `MSExchangeService`, `Microsoft.Exchange.Service.exe`, `/ews/exchange/`, service installation followed by listener creation, and unexpected service processes attached to HTTP.sys queues.

### Firewall and EDR Response

Isolate a suspected host, determine whether it is a legitimate Exchange server, verify the service configuration and executable hash, review port-443 listeners and command-shell child processes, and preserve volatile socket state, HTTP.sys output, and packet evidence before termination.

## MITRE ATT&CK Mapping

| Technique | ID | Evidence | Classification |
|---|---|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS listener and request handler | observed_local_listener |
| Encrypted Channel | T1573 | RC4/RSA-related protocol logic | confirmed_statically |
| Windows Service | T1543.003 | Listener hosted by installed service | observed_local_listener |
| Data Encoding | T1132.001 | Base64 request/response processing | confirmed_statically |
| Ingress Tool Transfer | T1105 | File-transfer command capability | capability_only |

Exfiltration over a C2 channel is not mapped as observed because no exfiltration occurred.

## Key Findings

- The malware contained an HTTPS listener at `/ews/exchange/`.
- The service registered an active HTTP.sys request queue.
- Port 443 appeared under PID 4/System because HTTP.sys owned the kernel socket.
- HTTP.sys linked the queue to `MSExchangeService` and `Microsoft.Exchange.Service.exe`.
- No request reached the listener and no external connection was recorded.
- No C2 IP or domain was identified.
- No SSL certificate binding was observed for `0.0.0.0:443`.
- No malware-specific persistent URL ACL was observed.
- No packet capture was available.

## Not Observed

- Inbound request
- Outbound connection
- External C2 IP
- External C2 domain
- DNS lookup attributed to the malware
- TLS session
- HTTP request
- HTTP response
- Attacker command
- File transfer
- Data exfiltration
- Lateral movement
- Production network impact

## Evidence Limitations

- The VM adapter was disabled and no inbound test request was sent.
- No external command-and-control traffic existed.
- No PCAP, PCAPNG, or ETL was collected.
- No TLS handshake, DNS activity, request body, or response body was captured.
- No file-transfer session or attacker command occurred.
- No external IP or domain was identified.
- Static fields were not observed on the wire.
- The raw Procmon PML was unusable and provided no recoverable network events.
- Laboratory paths and process IDs are environmental.

## Screenshot Evidence

### Evidence: Pre-execution VMware snapshot

![VMware snapshot before analysis](../../screenshots/Pre-Noriben_Turla_Neuron_Snapshot.png)

**Plain-language explanation:** The snapshot allowed the offline test computer to be restored after analysis.

**Technical finding:** A pre-Noriben restore point was created before controlled execution.

**Evidence classification:** supporting_context.

**Limitation:** The screenshot documents a safety control, not network traffic.

### Evidence: HTTPS listener initialization

![dnSpy HTTPS listener initialization](../../screenshots/TurlaNeuron_08_dnSpy_Service_OnStart_HTTPS_Listener.png)

**Plain-language explanation:** The code shows that the service was designed to open the Exchange-themed web address when it started.

**Technical finding:** `OnStart` registers `https://*:443/ews/exchange/` with `WebServerUtils.SendResponse`.

**Evidence classification:** confirmed_statically.

**Limitation:** Source code proves capability, not that a remote system connected.

### Evidence: Request validation logic

![dnSpy request validation logic](../../screenshots/TurlaNeuron_10_dnSpy_SendResponse_Request_Validation.png)

**Plain-language explanation:** The service expected messages containing specific names and a hidden identifier before processing them.

**Technical finding:** Decompiled parsing and validation logic includes `cid`, `cadataKey`, and the validation GUID.

**Evidence classification:** confirmed_statically.

**Limitation:** These values were not observed in captured traffic.

### Evidence: Encrypted command-channel processing

![dnSpy encrypted cadata command-channel processing](../../screenshots/TurlaNeuron_11_dnSpy_Cadata_RC4_Remote_Storage_Command_Channel.png)

**Plain-language explanation:** The code could decode and decrypt specially formatted instructions and encode responses.

**Technical finding:** `cadata`, `cadataSig`, Base64, JSON, RC4-style processing, and fallback GUID logic are visible.

**Evidence classification:** confirmed_statically.

**Limitation:** No real request, response, or protocol session was collected.

### Evidence: HTTP.sys request queue

![HTTP.sys EWS Exchange URL registration](../../screenshots/TurlaNeuron_25_Dynamic_HTTPsys_EWS_Exchange_URL_Registration.png)

**Plain-language explanation:** Windows confirmed that the service was waiting at the hidden address, but no request arrived.

**Technical finding:** An active queue links `HTTPS://*:443/EWS/EXCHANGE/` to `MSExchangeService` and the sample process, with zero arrived and rejected requests.

**Evidence classification:** confirmed_by_http_sys.

**Limitation:** A local queue is not proof of remote communication or a successful TLS session.

## Evidence References

- [Dynamic analysis](../dynamic/turla_neuron_dynamic_analysis.md)
- [Noriben analysis](../noriben/turla_neuron_noriben_analysis.md)
- [Procmon analysis](../procmon/turla_neuron_procmon_analysis.md)
- [dnSpy analysis](../dnspy/turla_neuron_dnspy_analysis.md)
- [Static analysis](../static/turla_neuron_static_analysis.md)
- [IOC package](../../iocs/turla_neuron_iocs.md)
- [Incident report](../../reports/incident-report.md)
