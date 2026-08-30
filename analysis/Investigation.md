# SOC Network Traffic Investigation

## 1. Investigation Overview

**Investigation ID:** `INC-2026-001`
**Date:** 30 August 2026
**Environment:** Lab Environment
**Analyst:** SOC Analyst
**Primary Tool:** Wireshark
**Capture File:** `investigation.pcapng`

### Objective

The objective of this investigation is to analyze network traffic captured from a monitored workstation and identify potentially abnormal network behavior.

The investigation focuses on:

* TCP connection establishment
* DNS activity
* Destination port activity
* Identification of possible reconnaissance behavior
* Construction of an incident timeline
* Identification of indicators of interest

---

# 2. Investigation Scenario

A monitored workstation was observed generating unusual network traffic.

The workstation initially demonstrated normal internet communication, including a successful TCP connection to a remote HTTPS service.

Later in the capture, the workstation generated multiple TCP SYN packets toward the local gateway/target host across several destination ports.

A DNS query for a synthetic/non-standard domain was also observed and returned an NXDomain response.

The investigation was performed to determine whether these activities represented abnormal network behavior.

---

# 3. Network Entities

| Attribute            | Observed Value     |
| -------------------- | ------------------ |
| Source Host          | `192.168.100.32`   |
| Target Host          | `192.168.100.1`    |
| Observed Remote Host | `18.154.7.97`      |
| Associated Domain    | `search.brave.com` |
| DNS Server           | `192.168.100.1`    |
| Target Ports         | `21, 22, 23, 25`   |
| Primary Protocols    | TCP, DNS, TLSv1.3  |

> **Note:** The IP/domain association above represents what was observed during the investigation. The capture itself does not establish whether a remote host is malicious.

---

# 4. TCP 3-Way Handshake Analysis

### Display Filter

```text
tcp.stream == 4
```

### Observation

An early TCP stream showed a normal and successful TCP 3-way handshake between the monitored workstation and a remote HTTPS service.

### Evidence

The following packets were observed:

```text
Frame 212  → SYN
Frame 216  → SYN, ACK
Frame 217  → ACK
```

The connection was initiated by:

```text
192.168.100.32:49185
        ↓
18.154.7.97:443
```

The successful sequence demonstrates:

```text
Client → Server : SYN
Server → Client : SYN, ACK
Client → Server : ACK
```

The connection was subsequently followed by TLSv1.3 encrypted communication.

### Assessment

This traffic represents a normal TCP connection establishment and provides a useful baseline for comparison with the later abnormal connection attempts.

---

# 5. DNS Traffic Investigation

### Display Filter

```text
dns
```

### Observation

The monitored workstation generated a DNS query for:

```text
suspicious-recon-domain-test.local
```

The query was directed to:

```text
192.168.100.1
```

Both A and AAAA queries were observed.

### Evidence

At approximately:

```text
15:36:38
```

the workstation requested resolution of the domain.

The DNS server returned:

```text
NXDomain
```

The relevant response was observed in:

```text
Frame 28588
```

### Assessment

The domain appears to be a synthetic/non-standard test domain in this lab environment.

The NXDomain response by itself does **not** prove malicious activity. However, the DNS event is relevant because it occurred during the same general period as the observed reconnaissance-like TCP activity.

---

# 6. TCP Port Activity Analysis

### Display Filter

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Observation

Multiple outbound TCP SYN packets originated from:

```text
192.168.100.32
```

and targeted:

```text
192.168.100.1
```

across multiple destination ports.

Observed ports:

| Port | Common Service | Observation          |
| ---: | -------------- | -------------------- |
|   21 | FTP            | SYN attempt observed |
|   22 | SSH            | SYN attempt observed |
|   23 | Telnet         | SYN attempt observed |
|   25 | SMTP           | SYN attempt observed |

The attempts occurred within a relatively short period.

### Traffic Pattern

The observed pattern can be represented as:

```text
192.168.100.32
       │
       ├── SYN → 192.168.100.1:21
       ├── SYN → 192.168.100.1:22
       ├── SYN → 192.168.100.1:23
       └── SYN → 192.168.100.1:25
```

Several packets were marked as TCP retransmissions.

### Important Interpretation

TCP retransmission indicates that the expected response to a previous transmission was not received within the expected period.

Therefore, the retransmissions should **not automatically be interpreted as proof that the destination ports are closed or filtered**.

Possible explanations include:

* Firewall filtering
* No service listening
* Packet loss
* Network conditions
* Other TCP/network behavior

Additional evidence would be required to determine the exact reason.

---

# 7. Reconnaissance Assessment

The combination of:

* One source workstation
* One internal target
* Multiple destination ports
* Repeated TCP SYN attempts
* Short time interval
* Several retransmissions

is **indicative of reconnaissance or port-scanning behavior**.

The observed traffic is therefore classified as:

> **Potential internal network reconnaissance / port scanning**

This assessment is based on the network behavior visible in the PCAP.

The PCAP alone does not establish:

* The process responsible
* The user responsible
* The original intent
* Whether exploitation occurred
* Whether the activity was authorized

These questions would require additional endpoint or authentication evidence.

---

# 8. Incident Timeline

| Time     | Source         | Destination      | Protocol | Event                                         |
| -------- | -------------- | ---------------- | -------- | --------------------------------------------- |
| 15:32:33 | 192.168.100.32 | 18.154.7.97:443  | TCP      | Successful TCP 3-way handshake                |
| 15:32:33 | 192.168.100.32 | 18.154.7.97:443  | TLSv1.3  | Encrypted application communication           |
| 15:35:59 | 192.168.100.32 | 192.168.100.1:21 | TCP      | SYN connection attempt                        |
| 15:36:21 | 192.168.100.32 | 192.168.100.1:22 | TCP      | SYN connection attempt                        |
| 15:36:38 | 192.168.100.32 | 192.168.100.1    | DNS      | Query for synthetic domain; NXDomain response |
| 15:36:42 | 192.168.100.32 | 192.168.100.1:23 | TCP      | SYN connection attempt                        |
| 15:36:43 | 192.168.100.32 | 192.168.100.1:25 | TCP      | SYN connection attempt                        |

---

# 9. Indicators of Interest

### Source

```text
192.168.100.32
```

### Target

```text
192.168.100.1
```

### Observed Destination Ports

```text
21
22
23
25
```

### DNS Domain

```text
suspicious-recon-domain-test.local
```

### Network Signature

```text
Multiple TCP SYN connection attempts
from a single internal host toward
multiple destination ports.
```

### Classification

```text
Potential Internal Reconnaissance /
Port Scanning
```

---

# 10. Severity Assessment

## Severity: MEDIUM

### Rationale

The observed traffic is consistent with internal network reconnaissance.

However, the available PCAP does not provide evidence of:

* Successful exploitation
* Credential compromise
* Malware execution
* Data exfiltration
* Lateral movement

Therefore, the activity should be treated as suspicious and investigated further rather than immediately classified as a confirmed compromise.

---

# 11. Recommended SOC Response

### 1. Endpoint Investigation

Investigate workstation:

```text
192.168.100.32
```

Review:

* Running processes
* Active network connections
* Process execution history
* PowerShell activity
* Command-line activity
* Security logs
* EDR telemetry

The objective is to identify the process responsible for the connection attempts.

### 2. Log Correlation

Correlate the network timestamps with endpoint telemetry.

If Sysmon is available, review:

```text
Event ID 3 — Network Connection
```

This may help associate network connections with a specific process and user context.

### 3. Network Investigation

Review additional traffic before and after:

```text
15:35:59
```

Look for:

* Additional destination IPs
* Additional ports
* Repeated scanning patterns
* Unusual DNS activity
* Subsequent connections to identified services

### 4. Containment

If the activity is confirmed to be unauthorized or malicious, consider isolating the affected workstation from the internal network while the endpoint investigation is performed.

---

# 12. Limitations

This investigation is based solely on the available network packet capture.

The PCAP cannot independently determine:

* Which application generated the traffic
* Which user initiated the activity
* Whether the activity was intentional
* Whether exploitation occurred outside the captured traffic
* Whether the workstation was compromised before the capture

Additional endpoint, authentication, firewall, DNS, and EDR logs would improve confidence in the investigation.

---

# 13. Final Conclusion

The investigation identified a sequence of TCP SYN connection attempts originating from `192.168.100.32` and targeting multiple ports on `192.168.100.1`.

The observed pattern is consistent with **potential internal reconnaissance / port-scanning activity**.

A synthetic DNS query for `suspicious-recon-domain-test.local` was also observed during the same period and returned NXDomain. This DNS event is considered supporting context rather than independent proof of malicious activity.

No evidence of successful exploitation or data exfiltration was identified within the analyzed traffic.

Further endpoint and log investigation is recommended to determine the process and user responsible for the observed activity and to establish whether the reconnaissance was authorized.

**Final Assessment: MEDIUM — Suspicious Internal Reconnaissance Activity**
