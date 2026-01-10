# CySA+ Linux Attack Chain Detection Lab (Splunk)

## Overview
This repository documents a full multi-stage Linux intrusion simulated in a home SOC lab and analyzed using Splunk.  
The lab is aligned with CompTIA CySA+ (CS0-003) and focuses on **behavioral detection**, **MITRE ATT&CK mapping**, and **analyst decision-making**, including failed attack interpretation.

---

## Lab Architecture

**Attacker / Compromised Host**
- Raspberry Pi (Linux)
- Role: execution, C2 beaconing, persistence, discovery, exfiltration

**SOC / Analysis Platform**
- Splunk SOC VM
- Role: log ingestion, detection, correlation

**Logs & Telemetry**
- syslog
- auth.log
- cron
- HTTP/network activity

---

## Attack Chain Summary

| Stage | MITRE Tactic | Technique | Outcome |
|------|-------------|-----------|---------|
| Script Execution | Execution | T1059 | Successful |
| HTTP Beaconing | Command & Control | T1071.001 | Successful |
| Cron Persistence | Persistence | T1053.003 | Successful |
| Host & Network Recon | Discovery | T1082 / T1016 / T1033 | Successful |
| SSH Lateral Movement | Lateral Movement | T1021.004 | Attempted / Blocked |
| HTTP Data Exfiltration | Exfiltration | T1041 | Successful |

---

## Key Analyst Findings

- Detection relied on **event correlation**, not single alerts
- SSH lateral movement was **attempted but blocked** (`connection refused`)
- Absence of authentication logs does **not** indicate absence of attack
- Successful HTTP exfiltration confirms attacker end-goal intent

---

## Splunk Detection Examples

## Execution — Execution (T1059)

### What was observed
- Bash executed a staged script (`payload.sh`)
- File permissions modified using `chmod +x`

### Why this is suspicious
- Script-based execution is common in early attack stages
- Often used to launch persistence or C2 mechanisms

### MITRE Mapping
- Tactic: Execution
- Technique: T1059 — Command and Scripting Interpreter

### Splunk Detection Query
```spl
index=linux process_name=bash
(command="*payload.sh*" OR command="*chmod +x*")
| table _time host user command
```


##  HTTP BEACONING — T1071.001


## HTTP Beaconing — Command & Control (T1071.001)

### What was observed
- Periodic outbound HTTP GET requests
- Requests occurred at regular time intervals
- Low data volume per request

### Why this is suspicious
- Humans do not generate perfectly timed traffic
- Regular intervals strongly indicate automated C2 beaconing

### MITRE Mapping
- Tactic: Command & Control
- Technique: T1071.001 — Web Protocols

### Splunk Detection Query
```spl
index=net* http_method=GET
| bin _time span=1m
| stats count by src_ip dest_ip _time
| where count > 3
```

## Cron Persistence — Persistence (T1053.003)

### What was observed
- A cron job configured with `@reboot`
- Script executed from a user home directory
- Persistence survived system restarts

### Why this is suspicious
- Uses a native OS scheduling mechanism
- Blends in with legitimate administrative activity
- Common Linux malware persistence technique

### MITRE Mapping
- Tactic: Persistence
- Technique: T1053.003 — Cron

### Splunk Detection Query
```spl
index=linux "@reboot"
| table _time host user message



##  HOST & NETWORK DISCOVERY — T1082 / T1016 / T1033


## Host & Network Discovery — Discovery (T1082 / T1016 / T1033)

### What was observed
- Multiple system and network reconnaissance commands
- Commands executed within a short time window

### Why this is suspicious
- Individual commands are benign
- Command clustering indicates post-compromise enumeration
- Strong behavioral detection signal

### MITRE Mapping
- Tactic: Discovery
- Techniques:
  - T1082 — System Information Discovery
  - T1016 — Network Configuration Discovery
  - T1033 — Account Discovery

### Splunk Detection Query
```spl
index=linux process_name=bash
(command="whoami" OR command="uname -a" OR command="ip a")
| bin _time span=2m
| stats count values(command) by host user _time
| where count >= 3


## SSH Lateral Movement Attempt — Lateral Movement (T1021.004)

### What was observed
- SSH connection attempts to another internal host
- Connection refused by the target system

### Why this is significant
- Indicates attempted lateral movement
- Failure occurred before authentication
- Explains absence of authentication logs

### MITRE Mapping
- Tactic: Lateral Movement
- Technique: T1021.004 — SSH

### Splunk Detection Query
```spl
index=linux "Connection refused"


## HTTP Data Exfiltration — Exfiltration (T1041)

### What was observed
- HTTP POST request with binary payload
- Data compressed prior to transfer

### Why this is suspicious
- Compression + POST is common for data theft
- Indicates attacker end-goal behavior

### MITRE Mapping
- Tactic: Exfiltration
- Technique: T1041 — Exfiltration Over C2 Channel

### Splunk Detection Query
```spl
index=net* http_method=POST
| stats sum(bytes_out) by src_ip dest_ip
| where bytes_out > 50000















