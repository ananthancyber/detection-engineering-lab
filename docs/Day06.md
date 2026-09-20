# Day 06 — Network Authentication Detection

## Overview

Day 06 focused on detecting suspicious Windows network authentication activity by analyzing successful and failed network logons and correlating authentication events across the same source, account, and domain context.

The objective was to move beyond individual authentication events and develop a correlation-based detection capable of identifying a sequence where a failed network authentication is followed by a successful network authentication.

---

## Objectives

- Analyze Windows Network Logon activity using Event ID 4624 and Event ID 4625.
- Identify Logon Type 3 network authentication activity.
- Establish a baseline for network authentication behavior.
- Investigate remote authentication sources and account activity.
- Correlate failed and successful authentication events.
- Develop Sigma rules for network authentication detection.
- Create a temporal correlation rule for failed-to-successful authentication sequences.
- Validate the detection using Splunk Cloud.
- Map the detection to MITRE ATT&CK.
- Preserve reproducible evidence for the detection engineering workflow.

---

## Environment

| Component | Details |
|---|---|
| SIEM | Splunk Cloud |
| Endpoint | Windows 10 Client |
| Host | WIN10-CLIENT |
| Log Source | Windows Security Event Log |
| Collection | Splunk Universal Forwarder |
| Index | `main` |
| Sourcetype | `WinEventLog:Security` |
| Primary Events | 4624, 4625 |
| Authentication Type | Logon Type 3 |
| Detection Format | Sigma |
| Query Language | Splunk SPL |
| Framework | MITRE ATT&CK |

---

## 1. Network Authentication Baseline

The first step was to establish the normal distribution of Windows logon types.

The following SPL query was used:

~~~
index=main sourcetype="WinEventLog:Security" EventCode=4624
| stats count by Logon_Type
| sort - count
~~~

The search returned **1,150 successful authentication events** across six Logon Types.

The observed distribution included:

- Logon Type 5 — 891 events
- Logon Type 2 — 105 events
- Logon Type 3 — 59 events
- Logon Type 11 — 41 events
- Logon Type 7 — 29 events
- Logon Type 0 — 25 events

Logon Type 3 was selected for detailed analysis because it represents network-based authentication activity.

### Evidence

![Day 06 Logon Type Baseline](../screenshots/Day06/Day06-01-Logon-Type-Baseline.png)

---

## 2. Network Logon Analysis

The following query was used to analyze Event ID 4624 with Logon Type 3:

~~~
index=main sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3
| stats count by Account_Name, Account_Domain, Source_Network_Address, host
| sort - count
~~~

The analysis identified **59 Logon Type 3 successful authentication events**.

The results showed both local/system-generated authentication activity and authentication originating from the remote source:

`192.168.159.129`

The remote source was therefore investigated further.

### Evidence

![Day 06 Network Logon Analysis](../screenshots/Day06/Day06-02-Network-Logon-Analysis.png)

---

## 3. Remote Network Logon Details

The next step was to inspect the remote authentication events and identify the associated account, source address, authentication package, and logon process.

The analysis identified activity involving:

- Source: `192.168.159.129`
- Host: `WIN10-CLIENT`
- Logon Type: `3`
- Authentication Package: `NTLM`
- Logon Process: `NtLmSsp`
- Accounts including `pt_test` and `bh_enum`

This provided the context required to distinguish ordinary local authentication from remote network authentication.

### Evidence

![Day 06 Remote Network Logon Details](../screenshots/Day06/Day06-03-Remote-Network-Logon-Details.png)

---

## 4. Remote Authentication Correlation

Authentication activity from `192.168.159.129` was correlated across Event ID 4624 and Event ID 4625.

The following query was used to inspect successful and failed network authentication events:

~~~
index=main sourcetype="WinEventLog:Security" Logon_Type=3
(EventCode=4624 OR EventCode=4625)
| table _time EventCode Account_Name Account_Domain Source_Network_Address Logon_Type Authentication_Package Logon_Process host
| sort _time
~~~

The correlation showed that the same remote source generated both failed and successful network authentication events.

This provided the basis for developing a sequence-based detection rather than relying on a single authentication event.

### Evidence

![Day 06 Remote Authentication Correlation](../screenshots/Day06/Day06-04-Remote-Authentication-Correlation.png)

---

## 5. Network Authentication Summary

A combined summary of successful and failed network authentication events was created using:

~~~
index=main sourcetype="WinEventLog:Security"
Logon_Type=3
(EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4624)) as successful_logons
    count(eval(EventCode=4625)) as failed_logons
    earliest(_time) as first_seen
    latest(_time) as last_seen
    by Source_Network_Address, Account_Name, Account_Domain, host
| eval total_events=successful_logons+failed_logons
| where failed_logons > 0 AND successful_logons > 0
| sort - total_events
~~~

The search identified authentication entities where both failed and successful network authentication activity was present.

For the investigated remote source `192.168.159.129`, the results included:

| Account Context | Successful | Failed | Total |
|---|---:|---:|---:|
| Unspecified account context | 6 | 3 | 9 |
| CORP domain context | 6 | 2 | 8 |
| `pt_test` | 4 | 1 | 5 |
| `bh_enum` | 2 | 2 | 4 |
| `bh_enum` / `CORP` | 2 | 2 | 4 |

### Evidence

![Day 06 Network Authentication Summary](../screenshots/Day06/Day06-05-Network-Authentication-Summary.png)

---

## 6. Network Logon Source Context

A successful network authentication event was examined in greater detail to determine the originating workstation and authentication context.

The investigation identified:

- Source Network Address: `192.168.159.129`
- Host: `WIN10-CLIENT`
- Account: `bh_enum`
- Domain: `CORP`
- Logon Type: `3`
- Authentication Package: `NTLM`
- Logon Process: `NtLmSsp`
- Workstation Name: `KALI`

This established a clear remote authentication relationship between the Kali system and the Windows client.

### Evidence

![Day 06 Network Logon Source Context](../screenshots/Day06/Day06-06-Network-Logon-Source-Context.png)

---

## 7. Raw Network Logon Event

The raw Windows Security event was inspected to validate the underlying telemetry.

The event contained:

- `EventCode=4624`
- `LogonType=3`
- `Keywords=Audit Success`
- `TaskCategory=Logon`
- `Authentication Package=NTLM`
- `Logon Process=NtLmSsp`

The raw event confirmed that the structured Splunk fields originated from the Windows Security auditing telemetry.

### Evidence

![Day 06 Network Logon Raw Event](../screenshots/Day06/Day06-07-Network-Logon-Raw-Event.png)

---

# 8. Failed-to-Successful Authentication Sequence

The detection logic was then extended to identify cases where a failed network authentication was followed by a successful network authentication.

The correlation query evaluated:

- Source Network Address
- Account Name
- Account Domain
- Host
- First failed authentication
- Last failed authentication
- First successful authentication
- Last successful authentication

The SPL query used was:

~~~
index=main sourcetype="WinEventLog:Security" Logon_Type=3
(EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4624)) as successful_logons
    count(eval(EventCode=4625)) as failed_logons
    earliest(eval(if(EventCode=4625,_time,null()))) as first_failed
    latest(eval(if(EventCode=4625,_time,null()))) as last_failed
    earliest(eval(if(EventCode=4624,_time,null()))) as first_success
    latest(eval(if(EventCode=4624,_time,null()))) as last_success
    by Source_Network_Address, Account_Name, Account_Domain, host
| where failed_logons > 0
    AND successful_logons > 0
    AND first_failed < first_success
| eval sequence="Failed authentication followed by successful authentication"
| sort - first_success
~~~

The search returned **62 authentication events** and identified **2 matching authentication sequences**.

Both detected sequences involved the remote source:

`192.168.159.129`

and the account:

`bh_enum`

The results showed:

- 2 successful logons
- 2 failed logons
- Failed authentication occurred before successful authentication
- Remote source: `192.168.159.129`
- Host: `WIN10-CLIENT`

The sequence was treated as a suspicious authentication pattern requiring investigation rather than automatically classified as malicious.

### Evidence

![Day 06 Failed to Successful Authentication Sequence](../screenshots/Day06/Day06-08-Failed-to-Successful-Authentication-Sequence.png)

---

# 9. Rule 005 Detection Validation

The sequence detection was implemented as Rule 005.

### Rule

**File:**

`Sigma-rules/windows/lateral-movement/windows-failed-to-successful-network-logon.yml`

### Detection Concept

Rule 005 correlates:

1. Failed network logon — Event ID 4625, Logon Type 3
2. Successful network logon — Event ID 4624, Logon Type 3

The correlation is grouped by:

- `Source_Network_Address`
- `Account_Name`
- `Account_Domain`

with a:

`10m`

correlation window.

### Rule 005 UUID

`5d8e7c41-4624-4f92-a105-005fa1ed0a05`

### Supporting Rule UUIDs

Failed network logon:

`61f2a8c3-4625-4b91-a201-006fa1ed0a06`

Successful network logon:

`72a3b9d4-4624-4c82-b312-007fa1ed0a07`

Rule 005 references these actual UUIDs for correlation.

### Detection Result

The corresponding Splunk validation query produced **2 matching failed-to-successful authentication sequences**.

### Evidence

![Day 06 Rule 005 Detection Results](../screenshots/Day06/Day06-09-Rule-005-Detection-Results.png)

---

# 10. Detection Logic

The overall detection workflow was:

~~~
Windows Security Events
        |
        v
Event ID 4624 / 4625
        |
        v
Logon Type 3 Filtering
        |
        v
Remote Source Identification
        |
        v
Failed + Successful Authentication Correlation
        |
        v
Temporal Sequence Analysis
        |
        v
Rule 005 Detection
        |
        v
SOC Investigation
~~~

The workflow demonstrates how raw Windows authentication telemetry can be transformed into a contextual detection rather than treating individual events in isolation.

---

# 11. MITRE ATT&CK Mapping

The detection is associated with:

**MITRE ATT&CK T1021 — Remote Services**

The detection focuses on remote/network authentication behavior that may provide context for lateral movement investigations.

The detection does not independently prove lateral movement. It identifies an authentication sequence that can be investigated alongside source host, account, authentication protocol, timing, and other telemetry.

---

# 12. Evidence Register

| Evidence | Purpose |
|---|---|
| `Day06-01-Logon-Type-Baseline.png` | Windows logon type baseline |
| `Day06-02-Network-Logon-Analysis.png` | Network Logon Type 3 analysis |
| `Day06-03-Remote-Network-Logon-Details.png` | Remote authentication details |
| `Day06-04-Remote-Authentication-Correlation.png` | Failed/successful authentication correlation |
| `Day06-05-Network-Authentication-Summary.png` | Authentication activity summary |
| `Day06-06-Network-Logon-Source-Context.png` | Remote source and workstation context |
| `Day06-07-Network-Logon-Raw-Event.png` | Raw Windows Security event validation |
| `Day06-08-Failed-to-Successful-Authentication-Sequence.png` | Failed-to-successful authentication sequence |
| `Day06-09-Rule-005-Detection-Results.png` | Final Rule 005 validation |

---

# 13. Repository Artifacts

Day 06 produced the following detection engineering artifacts:

### Sigma Rules

`Sigma-rules/windows/lateral-movement/windows-failed-network-logon.yml`

`Sigma-rules/windows/lateral-movement/windows-successful-network-logon.yml`

`Sigma-rules/windows/lateral-movement/windows-failed-to-successful-network-logon.yml`

### SPL

`splunk-queries/authentication/failed-to-successful-network-logon.spl`

### Validation

`validation/rule-005-validation.md`

### MITRE Coverage

`mitre-coverage/day06-network-authentication-detection.md`

### Documentation

`docs/Day06.md`

---

# 14. Quantified Outcomes

| Metric | Result |
|---|---:|
| Successful Windows logon events analyzed | 1,150 |
| Logon Type 3 successful events | 59 |
| Combined authentication events evaluated | 62 |
| Authentication sequence matches | 2 |
| Correlated account | `bh_enum` |
| Investigated remote source | `192.168.159.129` |
| Detection rules created/used | 3 |
| Final correlation rule | Rule 005 |
| Correlation window | 10 minutes |
| Primary Windows events | 4624, 4625 |
| MITRE ATT&CK technique | T1021 |

---

# 15. SOC Investigation Perspective

Day 06 demonstrates a progression from basic Windows authentication monitoring to contextual detection engineering.

The investigation began with a broad authentication baseline, narrowed the analysis to network logons, identified remote authentication sources, examined raw Windows Security telemetry, and finally correlated failed and successful authentication activity.

The resulting Rule 005 detection provides a repeatable method for identifying authentication sequences that warrant further SOC investigation.

---

# 16. Skills Demonstrated

- Windows Security Event Analysis
- Network Authentication Monitoring
- Event ID 4624 Analysis
- Event ID 4625 Analysis
- Logon Type 3 Analysis
- Splunk Cloud
- SPL Query Development
- Authentication Correlation
- Temporal Detection Logic
- Sigma Rule Development
- Detection Validation
- MITRE ATT&CK Mapping
- SOC Investigation
- Evidence-Based Detection Engineering

---

## Day 06 Summary

Day 06 successfully implemented a network authentication detection workflow using Windows Security telemetry and Splunk Cloud.

The final detection correlates failed and successful Logon Type 3 authentication events by source and account context within a defined time window.

The validated result produced **2 failed-to-successful authentication sequences**, demonstrating the complete workflow from Windows telemetry collection through investigation, correlation, Sigma rule development, SPL validation, MITRE mapping, and evidence-based documentation.