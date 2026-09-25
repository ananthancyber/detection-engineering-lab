# Rule 005 Validation — Failed Network Logon Followed by Successful Network Logon

## 1. Validation Overview

Rule 005 was developed to detect a Windows network authentication pattern in which a failed network logon is followed by a successful network logon from the same source and account context.

The detection focuses on Windows Security Event IDs:

- `4625` — An account failed to log on
- `4624` — An account was successfully logged on
- `Logon Type 3` — Network authentication

This detection is particularly useful for identifying authentication activity that may require investigation, including repeated credential failures followed by a successful authentication from the same source.

The detection was validated using Windows Security telemetry collected from the `WIN10-CLIENT` endpoint and analyzed in Splunk Cloud.

---

## 2. Detection Objective

The objective of Rule 005 is to identify the following sequence:

~~~
Event ID 4625
Failed Network Logon
        ↓
Same source / account context
        ↓
Event ID 4624
Successful Network Logon
~~~

The detection should identify the sequence only when:

1. A failed authentication event is present.
2. A successful authentication event is present.
3. Both events use Network Logon (`Logon Type 3`).
4. The failed authentication occurs before the successful authentication.
5. The authentication activity can be correlated using source and account context.

---

## 3. Detection Artifacts

### Sigma Correlation Rule

**File:**

`../sigma-rules/windows/lateral-movement/windows-failed-to-successful-network-logon.yml`

**Rule Title:**

`Failed Network Logon Followed by Successful Network Logon`

**Rule ID:**

`5d8e7c41-4624-4f92-a105-005fa1ed0a05`

**Severity:**

Medium

### Supporting Sigma Rules

**Failed Network Logon**

`../sigma-rules/windows/lateral-movement/windows-failed-network-logon.yml`

Rule ID:

`61f2a8c3-4625-4b91-a201-006fa1ed0a06`

**Successful Network Logon**

`../sigma-rules/windows/lateral-movement/windows-successful-network-logon.yml`

Rule ID:

`72a3b9d4-4624-4c82-b312-007fa1ed0a07`

---

## 4. Windows Security Telemetry Validation

The Windows Security event stream was first reviewed to confirm that the required authentication telemetry was available.

The investigation focused on Event IDs `4624` and `4625` with `Logon Type 3`.

### Evidence — Logon Type Baseline

![Logon Type Baseline](../screenshots/Day06/Day06-01-Logon-Type-Baseline.png)

**Evidence:** `Day06-01-Logon-Type-Baseline.png`

The baseline confirmed the presence of multiple Windows authentication logon types in the collected Security telemetry.

This established the required telemetry foundation for isolating Network Logon activity.

---

## 5. Network Logon Analysis

Network authentication activity was then isolated using `Logon_Type=3`.

The analysis identified:

- `1,150` Event ID 4624 events across the available authentication dataset.
- `59` Event ID 4624 events associated with the tested remote source `192.168.159.129`.
- Network authentication activity involving accounts including `pt_test` and `bh_enum`.

### Evidence — Network Logon Analysis

![Network Logon Analysis](../screenshots/Day06/Day06-02-Network-Logon-Analysis.png)

**Evidence:** `Day06-02-Network-Logon-Analysis.png`

The results demonstrated that Logon Type 3 activity was present and could be queried using Splunk.

---

## 6. Remote Network Logon Details

The network authentication events were examined at the individual event level to identify the source, account, authentication package, logon process, and workstation context.

### Evidence — Remote Network Logon Details

![Remote Network Logon Details](../screenshots/Day06/Day06-03-Remote-Network-Logon-Details.png)

**Evidence:** `Day06-03-Remote-Network-Logon-Details.png`

The event-level analysis provided the context required to correlate authentication activity rather than relying only on event counts.

---

## 7. Remote Authentication Correlation

Authentication activity from the remote source was correlated across successful and failed authentication events.

The investigation identified the following relevant source:

~~~
Source Network Address: 192.168.159.129
Host: WIN10-CLIENT
Logon Type: 3
Authentication Package: NTLM
Logon Process: NtLmSsp
~~~

### Evidence — Remote Authentication Correlation

![Remote Authentication Correlation](../screenshots/Day06/Day06-04-Remote-Authentication-Correlation.png)

**Evidence:** `Day06-04-Remote-Authentication-Correlation.png`

This evidence established the authentication context required for the Rule 005 correlation.

---

## 8. Network Authentication Summary

The authentication activity was summarized by source, account, domain, and host.

The investigation identified authentication activity involving:

- `192.168.159.129`
- `WIN10-CLIENT`
- `pt_test`
- `bh_enum`
- `CORP`
- `CORP.LOCAL`

### Evidence — Network Authentication Summary

![Network Authentication Summary](../screenshots/Day06/Day06-05-Network-Authentication-Summary.png)

**Evidence:** `Day06-05-Network-Authentication-Summary.png`

The summary demonstrated that both successful and failed network authentication activity was present in the telemetry.

---

## 9. Network Logon Source Context

The source context was investigated to determine the originating system associated with the authentication activity.

The observed source was:

~~~
Source IP: 192.168.159.129
Observed workstation context: KALI
Destination endpoint: WIN10-CLIENT
~~~

### Evidence — Network Logon Source Context

![Network Logon Source Context](../screenshots/Day06/Day06-06-Network-Logon-Source-Context.png)

**Evidence:** `Day06-06-Network-Logon-Source-Context.png`

This source context was important for establishing the relationship between the authentication activity and the originating system.

---

## 10. Raw Network Logon Event Validation

The underlying Windows Security event was inspected directly to verify the raw event fields rather than relying exclusively on extracted Splunk fields.

The raw event confirmed:

- `LogName=Security`
- `EventCode=4624`
- `TaskCategory=Logon`
- `Logon Type=3`
- Windows Security auditing information
- Authentication context associated with the network logon

### Evidence — Network Logon Raw Event

![Network Logon Raw Event](../screenshots/Day06/Day06-07-Network-Logon-Raw-Event.png)

**Evidence:** `Day06-07-Network-Logon-Raw-Event.png`

This provided direct validation of the underlying Windows Security telemetry.

---

## 11. Failed-to-Successful Authentication Sequence

The authentication timeline was analyzed to identify cases where failed network authentication occurred before successful network authentication.

The observed sequence included:

~~~
Source: 192.168.159.129
Account: bh_enum
Logon Type: 3

4625 — Failed Network Logon
        ↓
4625 — Failed Network Logon
        ↓
4624 — Successful Network Logon
        ↓
4624 — Successful Network Logon
~~~

The sequence demonstrated that the same authentication context contained both failed and successful network authentication events.

### Evidence — Failed-to-Successful Authentication Sequence

![Failed to Successful Authentication Sequence](../screenshots/Day06/Day06-08-Failed-to-Successful-Authentication-Sequence.png)

**Evidence:** `Day06-08-Failed-to-Successful-Authentication-Sequence.png`

This evidence established the temporal authentication pattern targeted by Rule 005.

---

## 12. Rule 005 SPL Detection

The final detection was implemented in Splunk using the following correlation logic:

~~~
index=main sourcetype="WinEventLog:Security" Logon_Type=3 (EventCode=4624 OR EventCode=4625)
| stats count(eval(EventCode=4624)) as successful_logons count(eval(EventCode=4625)) as failed_logons earliest(eval(if(EventCode=4625,_time,null()))) as first_failed latest(eval(if(EventCode=4625,_time,null()))) as last_failed earliest(eval(if(EventCode=4624,_time,null()))) as first_success latest(eval(if(EventCode=4624,_time,null()))) as last_success by Source_Network_Address, Account_Name, Account_Domain, host
| where failed_logons > 0 AND successful_logons > 0 AND first_failed < first_success
| eval sequence="Failed authentication followed by successful authentication"
| sort - first_success
~~~

The query performs the following operations:

1. Restricts the dataset to Windows Security logs.
2. Restricts authentication activity to Logon Type 3.
3. Includes Event IDs 4624 and 4625.
4. Counts successful and failed authentication events.
5. Calculates the first and last failed authentication times.
6. Calculates the first and last successful authentication times.
7. Groups events by source, account, domain, and host.
8. Requires both failed and successful authentication activity.
9. Requires the first failed authentication to occur before the first successful authentication.
10. Labels the resulting sequence for analyst investigation.

---

## 13. Rule 005 Detection Results

The final SPL detection returned:

**62 authentication events evaluated**

The correlation identified:

**2 matching failed-to-successful authentication sequences**

The strongest observed sequence involved:

~~~
Source Network Address: 192.168.159.129
Account: bh_enum
Host: WIN10-CLIENT
Successful Logons: 2
Failed Logons: 2
Logon Type: 3
~~~

The first failed authentication occurred before the first successful authentication, satisfying the temporal condition of the detection.

### Evidence — Rule 005 Detection Results

![Rule 005 Detection Results](../screenshots/Day06/Day06-09-Rule-005-Detection-Results.png)

**Evidence:** `Day06-09-Rule-005-Detection-Results.png`

This is the primary validation evidence for Rule 005 because it shows the final detection query and the resulting correlated authentication sequences.

---

## 14. Validation Results

| Validation Test | Result |
|---|---|
| Windows Security logs available | PASS |
| Event ID 4624 available | PASS |
| Event ID 4625 available | PASS |
| Logon Type 3 available | PASS |
| Network authentication source identified | PASS |
| Failed network authentication identified | PASS |
| Successful network authentication identified | PASS |
| Failed authentication occurred before successful authentication | PASS |
| Source correlation performed | PASS |
| Account correlation performed | PASS |
| Host correlation performed | PASS |
| Final Splunk correlation returned results | PASS |
| Rule 005 detection validated | PASS |

---

## 15. Quantified Validation Results

The validation produced the following measurable results:

| Metric | Result |
|---|---:|
| Authentication events evaluated | 62 |
| Matching authentication sequences | 2 |
| Failed logons in primary sequence | 2 |
| Successful logons in primary sequence | 2 |
| Primary source IPs observed | 1 |
| Primary account observed | `bh_enum` |
| Primary endpoint | `WIN10-CLIENT` |
| Logon Type | 3 |
| Supporting Sigma rules | 2 |
| Correlation Sigma rule | 1 |
| Splunk detection query | 1 |
| Primary detection evidence | 1 |

---

## 16. SOC Investigation Interpretation

A failed network authentication followed by a successful network authentication should be treated as an investigation signal rather than automatically classified as malicious.

The observed activity may have several legitimate explanations, including:

- Incorrect credentials followed by a successful retry
- Automated authentication retries
- Administrative troubleshooting
- Legitimate service authentication
- Domain authentication behaviour

The same pattern can also be relevant to security investigations when combined with additional indicators such as:

- Unexpected source systems
- Unusual accounts
- Abnormal authentication times
- Multiple targeted accounts
- Suspicious endpoint activity
- Credential abuse indicators
- Lateral movement activity
- Other authentication anomalies

In this lab, the source context and authentication telemetry were examined before treating the sequence as a detection result.

---

## 17. MITRE ATT&CK Mapping

### T1110 — Brute Force

The detection identifies a failed network authentication followed by a successful network authentication from the same source and account context within a defined time window.

This behavior is mapped to MITRE ATT&CK T1110 because repeated authentication failures followed by a successful authentication can represent a brute-force-related authentication pattern requiring further investigation.

The detection does not by itself establish malicious activity. Analysts should review the source, account, authentication context, timing, and surrounding activity before determining the cause.

**MITRE ATT&CK Tactic:** Credential Access
---

## 18. Evidence Register

| Evidence | Purpose |
|---|---|
| `Day06-01-Logon-Type-Baseline.png` | Establishes Windows logon-type baseline |
| `Day06-02-Network-Logon-Analysis.png` | Shows Logon Type 3 network authentication activity |
| `Day06-03-Remote-Network-Logon-Details.png` | Provides event-level network authentication details |
| `Day06-04-Remote-Authentication-Correlation.png` | Shows remote authentication correlation |
| `Day06-05-Network-Authentication-Summary.png` | Summarizes network authentication activity |
| `Day06-06-Network-Logon-Source-Context.png` | Establishes source and workstation context |
| `Day06-07-Network-Logon-Raw-Event.png` | Validates raw Windows Security event telemetry |
| `Day06-08-Failed-to-Successful-Authentication-Sequence.png` | Demonstrates the failed-to-successful authentication sequence |
| `Day06-09-Rule-005-Detection-Results.png` | Shows final Rule 005 Splunk detection results |

---

## 19. Repository Artifacts

The following Rule 005 artifacts are maintained in the project repository:

### Sigma Rules

`../sigma-rules/windows/lateral-movement/windows-failed-network-logon.yml`

`../sigma-rules/windows/lateral-movement/windows-successful-network-logon.yml`

`../sigma-rules/windows/lateral-movement/windows-failed-to-successful-network-logon.yml`

### Splunk Query

`../splunk-queries/authentication/failed-to-successful-network-logon.spl`

### Validation

`validation/rule-005-validation.md`

### Evidence

`../screenshots/Day06/`

---

## 20. Final Validation Statement

Rule 005 successfully detected a temporal authentication pattern in Windows Security telemetry where failed Network Logon activity was followed by successful Network Logon activity.

The final Splunk implementation analyzed **62 authentication events** and identified **2 matching failed-to-successful authentication sequences**.

The primary validated sequence involved:

~~~
Source: 192.168.159.129
Account: bh_enum
Host: WIN10-CLIENT
Failed Logons: 2
Successful Logons: 2
Logon Type: 3
~~~

The combination of Windows Security Event IDs 4625 and 4624, Logon Type 3, source correlation, account correlation, temporal ordering, and direct Splunk validation provides documented evidence that the Rule 005 detection logic operates against the collected lab telemetry.

**Validation Status: PASS**

**Rule 005 — Failed Network Logon Followed by Successful Network Logon: VALIDATED**