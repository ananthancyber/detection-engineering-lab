# Day 03 — Authentication Detection MITRE ATT&CK Coverage

## Overview

Day 03 focused on detecting Windows authentication failures using Windows Security Event ID `4625`.

Two detection rules were created and validated in Splunk Cloud:

1. Windows Failed Logon Attempt
2. Multiple Windows Failed Logon Attempts

The detections were mapped to the relevant MITRE ATT&CK technique to demonstrate how Windows authentication telemetry can support SOC investigations.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | `WIN10-CLIENT` |
| Domain | `CORP / CORP.LOCAL` |
| SIEM | Splunk Cloud |
| Log Collector | Splunk Universal Forwarder |
| Log Source | Windows Security Event Log |
| Event ID | `4625` |
| Detection Platform | Sigma and Splunk SPL |

## Detection Coverage Summary

| Rule | Detection | Event ID | Detection Logic | MITRE ATT&CK |
|---|---|---:|---|---|
| Rule-001 | Windows Failed Logon Attempt | `4625` | Detects individual failed logon events | T1110 — Brute Force |
| Rule-002 | Multiple Windows Failed Logon Attempts | `4625` | Detects five or more failed logons from the same source within five minutes | T1110 — Brute Force |

## MITRE ATT&CK Technique

### T1110 — Brute Force

**Tactic:** Credential Access

The detections provide authentication telemetry that can support investigations into possible brute-force activity.

Repeated failed logons may be associated with:

- Password guessing
- Repeated credential attempts
- Automated authentication activity
- Password spraying investigations
- Account misuse investigations

However, Event ID `4625` alone does not prove that a brute-force attack occurred.

Additional investigation is required to determine whether the activity is malicious.

## Rule-001 Coverage

### Detection Name

~~~text
Windows Failed Logon Attempt
~~~

### Detection Purpose

Rule-001 identifies Windows Security Event ID `4625`, which represents a failed logon attempt.

The rule provides the initial event-level detection required for authentication monitoring.

### Detection Logic

~~~text
Event ID = 4625
~~~

### Related Files

~~~text
Sigma Rule:
sigma-rules/windows/credential-access/windows-failed-logon.yml

Splunk Query:
splunk-queries/authentication/failed-logon-4625.spl

Validation Report:
validation/rule-001-validation.md
~~~

### Validation Evidence

![Windows Event ID 4625 analysis](../screenshots/Day03/Day03-01-Event-4625-Analysis.png)

![Failed logon account analysis](../screenshots/Day03/Day03-02-Failed-Logon-Account-Analysis.png)

![Failed logon source analysis](../screenshots/Day03/Day03-03-Failed-Logon-Source-Analysis.png)

![Non-local failed logon analysis](../screenshots/Day03/Day03-04-Non-Local-Failed-Logon-Analysis.png)

![First Sigma rule](../screenshots/Day03/Day03-05-First-Sigma-Rule.png)

![Failed logon SPL detection](../screenshots/Day03/Day03-06-SPL-Failed-Logon-Detection.png)

![Failed logon SPL query file](../screenshots/Day03/Day03-07-SPL-Query-File.png)

## Rule-001 Validation Outcome

The detection successfully identified Windows Event ID `4625` events in Splunk Cloud.

Observed results included:

- `36` failed-logon events
- Failed authentication attempts involving multiple accounts
- Local and network-related source addresses
- Authentication activity from `192.168.159.129`
- Logon Type `3` network logon activity

### Rule-001 Quantified Results

| Metric | Result |
|---|---:|
| Failed-logon events analyzed | 36 |
| Sigma rules created | 1 |
| SPL queries created | 1 |
| Windows Event IDs analyzed | 1 |
| MITRE ATT&CK techniques referenced | 1 |

## Rule-002 Coverage

### Detection Name

~~~text
Multiple Windows Failed Logon Attempts
~~~

### Detection Purpose

Rule-002 extends the first detection by applying time-based correlation.

It identifies repeated failed logons from the same source network address within a five-minute window.

### Detection Logic

~~~text
Event ID 4625
+
Same source network address
+
Five-minute time window
+
Five or more failed logons
=
Potential repeated failed-logon activity
~~~

### Related Files

~~~text
Sigma Rule:
sigma-rules/windows/credential-access/windows-repeated-failed-logons.yml

Splunk Query:
splunk-queries/authentication/repeated-failed-logons-5min.spl

Validation Report:
validation/rule-002-validation.md
~~~

### Validation Evidence

![Repeated failed logon Sigma rule](../screenshots/Day03/Day03-08-Repeated-Failed-Logon-Sigma-Rule.png)

![Repeated failed logon Splunk results](../screenshots/Day03/Day03-09-Repeated-Failed-Logon-SPL-Results.png)

## Rule-002 Validation Outcome

The correlation query successfully identified repeated failed-logon activity.

The query returned three matching detection windows.

| Source Address | Host | Failed Logons | Unique Accounts |
|---|---|---:|---:|
| `::1` | `WIN10-CLIENT` | 10 | 2 |
| `::1` | `WIN10-CLIENT` | 10 | 2 |
| `::1` | `WIN10-CLIENT` | 8 | 2 |

### Rule-002 Quantified Results

| Metric | Result |
|---|---:|
| Failed-logon events searched | 36 |
| Matching five-minute windows | 3 |
| Highest failed-logon count | 10 |
| Lowest matching failed-logon count | 8 |
| Unique targeted accounts | 2 |
| Correlation threshold | 5 events |
| Correlation window | 5 minutes |
| Sigma correlation rules created | 1 |
| SPL correlation queries created | 1 |

## Investigation Notes

The source address identified in Rule-002 was:

~~~text
::1
~~~

The IPv6 address `::1` represents the local loopback interface.

This indicates that the observed authentication activity originated locally from the Windows endpoint.

The activity should be recorded as:

~~~text
Repeated failed-logon activity requiring investigation
~~~

It should not automatically be classified as a confirmed brute-force attack.

## Analyst Investigation Checklist

When this detection triggers, the analyst should review:

1. Source IP address
2. Destination host
3. Targeted account names
4. Number of unique targeted accounts
5. Logon type
6. Failure reason
7. Related successful logons
8. Process or service responsible for the activity
9. Whether the source is local or remote
10. Whether similar activity occurred on other endpoints
11. Whether the account is a user, service account, or machine account
12. Whether the activity matches an approved lab or administrative action

## False-Positive Considerations

Possible legitimate causes include:

- Incorrect passwords
- Invalid usernames
- Expired accounts
- Locked accounts
- Misconfigured services
- Scheduled tasks using outdated credentials
- Machine-account authentication failures
- Legitimate administrative troubleshooting
- Local authentication activity
- Lab-generated testing

## Detection Engineering Limitations

The current detections do not yet:

- Exclude loopback addresses
- Distinguish user accounts from machine accounts
- Detect password spraying across multiple hosts
- Correlate failed and successful logons
- Identify the responsible process
- Enrich source IPs with asset information
- Enrich accounts with identity information
- Automatically suppress known service-account activity
- Generate an automated response

These are potential improvements for future detection-engineering tasks.

## Coverage Assessment

| Coverage Area | Status |
|---|---|
| Windows failed-logon monitoring | Implemented |
| Event ID 4625 detection | Implemented |
| Sigma event rule | Implemented |
| Splunk SPL query | Implemented |
| Time-based correlation | Implemented |
| Source-based grouping | Implemented |
| Threshold-based detection | Implemented |
| False-positive documentation | Implemented |
| MITRE ATT&CK mapping | Implemented |
| Automated response | Not implemented |
| Password-spraying detection | Planned |
| Cross-host correlation | Planned |

## Evidence Index

### Rule-001 Evidence

~~~text
screenshots/Day03/Day03-01-Event-4625-Analysis.png
screenshots/Day03/Day03-02-Failed-Logon-Account-Analysis.png
screenshots/Day03/Day03-03-Failed-Logon-Source-Analysis.png
screenshots/Day03/Day03-04-Non-Local-Failed-Logon-Analysis.png
screenshots/Day03/Day03-05-First-Sigma-Rule.png
screenshots/Day03/Day03-06-SPL-Failed-Logon-Detection.png
screenshots/Day03/Day03-07-SPL-Query-File.png
~~~

### Rule-002 Evidence

~~~text
screenshots/Day03/Day03-08-Repeated-Failed-Logon-Sigma-Rule.png
screenshots/Day03/Day03-09-Repeated-Failed-Logon-SPL-Results.png
~~~

## Day 03 Quantified Outcomes

| Metric | Result |
|---|---:|
| Sigma rules created | 2 |
| SPL queries created | 2 |
| Validation reports created | 2 |
| Windows Event IDs analyzed | 1 |
| Failed-logon events analyzed | 36 |
| Matching correlation windows | 3 |
| Highest events in one correlation window | 10 |
| Detection threshold tested | 5 events |
| Detection window tested | 5 minutes |
| MITRE ATT&CK techniques mapped | 1 |
| Evidence screenshots collected | 9 |

## Professional Portfolio Value

Day 03 demonstrates practical experience in:

- Windows authentication monitoring
- Windows Security Event analysis
- Sigma rule development
- Splunk SPL development
- Time-based event correlation
- Threshold-based detection engineering
- Source IP investigation
- Account activity analysis
- False-positive identification
- MITRE ATT&CK mapping
- SOC investigation documentation
- Evidence-based detection validation

## Conclusion

Day 03 established the authentication-monitoring foundation of the Detection Engineering Lab.

The project progressed from detecting individual Windows failed-logon events to identifying repeated failed-logon activity using time-based correlation.

The detections were validated against Windows Security telemetry collected in Splunk Cloud and documented with Sigma rules, SPL queries, validation reports, investigation notes, MITRE ATT&CK mapping, and supporting evidence.

