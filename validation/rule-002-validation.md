# Rule 002 — Repeated Windows Failed Logon Detection Validation

## Detection Overview

| Field | Details |
|---|---|
| Detection Name | Multiple Windows Failed Logon Attempts |
| Rule ID | Rule-002 |
| Detection Type | Sigma Correlation Rule |
| Sigma Rule | `sigma-rules/windows/credential-access/windows-repeated-failed-logons.yml` |
| SPL Query | `splunk-queries/authentication/repeated-failed-logons-5min.spl` |
| Windows Event ID | `4625` |
| Detection Window | 5 minutes |
| Detection Threshold | 5 or more failed logons |
| SIEM Platform | Splunk Cloud |
| Endpoint | `WIN10-CLIENT` |
| Severity | Medium |
| Validation Status | Passed |

## Objective

Validate a correlation-based detection that identifies repeated Windows failed-logon events from the same source network address within a five-minute time window.

The detection is designed to identify activity that may be related to:

- Brute-force attempts
- Password spraying
- Repeated authentication failures
- Automated authentication activity
- Misconfigured services

## Detection Logic

The detection uses the following conditions:

~~~text
Windows Event ID 4625
+
Same source network address
+
Five-minute time window
+
Five or more failed logons
=
Potential repeated failed-logon activity
~~~

The query also extracts:

- Failed-logon count
- Number of unique targeted accounts
- Targeted account names
- Logon types
- Source network address
- Affected host

## Sigma Rule

The Sigma rule is stored at:

~~~text
sigma-rules/windows/credential-access/windows-repeated-failed-logons.yml
~~~

The rule references the first failed-logon detection and applies a correlation threshold of:

~~~text
5 or more failed logons
within 5 minutes
grouped by source network address
~~~

## Splunk Correlation Query

The SPL query is stored at:

~~~text
splunk-queries/authentication/repeated-failed-logons-5min.spl
~~~

The query used for validation was:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count dc(Account_Name) as unique_accounts values(Account_Name) as targeted_accounts values(Logon_Type) as logon_types by _time, Source_Network_Address, host
| where count >= 5
| sort - count
~~~

## Validation Results

The query returned three matching detection windows.

| Source Address | Host | Failed Logons | Unique Accounts |
|---|---|---:|---:|
| `::1` | `WIN10-CLIENT` | 10 | 2 |
| `::1` | `WIN10-CLIENT` | 10 | 2 |
| `::1` | `WIN10-CLIENT` | 8 | 2 |

## Observed Activity

The detection identified:

- Source address: `::1`
- Host: `WIN10-CLIENT`
- Failed-logon counts between `8` and `10`
- Two unique targeted accounts
- Logon types including `2` and `11`

All three result windows met the configured threshold of five or more failed logons within five minutes.

## Detection Result

**PASS — The correlation query successfully identified repeated failed-logon activity.**

The validation confirmed that:

- Windows Event ID `4625` events were searchable.
- Events were grouped into five-minute windows.
- Events were grouped by source network address and host.
- The threshold condition worked correctly.
- The number of failed logons was calculated.
- Unique targeted accounts were identified.
- Targeted account names were extracted.
- Logon types were extracted.

## SOC Investigation Observation

The detected source address was:

~~~text
::1
~~~

The IPv6 address `::1` represents the local loopback interface.

This indicates that the observed authentication activity originated locally from the Windows endpoint rather than from an external network host.

Therefore, the activity should be classified as:

~~~text
Repeated failed-logon activity requiring investigation
~~~

It should not automatically be classified as a confirmed brute-force attack.

## Possible Explanations

Potential explanations include:

- Lab-generated authentication testing
- Incorrect local credentials
- Local administrative activity
- Misconfigured services
- Scheduled tasks using outdated credentials
- Automated authentication attempts
- Account or password testing

## False-Positive Considerations

The detection may generate alerts for:

- Users repeatedly entering incorrect passwords
- Expired or locked accounts
- Services using outdated credentials
- Scheduled tasks with incorrect credentials
- Machine-account authentication failures
- Legitimate administrative troubleshooting
- Local authentication activity

## Recommended Investigation Steps

When this detection triggers, a SOC analyst should investigate:

1. Source IP address
2. Affected host
3. Targeted account names
4. Number of unique targeted accounts
5. Logon type
6. Failure reason
7. Related successful logons
8. Process or service responsible for the activity
9. Whether the source is local or remote
10. Whether similar activity occurred on other endpoints

## MITRE ATT&CK Mapping

### T1110 — Brute Force

Repeated failed-logon events can provide useful telemetry for investigating brute-force activity.

However, repeated failed logons alone do not prove that a brute-force attack occurred.

Additional context is required before confirming malicious activity.

## Quantified Outcomes

| Metric | Result |
|---|---:|
| Failed-logon events searched | 36 |
| Matching five-minute windows | 3 |
| Highest failed-logon count in one window | 10 |
| Lowest matching failed-logon count | 8 |
| Unique targeted accounts in matching windows | 2 |
| Sigma correlation rules created | 1 |
| SPL correlation queries created | 1 |
| Detection threshold | 5 events |
| Detection time window | 5 minutes |
| MITRE ATT&CK techniques referenced | 1 |

## Evidence

The following screenshots were collected during Rule 002 development and validation:

### Sigma Rule Evidence

![Rule 002 Sigma rule](../screenshots/Day03/Day03-08-Repeated-Failed-Logon-Sigma-Rule.png)

### Splunk Correlation Results

![Rule 002 Splunk results](../screenshots/Day03/Day03-09-Repeated-Failed-Logon-SPL-Results.png)

## Evidence File Locations

~~~text
screenshots/Day03/Day03-08-Repeated-Failed-Logon-Sigma-Rule.png
screenshots/Day03/Day03-09-Repeated-Failed-Logon-SPL-Results.png
~~~

## Limitations

The current correlation groups events by source network address and host.

It does not yet:

- Exclude loopback addresses
- Distinguish users from machine accounts
- Compare failed and successful logons
- Detect password spraying across multiple hosts
- Identify the responsible process
- Enrich the source with asset or identity information
- Automatically suppress known service-account activity

These improvements can be added during future detection-engineering tasks.

## Conclusion

Rule 002 successfully detected repeated Windows failed-logon activity using a five-minute correlation window and a threshold of five or more events.

The detection produced three matching windows with eight to ten failed logons and two unique targeted accounts.

The result demonstrates that the lab can move beyond single-event detection into threshold-based correlation and behavioral detection.

The observed source was the local loopback address `::1`, so the activity requires further investigation before being classified as malicious.

This rule provides the foundation for future brute-force, password-spraying, and authentication-anomaly detections.