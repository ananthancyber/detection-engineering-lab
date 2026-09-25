# Day 11 — MITRE ATT&CK Coverage & Detection Quality Review

## 1. Overview

Day 11 focused on performing a project-wide review of the detection engineering work completed during Days 03–09.

The objective was to verify that the project's:

- Sigma rules
- Splunk detections
- Validation reports
- MITRE ATT&CK mappings
- Detection severity
- False-positive considerations
- Correlation logic
- Repository references

were technically consistent and aligned with the behaviors actually validated in the Windows laboratory environment.

No new detection rule was created during Day 11.

The review focused on improving the quality and consistency of the existing detection engineering artifacts.

---

# 2. Day 11 Objectives

The primary objectives were:

1. Review all primary detection rules.
2. Review supporting Sigma rules.
3. Review MITRE ATT&CK mappings.
4. Review validation reports.
5. Check Sigma correlation syntax.
6. Check consistency between Sigma and validation documentation.
7. Review false-positive handling.
8. Identify incorrect or overly broad MITRE mappings.
9. Synchronize corrected mappings across the repository.
10. Create project-wide MITRE ATT&CK coverage documentation.

---

# 3. Project Scope Reviewed

The Day 11 review covered:

| Artifact | Reviewed |
|---|---:|
| Primary detection rules | 8 |
| Sigma YAML files | 11 |
| Splunk detection queries | 8 |
| Validation reports | 8 |
| Day-level MITRE coverage documents | 7 |
| Detection-focused days | Days 03–09 |
| SOC investigation workflow | Day 10 |

The repository was clean and synchronized with the remote repository before the review began.

---

# 4. Detection Inventory

The project contains eight primary detection rules.

| Rule | Detection | Event ID(s) | MITRE ATT&CK |
|---|---|---|---|
| Rule 001 | Windows Failed Logon Attempt | 4625 | T1110 |
| Rule 002 | Multiple Windows Failed Logon Attempts | 4625 | T1110 |
| Rule 003 | PowerShell Encoded Command Execution | 4688 | T1059.001 |
| Rule 004 | Windows Scheduled Task Created | 4698 | T1053.005 |
| Rule 005 | Failed Network Logon Followed by Successful Network Logon | 4625, 4624 | T1110 |
| Rule 006 | Windows Local Administrator Group Membership Change | 4732 | T1098.007 |
| Rule 007 | Windows Administrators Group Enumeration via Net1 | 4799 | T1069.001 |
| Rule 008 | Windows Administrator Privileged Command Shell Execution | 4672, 4688 | T1059.003 |

---

# 5. Sigma Rule Review

The Sigma repository was reviewed to verify:

- Rule IDs
- Detection descriptions
- Event IDs
- Detection conditions
- Severity
- False-positive considerations
- MITRE tags
- Correlation structure
- Supporting-rule relationships

The project contains 11 Sigma files supporting eight primary detection scenarios.

The additional Sigma files are used as supporting rules for correlation-based detections.

---

# 6. Rule 001 Review

### Windows Failed Logon Attempt

**Event ID:** 4625

**MITRE ATT&CK:** T1110 — Brute Force

**Severity:** Low

The rule detects Windows Security Event ID 4625 failed authentication activity.

The review confirmed that the rule appropriately treats failed authentication as an investigation signal rather than automatically classifying every failed authentication event as malicious.

Documented false-positive considerations include:

- Incorrect passwords
- Invalid usernames
- Expired or locked accounts
- Misconfigured services
- Legitimate administrative activity

**Review Status:** Consistent

No change was required.

---

# 7. Rule 002 Review

### Multiple Windows Failed Logon Attempts

**Event ID:** 4625

**Detection Type:** Event-count correlation

**Threshold:** 5 or more events

**Timespan:** 5 minutes

**MITRE ATT&CK:** T1110 — Brute Force

**Severity:** Medium

The rule identifies repeated failed authentication events from the same source within a five-minute period.

The review confirmed that the correlation logic and MITRE mapping were consistent with the detection behavior.

Documented false-positive considerations include:

- Repeated incorrect passwords
- Misconfigured services
- Scheduled tasks using outdated credentials
- Legitimate administrative troubleshooting

**Review Status:** Consistent

No change was required.

---

# 8. Rule 003 Review

### PowerShell Encoded Command Execution

**Event ID:** 4688

**MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Severity:** Medium

The detection identifies PowerShell process creation containing encoded-command execution indicators.

The rule was previously validated using controlled PowerShell activity and Windows Event ID 4688.

The review confirmed consistency between:

- Sigma detection
- Splunk implementation
- Validation report
- MITRE mapping

**Review Status:** Consistent

No change was required.

---

# 9. Rule 004 Review

### Windows Scheduled Task Created

**Event ID:** 4698

**MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

**Severity:** Medium

The detection identifies Windows scheduled-task creation through Security Event ID 4698.

The validation process included enabling the required Windows auditing configuration and generating a controlled scheduled-task creation event.

The review confirmed consistency between the detection logic, validation evidence, and MITRE mapping.

**Review Status:** Consistent

No change was required.

---

# 10. Rule 005 Review

### Failed Network Logon Followed by Successful Network Logon

**Event IDs:** 4625 and 4624

**Logon Type:** 3

**Correlation Type:** Temporal ordered

**Timespan:** 10 minutes

**Severity:** Medium

The detection identifies a failed network authentication followed by a successful network authentication from the same source and account context.

## Issue Identified

The original Sigma rule contained an indentation issue in the correlation section.

The original structure contained:

~~~yaml
correlation:
  type: temporal_ordered
    rules:
~~~

This was corrected to:

~~~yaml
correlation:
  type: temporal_ordered
  rules:
    - 61f2a8c3-4625-4b91-a201-006fa1ed0a06
    - 72a3b9d4-4624-4c82-b312-007fa1ed0a07
~~~

## MITRE Mapping Review

The original detection was associated with lateral movement / Valid Accounts.

The review determined that the validated behavior was more directly represented as an authentication-failure pattern requiring investigation.

The mapping was therefore updated to:

~~~text
T1110 — Brute Force
Tactic: Credential Access
~~~

The detection does not independently establish malicious activity, credential compromise, valid-account abuse, or lateral movement.

## Repository Synchronization

The following artifacts were synchronized:

~~~text
sigma-rules/windows/lateral-movement/windows-failed-to-successful-network-logon.yml

validation/rule-005-validation.md

mitre-coverage/day06-network-authentication-detection.md
~~~

**Review Status:** Corrected and synchronized

---

# 11. Rule 006 Review

### Windows Local Administrator Group Membership Change

**Event ID:** 4732

**Severity:** High

The detection identifies a member being added to the local Windows `Administrators` security group.

## MITRE Mapping Review

The original mapping used:

~~~text
T1098 — Account Manipulation
~~~

The review identified a more specific ATT&CK sub-technique corresponding to the observed behavior:

~~~text
T1098.007 — Account Manipulation: Additional Local or Domain Groups
~~~

The Sigma mapping was updated to:

~~~yaml
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1098.007
~~~

## Repository Synchronization

The validation report was updated to use the same sub-technique:

~~~text
T1098.007 — Account Manipulation: Additional Local or Domain Groups
~~~

The Day 07 MITRE coverage document was checked and already contained the more specific mapping.

The following artifacts are therefore aligned:

~~~text
sigma-rules/windows/account-privilege/windows-local-administrator-group-membership-change.yml

validation/rule-006-validation.md

mitre-coverage/day07-account-privilege-detection.md
~~~

**Review Status:** Corrected and synchronized

---

# 12. Rule 007 Review

### Windows Administrators Group Enumeration via Net1

**Event ID:** 4799

**MITRE ATT&CK:** T1069.001 — Permission Groups Discovery: Local Groups

**Severity:** Medium

The detection focuses on:

~~~text
Event ID 4799
+
Administrators group
+
net1.exe
~~~

The review confirmed that the detection was appropriately narrowed after analyzing the baseline of Windows discovery telemetry.

The baseline contained substantial legitimate discovery activity from Windows and security-related processes.

The final detection therefore does not alert on every Event ID 4799 event.

**Review Status:** Consistent

No change was required.

---

# 13. Rule 008 Review

### Windows Administrator Privileged Command Shell Execution

**Event IDs:** 4672 and 4688

**MITRE ATT&CK:** T1059.003 — Windows Command Shell

**Correlation Window:** 15 minutes

**Severity:** High

The detection correlates:

~~~text
Event ID 4672
Administrator privileged session
        ↓
Same Windows Logon ID
        ↓
Event ID 4688
cmd.exe process creation
~~~

The review confirmed consistency between:

- Supporting Sigma Rule 1
- Supporting Sigma Rule 2
- Primary Sigma Rule 008
- Splunk correlation query
- Validation report
- MITRE coverage documentation

The controlled validation successfully correlated the expected privileged session with `cmd.exe` execution.

**Review Status:** Consistent

No change was required.

---

# 14. MITRE ATT&CK Coverage Review

The project currently covers the following techniques and sub-techniques:

| ATT&CK ID | Technique | Tactic | Rules |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | 001, 002, 005 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | 003 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | 004 |
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | Persistence / Privilege Escalation | 006 |
| T1069.001 | Permission Groups Discovery: Local Groups | Discovery | 007 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | 008 |

The project does not claim comprehensive coverage of these ATT&CK techniques.

The mappings represent the behaviors actually implemented and validated in the laboratory environment.

---

# 15. Validation Review

All eight validation reports were reviewed.

The review confirmed that the project maintains dedicated validation documentation for each primary detection:

~~~text
validation/
├── rule-001-validation.md
├── rule-002-validation.md
├── rule-003-validation.md
├── rule-004-validation.md
├── rule-005-validation.md
├── rule-006-validation.md
├── rule-007-validation.md
└── rule-008-validation.md
~~~

The validation documentation covers:

- Telemetry availability
- Detection logic
- Controlled validation
- SPL implementation
- Sigma implementation
- MITRE mapping
- False-positive considerations
- Evidence
- Quantified validation outcomes

---

# 16. False-Positive Quality Review

The project consistently documents legitimate activity that may generate detection signals.

Examples include:

- Incorrect credentials
- Administrative activity
- IT support
- Endpoint management
- Software deployment
- System maintenance
- Scheduled tasks
- Security monitoring
- Security assessment
- Windows discovery processes
- Legitimate command-line activity

The review confirmed that the detections are generally presented as **investigation signals**, rather than automatic classifications of malicious activity.

This is particularly important for:

- Failed authentication
- Scheduled task creation
- Local administrator membership changes
- Group enumeration
- Privileged command-shell execution

---

# 17. Detection Quality Principles Demonstrated

The project demonstrates several practical detection engineering principles.

## Telemetry-Driven Development

Detection scenarios were selected based on telemetry that was actually available and observable in the laboratory.

## Baseline Analysis

Normal and high-volume activity was analyzed before final detection logic was selected.

## Contextual Detection

Where possible, detections incorporate additional context such as:

- Account
- Source address
- Group
- Process
- Logon ID
- Logon type
- Temporal sequence

## Controlled Validation

Controlled benign activity was used to generate known security telemetry and verify detection behavior.

## False-Positive Awareness

Legitimate administrative and system activity was considered during detection design.

## MITRE Alignment

ATT&CK mappings were reviewed against the actual behavior represented by each detection.

## Evidence-Based Documentation

Detection decisions were supported by screenshots, raw events, Splunk results, validation reports, and repository artifacts.

---

# 18. Repository Consistency Review

The following relationship was reviewed across the project:

~~~text
Windows Telemetry
      ↓
Detection Logic
      ↓
Sigma Rule
      ↓
Splunk SPL
      ↓
Validation Report
      ↓
MITRE Mapping
      ↓
Evidence
~~~

The review specifically checked that MITRE mappings remained consistent across the different documentation layers.

Two synchronization activities were required:

### Rule 005

Updated:

~~~text
Sigma
Validation
Day 06 MITRE Coverage
~~~

to use:

~~~text
T1110 — Brute Force
~~~

### Rule 006

Updated:

~~~text
Sigma
Validation
~~~

and verified Day 07 MITRE coverage using:

~~~text
T1098.007 — Account Manipulation:
Additional Local or Domain Groups
~~~

---

# 19. Quantified Day 11 Outcomes

| Metric | Result |
|---|---:|
| Primary detection rules reviewed | 8 |
| Sigma YAML files reviewed | 11 |
| Splunk queries reviewed | 8 |
| Validation reports reviewed | 8 |
| Day-level MITRE documents reviewed | 7 |
| Detection mappings corrected | 2 |
| Sigma correlation syntax corrections | 1 |
| MITRE synchronization updates | 2 detection areas |
| New detection rules created | 0 |

Day 11 was intentionally focused on **quality assurance and project-wide consistency**, rather than creating another detection.

---

# 20. Project-Wide MITRE Coverage Artifact

The consolidated project-wide MITRE coverage document was created at:

~~~text
mitre-coverage/project-mitre-coverage.md
~~~

The document provides:

- Project-wide detection inventory
- MITRE ATT&CK coverage
- Tactic coverage
- Detection-to-technique mapping
- Sigma coverage
- Splunk coverage
- Validation coverage
- False-positive considerations
- Detection quality review
- Repository mapping
- Quantified project outcomes

---

# 21. Day 11 Evidence

Day 11 is primarily a documentation and repository-quality review day.

The main evidence consists of the reviewed project artifacts rather than a new attack simulation.

### Reviewed Sigma Evidence

~~~text
sigma-rules/windows/
~~~

### Reviewed Splunk Evidence

~~~text
splunk-queries/
~~~

### Reviewed Validation Evidence

~~~text
validation/
~~~

### Reviewed MITRE Evidence

~~~text
mitre-coverage/
~~~

### Primary Day 11 Artifact

~~~text
mitre-coverage/project-mitre-coverage.md
~~~

---

# 22. Skills Demonstrated

## Detection Engineering

- Detection rule quality review
- Sigma rule analysis
- Correlation logic review
- Detection tuning
- False-positive analysis
- Detection consistency validation

## SIEM Engineering

- Splunk detection review
- SPL implementation analysis
- Event correlation
- Windows Security telemetry analysis

## Threat Detection

- Authentication detection
- PowerShell detection
- Scheduled-task detection
- Privileged group monitoring
- Windows discovery detection
- Command-shell detection

## MITRE ATT&CK

- Technique mapping
- Sub-technique mapping
- Tactic identification
- Detection-to-technique alignment

## SOC Engineering

- Detection quality assessment
- Investigation signal classification
- Evidence-based analysis
- Analyst context development

## Documentation

- Cross-artifact consistency
- Detection documentation
- Validation documentation
- Repository organization
- Recruiter-facing technical presentation

---

# 23. Day 11 Outcome

Day 11 completed a project-wide quality review of the detection engineering work developed during Days 03–09.

The review confirmed that the project contains:

- 8 primary detection rules
- 11 Sigma YAML files
- 8 Splunk detection queries
- 8 validation reports
- 7 day-level MITRE coverage documents
- 1 project-wide MITRE coverage document

Two detection mappings required refinement.

Rule 005 was corrected to use:

~~~text
T1110 — Brute Force
~~~

and Rule 006 was refined to:

~~~text
T1098.007 — Account Manipulation:
Additional Local or Domain Groups
~~~

The Rule 005 Sigma correlation indentation was also corrected.

The associated validation and MITRE documentation were synchronized to maintain consistency across the repository.

Day 11 demonstrates that detection engineering is not limited to creating alerts. It also requires continuous review of:

~~~text
Detection Logic
      ↓
Telemetry
      ↓
Validation
      ↓
MITRE Mapping
      ↓
False Positives
      ↓
Documentation
      ↓
Repository Consistency
~~~

The project is now prepared for the final phase: **Day 12 — Final Validation and README/Portfolio Polish**.

---

# 24. Day 11 Status

**MITRE ATT&CK Coverage Review: COMPLETE**

**Detection Quality Review: COMPLETE**

**Sigma Review: COMPLETE**

**Validation Review: COMPLETE**

**MITRE Consistency Review: COMPLETE**

**Repository Documentation Review: COMPLETE**

**Day 11 Status: COMPLETE**