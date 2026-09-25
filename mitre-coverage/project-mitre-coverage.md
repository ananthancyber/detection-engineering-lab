# Project-Wide MITRE ATT&CK Coverage

## 1. Overview

This document provides the project-wide MITRE ATT&CK coverage for the **Project 04 — Detection Engineering Lab**.

The purpose of this review is to consolidate the detection engineering work completed across Days 03–09 and demonstrate how each validated detection maps to a specific adversary behavior represented in the MITRE ATT&CK framework.

The coverage review also evaluates:

- Detection intent
- Windows Security telemetry
- Sigma implementation
- Splunk implementation
- Validation evidence
- MITRE ATT&CK mapping
- Detection severity
- False-positive considerations
- Correlation logic
- Detection quality

The project follows an evidence-driven detection engineering approach:

~~~
Windows Telemetry
      ↓
Baseline Analysis
      ↓
Behavior Identification
      ↓
Detection Logic
      ↓
Splunk SPL
      ↓
Sigma Rule
      ↓
Controlled Validation
      ↓
MITRE ATT&CK Mapping
      ↓
SOC Investigation Context
~~~

---

# 2. Project Detection Coverage

The project contains **8 primary detection rules** supported by Windows Security telemetry and validated through Splunk Cloud.

| Rule | Detection | Primary Event ID(s) | Detection Type | MITRE ATT&CK | Tactic | Severity | Validation |
|---|---|---|---|---|---|---|---|
| Rule 001 | Windows Failed Logon Attempt | 4625 | Single-event | T1110 | Credential Access | Low | Validated |
| Rule 002 | Multiple Windows Failed Logon Attempts | 4625 | Event-count correlation | T1110 | Credential Access | Medium | Validated |
| Rule 003 | PowerShell Encoded Command Execution | 4688 | Process / command-line | T1059.001 | Execution | Medium | Validated |
| Rule 004 | Windows Scheduled Task Created | 4698 | Persistence event | T1053.005 | Persistence | Medium | Validated |
| Rule 005 | Failed Network Logon Followed by Successful Network Logon | 4625, 4624 | Temporal correlation | T1110 | Credential Access | Medium | Validated |
| Rule 006 | Windows Local Administrator Group Membership Change | 4732 | Account / privilege activity | T1098.007 | Persistence, Privilege Escalation | High | Validated |
| Rule 007 | Windows Administrators Group Enumeration via Net1 | 4799 | Discovery / process context | T1069.001 | Discovery | Medium | Validated |
| Rule 008 | Windows Administrator Privileged Command Shell Execution | 4672, 4688 | Multi-event correlation | T1059.003 | Execution | High | Validated |

---

# 3. MITRE ATT&CK Coverage Summary

The project currently provides validated coverage across the following MITRE ATT&CK techniques and sub-techniques:

| ATT&CK ID | Technique | Tactic | Project Coverage |
|---|---|---|---|
| T1110 | Brute Force | Credential Access | Rules 001, 002, 005 |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | Rule 003 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | Rule 004 |
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | Persistence, Privilege Escalation | Rule 006 |
| T1069.001 | Permission Groups Discovery: Local Groups | Discovery | Rule 007 |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Execution | Rule 008 |

---

# 4. Credential Access Coverage

## T1110 — Brute Force

### Covered by

- Rule 001 — Windows Failed Logon Attempt
- Rule 002 — Multiple Windows Failed Logon Attempts
- Rule 005 — Failed Network Logon Followed by Successful Network Logon

### Rule 001 — Windows Failed Logon Attempt

**Event ID:** 4625

**Detection Type:** Single-event detection

**Severity:** Low

**Sigma Rule:**

~~~
sigma-rules/windows/credential-access/windows-failed-logon.yml
~~~

**Splunk Query:**

~~~
splunk-queries/authentication/failed-logon-4625.spl
~~~

**Validation:**

~~~
validation/rule-001-validation.md
~~~

The detection identifies Windows Security Event ID 4625 failed authentication activity.

The detection is intentionally treated as an investigation signal because a failed authentication event can result from normal user behavior, incorrect credentials, expired accounts, service configuration problems, or administrative activity.

### Rule 002 — Multiple Windows Failed Logon Attempts

**Event ID:** 4625

**Detection Type:** Event-count correlation

**Threshold:** 5 or more events

**Timespan:** 5 minutes

**Severity:** Medium

**Sigma Rule:**

~~~
sigma-rules/windows/credential-access/windows-repeated-failed-logons.yml
~~~

**Splunk Query:**

~~~
splunk-queries/authentication/repeated-failed-logons-5min.spl
~~~

**Validation:**

~~~
validation/rule-002-validation.md
~~~

The detection increases contextual confidence by identifying repeated failed authentication activity from the same source within a defined time window.

The baseline and validation process confirmed that repeated authentication failures require investigation but do not automatically establish malicious activity.

### Rule 005 — Failed Network Logon Followed by Successful Network Logon

**Event IDs:** 4625 and 4624

**Logon Type:** 3

**Detection Type:** Temporal correlation

**Timespan:** 10 minutes

**Severity:** Medium

**Sigma Rule:**

~~~
sigma-rules/windows/lateral-movement/windows-failed-to-successful-network-logon.yml
~~~

**Supporting Sigma Rules:**

~~~
sigma-rules/windows/lateral-movement/windows-failed-network-logon.yml
sigma-rules/windows/lateral-movement/windows-successful-network-logon.yml
~~~

**Splunk Query:**

~~~
splunk-queries/authentication/failed-to-successful-network-logon.spl
~~~

**Validation:**

~~~
validation/rule-005-validation.md
~~~

The detection identifies a failed network authentication followed by a successful network authentication from the same source and account context.

The validated behavior is mapped to **T1110 — Brute Force** as an authentication pattern that can warrant investigation.

The detection does not independently establish credential compromise, valid-account abuse, or malicious lateral movement.

---

# 5. Execution Coverage

## T1059.001 — Command and Scripting Interpreter: PowerShell

### Covered by

- Rule 003 — PowerShell Encoded Command Execution

**Event ID:** 4688

**Detection Type:** Process creation / command-line analysis

**Severity:** Medium

**Sigma Rule:**

~~~
sigma-rules/windows/execution/windows-powershell-encoded-command.yml
~~~

**Splunk Query:**

~~~
splunk-queries/process-creation/powershell-encoded-command.spl
~~~

**Validation:**

~~~
validation/rule-003-validation.md
~~~

The detection identifies PowerShell process creation containing encoded-command execution indicators.

A baseline was first performed against existing Event ID 4688 telemetry. The controlled validation then generated a known PowerShell process containing an encoded command indicator.

The controlled event was successfully ingested into Splunk Cloud and identified by the final detection query.

---

## T1059.003 — Command and Scripting Interpreter: Windows Command Shell

### Covered by

- Rule 008 — Windows Administrator Privileged Command Shell Execution

**Event IDs:** 4672 and 4688

**Detection Type:** Multi-event correlation

**Correlation Window:** 15 minutes

**Severity:** High

**Sigma Rules:**

Supporting Rule:

~~~
sigma-rules/windows/execution/windows-administrator-special-privileges.yml
~~~

Supporting Rule:

~~~
sigma-rules/windows/execution/windows-administrator-command-shell.yml
~~~

Primary Rule:

~~~
sigma-rules/windows/execution/windows-administrator-privileged-command-shell.yml
~~~

**Splunk Query:**

~~~
splunk-queries/correlation/administrator-privileged-command-shell.spl
~~~

**Validation:**

~~~
validation/rule-008-validation.md
~~~

The detection correlates:

~~~
Event ID 4672
Administrator privileged session
        ↓
Same Windows Logon ID
        ↓
Event ID 4688
cmd.exe process creation
~~~

The controlled validation successfully produced the expected privileged-session and command-shell sequence.

The validated controlled sequence produced:

- 1 Event ID 4672
- 1 Event ID 4688
- 1 matching Logon ID
- 1 successful detection
- 100% controlled validation success

The detection is treated as a contextual investigation signal because legitimate administrators, IT support personnel, endpoint management tools, and system maintenance can generate similar activity.

---

# 6. Persistence Coverage

## T1053.005 — Scheduled Task/Job: Scheduled Task

### Covered by

- Rule 004 — Windows Scheduled Task Created

**Event ID:** 4698

**Detection Type:** Windows Security event detection

**Severity:** Medium

**Sigma Rule:**

~~~
sigma-rules/windows/persistence/windows-scheduled-task-created.yml
~~~

**Splunk Query:**

~~~
splunk-queries/persistence/scheduled-task-created-4698.spl
~~~

**Validation:**

~~~
validation/rule-004-validation.md
~~~

The initial telemetry search did not contain the required Event ID 4698 telemetry.

Windows auditing was subsequently enabled for the required event category, after which a controlled scheduled-task creation generated Event ID 4698.

The final detection successfully identified the controlled scheduled-task creation.

The controlled validation achieved:

~~~
Expected controlled event: 1
Detected controlled event: 1
Detection coverage: 100%
~~~

The detection is designed as an investigation signal because legitimate scheduled tasks are common in Windows environments.

---

## T1098.007 — Account Manipulation: Additional Local or Domain Groups

### Covered by

- Rule 006 — Windows Local Administrator Group Membership Change

**Event ID:** 4732

**Detection Type:** Account / privilege activity

**Severity:** High

**Sigma Rule:**

~~~
sigma-rules/windows/account-privilege/windows-local-administrator-group-membership-change.yml
~~~

**Splunk Query:**

~~~
splunk-queries/account-privilege/local-administrator-group-membership-change.spl
~~~

**Validation:**

~~~
validation/rule-006-validation.md
~~~

The detection identifies a member being added to the local Windows `Administrators` security group.

A controlled temporary account was created and added to the local Administrators group.

Windows generated Event ID 4732 and the event was successfully ingested into Splunk Cloud.

The controlled account's security identifier was correlated with the `Member` field in the Windows Security event.

Controlled validation achieved:

~~~
Expected controlled event: 1
Detected controlled event: 1
Detection coverage: 100%
~~~

The activity is mapped to **T1098.007 — Account Manipulation: Additional Local or Domain Groups**.

Legitimate administrative activity, endpoint management, software installation, and IT support can also generate this event and should be considered during investigation.

---

# 7. Discovery Coverage

## T1069.001 — Permission Groups Discovery: Local Groups

### Covered by

- Rule 007 — Windows Administrators Group Enumeration via Net1

**Event ID:** 4799

**Detection Type:** Discovery / process-context detection

**Severity:** Medium

**Sigma Rule:**

~~~
sigma-rules/windows/discovery/windows-administrators-group-enumeration.yml
~~~

**Splunk Query:**

~~~
splunk-queries/discovery/administrators-group-enumeration.spl
~~~

**Validation:**

~~~
validation/rule-007-validation.md
~~~

The initial discovery baseline contained:

- 427 Event ID 4798 events
- 592 Event ID 4799 events
- 1,019 combined discovery events

The baseline identified legitimate high-volume enumeration activity from processes such as:

- `wazuh-agent.exe`
- `svchost.exe`
- `VSSVC.exe`
- `WmiPrvSE.exe`
- `SearchIndexer.exe`
- `consent.exe`

Rather than detecting every Event ID 4799 event, the final detection focuses on:

~~~
Event ID 4799
AND
Group Name = Administrators
AND
Process Name = net1.exe
~~~

A controlled discovery test generated Event ID 4799 through Windows built-in discovery commands.

The final SPL detection returned one matching event.

Controlled validation achieved:

~~~
Expected controlled detection events: 1
Detected events: 1
Detection coverage: 100%
~~~

This demonstrates telemetry-driven detection tuning based on observed baseline activity.

---

# 8. Detection Coverage by Tactic

| MITRE Tactic | Techniques Covered | Rules |
|---|---|---|
| Credential Access | T1110 | 001, 002, 005 |
| Execution | T1059.001, T1059.003 | 003, 008 |
| Persistence | T1053.005, T1098.007 | 004, 006 |
| Privilege Escalation | T1098.007 | 006 |
| Discovery | T1069.001 | 007 |

The project therefore demonstrates detection engineering across five MITRE ATT&CK tactical areas represented by the validated rules.

---

# 9. Detection Engineering Quality Review

The Day 11 review examined the consistency between:

~~~
Sigma Rule
     ↓
Splunk SPL
     ↓
Validation Report
     ↓
MITRE Coverage
     ↓
Evidence
~~~

The review focused on:

- Correct Event IDs
- Detection intent
- MITRE technique accuracy
- Severity
- False-positive handling
- Correlation logic
- Validation evidence
- Repository references
- Consistency between implementation and documentation

## Quality Review Findings

### Rule 001

**Status:** Consistent

Event ID 4625 is used consistently across the Sigma rule, SPL detection, and validation documentation.

### Rule 002

**Status:** Consistent

The five-event / five-minute correlation logic is represented consistently across the detection and validation artifacts.

### Rule 003

**Status:** Consistent

PowerShell encoded-command detection uses Event ID 4688 and maps to T1059.001.

### Rule 004

**Status:** Consistent

Scheduled task creation uses Event ID 4698 and maps to T1053.005.

### Rule 005

**Status:** Corrected

The review identified two issues:

1. Incorrect YAML indentation under `correlation`.
2. MITRE mapping was previously documented as Valid Accounts / lateral movement.

The correlation syntax was corrected and the mapping was aligned to:

~~~
T1110 — Brute Force
Tactic: Credential Access
~~~

The validation and Day 06 MITRE documentation were synchronized with the updated mapping.

### Rule 006

**Status:** Corrected

The original mapping used:

~~~
T1098 — Account Manipulation
~~~

The review identified a more specific ATT&CK sub-technique applicable to the observed behavior:

~~~
T1098.007 — Account Manipulation:
Additional Local or Domain Groups
~~~

The Sigma rule, validation report, and Day 07 MITRE documentation were synchronized to the more specific mapping.

### Rule 007

**Status:** Consistent

The detection maps to:

~~~
T1069.001 — Permission Groups Discovery: Local Groups
~~~

The detection behavior, Event ID 4799, Administrators group context, and `net1.exe` process context are aligned.

### Rule 008

**Status:** Consistent

The detection correlates Event IDs 4672 and 4688 using the Windows Logon ID and maps to:

~~~
T1059.003 — Windows Command Shell
~~~

The 15-minute correlation window is documented consistently across the Sigma, SPL, validation, and MITRE artifacts.

---

# 10. False-Positive Management

The project does not treat the presence of a Windows Security event as automatic evidence of malicious behavior.

False-positive considerations were documented throughout the detection lifecycle.

Examples include:

- Incorrect passwords
- Expired or locked accounts
- Misconfigured services
- Legitimate administrative activity
- IT support
- Endpoint management
- Scheduled tasks using outdated credentials
- Software deployment
- System maintenance
- Security monitoring
- Security assessment
- Legitimate Windows discovery activity

The project uses contextual detection techniques where appropriate, including:

- Source address
- Account
- Account domain
- Event ID
- Logon type
- Windows Logon ID
- Process name
- Command-line context
- Target group
- Temporal relationships

This approach reduces reliance on isolated event signatures and provides additional context for SOC investigation.

---

# 11. Detection Validation Summary

The project uses controlled validation wherever practical.

| Rule | Controlled Validation | Result |
|---|---|---|
| Rule 001 | Windows Event ID 4625 telemetry | Passed |
| Rule 002 | Repeated failed-logon correlation | Passed |
| Rule 003 | Controlled PowerShell encoded-command execution | 1/1 |
| Rule 004 | Controlled scheduled-task creation | 1/1 |
| Rule 005 | Failed → successful network authentication sequence | Validated |
| Rule 006 | Controlled Administrators group membership change | 1/1 |
| Rule 007 | Controlled Administrators group enumeration | 1/1 |
| Rule 008 | Controlled privileged `cmd.exe` execution | 1/1 |

The validation evidence is maintained in:

~~~
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

---

# 12. Sigma Coverage

The project contains **11 Sigma YAML files** supporting the 8 primary detection rules.

The additional Sigma files represent supporting detections used by correlation-based rules.

### Rule 005 Supporting Rules

~~~
windows-failed-network-logon.yml
windows-successful-network-logon.yml
windows-failed-to-successful-network-logon.yml
~~~

### Rule 008 Supporting Rules

~~~
windows-administrator-special-privileges.yml
windows-administrator-command-shell.yml
windows-administrator-privileged-command-shell.yml
~~~

The remaining primary rules use individual Sigma implementations.

This structure separates:

- Individual event detections
- Supporting correlation components
- Primary correlation detections

---

# 13. Splunk Detection Coverage

The project contains Splunk implementations for the validated detection scenarios.

Repository structure:

~~~
splunk-queries/
├── account-privilege/
│   └── local-administrator-group-membership-change.spl
├── authentication/
│   ├── failed-logon-4625.spl
│   ├── repeated-failed-logons-5min.spl
│   └── failed-to-successful-network-logon.spl
├── correlation/
│   └── administrator-privileged-command-shell.spl
├── discovery/
│   └── administrators-group-enumeration.spl
├── persistence/
│   └── scheduled-task-created-4698.spl
└── process-creation/
    └── powershell-encoded-command.spl
~~~

The SPL implementations demonstrate:

- Windows Security event filtering
- Raw event parsing
- Field extraction
- Event aggregation
- Temporal correlation
- Process context analysis
- Account correlation
- Logon ID correlation
- Detection result generation

---

# 14. MITRE Coverage by Project Day

| Day | Detection Focus | Rule | MITRE ATT&CK |
|---|---|---|---|
| Day 03 | Authentication / Failed Logons | 001, 002 | T1110 |
| Day 04 | PowerShell Encoded Command | 003 | T1059.001 |
| Day 05 | Scheduled Task Creation | 004 | T1053.005 |
| Day 06 | Network Authentication Correlation | 005 | T1110 |
| Day 07 | Local Administrator Group Change | 006 | T1098.007 |
| Day 08 | Administrators Group Enumeration | 007 | T1069.001 |
| Day 09 | Privileged Command Shell | 008 | T1059.003 |
| Day 10 | SOC Investigation Workflow | Existing Rule 008 | T1059.003 |

Day 10 did not introduce a new detection. It demonstrated the SOC investigation workflow using the existing Rule 008 alert.

---

# 15. Evidence-Driven Detection Engineering

The project deliberately follows a telemetry-first methodology.

Rather than selecting detections solely from theoretical ATT&CK techniques, the project first examined available Windows Security telemetry.

Examples include:

### Day 05

Registry telemetry was investigated but did not provide the required reliable detection data. The project therefore moved to Scheduled Task Creation using Event ID 4698.

### Day 08

Event IDs 4798 and 4799 produced substantial legitimate enumeration activity. Process-level analysis was then used to focus the final detection on Administrators group enumeration through `net1.exe`.

### Day 09

An explicit-credential correlation path was investigated but produced excessive normal Windows activity. The final detection scenario was therefore changed to privileged Administrator session followed by `cmd.exe` execution.

These decisions demonstrate that detection selection was based on **observed telemetry and validation results**, rather than simply creating theoretical detections.

---

# 16. Detection Engineering Lifecycle

The project demonstrates the following repeatable workflow:

~~~
1. Identify telemetry
        ↓
2. Establish baseline
        ↓
3. Analyze normal activity
        ↓
4. Identify detection opportunity
        ↓
5. Define detection logic
        ↓
6. Implement SPL
        ↓
7. Implement Sigma
        ↓
8. Generate controlled activity
        ↓
9. Validate detection
        ↓
10. Map to MITRE ATT&CK
        ↓
11. Document false positives
        ↓
12. Prepare SOC investigation context
~~~

This lifecycle is repeated across the detection scenarios and provides a practical representation of detection engineering work.

---

# 17. Quantified Project Coverage

The project currently documents:

| Metric | Result |
|---|---:|
| Primary detection rules | 8 |
| Sigma YAML files | 11 |
| Splunk detection queries | 8 |
| Validation reports | 8 |
| MITRE day-level coverage documents | 7 |
| MITRE ATT&CK techniques/sub-techniques represented | 6 |
| Detection-focused project days | 7 |
| SOC investigation workflow days | 1 |
| Controlled 1/1 validations documented | 4 |
| Highest documented detection severity | High |
| Primary MITRE tactical areas represented | 5 |

The metrics describe the documented project artifacts and validation activities rather than claiming production SOC performance.

---

# 18. Repository Mapping

The project-wide MITRE coverage connects the following repository components:

~~~
Project-04-Detection-Engineering-Lab/
│
├── docs/
│   ├── Day03.md
│   ├── Day04.md
│   ├── Day05.md
│   ├── Day06.md
│   ├── Day07.md
│   ├── Day08.md
│   ├── Day09.md
│   └── Day10.md
│
├── mitre-coverage/
│   ├── day03-authentication-detections.md
│   ├── day04-process-creation-detection.md
│   ├── day05-scheduled-task-detection.md
│   ├── day06-network-authentication-detection.md
│   ├── day07-account-privilege-detection.md
│   ├── day08-windows-discovery-detection.md
│   ├── day09-privileged-command-shell-detection.md
│   └── project-mitre-coverage.md
│
├── sigma-rules/
│   └── windows/
│
├── splunk-queries/
│
├── validation/
│   ├── rule-001-validation.md
│   ├── rule-002-validation.md
│   ├── rule-003-validation.md
│   ├── rule-004-validation.md
│   ├── rule-005-validation.md
│   ├── rule-006-validation.md
│   ├── rule-007-validation.md
│   └── rule-008-validation.md
│
└── screenshots/
    ├── Day03/
    ├── Day04/
    ├── Day05/
    ├── Day06/
    ├── Day07/
    ├── Day08/
    ├── Day09/
    └── Day10/
~~~

---

# 19. Day 11 Review Outcome

The project-wide MITRE and detection quality review confirmed that the majority of the detection implementations were internally consistent.

Two concrete quality improvements were identified and implemented:

### Rule 005

The correlation YAML indentation was corrected and the MITRE mapping was aligned to:

~~~
T1110 — Brute Force
Credential Access
~~~

The associated validation and Day 06 MITRE documentation were also synchronized.

### Rule 006

The MITRE mapping was refined from the parent technique:

~~~
T1098 — Account Manipulation
~~~

to the more specific sub-technique:

~~~
T1098.007 — Account Manipulation:
Additional Local or Domain Groups
~~~

The associated validation and Day 07 MITRE documentation were verified for consistency.

No additional detection rules were created during this review.

---

# 20. Final MITRE Coverage Status

The project currently provides documented and validated coverage for:

~~~
T1110
Brute Force
Credential Access

T1059.001
Command and Scripting Interpreter: PowerShell
Execution

T1053.005
Scheduled Task/Job: Scheduled Task
Persistence

T1098.007
Account Manipulation: Additional Local or Domain Groups
Persistence / Privilege Escalation

T1069.001
Permission Groups Discovery: Local Groups
Discovery

T1059.003
Command and Scripting Interpreter: Windows Command Shell
Execution
~~~

The coverage represents the behaviors actually implemented and validated in the Windows laboratory environment.

The project does not claim that these detections provide comprehensive enterprise coverage of the corresponding ATT&CK techniques.

---

# 21. Day 11 Status

**MITRE ATT&CK Coverage Review: COMPLETE**

**Detection Quality Review: COMPLETE**

**Sigma Consistency Review: COMPLETE**

**Validation Consistency Review: COMPLETE**

**MITRE Documentation Consistency: COMPLETE**

**Primary Detection Rules Reviewed: 8**

**MITRE ATT&CK Coverage: 6 techniques/sub-techniques**

**Corrections Implemented: 2 detection mappings + 1 Sigma correlation syntax correction**

The project is now ready for the final Day 12 phase: **Final Validation + README and Portfolio Polish**.