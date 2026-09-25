# Detection Engineering Lab

**Building, validating, and documenting Windows security detections using Splunk Cloud, Sigma, SPL, MITRE ATT&CK, controlled validation, and SOC investigation workflows.**

[![Platform](https://img.shields.io/badge/Platform-Splunk%20Cloud-black?logo=splunk)](https://www.splunk.com/)
[![Endpoint](https://img.shields.io/badge/Endpoint-Windows%2010-blue?logo=windows)](https://www.microsoft.com/windows)
[![Detection](https://img.shields.io/badge/Detection-Sigma-orange)](https://sigmahq.io/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Rules](https://img.shields.io/badge/Primary%20Detections-8-brightgreen)](#detection-coverage)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

---

## 30-Second Summary

| | |
|---|---|
| **What it is** | A self-built SOC and detection engineering laboratory focused on Windows security telemetry, Splunk Cloud, Sigma detection rules, SPL, MITRE ATT&CK, and controlled validation. |
| **Primary detections** | **8 validated detection scenarios** covering authentication, execution, persistence, privilege activity, and discovery. |
| **Sigma coverage** | **11 Sigma YAML files** including primary and supporting correlation rules. |
| **Splunk coverage** | **8 SPL detection queries** for Windows Security telemetry. |
| **Validation** | **8 dedicated validation reports** documenting telemetry, detection logic, results, and false-positive considerations. |
| **MITRE ATT&CK coverage** | T1110, T1059.001, T1053.005, T1098.007, T1069.001, T1059.003 |
| **Investigation workflow** | Alert triage → timeline reconstruction → process context → authentication context → analyst disposition. |
| **Development approach** | Telemetry first → baseline → detection → controlled validation → evidence → MITRE mapping → quality review. |
| **Project duration** | 12-day detection engineering roadmap, with Days 01–11 documented and Day 12 dedicated to final repository validation and portfolio polish. |

---

## Table of Contents

- [Detection Engineering Lab](#detection-engineering-lab)
  - [30-Second Summary](#30-second-summary)
  - [Table of Contents](#table-of-contents)
  - [Why This Project](#why-this-project)
- [Detection Engineering Methodology](#detection-engineering-methodology)
- [Detection Coverage](#detection-coverage)
- [MITRE ATT\&CK Coverage](#mitre-attck-coverage)
- [Validation Approach](#validation-approach)
- [SOC Investigation Workflow](#soc-investigation-workflow)
- [Lab Environment](#lab-environment)
    - [Technologies](#technologies)
- [Repository Structure](#repository-structure)
- [Day-by-Day Build Log](#day-by-day-build-log)
- [Detection Engineering Highlights](#detection-engineering-highlights)
  - [Authentication Detection](#authentication-detection)
  - [PowerShell Detection](#powershell-detection)
  - [Scheduled Task Detection](#scheduled-task-detection)
  - [Network Authentication Correlation](#network-authentication-correlation)
  - [Local Administrator Group Monitoring](#local-administrator-group-monitoring)
  - [Windows Discovery](#windows-discovery)
  - [Privileged Command Shell Correlation](#privileged-command-shell-correlation)
- [Quality Review](#quality-review)
    - [Rule 005](#rule-005)
    - [Rule 006](#rule-006)
- [Quantified Project Outcomes](#quantified-project-outcomes)
- [Skills Demonstrated](#skills-demonstrated)
    - [SIEM \& Detection Engineering](#siem--detection-engineering)
    - [Windows Security Monitoring](#windows-security-monitoring)
    - [Detection Engineering Practices](#detection-engineering-practices)
    - [Threat Detection](#threat-detection)
    - [SOC Operations](#soc-operations)
    - [Documentation](#documentation)
- [Portfolio Relevance](#portfolio-relevance)
- [Author](#author)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Why This Project

Many beginner SIEM projects stop after installing a SIEM and searching through logs.

This project focuses on the complete detection engineering workflow:

1. Identify the telemetry that actually exists.
2. Establish a baseline of normal activity.
3. Select a behavior that can be observed reliably.
4. Develop the detection logic.
5. Implement the detection in Sigma and SPL.
6. Generate controlled activity in the laboratory.
7. Verify that the expected telemetry is produced.
8. Confirm that the detection identifies the behavior.
9. Document false-positive considerations.
10. Map the behavior to MITRE ATT&CK.
11. Preserve screenshots and validation evidence.
12. Review the detection for technical consistency.

The project deliberately documents telemetry-driven pivots.

For example, the originally planned registry-based persistence detection was not retained when the required registry telemetry was unavailable. The project instead pivoted to Windows Scheduled Task Creation using Event ID 4698.

Similarly, the Day 9 correlation scenario was selected after testing candidate telemetry paths and choosing a correlation that could be reliably validated in the environment.

This approach reflects practical detection engineering: **build from observable telemetry rather than assuming that a data source exists.**

---

# Detection Engineering Methodology

The project follows this workflow:

~~~text
Windows Security Telemetry
        ↓
Telemetry Availability Check
        ↓
Baseline Analysis
        ↓
Detection Design
        ↓
Sigma Rule
        ↓
Splunk SPL
        ↓
Controlled Validation
        ↓
Detection Result
        ↓
False-Positive Review
        ↓
MITRE ATT&CK Mapping
        ↓
Evidence Documentation
        ↓
Detection Quality Review
~~~

The goal is not simply to write a rule.

The goal is to demonstrate that the rule is:

- Based on available telemetry
- Reproducible
- Testable
- Documented
- Mapped to an appropriate ATT&CK technique
- Considered in the context of legitimate activity

---

# Detection Coverage

| Rule | Detection | Event ID(s) | Detection Type | MITRE ATT&CK | Result |
|---|---|---|---|---|---|
| **001** | Windows Failed Logon Attempt | 4625 | Event | T1110 — Brute Force | 36 events analyzed |
| **002** | Multiple Failed Logons | 4625 | Correlation | T1110 — Brute Force | 3 matching 5-minute windows |
| **003** | PowerShell Encoded Command Execution | 4688 | Process / Command Line | T1059.001 — PowerShell | 1/1 controlled detection |
| **004** | Windows Scheduled Task Creation | 4698 | Persistence Event | T1053.005 — Scheduled Task | 1/1 controlled detection |
| **005** | Failed Network Logon → Successful Network Logon | 4625, 4624 | Temporal Correlation | T1110 — Brute Force | 62 events evaluated, 2 matching sequences |
| **006** | Local Administrator Group Membership Change | 4732 | Account / Privilege Activity | T1098.007 — Additional Local or Domain Groups | 1/1 controlled detection |
| **007** | Administrators Group Enumeration via `net1.exe` | 4799 | Process-Scoped Discovery | T1069.001 — Local Groups | 1 precise detection |
| **008** | Administrator Privileged Command Shell Execution | 4672, 4688 | Multi-Event Correlation | T1059.003 — Windows Command Shell | Controlled correlation validated |

Each primary detection is represented by corresponding repository artifacts:

- Sigma rule(s)
- SPL query
- Validation report
- MITRE coverage documentation
- Evidence screenshots where applicable

---

# MITRE ATT&CK Coverage

The project currently covers six MITRE ATT&CK techniques/sub-techniques.

| ATT&CK ID | Technique | Tactic | Detection |
|---|---|---|---|
| **T1110** | Brute Force | Credential Access | Rules 001, 002, 005 |
| **T1059.001** | Command and Scripting Interpreter: PowerShell | Execution | Rule 003 |
| **T1053.005** | Scheduled Task/Job: Scheduled Task | Persistence | Rule 004 |
| **T1098.007** | Account Manipulation: Additional Local or Domain Groups | Persistence / Privilege Escalation | Rule 006 |
| **T1069.001** | Permission Groups Discovery: Local Groups | Discovery | Rule 007 |
| **T1059.003** | Command and Scripting Interpreter: Windows Command Shell | Execution | Rule 008 |

The project-wide ATT&CK analysis is documented in:

[`mitre-coverage/project-mitre-coverage.md`](mitre-coverage/project-mitre-coverage.md)

Day-specific ATT&CK documentation is available in:

[`mitre-coverage/`](mitre-coverage/)

---

# Validation Approach

Validation was performed using a combination of:

- Baseline analysis
- Existing Windows Security telemetry
- Controlled benign activity
- Event correlation
- Splunk search results
- Raw event inspection
- Field extraction
- Screenshot evidence
- Validation reports

The validation philosophy is:

~~~text
Baseline
   ↓
Generate Controlled Activity
   ↓
Observe Windows Event
   ↓
Run Detection
   ↓
Verify Expected Match
   ↓
Record Result
   ↓
Document False Positives
~~~

The repository contains eight dedicated validation reports:

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

Not every detection represents the same type of validation.

Some rules use controlled 1:1 validation, while others rely on baseline and correlation analysis. The validation reports document the specific evidence and methodology used for each rule.

---

# SOC Investigation Workflow

Day 10 demonstrates how an alert generated by the detection engineering pipeline can be investigated as a SOC analyst.

The investigation used Rule 008 as the existing detection and followed:

~~~text
Alert
 ↓
Initial Triage
 ↓
Logon ID Identification
 ↓
Timeline Reconstruction
 ↓
Process Context
 ↓
Authentication Context
 ↓
Evidence Correlation
 ↓
Analyst Disposition
~~~

The investigation correlated:

- Windows Security Event ID 4672
- Windows Security Event ID 4688
- Administrator account context
- Windows Logon ID
- `cmd.exe` process creation
- Authentication context
- Process timeline

The controlled activity was documented as a benign validation scenario.

Documentation:

[`docs/Day10.md`](docs/Day10.md)

---

# Lab Environment

| Component | Details |
|---|---|
| **Host OS** | Windows 11 |
| **Monitored Endpoint** | Windows 10 Client VM (`WIN10-CLIENT`) |
| **Domain** | `CORP` / `CORP.LOCAL` |
| **SIEM** | Splunk Cloud |
| **Log Collection** | Splunk Universal Forwarder |
| **Log Source** | Windows Security Event Log |
| **Splunk Index** | `main` |
| **Sourcetype** | `WinEventLog:Security` |
| **Detection Format** | Sigma |
| **Query Language** | Splunk Processing Language (SPL) |
| **Framework** | MITRE ATT&CK |

### Technologies

- Splunk Cloud
- Splunk Universal Forwarder
- Sigma
- Splunk SPL
- Windows Security Event Logs
- PowerShell
- Windows command shell
- Git
- GitHub
- MITRE ATT&CK

---

# Repository Structure

~~~text
Project-04-Detection-Engineering-Lab/
│
├── docs/
│   ├── Day01.md
│   ├── Day02.md
│   ├── Day03.md
│   ├── Day04.md
│   ├── Day05.md
│   ├── Day06.md
│   ├── Day07.md
│   ├── Day08.md
│   ├── Day09.md
│   ├── Day10.md
│   └── Day11.md
│
├── sigma-rules/
│   └── windows/
│       ├── account-privilege/
│       ├── credential-access/
│       ├── discovery/
│       ├── execution/
│       ├── lateral-movement/
│       └── persistence/
│
├── splunk-queries/
│   ├── account-privilege/
│   ├── authentication/
│   ├── correlation/
│   ├── discovery/
│   ├── persistence/
│   └── process-creation/
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
├── screenshots/
│   ├── Day01/
│   ├── Day02/
│   ├── Day03/
│   ├── Day04/
│   ├── Day05/
│   ├── Day06/
│   ├── Day07/
│   ├── Day08/
│   ├── Day09/
│   └── Day10/
│
├── LICENSE
└── README.md
~~~

---

# Day-by-Day Build Log

| Day | Focus | Key Result |
|---|---|---|
| **01** | Lab and Splunk foundation | Detection engineering environment established |
| **02** | Windows telemetry and ingestion | Windows Security telemetry confirmed in Splunk |
| **03** | Authentication detection | Rules 001–002: failed logon and repeated failed logon correlation |
| **04** | Process creation / PowerShell | Rule 003: encoded PowerShell command detection |
| **05** | Persistence | Telemetry assessment followed by pivot to scheduled-task detection; Rule 004 |
| **06** | Network authentication | Rule 005: failed → successful network authentication correlation |
| **07** | Account and privilege activity | Rule 006: local Administrators group membership change |
| **08** | Windows discovery | Rule 007: Administrators group enumeration via `net1.exe` |
| **09** | Advanced correlation | Rule 008: Administrator privileged session → `cmd.exe` execution |
| **10** | SOC investigation workflow | Alert triage, timeline, process context, authentication context, disposition |
| **11** | MITRE coverage and quality review | Project-wide ATT&CK review, mapping corrections, Sigma consistency review |
| **12** | Final validation and portfolio polish | Final repository and README quality review |

Detailed documentation:

[`docs/`](docs/)

---

# Detection Engineering Highlights

## Authentication Detection

Windows Event ID 4625 was analyzed for failed authentication activity.

The project includes both:

- Single failed-logon detection
- Repeated failed-logon correlation

The repeated failed-logon rule uses a five-minute event-count correlation.

---

## PowerShell Detection

Windows Event ID 4688 was used to analyze process creation.

A controlled PowerShell encoded-command test generated the expected process-creation telemetry.

The detection is mapped to:

~~~text
T1059.001 — Command and Scripting Interpreter: PowerShell
~~~

---

## Scheduled Task Detection

Registry-based persistence was initially investigated.

The required registry telemetry was not available in the environment, so the detection strategy was changed to Windows Scheduled Task Creation using Event ID 4698.

This resulted in a validated scheduled-task detection mapped to:

~~~text
T1053.005 — Scheduled Task/Job: Scheduled Task
~~~

---

## Network Authentication Correlation

Rule 005 correlates:

~~~text
Failed Network Authentication
        ↓
Successful Network Authentication
~~~

The detection evaluates the authentication sequence using Windows Security Events 4625 and 4624.

The project deliberately avoids treating this sequence alone as proof of malicious activity.

---

## Local Administrator Group Monitoring

Rule 006 monitors Event ID 4732 for additions to the local `Administrators` group.

The controlled test account's SID was correlated against the Windows local-account information to validate the identity represented by the event.

The detection is mapped to:

~~~text
T1098.007 — Account Manipulation:
Additional Local or Domain Groups
~~~

---

## Windows Discovery

Rule 007 focuses on Administrators group enumeration associated with:

~~~text
Event ID 4799
+
Administrators
+
net1.exe
~~~

A 1,019-event discovery baseline was analyzed before narrowing the detection to the more specific process context.

---

## Privileged Command Shell Correlation

Rule 008 correlates:

~~~text
Event ID 4672
Administrator Special Privileges
        ↓
Same Logon ID
        ↓
Event ID 4688
cmd.exe Execution
~~~

The production correlation uses a 15-minute window and is mapped to:

~~~text
T1059.003 — Command and Scripting Interpreter:
Windows Command Shell
~~~

---

# Quality Review

Day 11 performed a project-wide detection quality review.

The review covered:

- Sigma rule structure
- Correlation logic
- MITRE mappings
- Severity
- False-positive considerations
- Validation reports
- SPL implementation
- Cross-document consistency

Two important mapping refinements were made.

### Rule 005

The primary failed-to-successful network authentication correlation was refined to:

~~~text
T1110 — Brute Force
~~~

The detection is treated as an investigation signal rather than proof of credential compromise, lateral movement, or malicious activity.

### Rule 006

The broader T1098 mapping was refined to:

~~~text
T1098.007 — Account Manipulation:
Additional Local or Domain Groups
~~~

These changes were synchronized across the relevant Sigma, validation, and MITRE documentation.

---

# Quantified Project Outcomes

| Metric | Result |
|---|---:|
| **Primary detection scenarios** | 8 |
| **Sigma YAML files** | 11 |
| **Splunk SPL queries** | 8 |
| **Validation reports** | 8 |
| **Day-by-day documentation** | 11 |
| **Day-level MITRE documents** | 7 |
| **Project-wide MITRE document** | 1 |
| **MITRE techniques/sub-techniques** | 6 |
| **Detection-focused days** | 7 |
| **SOC investigation workflow days** | 1 |
| **Highest detection severity** | High |
| **Primary technologies** | Splunk, Sigma, Windows Security Logs, MITRE ATT&CK |

The repository contains both event-based and correlation-based detection engineering examples.

---

# Skills Demonstrated

### SIEM & Detection Engineering

- Splunk Cloud
- Splunk SPL
- Windows Security Event Log analysis
- Sigma rule authoring
- Event-based detection
- Correlation-based detection
- Field extraction using `rex`
- Statistical correlation using `stats`
- Detection filtering and tuning

### Windows Security Monitoring

- Authentication events
- Process creation
- PowerShell activity
- Scheduled task creation
- Privileged account activity
- Local group membership changes
- Permission group discovery
- Command-shell execution

### Detection Engineering Practices

- Telemetry validation
- Baseline analysis
- Detection scoping
- Controlled validation
- False-positive analysis
- Correlation logic
- Evidence collection
- Detection quality review

### Threat Detection

- MITRE ATT&CK mapping
- Credential access detection
- Execution detection
- Persistence detection
- Privilege escalation monitoring
- Discovery detection

### SOC Operations

- Alert triage
- Timeline reconstruction
- Process context analysis
- Authentication context analysis
- Evidence correlation
- Analyst disposition
- Investigation documentation

### Documentation

- Technical documentation
- Validation reporting
- Evidence management
- Repository organization
- Detection-to-MITRE mapping
- Recruiter-facing project presentation

---

# Portfolio Relevance

This project demonstrates practical experience across the detection engineering lifecycle rather than only theoretical knowledge.

It provides evidence of experience with:

**SOC Monitoring**

→ Windows security telemetry
→ Authentication monitoring
→ Process monitoring
→ Alert investigation

**Detection Engineering**

→ Sigma
→ SPL
→ Event detection
→ Correlation detection
→ Detection tuning

**Threat Detection**

→ MITRE ATT&CK
→ Credential Access
→ Execution
→ Persistence
→ Privilege Escalation
→ Discovery

**SOC Investigation**

→ Alert triage
→ Timeline reconstruction
→ Process context
→ Authentication context
→ Evidence-based disposition

---

# Author

**Ananthan D**

B.Tech Information Technology Graduate
Cybersecurity & SOC Analyst Aspirant

- GitHub: [ananthancyber](https://github.com/ananthancyber)
- LinkedIn: [Ananthan D](https://www.linkedin.com/in/ananthan-d-ab295321b)

---

# Disclaimer

This is an educational portfolio project conducted in a controlled and authorized laboratory environment.

All simulated activity was performed against laboratory systems used for the project. No unauthorized systems, networks, accounts, or third-party environments were targeted.

Detection results represent the telemetry and configuration available within this laboratory environment.

---

# License

MIT License — see [`LICENSE`](LICENSE).
