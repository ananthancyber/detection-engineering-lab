# Project 04 — Detection Engineering Lab

> A hands-on detection engineering laboratory focused on building, validating, and documenting security detections using real Windows security telemetry, Splunk Cloud, Sigma rules, SPL, and MITRE ATT&CK.

![Detection Engineering](https://img.shields.io/badge/Focus-Detection%20Engineering-blue)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Cloud-orange)
![Sigma](https://img.shields.io/badge/Rules-Sigma-red)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)

---

## Overview

This project is a practical **Detection Engineering Lab** designed to simulate how security detections are developed and validated in a SOC environment.

Instead of relying only on predefined SIEM alerts, the project follows a detection engineering workflow:

~~~text
Security Telemetry
       ↓
Event Analysis
       ↓
Baseline Establishment
       ↓
Detection Logic
       ↓
Sigma Rule
       ↓
SPL Query
       ↓
Controlled Validation
       ↓
Evidence Collection
       ↓
MITRE ATT&CK Mapping
       ↓
Documentation
~~~

The laboratory uses **Windows Security Event Logs collected through Splunk Universal Forwarder and analyzed in Splunk Cloud**.

Detection logic is implemented using both:

- **Sigma** for portable detection rules
- **Splunk SPL** for SIEM-specific detection queries

Each detection is validated against real telemetry or a controlled test scenario before being documented.

---

# Objectives

The primary objectives of this project are to:

- Build practical detection engineering skills
- Analyze Windows security telemetry
- Understand Windows Event IDs relevant to SOC investigations
- Establish behavioral baselines before writing detections
- Develop Sigma detection rules
- Develop Splunk SPL queries
- Validate detections using controlled security scenarios
- Map detections to MITRE ATT&CK techniques
- Identify potential false positives
- Collect reproducible evidence
- Document detections in a professional SOC-oriented format
- Build a portfolio demonstrating practical blue-team capabilities

---

# Lab Environment

## Host Environment

| Component | Configuration |
|---|---|
| Host OS | Windows 11 |
| Virtualization | VMware Workstation |
| SIEM | Splunk Cloud |
| Log Collection | Splunk Universal Forwarder |

## Virtual Lab

| System | Role |
|---|---|
| Windows Server | Active Directory Domain Controller |
| Windows 10 | Domain Client / Detection Endpoint |
| Kali Linux | Security Testing / Attack Simulation |
| Ubuntu | Supporting Security Infrastructure |

## Windows Environment

~~~text
Domain: corp.local

Domain Controller:
AD-DC.corp.local

Windows Client:
WIN10-CLIENT
~~~

---

# Detection Engineering Workflow

Each detection follows a repeatable engineering process.

## 1. Identify Telemetry

Determine which Windows event source contains the required security information.

Examples:

- Windows Security Event Logs
- Process Creation Events
- Authentication Events
- Command-Line Telemetry

## 2. Analyze the Event

Understand:

- Event ID
- Important fields
- Account information
- Source information
- Process information
- Command-line information
- Parent process
- Host information

## 3. Establish a Baseline

Before creating a detection, normal activity is analyzed.

This helps distinguish:

- Common legitimate activity
- Administrative activity
- Security tooling
- Suspicious behavior
- Rare or anomalous patterns

## 4. Develop Detection Logic

Detection logic is implemented using:

- Sigma
- Splunk SPL

## 5. Validate

The detection is tested against:

- Existing telemetry
- Historical events
- Controlled test activity

## 6. Collect Evidence

Relevant Splunk results, rules, queries, and validation results are captured as evidence.

## 7. Map to MITRE ATT&CK

Detections are mapped to relevant ATT&CK techniques and sub-techniques.

## 8. Document

Each detection receives:

- Detection description
- Technical logic
- Validation result
- Evidence
- MITRE mapping
- Quantified outcome

---

# Current Detection Coverage

The project currently contains **3 detection rules** covering authentication and PowerShell execution activity.

| Rule | Detection | Windows Event | MITRE ATT&CK | Severity |
|---|---|---:|---|---|
| 001 | Windows Failed Logon Attempt | 4625 | T1110 | Low |
| 002 | Multiple Windows Failed Logon Attempts | 4625 | T1110 | Medium |
| 003 | PowerShell Encoded Command Execution | 4688 | T1059.001 | Medium |

> Severity represents the current detection design and is not intended to determine whether an observed event is malicious without investigation.

---

# Detection 001 — Windows Failed Logon Attempt

## Objective

Detect Windows authentication failures using **Security Event ID 4625**.

## Detection Concept

Repeated authentication failures can be relevant to credential-access investigations.

The detection focuses on failed logon telemetry and extracts fields such as:

- Account name
- Account domain
- Source network address
- Logon type
- Host

## Sigma Rule

~~~text
sigma-rules/windows/credential-access/windows-failed-logon.yml
~~~

## Splunk Query

~~~text
splunk-queries/authentication/failed-logon-4625.spl
~~~

The detection query groups failed authentication activity by relevant account and source fields to support investigation.

## Validation

The dataset contained:

- 36 failed-logon events analyzed
- Source IP and account information available for investigation
- Multiple authentication failures identified

The rule was validated against actual Windows Security telemetry.

## MITRE ATT&CK

**T1110 — Brute Force**

The detection provides telemetry relevant to investigating repeated authentication failures and potential credential-access activity.

---

# Detection 002 — Multiple Windows Failed Logons

## Objective

Identify repeated failed authentication attempts occurring within a short time window.

## Detection Logic

The detection groups Event ID 4625 events by source address within a **5-minute window**.

The current threshold is:

~~~text
5 or more failed logon events within 5 minutes
~~~

## Sigma Rule

~~~text
sigma-rules/windows/credential-access/windows-repeated-failed-logons.yml
~~~

## Splunk Query

~~~text
splunk-queries/authentication/repeated-failed-logons-5min.spl
~~~

## Validation Results

The detection identified:

- 3 matching five-minute windows
- Maximum of 10 failed-logon events within a window
- 28 events across the matching windows
- 2 targeted accounts in the observed matching activity

The observed source included:

~~~text
::1
~~~

This represents the IPv6 loopback address and therefore the observed activity was treated as **authentication activity requiring investigation**, rather than automatically classified as a confirmed attack.

## MITRE ATT&CK

**T1110 — Brute Force**

The detection provides a behavioral layer above individual failed authentication events.

---

# Detection 003 — PowerShell Encoded Command Execution

## Objective

Detect PowerShell process creation where the command line contains encoded-command execution indicators.

## Windows Telemetry

The detection uses:

**Event ID 4688 — Process Creation**

Important fields observed during analysis included:

- `New_Process_Name`
- `Process_Command_Line`
- `Creator_Process_Name`
- `Creator_Process_ID`
- `New_Process_ID`
- `Account_Name`
- `Account_Domain`
- `Token_Elevation_Type`
- `Mandatory_Label`
- `Logon_ID`

## Baseline Analysis

The process creation dataset contained:

- **11,956** Event ID 4688 events
- **369** unique process/parent-process combinations
- **2,673** unique process/command-line/parent combinations
- **402** PowerShell-related events
- **31** distinct PowerShell process/command-line combinations

The baseline analysis was important because PowerShell activity was also observed from legitimate administrative and security tooling.

Therefore, the detection does not treat every PowerShell execution as malicious.

---

## Suspicious PowerShell Pattern

The initial search looked for command-line indicators such as:

~~~text
-EncodedCommand
-enc
DownloadString
IEX
Invoke-Expression
~~~

The initial baseline returned:

~~~text
0 matching events
~~~

This established a clean baseline before performing the controlled validation.

---

## Controlled Validation

A harmless PowerShell encoded-command test was executed on the Windows client.

The test generated:

- Event ID 4688
- `powershell.exe`
- Account: `alice`
- Host: `WIN10-CLIENT`
- Command line containing `-EncodedCommand`

The resulting event was successfully collected by Splunk and detected by the final SPL query.

## Detection Result

~~~text
1 controlled test event
1 detected event
100% controlled-test detection
~~~

The test payload was benign and was used only to validate detection telemetry.

---

## Sigma Rule

~~~text
sigma-rules/windows/execution/windows-powershell-encoded-command.yml
~~~

## Splunk Query

~~~text
splunk-queries/process-creation/powershell-encoded-command.spl
~~~

## MITRE ATT&CK

**T1059.001 — Command and Scripting Interpreter: PowerShell**

The detection focuses on PowerShell execution behavior containing encoded-command indicators.

Encoded PowerShell is treated as a suspicious indicator requiring investigation rather than automatically being classified as malicious.

---

# Detection Engineering Metrics

Current project results:

| Metric | Result |
|---|---:|
| Detection Rules | 3 |
| SPL Detection Queries | 3 |
| Validation Reports | 3 |
| MITRE ATT&CK Techniques | 2 |
| Windows Event IDs Analyzed | 2 |
| Failed Logon Events Analyzed | 36 |
| Matching Repeated-Failure Windows | 3 |
| Maximum Failures in Matching Window | 10 |
| Events Across Matching Windows | 28 |
| Process Creation Events Analyzed | 11,956 |
| Unique Process/Parent Combinations | 369 |
| Unique Process/Command-Line/Parent Combinations | 2,673 |
| PowerShell Events Analyzed | 402 |
| PowerShell Process/Command-Line Combinations | 31 |
| Controlled Encoded PowerShell Tests | 1 |
| Controlled Test Events Detected | 1 |

---

# MITRE ATT&CK Coverage

Current detection coverage includes:

| Technique | Name | Detection |
|---|---|---|
| T1110 | Brute Force | Failed logon detections |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Encoded PowerShell detection |

MITRE coverage documentation is maintained in:

~~~text
mitre-coverage/
~~~

---

# Repository Structure

~~~text
Project-04-Detection-Engineering-Lab/
│
├── docs/
│   ├── Day01.md
│   ├── Day02.md
│   ├── Day03.md
│   └── Day04.md
│
├── mitre-coverage/
│   ├── day03-authentication-detections.md
│   └── day04-process-creation-detection.md
│
├── sigma-rules/
│   └── windows/
│       ├── credential-access/
│       │   ├── windows-failed-logon.yml
│       │   └── windows-repeated-failed-logons.yml
│       │
│       └── execution/
│           └── windows-powershell-encoded-command.yml
│
├── splunk-queries/
│   ├── authentication/
│   │   ├── failed-logon-4625.spl
│   │   └── repeated-failed-logons-5min.spl
│   │
│   └── process-creation/
│       └── powershell-encoded-command.spl
│
├── validation/
│   ├── rule-001-validation.md
│   ├── rule-002-validation.md
│   └── rule-003-validation.md
│
├── screenshots/
│   ├── Day03/
│   └── Day04/
│
├── LICENSE
└── README.md
~~~

---

# Evidence & Documentation

The project maintains evidence for each detection rather than documenting only the final rule.

Evidence includes:

- Splunk searches
- Event analysis
- Baseline results
- Detection results
- Sigma rules
- SPL queries
- Controlled test results
- MITRE ATT&CK mappings
- Validation reports

Daily documentation is available under:

~~~text
docs/
~~~

Validation documentation is available under:

~~~text
validation/
~~~

Detection coverage is available under:

~~~text
mitre-coverage/
~~~

Screenshots and supporting evidence are maintained under:

~~~text
screenshots/
~~~

---

# Skills Demonstrated

## Security Monitoring

- Windows Security Event Log analysis
- Authentication monitoring
- Process creation monitoring
- PowerShell telemetry analysis
- Command-line analysis

## Detection Engineering

- Detection logic development
- Behavioral baselining
- Threshold-based detection
- Pattern-based detection
- False-positive consideration
- Controlled detection validation

## SIEM

- Splunk Cloud
- Splunk SPL
- Event filtering
- Statistical aggregation
- Time-window analysis
- Field-based investigation

## Detection-as-Code

- Sigma
- Structured detection rules
- Detection rule versioning
- Repository-based rule organization

## Threat Detection

- Credential-access monitoring
- Brute-force-related activity detection
- PowerShell execution monitoring
- Encoded PowerShell detection

## Threat Frameworks

- MITRE ATT&CK
- T1110 — Brute Force
- T1059.001 — PowerShell

## Documentation

- Detection validation reports
- Evidence collection
- Technical documentation
- Reproducible investigation workflow
- Quantified detection outcomes

---

# Project Methodology

A key principle of this project is:

~~~text
Do not write a detection first and search for evidence later.

Analyze the telemetry first.
Understand normal behavior.
Establish a baseline.
Define the detection logic.
Validate it.
Then document the result.
~~~

This approach is intended to reflect a practical detection engineering workflow rather than simply creating static SIEM queries.

---

# Project Status

| Component | Status |
|---|---|
| Splunk Cloud Environment | Completed |
| Windows Log Collection | Completed |
| Windows Authentication Analysis | Completed |
| Failed Logon Detection | Completed |
| Repeated Failed Logon Detection | Completed |
| Process Creation Analysis | Completed |
| PowerShell Analysis | Completed |
| Encoded PowerShell Detection | Completed |
| Sigma Rules | Completed for current detections |
| SPL Queries | Completed for current detections |
| Validation Reports | Completed for current detections |
| MITRE ATT&CK Mapping | Completed for current detections |
| Evidence Documentation | Completed through Day 04 |
| Detection Engineering Lab | In Progress |

---

# Portfolio Value

This project demonstrates practical experience with a complete detection engineering lifecycle:

~~~text
Telemetry
   ↓
Analysis
   ↓
Baseline
   ↓
Detection Development
   ↓
Sigma
   ↓
SPL
   ↓
Validation
   ↓
MITRE ATT&CK
   ↓
Evidence
   ↓
Documentation
~~~

The project is designed to demonstrate skills relevant to entry-level:

- SOC Analyst
- SOC Analyst L1
- Security Operations
- Blue Team
- Detection Engineering
- Security Monitoring
- SIEM Analyst

---

# Author

**Ananthan D**

B.Tech — Information Technology

Cybersecurity | SOC | Blue Team | Detection Engineering

GitHub: `https://github.com/ananthancyber`

---

# License

This project is licensed under the MIT License.

See `LICENSE` for details.