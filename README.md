# 🛡️ Detection Engineering Lab

**Splunk Cloud · Sigma · SPL · Windows Security Logs · Splunk Universal Forwarder · MITRE ATT&CK**

A hands-on **SOC-focused detection engineering laboratory** built to demonstrate the complete lifecycle of developing, validating, documenting, and organizing security detections using real Windows telemetry.

The project focuses on moving beyond simple log searching by applying a practical detection engineering workflow:

**Telemetry → Baseline → Behavioral Analysis → Detection Logic → Controlled Validation → Sigma → MITRE ATT&CK → Evidence → Documentation**

---

## 🎯 Project Overview

This project simulates a practical detection engineering workflow using a Windows 10 endpoint and Splunk Cloud.

The lab collects Windows Security Event Logs through the **Splunk Universal Forwarder**, analyzes security-relevant activity in Splunk, develops detection logic using **SPL and Sigma**, validates detections through controlled lab activity, and maps the resulting detections to **MITRE ATT&CK**.

The project is designed from a **SOC analyst and detection engineer perspective**, with emphasis on:

- Understanding available telemetry before writing detections
- Establishing behavioral baselines
- Identifying suspicious or security-relevant patterns
- Developing focused detection logic
- Reducing unnecessary detection noise
- Validating detections using controlled activity
- Creating reusable Sigma rules
- Mapping detections to MITRE ATT&CK
- Maintaining evidence for every major detection
- Documenting the complete engineering process

---

## 🏗️ Lab Architecture

~~~text
                         ┌──────────────────────────┐
                         │      Windows 10          │
                         │       WIN10-CLIENT        │
                         │                          │
                         │  Windows Security Logs   │
                         │  Authentication Events   │
                         │  Process Creation        │
                         │  Persistence Events      │
                         │  Discovery Events        │
                         └────────────┬─────────────┘
                                      │
                                      │ Splunk Universal
                                      │ Forwarder
                                      ▼
                         ┌──────────────────────────┐
                         │       Splunk Cloud        │
                         │                          │
                         │  Windows Security Logs   │
                         │  SPL Investigation       │
                         │  Detection Queries       │
                         │  Validation              │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                         ┌──────────────────────────┐
                         │    Detection Engineering │
                         │                          │
                         │  SPL Detection            │
                         │  Sigma Rules              │
                         │  MITRE ATT&CK             │
                         │  Validation Reports       │
                         │  Evidence                  │
                         └──────────────────────────┘
~~~

---

# 🔍 Detection Engineering Methodology

Each detection follows a repeatable workflow.

~~~text
1. Telemetry Assessment
          ↓
2. Event Identification
          ↓
3. Baseline Development
          ↓
4. Behavioral Analysis
          ↓
5. Detection Scenario Selection
          ↓
6. Controlled Security Activity
          ↓
7. Event Validation
          ↓
8. SPL Detection
          ↓
9. Sigma Rule
          ↓
10. MITRE ATT&CK Mapping
          ↓
11. Evidence Collection
          ↓
12. Validation Documentation
~~~

This methodology ensures that detections are based on **observed and validated telemetry**, rather than assumptions about what the environment should contain.

---

# 🧪 Detection Coverage

The project currently contains **7 primary numbered detection rules** covering multiple security behaviors.

| Rule | Day | Detection | Windows Telemetry | Security Area |
|---|---:|---|---|---|
| Rule 001 | 03 | Windows Failed Logon | Event ID 4625 | Credential Access |
| Rule 002 | 03 | Repeated Failed Logons | Event ID 4625 | Credential Access |
| Rule 003 | 04 | PowerShell Encoded Command | Event ID 4688 | Execution |
| Rule 004 | 05 | Scheduled Task Creation | Event ID 4698 | Persistence |
| Rule 005 | 06 | Failed-to-Successful Network Logon Sequence | Events 4624/4625 | Authentication / Lateral Movement |
| Rule 006 | 07 | Local Administrator Group Membership Change | Event ID 4732 | Account / Privilege Activity |
| Rule 007 | 08 | Administrators Group Enumeration via `net1.exe` | Event ID 4799 | Discovery |

The project also contains supporting Sigma rules used as components of the Day 06 network-authentication correlation detection.

---

# 📊 Detection Highlights

## Day 03 — Authentication Detection

Analyzed Windows authentication failures and developed detections for:

- Individual failed logons
- Repeated failed logon activity
- Failed authentication patterns over time

### Key telemetry

~~~text
Event ID 4625
~~~

### Detection focus

**Credential Access / Brute Force behavior**

---

## Day 04 — Process Creation & PowerShell Detection

Analyzed Windows process creation telemetry and established a process-command-line baseline.

A controlled PowerShell encoded-command test was performed to validate detection of:

~~~text
PowerShell
+
EncodedCommand
+
Process Creation Event 4688
~~~

### Key telemetry

~~~text
Event ID 4688
~~~

### MITRE ATT&CK

~~~text
T1059.001 — PowerShell
~~~

---

## Day 05 — Scheduled Task Persistence Detection

Telemetry assessment showed that the initially considered registry-based persistence scenario did not have sufficient validated telemetry in the environment.

The detection scenario was therefore changed to **Scheduled Task Creation**, demonstrating telemetry-driven detection engineering.

### Key telemetry

~~~text
Event ID 4698
~~~

A controlled scheduled task was created and successfully detected.

### Detection result

~~~text
1 controlled scheduled task
        ↓
1 Event ID 4698
        ↓
1 detection
        ↓
100% controlled validation
~~~

### MITRE ATT&CK

~~~text
T1053.005 — Scheduled Task/Job: Scheduled Task
~~~

---

## Day 06 — Network Authentication Detection

Analyzed Windows network authentication using:

~~~text
Event ID 4624
Event ID 4625
Logon Type 3
~~~

The detection focused on a sequence where failed network authentication was followed by successful network authentication.

The investigation included:

- Network logon baseline
- Remote authentication analysis
- Source IP analysis
- Authentication correlation
- Failed-to-successful authentication sequencing

This detection demonstrates correlation-based analysis rather than relying on a single Windows event.

---

## Day 07 — Account & Privilege Activity Detection

Focused on local security group membership changes using:

~~~text
Event ID 4732
~~~

A controlled test account was added to the local `Administrators` group.

The generated Event 4732 was correlated with the test account's Security Identifier (SID).

### Detection chain

~~~text
D7TestUser
      ↓
Added to Administrators
      ↓
Event ID 4732
      ↓
Member SID identified
      ↓
SID correlated with test account
      ↓
SPL Detection
      ↓
Sigma Rule 006
~~~

### MITRE ATT&CK

~~~text
T1098.007 — Account Manipulation: Additional Local or Domain Groups
~~~

---

## Day 08 — Windows Discovery Detection

Day 08 focused on local permission-group discovery.

Initial telemetry analysis identified:

~~~text
Event ID 4798 → 427 events
Event ID 4799 → 592 events
Total         → 1,019 events
~~~

Process-level analysis demonstrated that many events were generated by legitimate Windows services and security tooling.

Examples included:

- `wazuh-agent.exe`
- `svchost.exe`
- `VSSVC.exe`
- `WmiPrvSE.exe`
- `SearchIndexer.exe`
- `consent.exe`

Rather than detecting every Event 4799, the detection was narrowed to:

~~~text
Event ID 4799
        +
Administrators
        +
net1.exe
~~~

A controlled test using:

~~~powershell
net user

net localgroup

net localgroup Administrators
~~~

successfully generated Event ID 4799 for the local `Administrators` group.

### Rule 007 Result

~~~text
1 controlled discovery event
        ↓
1 matching SPL detection
        ↓
100% controlled validation
~~~

### MITRE ATT&CK

~~~text
T1069.001 — Permission Groups Discovery: Local Groups
~~~

---

# 📈 Project Metrics

The lab emphasizes measurable detection outcomes rather than simply listing tools used.

Current documented outcomes include:

| Metric | Result |
|---|---:|
| Primary numbered detection rules | **7** |
| Day 03 failed-logon events analyzed | **36** |
| Day 03 matching failed-logon windows | **3** |
| Day 04 Event 4688 baseline | **11,956+** |
| Day 04 PowerShell events analyzed | **402** |
| Day 05 scheduled-task baseline events | **2** |
| Day 05 controlled scheduled-task detections | **1 / 1** |
| Day 06 successful network logons analyzed | **1,150** |
| Day 06 Logon Type 3 events | **59** |
| Day 06 matching authentication sequences | **2** |
| Day 07 Event 4732 baseline events | **2** |
| Day 07 controlled privileged-group detection | **1 / 1** |
| Day 08 Event 4798 baseline | **427** |
| Day 08 Event 4799 baseline | **592** |
| Day 08 combined discovery events | **1,019** |
| Day 08 controlled discovery detections | **1 / 1** |

> Detection validation percentages represent controlled lab validation results and should not be interpreted as production detection accuracy.

---

# 🧰 Technology Stack

### SIEM & Detection

- **Splunk Cloud**
- **Splunk Processing Language (SPL)**
- **Sigma**

### Endpoint & Telemetry

- **Windows 10**
- **Windows Security Event Log**
- **Splunk Universal Forwarder**

### Security Framework

- **MITRE ATT&CK**

### Documentation & Development

- Markdown
- YAML
- Git
- GitHub
- Visual Studio Code

---

# 📂 Repository Structure

~~~text
Project-04-Detection-Engineering-Lab/
│
├── docs/
│   ├── Day03.md
│   ├── Day04.md
│   ├── Day05.md
│   ├── Day06.md
│   ├── Day07.md
│   └── Day08.md
│
├── mitre-coverage/
│   ├── day03-authentication-detections.md
│   ├── day04-process-creation-detection.md
│   ├── day05-scheduled-task-detection.md
│   ├── day06-network-authentication-detection.md
│   ├── day07-account-privilege-detection.md
│   └── day08-windows-discovery-detection.md
│
├── screenshots/
│   ├── Day03/
│   ├── Day04/
│   ├── Day05/
│   ├── Day06/
│   ├── Day07/
│   └── Day08/
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
│   ├── discovery/
│   ├── persistence/
│   └── process-creation/
│
├── validation/
│   ├── rule-001-validation.md
│   ├── rule-002-validation.md
│   ├── rule-003-validation.md
│   ├── rule-004-validation.md
│   ├── rule-005-validation.md
│   ├── rule-006-validation.md
│   └── rule-007-validation.md
│
├── LICENSE
└── README.md
~~~

---

# 📁 Evidence Strategy

Every major detection is supported by technical evidence.

Evidence includes:

- Splunk search results
- Windows event analysis
- Raw event data
- Field extraction
- Baseline analysis
- Controlled security activity
- Detection results
- Sigma rule implementation
- Validation results

Evidence is organized by project day:

~~~text
screenshots/
├── Day03/
├── Day04/
├── Day05/
├── Day06/
├── Day07/
└── Day08/
~~~

This provides a traceable relationship between:

~~~text
Detection
   ↓
SPL
   ↓
Windows Telemetry
   ↓
Validation
   ↓
Screenshot Evidence
   ↓
Documentation
~~~

---

# 🧩 Detection Development Examples

## Failed Logon Detection

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
~~~

Used as the foundation for failed authentication analysis.

---

## Process Creation Detection

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
~~~

Used to investigate process creation and PowerShell command-line activity.

---

## Scheduled Task Detection

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4698
~~~

Used to detect Windows scheduled task creation.

---

## Administrators Group Membership Change

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
~~~

Used to identify local security group membership changes involving the Administrators group.

---

## Administrators Group Enumeration

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4799
| rex field=_raw "Account Name:\s+(?<SubjectAccount>[^\r\n]+)"
| rex field=_raw "Group Name:\s+(?<GroupName>[^\r\n]+)"
| rex field=_raw "Group Domain:\s+(?<GroupDomain>[^\r\n]+)"
| rex field=_raw "Process Name:\s+(?<ProcessName>[^\r\n]+)"
| search ProcessName="*net1.exe" GroupName="Administrators"
| eval Detection="Administrators Group Enumeration via net1.exe"
| table _time host SubjectAccount GroupName GroupDomain ProcessName EventCode Detection
| sort - _time
~~~

---

# 🗺️ MITRE ATT&CK Coverage

The project maps detection scenarios to relevant MITRE ATT&CK behaviors.

| Technique | Detection Area |
|---|---|
| T1110 | Failed authentication / brute-force-related activity |
| T1059.001 | PowerShell execution |
| T1053.005 | Scheduled Task persistence |
| T1021 | Network authentication / lateral movement context |
| T1098.007 | Additional local/domain group membership |
| T1069.001 | Local permission-group discovery |

The mappings are documented individually within:

~~~text
mitre-coverage/
~~~

Each mapping connects the observed behavior with:

- Windows telemetry
- Detection logic
- Validation evidence
- SPL implementation
- Sigma implementation
- SOC investigation context

---

# 🔬 Detection Validation Philosophy

A detection is not considered complete simply because a query returns results.

The project uses controlled validation wherever practical.

The validation process includes:

### 1. Baseline

Understand normal telemetry volume and behavior.

### 2. Scenario Selection

Select a detection scenario supported by available telemetry.

### 3. Controlled Activity

Generate known security-relevant activity in the isolated lab.

### 4. Telemetry Verification

Confirm the Windows Security event is generated and ingested.

### 5. Detection Verification

Run the final SPL detection against the telemetry.

### 6. Sigma Implementation

Represent the detection using Sigma.

### 7. Evidence

Capture screenshots and preserve the validation trail.

### 8. Documentation

Record the complete process in the repository.

---

# 🎯 SOC Skills Demonstrated

This project demonstrates practical skills relevant to entry-level SOC and detection engineering roles.

### SIEM

- Splunk Cloud
- SPL
- Windows Security Log analysis
- Event filtering
- Statistical analysis
- Event correlation
- Detection query development

### Detection Engineering

- Detection lifecycle
- Telemetry assessment
- Baseline development
- Detection tuning
- Process-based detection
- Correlation logic
- False-positive analysis
- Controlled validation

### Windows Security

- Authentication monitoring
- Failed logon analysis
- Process creation monitoring
- PowerShell monitoring
- Scheduled task monitoring
- Group membership monitoring
- Privilege activity analysis
- Local group discovery

### Threat Detection

- Credential access detection
- Execution detection
- Persistence detection
- Authentication analysis
- Account manipulation detection
- Discovery detection

### Threat Framework

- MITRE ATT&CK
- Technique mapping
- Detection coverage analysis

### Documentation

- Technical documentation
- Detection validation reports
- Evidence management
- Markdown
- YAML
- Git/GitHub workflow

---

# 👨‍💻 Project Learning Outcomes

Through this project, I practiced how to:

- Start with telemetry instead of assumptions
- Understand Windows Security Event IDs
- Establish behavioral baselines
- Identify legitimate background activity
- Develop focused detection logic
- Reduce unnecessary detection noise
- Correlate security events
- Extract useful fields from raw Windows events
- Write SPL detections
- Develop Sigma rules
- Validate detections using controlled activity
- Map detections to MITRE ATT&CK
- Document detection engineering decisions
- Preserve evidence for technical review
- Present detection work in a recruiter-readable format

---

# 📸 Evidence & Documentation

The project contains detailed technical documentation for each completed day.

### Day 03 — Authentication Detection

~~~text
docs/Day03.md
validation/rule-001-validation.md
validation/rule-002-validation.md
mitre-coverage/day03-authentication-detections.md
screenshots/Day03/
~~~

### Day 04 — Process Creation Detection

~~~text
docs/Day04.md
validation/rule-003-validation.md
mitre-coverage/day04-process-creation-detection.md
screenshots/Day04/
~~~

### Day 05 — Scheduled Task Detection

~~~text
docs/Day05.md
validation/rule-004-validation.md
mitre-coverage/day05-scheduled-task-detection.md
screenshots/Day05/
~~~

### Day 06 — Network Authentication Detection

~~~text
docs/Day06.md
validation/rule-005-validation.md
mitre-coverage/day06-network-authentication-detection.md
screenshots/Day06/
~~~

### Day 07 — Account & Privilege Activity

~~~text
docs/Day07.md
validation/rule-006-validation.md
mitre-coverage/day07-account-privilege-detection.md
screenshots/Day07/
~~~

### Day 08 — Windows Discovery Detection

~~~text
docs/Day08.md
validation/rule-007-validation.md
mitre-coverage/day08-windows-discovery-detection.md
screenshots/Day08/
~~~

---

# 💼 Portfolio Relevance

This project demonstrates practical experience with a workflow similar to the work performed by SOC and detection engineering teams:

~~~text
Collect
  ↓
Investigate
  ↓
Baseline
  ↓
Detect
  ↓
Validate
  ↓
Tune
  ↓
Map
  ↓
Document
~~~

Rather than presenting only screenshots or isolated queries, the repository preserves the **reasoning, implementation, validation, and evidence behind each detection**.

This makes the project suitable for demonstrating practical knowledge during:

- SOC Analyst interviews
- Cybersecurity internship applications
- Blue Team interviews
- Detection Engineering discussions
- SIEM-focused technical interviews

---

# 🚀 Current Project Status

~~~text
Day 01  — Lab & Splunk Setup                  ✅
Day 02  — Windows Telemetry & Ingestion       ✅
Day 03  — Authentication Detection            ✅
Day 04  — Process Creation Detection          ✅
Day 05  — Scheduled Task Detection            ✅
Day 06  — Network Authentication Detection   ✅
Day 07  — Account & Privilege Detection       ✅
Day 08  — Windows Discovery Detection         ✅
Day 09  — Advanced Detection Correlation      ⏳
Day 10  — SOC Investigation Workflow           ⏳
Day 11  — MITRE Coverage & Quality Review      ⏳
Day 12  — Final Validation & Portfolio Polish  ⏳
~~~

---

# 📌 Project Status

**Current Status:** Active Development

**Completed:** Days 01–08

**Primary Detection Rules:** 7

**Detection Format:** Sigma + SPL

**SIEM:** Splunk Cloud

**Endpoint:** Windows 10

**Framework:** MITRE ATT&CK

**Repository:** `Project-04-Detection-Engineering-Lab`

---

# 👤 Author

**Ananthan D**

B.Tech Information Technology Graduate  
Aspiring SOC Analyst | Blue Team | Detection Engineering

### Areas of Interest

- SOC Operations
- Detection Engineering
- SIEM
- Threat Detection
- Windows Security
- Blue Team Operations
- Incident Investigation
- MITRE ATT&CK

---

# 📜 License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for details.

---

# ⭐ Project Summary

This Detection Engineering Lab demonstrates a practical approach to building security detections from real Windows telemetry.

The project combines:

**Splunk Cloud + Windows Security Logs + SPL + Sigma + MITRE ATT&CK + Controlled Validation + Technical Evidence**

with a focus on developing detections that are:

- Evidence-driven
- Testable
- Documented
- Reproducible
- Context-aware
- Relevant to SOC operations

**The goal is not simply to create alerts, but to understand the telemetry, build the detection, validate the behavior, document the evidence, and explain how the detection would support a real SOC investigation.**