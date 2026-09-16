# Project 04 — Detection Engineering Lab

[![Platform](https://img.shields.io/badge/Platform-Splunk%20Cloud-black?logo=splunk)](https://www.splunk.com/)
[![Endpoint](https://img.shields.io/badge/Endpoint-Windows%2010-blue?logo=windows)](https://www.microsoft.com/windows)
[![Detection Format](https://img.shields.io/badge/Detection-Sigma-orange)](https://sigmahq.io/)
[![Focus](https://img.shields.io/badge/Focus-Detection%20Engineering-red)](https://attack.mitre.org/)
[![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)](https://github.com/ananthancyber)

## Project Overview

This project is a hands-on **Detection Engineering Lab** designed to simulate how security analysts create, test, validate, and improve detections in a Security Information and Event Management system.

The project uses **Windows Security Event Logs**, **Splunk Cloud**, **Splunk Universal Forwarder**, **Sigma rules**, **Splunk Processing Language (SPL)**, and **MITRE ATT&CK mapping** to build a practical detection engineering workflow.

The main objective is to convert security events into meaningful detections that can support Security Operations Center activities such as alert triage, investigation, threat hunting, and incident response.

---

## Project Objectives

- Collect Windows Security Event Logs from a Windows endpoint.
- Forward endpoint telemetry to Splunk Cloud.
- Understand important Windows Security Event IDs.
- Create detection rules using the Sigma format.
- Convert detection logic into Splunk SPL queries.
- Simulate suspicious activities in a controlled lab environment.
- Validate whether detections identify the expected activity.
- Identify and reduce false positives.
- Map detections to MITRE ATT&CK techniques.
- Document the complete detection engineering lifecycle.
- Build a portfolio project that demonstrates practical SOC and blue-team skills.

---

## Detection Engineering Workflow

```text
Attack or Suspicious Activity
            ↓
Windows Security Event Logs
            ↓
Splunk Universal Forwarder
            ↓
Splunk Cloud
            ↓
SPL Search
            ↓
Sigma Detection Rule
            ↓
Validation and Investigation
            ↓
MITRE ATT&CK Mapping
            ↓
Detection Improvement
```

---

## Lab Environment

| Component | Details |
|---|---|
| Host Operating System | Windows 11 |
| Monitored Endpoint | Windows 10 Client VM |
| SIEM Platform | Splunk Cloud |
| Log Collection Agent | Splunk Universal Forwarder 10.4.3 |
| Log Source | Windows Security Event Log |
| Splunk Index | `main` |
| Sourcetype | `WinEventLog:Security` |
| Forwarding Port | `9997` over SSL |
| Detection Format | Sigma |
| Query Language | Splunk Processing Language |
| Framework | MITRE ATT&CK |

---

## Tools and Technologies

- **Splunk Cloud** — Log indexing, searching, investigation, and detection testing
- **Splunk Universal Forwarder** — Endpoint log collection and forwarding
- **Windows 10** — Monitored endpoint
- **PowerShell** — Endpoint verification and security event generation
- **Sigma** — Vendor-neutral detection rule format
- **SPL** — Splunk search and detection queries
- **MITRE ATT&CK** — Adversary behavior and technique mapping
- **Git and GitHub** — Version control and project documentation
- **Visual Studio Code** — Rule development and documentation

---

## Windows Security Events Investigated

### Event ID 4624 — Successful Logon

Event ID `4624` represents a successful account logon.

It can support investigations involving:

- User authentication
- Remote logons
- Suspicious account access
- Possible account compromise
- Lateral movement

Example SPL query:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624
```

---

### Event ID 4625 — Failed Logon

Event ID `4625` represents a failed account logon.

It can support detections involving:

- Brute-force attempts
- Password spraying
- Incorrect password attempts
- Suspicious authentication activity
- Repeated failed access attempts

Example SPL query:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
```

---

### Event ID 4688 — Process Creation

Event ID `4688` represents the creation of a new process.

It can support investigations involving:

- Suspicious command execution
- PowerShell activity
- Script execution
- Malware execution
- Living-off-the-land techniques
- Unusual parent-child process relationships

Example SPL query:

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
```

---

## Project Structure

```text
Project-04-Detection-Engineering-Lab/
│
├── docs/
│   ├── Day01.md
│   ├── Day02.md
│   ├── Day03.md
│   └── ...
│
├── mitre-coverage/
│   ├── attack-mapping.md
│   └── coverage-matrix.csv
│
├── screenshots/
│   ├── Day01/
│   ├── Day02/
│   │   ├── Day02-01-Windows-Version.png
│   │   ├── Day02-02-Windows-Event-Log-Service.png
│   │   ├── Day02-03-Windows-Firewall-Status.png
│   │   ├── Day02-04-Administrator-Access.png
│   │   ├── Day02-05-Windows-Host-Network-Info.png
│   │   ├── Day02-06-Network-Connectivity.png
│   │   ├── Day02-07-Universal-Forwarder-Installed.png
│   │   ├── Day02-08-HEC-Token-Created.png
│   │   ├── Day02-09-Windows-Security-Logs-in-Splunk.png
│   │   ├── Day02-10-Failed-Logon-Event-4625.png
│   │   ├── Day02-11-Successful-Logon-Events-4624.png
│   │   └── Day02-12-Process-Creation-Events-4688.png
│   └── ...
│
├── sigma-rules/
│   ├── windows/
│   │   ├── credential-access/
│   │   ├── persistence/
│   │   ├── lateral-movement/
│   │   └── execution/
│   └── README.md
│
├── splunk-queries/
│   ├── authentication/
│   ├── process-creation/
│   └── README.md
│
├── validation/
│   ├── rule-001-validation.md
│   ├── rule-002-validation.md
│   └── false-positive-analysis.md
│
├── LICENSE
└── README.md
```

> Additional files and folders will be added as the project progresses.

---

## Work Completed

### Day 01 — Project and SIEM Preparation

- Created the project repository.
- Prepared the project folder structure.
- Prepared the Splunk Cloud environment.
- Reviewed the purpose of Splunk Cloud and Universal Forwarder.
- Established the initial detection engineering workflow.

Documentation:

- [Day 01 Documentation](docs/Day01.md)

---

### Day 02 — Windows Security Log Ingestion and Validation

- Verified the Windows endpoint.
- Verified the Windows Event Log service.
- Verified Windows Firewall status.
- Verified administrator access.
- Verified network connectivity.
- Verified Splunk Universal Forwarder installation.
- Installed the Splunk Cloud credentials package.
- Verified the active forwarding destination.
- Confirmed Windows Security logs were indexed in Splunk Cloud.
- Tested Event IDs `4624`, `4625`, and `4688`.
- Captured technical evidence.
- Documented the completed work.

Documentation:

- [Day 02 Documentation](docs/Day02.md)

Evidence:

- [Day 02 Screenshots](screenshots/Day02/)

---

## Evidence and Validation

The project includes screenshots and documentation showing:

- Windows endpoint preparation
- Splunk Universal Forwarder installation
- Universal Forwarder service status
- Splunk Cloud configuration
- Windows Security log ingestion
- Successful logon events
- Failed logon events
- Process creation events
- SPL search results
- Detection rule testing
- Validation results

Evidence is organized by project day to make the workflow easy to review.

---

## Planned Detection Scenarios

The following detection scenarios are planned for the upcoming project stages:

| Detection Scenario | Relevant Data | Planned Status |
|---|---|---|
| Repeated failed logons | Event ID `4625` | Planned |
| Suspicious successful logon after failures | Event IDs `4625` and `4624` | Planned |
| Suspicious process creation | Event ID `4688` | Planned |
| Suspicious PowerShell execution | Process creation logs | Planned |
| Potential lateral movement | Logon and process events | Planned |
| Persistence-related activity | Windows security telemetry | Planned |
| False-positive analysis | Detection results | Planned |
| MITRE ATT&CK mapping | Detection techniques | Planned |

---

## Detection Rule Development Methodology

Each detection will follow the same development process:

```text
1. Understand the attack behavior
2. Identify the required Windows event logs
3. Identify relevant fields and Event IDs
4. Write the Sigma rule
5. Create the matching SPL query
6. Simulate or identify the activity
7. Execute the SPL query in Splunk
8. Verify the result
9. Review false positives
10. Improve the detection
11. Map the detection to MITRE ATT&CK
12. Document the evidence
```

---

## Example Sigma Rule Format

A future detection rule will follow the Sigma structure below:

```yaml
title: Example Windows Security Detection
id: example-detection-id
status: experimental
description: Detects a suspicious Windows security event.
author: Ananthan D
date: 2026/09/16
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
falsepositives:
  - Legitimate user authentication failures
level: medium
tags:
  - attack.credential_access
```

> This is an example structure for learning and documentation. Production rules will be created and validated during the project.

---

## Example SPL Query Format

A future detection query will be stored in the `splunk-queries/` folder.

Example:

```spl
index=main
sourcetype="WinEventLog:Security"
EventCode=4625
| stats count by Account_Name, src, host
| sort - count
```

The query will be tested and refined based on the available fields and actual event data.

---

## MITRE ATT&CK Integration

The project will map relevant detections to MITRE ATT&CK techniques.

Potential technique areas include:

- Credential Access
- Discovery
- Execution
- Persistence
- Lateral Movement
- Defense Evasion

The mapping will be based on the behavior detected by each rule and will be documented in:

```text
mitre-coverage/attack-mapping.md
```

---

## Skills Demonstrated

This project demonstrates practical experience in:

- SIEM log ingestion
- Windows Security Event Log analysis
- Splunk Cloud
- Splunk Universal Forwarder
- SPL query development
- Sigma rule creation
- Detection engineering
- Security event investigation
- Authentication monitoring
- Process monitoring
- Threat detection
- False-positive analysis
- MITRE ATT&CK mapping
- Technical documentation
- Git and GitHub version control
- SOC analyst workflow

---

## Troubleshooting Experience

### Universal Forwarder Had No Active Forward

Initially, the Universal Forwarder showed no active forwarding destination.

The issue was resolved by installing the Splunk Cloud credentials package and restarting the Universal Forwarder service.

### Splunk Cloud Credentials Package Was Not Found in Downloads

The `.spl` package was not available in the normal Downloads folder.

The file was located in the Universal Forwarder application directory:

```text
C:\Program Files\SplunkUniversalForwarder\etc\apps\splunkcloud\splunkclouduf.spl
```

The package was installed from its actual location.

---

## Current Project Status

```text
Project Status: In Progress

Completed:
- Project structure
- Splunk Cloud preparation
- Windows endpoint preparation
- Universal Forwarder installation
- Splunk Cloud forwarding configuration
- Windows Security log ingestion
- Initial SPL validation
- Day 01 documentation
- Day 02 documentation
- Evidence collection
```

Upcoming:

```text
- Create the first Sigma detection rule
- Create matching SPL queries
- Test detection logic
- Validate detection results
- Analyze false positives
- Map detections to MITRE ATT&CK
- Complete final documentation
```

---

## Portfolio Value

This project demonstrates the ability to work beyond basic tool installation by showing the complete process of:

```text
Collecting Logs
      ↓
Understanding Security Events
      ↓
Writing Detection Logic
      ↓
Testing in a SIEM
      ↓
Validating Results
      ↓
Improving Detections
      ↓
Documenting Findings
```

This workflow reflects important responsibilities commonly associated with:

- SOC Analyst
- SOC Analyst L1
- Blue Team Analyst
- Detection Engineering Intern
- Cybersecurity Intern
- Security Monitoring Analyst

---

## Author

**Ananthan D**

B.Tech Information Technology Graduate  
Cybersecurity and SOC Analyst Aspirant

### Profiles

- GitHub: [ananthancyber](https://github.com/ananthancyber)
- LinkedIn: [Ananthan D](https://www.linkedin.com/in/ananthan-d-ab295321b)

---

## Disclaimer

This project was created for educational and portfolio purposes in a controlled lab environment.

All testing activities are performed only on authorized systems and isolated virtual machines. No unauthorized systems, networks, or accounts are targeted.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.