# MITRE ATT&CK Coverage — Windows Scheduled Task Detection

## Detection Overview

| Field | Details |
|---|---|
| Detection | Windows Scheduled Task Creation |
| Rule | Rule 004 |
| Windows Event | 4698 — A scheduled task was created |
| MITRE ATT&CK | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Detection Category | Persistence / Scheduled Task |
| SIEM | Splunk Cloud |
| Detection Format | Sigma + Splunk SPL |
| Validation | Controlled Test |
| Validation Result | **PASS** |

---

## 1. MITRE ATT&CK Technique

### T1053.005 — Scheduled Task/Job: Scheduled Task

Windows scheduled tasks can be used to automatically execute programs or commands at defined times or system events.

From a defensive perspective, scheduled-task creation is useful security telemetry because newly created tasks can provide visibility into:

- Persistence activity
- Automated execution
- Administrative changes
- Software deployment
- Operating-system maintenance
- Potential attacker-created tasks

This detection monitors **Windows Security Event ID 4698**, which records the creation of a scheduled task.

---

## 2. Detection Objective

The objective of Rule 004 is to identify Windows scheduled-task creation events and provide analysts with sufficient context to investigate the activity.

The detection focuses on:

- Event ID 4698
- Creating host
- Creating account
- Scheduled task name
- Event message
- Raw task configuration

The detection does **not** automatically classify every scheduled-task creation as malicious.

Instead, it provides an investigation signal that can be correlated with additional endpoint and account context.

---

## 3. Detection Architecture

The validated telemetry flow was:

~~~text
Windows 10 Client
      │
      │ Scheduled Task Created
      ↓
Windows Security Event ID 4698
      │
      ↓
Windows Security Log
      │
      ↓
Splunk Universal Forwarder
      │
      ↓
Splunk Cloud
      │
      ↓
SPL Detection
      │
      ↓
Scheduled Task Identified
~~~

The complete telemetry path was successfully validated using a controlled scheduled-task creation.

---

## 4. Windows Telemetry

The relevant Windows Security event was:

~~~text
Event ID: 4698
Message: A scheduled task was created.
Task Category: Other Object Access Events
Keywords: Audit Success
~~~

Observed telemetry included:

| Field | Observed Information |
|---|---|
| EventCode | 4698 |
| Host | WIN10-CLIENT |
| Account | Administrator |
| Task Name | `\DetectionEngineering-Day05-Test` |
| Message | A scheduled task was created |
| Task Content | XML configuration available in raw event |

The task name and task configuration were confirmed within the raw event.

### Evidence

![Scheduled Task Event 4698](../screenshots/Day05/Day05-08-Scheduled-Task-Event-4698.png)

---

## 5. Audit Configuration

Before validation, the required Windows audit subcategory was checked.

Initial state:

~~~text
Other Object Access Events    No Auditing
~~~

The audit policy was enabled for successful events.

Final state:

~~~text
Other Object Access Events    Success
~~~

This allowed Windows to generate Event ID 4698 when the controlled scheduled task was created.

### Evidence

![Scheduled Task Audit Policy Enabled](../screenshots/Day05/Day05-06-Scheduled-Task-Audit-Policy-Enabled.png)

---

## 6. Controlled Validation

A benign scheduled task was created specifically to validate the detection:

~~~text
\DetectionEngineering-Day05-Test
~~~

The task was configured as a one-time scheduled task.

The purpose of the test was to generate known Windows telemetry and verify the complete detection pipeline.

### Evidence

![Controlled Scheduled Task Creation](../screenshots/Day05/Day05-07-Scheduled-Task-Creation-Test.png)

---

## 7. Event Analysis

The resulting Event ID 4698 event was inspected in Splunk.

The event contained:

- Host information
- Account information
- Event ID
- Scheduled task information
- Task XML content
- Security auditing metadata

The raw event confirmed that the task information was available even when some fields were not automatically extracted.

### Evidence

![Scheduled Task Event Details](../screenshots/Day05/Day05-09-Scheduled-Task-Event-Details.png)

![Scheduled Task Raw Event](../screenshots/Day05/Day05-10-Scheduled-Task-Raw-Event.png)

---

## 8. Scheduled Task Baseline

A baseline analysis was performed against Event ID 4698.

The observed dataset contained:

**2 scheduled-task creation events**

| Host | Account | Count |
|---|---|---:|
| WIN10-CLIENT | Administrator | 1 |
| WIN10-CLIENT | WIN10-CLIENT$ | 1 |

Observed task names included:

~~~text
\DetectionEngineering-Day05-Test

\Microsoft\Windows\UpdateOrchestrator\MusUx_LogonUpdateResults
~~~

The second task represents legitimate Windows operating-system activity.

This baseline demonstrates why Event ID 4698 should be treated as an investigation signal rather than automatically classified as malicious.

### Evidence

![Scheduled Task Baseline](../screenshots/Day05/Day05-11-Scheduled-Task-Baseline.png)

---

## 9. Task Name Extraction

The task name was extracted from the raw Windows event using SPL.

~~~spl
| rex field=_raw "Task Name:\s+(?<ScheduledTaskName>[^\r\n]+)"
~~~

The extraction successfully identified the observed scheduled-task names.

This provided a more useful investigation field for the final detection query.

### Evidence

![Scheduled Task Name Extraction](../screenshots/Day05/Day05-12-Scheduled-Task-Name-Extraction.png)

---

## 10. Sigma Detection

The corresponding Sigma rule is:

~~~text
sigma-rules/windows/persistence/windows-scheduled-task-created.yml
~~~

The rule detects:

~~~text
EventID: 4698
~~~

The detection is mapped to:

~~~text
attack.persistence
attack.t1053.005
~~~

The Sigma rule is intentionally broad at the event level because scheduled-task creation can be both legitimate and security-relevant.

---

## 11. Splunk Detection

The corresponding SPL query is:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4698
| rex field=_raw "Task Name:\s+(?<ScheduledTaskName>[^\r\n]+)"
| table _time host Account_Name ScheduledTaskName EventCode Message
| sort - _time
~~~

The query:

1. Searches Windows Security Event ID 4698.
2. Extracts the scheduled task name from the raw event.
3. Displays investigation-relevant fields.
4. Sorts results by event time.

### Evidence

![Scheduled Task Detection Results](../screenshots/Day05/Day05-13-Scheduled-Task-Detection-Results.png)

---

## 12. Controlled Detection Result

A focused search was performed against:

~~~text
\DetectionEngineering-Day05-Test
~~~

The search returned:

**1 matching Event ID 4698 event**

Observed values:

| Field | Result |
|---|---|
| Host | WIN10-CLIENT |
| Account | Administrator |
| Scheduled Task | `\DetectionEngineering-Day05-Test` |
| Event ID | 4698 |
| Message | A scheduled task was created |

### Evidence

![Controlled Scheduled Task Detection](../screenshots/Day05/Day05-14-Controlled-Scheduled-Task-Detection.png)

---

## 13. Quantified Detection Outcome

The controlled validation produced:

~~~text
1 controlled scheduled task
        ↓
1 Event ID 4698
        ↓
1 Splunk detection match
~~~

| Metric | Result |
|---|---:|
| Controlled tasks created | 1 |
| Expected Event ID | 4698 |
| Matching Event 4698 events | 1 |
| Detection matches | 1 |
| Controlled-test detection rate | **100%** |
| Baseline Event 4698 events | 2 |

### Validation Result

**PASS**

The controlled scheduled-task creation was successfully observed, forwarded to Splunk, extracted, and identified by the detection query.

---

## 14. False-Positive Context

Scheduled-task creation can be generated by legitimate system and administrative activity.

Observed legitimate activity included:

~~~text
\Microsoft\Windows\UpdateOrchestrator\MusUx_LogonUpdateResults
~~~

Potential legitimate sources include:

- Windows Update
- Operating-system components
- Enterprise software
- Security software
- Software deployment systems
- Administrative automation
- IT management tools

Therefore, an analyst should investigate the surrounding context before determining whether a scheduled-task creation event represents suspicious activity.

Useful investigation fields include:

- Task name
- Creating account
- Host
- Task XML
- Configured executable or command
- Creation timestamp
- Parent process
- Related authentication activity

---

## 15. Detection-to-ATT&CK Mapping

| Detection | Windows Event | MITRE Technique | Tactic |
|---|---:|---|---|
| Windows Scheduled Task Created | 4698 | T1053.005 — Scheduled Task/Job: Scheduled Task | Persistence |

### Coverage Statement

Rule 004 provides telemetry coverage for **Windows scheduled-task creation**, supporting investigations into potential scheduled-task-based persistence and automated execution.

The detection identifies the creation event; additional endpoint and contextual analysis is required to determine the intent and significance of the task.

---

## 16. Evidence Register

| Evidence | Purpose |
|---|---|
| [Day05-06 — Scheduled Task Audit Policy Enabled](../screenshots/Day05/Day05-06-Scheduled-Task-Audit-Policy-Enabled.png) | Confirms successful audit configuration |
| [Day05-07 — Scheduled Task Creation Test](../screenshots/Day05/Day05-07-Scheduled-Task-Creation-Test.png) | Shows controlled task creation |
| [Day05-08 — Event 4698](../screenshots/Day05/Day05-08-Scheduled-Task-Event-4698.png) | Confirms Event 4698 reached Splunk |
| [Day05-09 — Event Details](../screenshots/Day05/Day05-09-Scheduled-Task-Event-Details.png) | Shows detailed event telemetry |
| [Day05-10 — Raw Event](../screenshots/Day05/Day05-10-Scheduled-Task-Raw-Event.png) | Confirms task information in raw telemetry |
| [Day05-11 — Baseline](../screenshots/Day05/Day05-11-Scheduled-Task-Baseline.png) | Establishes scheduled-task creation baseline |
| [Day05-12 — Task Name Extraction](../screenshots/Day05/Day05-12-Scheduled-Task-Name-Extraction.png) | Validates task-name extraction |
| [Day05-13 — Detection Results](../screenshots/Day05/Day05-13-Scheduled-Task-Detection-Results.png) | Shows final SPL detection |
| [Day05-14 — Controlled Detection](../screenshots/Day05/Day05-14-Controlled-Scheduled-Task-Detection.png) | Provides focused 1/1 validation evidence |

---

## 17. Repository Artifacts

### Sigma Rule

~~~text
sigma-rules/windows/persistence/windows-scheduled-task-created.yml
~~~

### Splunk Detection

~~~text
splunk-queries/persistence/scheduled-task-created-4698.spl
~~~

### Validation Report

~~~text
validation/rule-004-validation.md
~~~

### MITRE Coverage

~~~text
mitre-coverage/day05-scheduled-task-detection.md
~~~

---

## 18. Detection Engineering Workflow Demonstrated

This detection demonstrates the following practical workflow:

~~~text
Telemetry Assessment
        ↓
Audit Policy Configuration
        ↓
Controlled Activity
        ↓
Event Generation
        ↓
Raw Event Verification
        ↓
Baseline Analysis
        ↓
Field Extraction
        ↓
Sigma Rule Development
        ↓
Splunk SPL Development
        ↓
Controlled Validation
        ↓
MITRE ATT&CK Mapping
        ↓
Evidence Documentation
~~~

This approach ensures the detection is based on telemetry that was actually available and validated in the lab.

---

## 19. Final Assessment

Rule 004 successfully provides detection coverage for Windows scheduled-task creation using Security Event ID 4698.

The detection was validated end-to-end using a controlled scheduled-task creation and achieved:

**1 controlled test → 1 Windows event → 1 Splunk detection**

**Controlled Detection Result: 100%**

**MITRE ATT&CK Coverage: T1053.005**

The detection is now documented with Sigma logic, Splunk SPL, validation evidence, baseline analysis, and MITRE ATT&CK mapping.