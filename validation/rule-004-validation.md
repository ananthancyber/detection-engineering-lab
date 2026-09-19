# Rule 004 Validation — Windows Scheduled Task Creation

## Detection Overview

| Field | Details |
|---|---|
| Rule ID | 004 |
| Detection | Windows Scheduled Task Created |
| Windows Event | 4698 |
| Detection Type | Persistence / Scheduled Task Creation |
| Sigma Rule | `sigma-rules/windows/persistence/windows-scheduled-task-created.yml` |
| Splunk Query | `splunk-queries/persistence/scheduled-task-created-4698.spl` |
| MITRE ATT&CK | T1053.005 — Scheduled Task/Job: Scheduled Task |
| Severity | Medium |
| Validation Status | **PASS** |

---

## 1. Validation Objective

The objective of this validation was to confirm that the detection can identify the creation of a Windows scheduled task using Security Event ID 4698.

The validation covered the complete detection pipeline:

~~~text
Scheduled Task Creation
        ↓
Windows Security Event ID 4698
        ↓
Windows Security Log
        ↓
Splunk Universal Forwarder
        ↓
Splunk Cloud
        ↓
SPL Detection Logic
        ↓
Scheduled Task Identified
~~~

The test used a controlled, benign scheduled task created specifically for detection validation.

---

## 2. Telemetry Preparation

Before testing the detection, the Windows client was checked for existing scheduled-task creation telemetry.

The initial Event ID 4698 search returned no events.

Windows auditing for:

~~~text
Other Object Access Events
~~~

was subsequently enabled for successful auditing.

The audit policy was verified with:

~~~text
Other Object Access Events    Success
~~~

This allowed Windows to generate Security Event ID 4698 when a scheduled task was created.

### Evidence

![Scheduled Task Audit Policy Enabled](../screenshots/Day05/Day05-06-Scheduled-Task-Audit-Policy-Enabled.png)

---

## 3. Controlled Test

A harmless scheduled task was created on the Windows 10 client for detection validation.

Test task:

~~~text
\DetectionEngineering-Day05-Test
~~~

The task was configured as a one-time scheduled task and was created for the sole purpose of generating controlled security telemetry.

### Evidence

![Controlled Scheduled Task Creation](../screenshots/Day05/Day05-07-Scheduled-Task-Creation-Test.png)

---

## 4. Event ID 4698 Verification

After the controlled task was created, Splunk was queried for:

~~~text
EventCode=4698
~~~

The search returned scheduled-task creation telemetry from:

~~~text
WIN10-CLIENT
~~~

The observed event contained:

- Event ID: `4698`
- Host: `WIN10-CLIENT`
- Account: `Administrator`
- Scheduled task creation message
- Scheduled task information
- Task XML content

### Evidence

![Scheduled Task Event 4698](../screenshots/Day05/Day05-08-Scheduled-Task-Event-4698.png)

---

## 5. Event Field Analysis

The Event ID 4698 event was inspected to identify the fields available for detection and investigation.

Important telemetry included:

| Field | Observed Value / Purpose |
|---|---|
| `EventCode` | 4698 |
| `host` | WIN10-CLIENT |
| `Account_Name` | Administrator |
| `TaskName` | Available within raw event |
| `TaskContent` | Available within raw event |
| `Message` | A scheduled task was created |
| `TaskCategory` | Other Object Access Events |
| `Keywords` | Audit Success |

The extracted `TaskName` field was not consistently populated by the existing field extraction, so the detection uses a `rex` extraction against `_raw` to reliably identify the scheduled task name.

### Evidence

![Scheduled Task Event Details](../screenshots/Day05/Day05-09-Scheduled-Task-Event-Details.png)

---

## 6. Raw Event Verification

The raw Windows Security event was inspected to confirm that the scheduled task information was actually present in the original telemetry.

The raw event contained the scheduled task information and XML configuration, including the task URI:

~~~text
\DetectionEngineering-Day05-Test
~~~

This confirmed that the required detection information existed in the raw event even where some fields were not automatically extracted.

### Evidence

![Scheduled Task Raw Event](../screenshots/Day05/Day05-10-Scheduled-Task-Raw-Event.png)

---

## 7. Scheduled Task Baseline

A baseline search was performed against Event ID 4698 before finalizing the detection logic.

The baseline identified:

| Host | Account | Event Count |
|---|---|---:|
| WIN10-CLIENT | Administrator | 1 |
| WIN10-CLIENT | WIN10-CLIENT$ | 1 |

Total observed Event ID 4698 events:

**2**

The observed scheduled tasks included:

~~~text
\DetectionEngineering-Day05-Test
\Microsoft\Windows\UpdateOrchestrator\MusUx_LogonUpdateResults
~~~

The Windows Update task demonstrates that scheduled-task creation can represent legitimate operating-system activity.

Therefore, Event ID 4698 is treated as a **detection signal requiring investigation**, rather than automatically being classified as malicious.

### Evidence

![Scheduled Task Baseline](../screenshots/Day05/Day05-11-Scheduled-Task-Baseline.png)

---

## 8. Scheduled Task Name Extraction

The scheduled task name was extracted from the raw Windows Security event using SPL `rex`.

Extraction pattern:

~~~spl
| rex field=_raw "Task Name:\s+(?<ScheduledTaskName>[^\r\n]+)"
~~~

The extraction successfully identified both observed task names, including the controlled test task.

### Evidence

![Scheduled Task Name Extraction](../screenshots/Day05/Day05-12-Scheduled-Task-Name-Extraction.png)

---

## 9. Detection Query

The final Splunk detection query is:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4698
| rex field=_raw "Task Name:\s+(?<ScheduledTaskName>[^\r\n]+)"
| table _time host Account_Name ScheduledTaskName EventCode Message
| sort - _time
~~~

The query:

1. Filters Windows Security Event ID 4698.
2. Extracts the scheduled task name from the raw event.
3. Presents investigation-relevant fields.
4. Sorts the newest events first.

---

## 10. Detection Results

The detection query successfully identified the observed scheduled-task creation events.

The result set contained:

**2 Event ID 4698 events**

The detection included both:

- The controlled test task
- A legitimate Windows Update scheduled task

This demonstrates that the detection is capable of identifying scheduled-task creation while retaining the context required for analyst investigation.

### Evidence

![Scheduled Task Detection Results](../screenshots/Day05/Day05-13-Scheduled-Task-Detection-Results.png)

---

## 11. Controlled Detection Validation

A focused validation search was performed against the controlled task:

~~~text
\DetectionEngineering-Day05-Test
~~~

The query returned:

**1 matching event**

Observed values:

| Field | Result |
|---|---|
| Host | WIN10-CLIENT |
| Account | Administrator |
| Task | `\DetectionEngineering-Day05-Test` |
| Event ID | 4698 |
| Message | A scheduled task was created |

### Evidence

![Controlled Scheduled Task Detection](../screenshots/Day05/Day05-14-Controlled-Scheduled-Task-Detection.png)

---

## 12. Validation Results

| Validation Metric | Result |
|---|---:|
| Controlled tasks created | 1 |
| Expected Event ID | 4698 |
| Matching Event 4698 events | 1 |
| Detection matches | 1 |
| Controlled-test detection rate | **100%** |
| Overall Event 4698 baseline | 2 |
| Validation status | **PASS** |

The controlled scheduled-task creation was successfully observed as Windows Security Event ID 4698 and identified by the Splunk detection query.

---

## 13. False-Positive Considerations

Scheduled-task creation is not inherently malicious.

Legitimate scheduled tasks may be created by:

- Windows operating-system components
- Windows Update
- Enterprise software
- Security products
- System administration
- Software deployment systems
- IT automation

The observed Windows Update scheduled task demonstrates this directly:

~~~text
\Microsoft\Windows\UpdateOrchestrator\MusUx_LogonUpdateResults
~~~

Analysts should therefore investigate scheduled-task creation using additional context such as:

- Task name
- Creating account
- Task XML
- Executable or command configured by the task
- Parent process
- Creation time
- Host context
- Whether the task is expected in the environment

---

## 14. MITRE ATT&CK Mapping

### T1053.005 — Scheduled Task/Job: Scheduled Task

The detection maps to MITRE ATT&CK technique **T1053.005**, which covers Windows scheduled tasks used for execution and potential persistence.

The detection identifies the creation event and provides the task name, account, host, and task configuration for further investigation.

---

## 15. Evidence Summary

| Evidence | Purpose |
|---|---|
| [Day05-06 — Audit Policy Enabled](../screenshots/Day05/Day05-06-Scheduled-Task-Audit-Policy-Enabled.png) | Confirms required auditing was enabled |
| [Day05-07 — Scheduled Task Creation Test](../screenshots/Day05/Day05-07-Scheduled-Task-Creation-Test.png) | Shows controlled task creation |
| [Day05-08 — Event 4698](../screenshots/Day05/Day05-08-Scheduled-Task-Event-4698.png) | Confirms Event ID 4698 reached Splunk |
| [Day05-09 — Event Details](../screenshots/Day05/Day05-09-Scheduled-Task-Event-Details.png) | Shows extracted event information |
| [Day05-10 — Raw Event](../screenshots/Day05/Day05-10-Scheduled-Task-Raw-Event.png) | Confirms task information exists in raw telemetry |
| [Day05-11 — Baseline](../screenshots/Day05/Day05-11-Scheduled-Task-Baseline.png) | Establishes observed scheduled-task activity |
| [Day05-12 — Task Name Extraction](../screenshots/Day05/Day05-12-Scheduled-Task-Name-Extraction.png) | Validates task-name extraction |
| [Day05-13 — Detection Results](../screenshots/Day05/Day05-13-Scheduled-Task-Detection-Results.png) | Shows final detection results |
| [Day05-14 — Controlled Detection](../screenshots/Day05/Day05-14-Controlled-Scheduled-Task-Detection.png) | Provides focused 1/1 validation evidence |

---

## 16. Validation Conclusion

Rule 004 successfully detected the controlled Windows scheduled-task creation through Security Event ID 4698.

The complete detection pipeline was validated:

~~~text
Audit Policy Enabled
        ↓
Scheduled Task Created
        ↓
Windows Security Event 4698
        ↓
Event Forwarded to Splunk
        ↓
Raw Task Information Confirmed
        ↓
Task Name Extracted
        ↓
SPL Detection Executed
        ↓
Controlled Test Identified
~~~

The controlled validation produced:

**1 controlled task → 1 Event 4698 → 1 detection match**

**Detection Result: PASS**

This validates Rule 004 as a functioning scheduled-task creation detection within the current Windows and Splunk lab environment.