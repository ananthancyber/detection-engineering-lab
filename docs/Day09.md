# Day 09 — Advanced Detection Correlation: Privileged Command Shell Execution

## 1. Overview

**Project:** Detection Engineering Lab  
**Day:** 09  
**Focus:** Advanced Detection Correlation  
**Platform:** Windows 10  
**SIEM:** Splunk Cloud  
**Detection Format:** Sigma + SPL  
**MITRE ATT&CK:** T1059.003 — Windows Command Shell  
**Status:** Complete

Day 09 focused on developing a multi-event detection that correlates a privileged Windows Administrator session with subsequent `cmd.exe` execution.

Rather than relying on a single process-creation event, the detection combines Windows Security Event ID **4672** and Event ID **4688** using the Windows **Logon ID** as the correlation key.

---

## 2. Detection Objective

The objective was to identify Windows Command Shell execution occurring within an Administrator privileged session.

The detection follows this sequence:

~~~text
Event ID 4672
Special privileges assigned to Administrator
        ↓
Same Windows Logon ID
        ↓
Event ID 4688
cmd.exe process creation
        ↓
Rule 008 Detection
Administrator Privileged Command Shell Execution
~~~

This approach provides additional context compared with detecting `cmd.exe` process creation independently.

---

## 3. Detection Scenario Selection

Several multi-event detection scenarios were investigated during Day 09.

An Explicit Credential Use correlation using Event ID 4648 was initially evaluated. The telemetry produced a large number of normal Windows authentication relationships and did not provide sufficient detection precision for the final scenario.

The investigation therefore moved to privileged-session and process-creation correlation using:

- Event ID 4672
- Event ID 4688
- Windows Logon ID
- Administrator account context
- `cmd.exe` process execution

This telemetry-driven approach resulted in the final Rule 008 detection.

### Investigative Evidence

`Day09-02-Explicit-Credential-Use-Baseline.png` documents the alternative telemetry path that was investigated but not selected for the final detection.

![Explicit Credential Use Baseline](../screenshots/Day09/Day09-02-Explicit-Credential-Use-Baseline.png)

---

## 4. Windows Security Telemetry Baseline

The Day 09 investigation began by reviewing the available Windows Security Event Log telemetry in Splunk.

### Evidence

**File:** `Day09-01-Security-Event-Baseline.png`

![Security Event Baseline](../screenshots/Day09/Day09-01-Security-Event-Baseline.png)

The baseline established the available Windows Security Event IDs and provided the telemetry foundation for selecting a correlation-based detection scenario.

---

## 5. Event ID 4672 — Privileged Session

Windows Security Event ID **4672** was used to establish privileged-session context.

The investigation focused on Administrator activity and extracted:

- Account Name
- Account Domain
- Windows Logon ID

The Logon ID was used as the primary correlation identifier between the privileged-session event and subsequent process-creation activity.

---

## 6. Event ID 4688 — Process Creation

Windows Security Event ID **4688** was used to identify process creation.

The final detection specifically searches for:

~~~text
C:\Windows\System32\cmd.exe
~~~

Relevant process information includes:

- Process name
- Creator account
- Creator Logon ID
- Event timestamp
- Host

The detection therefore combines process execution with the preceding privileged-session context.

---

## 7. Controlled Validation Activity

A controlled and benign command-shell activity was performed from an Administrator Command Prompt.

The validation command was:

~~~cmd
cmd.exe /c echo Day09-Administrator-Cmd-Test
~~~

This activity was designed only to generate process-creation telemetry for detection validation.

### Evidence

**File:** `Day09-03-Privileged-Command-Shell-Test.png`

![Controlled Privileged Command Shell Test](../screenshots/Day09/Day09-03-Privileged-Command-Shell-Test.png)

No persistence mechanism, account modification, registry modification, or other configuration change was introduced as part of this validation.

---

## 8. Baseline Privileged Command Shell Correlation

An existing Administrator privileged session was correlated with subsequent `cmd.exe` execution using the same Windows Logon ID.

### Observed Correlation

~~~text
Host:              WIN10-CLIENT
Account:           Administrator
Logon ID:          0xBDACF3
Privilege Event:   4672
Process Event:     4688
Process:           C:\Windows\System32\cmd.exe
Time Difference:   5.76 seconds
~~~

### Evidence

**File:** `Day09-04-Privileged-Command-Shell-Correlation.png`

![Privileged Command Shell Correlation](../screenshots/Day09/Day09-04-Privileged-Command-Shell-Correlation.png)

This provided baseline evidence that the required 4672 → 4688 relationship existed in the collected Windows Security telemetry.

---

## 9. Controlled Detection Validation

The controlled validation generated a matching Administrator privileged-session and `cmd.exe` process-creation sequence.

### Observed Result

~~~text
Host:               WIN10-CLIENT
Logon ID:           0x1B950D
Privileged Account: Administrator
Privilege Event:    4672
Privilege Time:     2026-09-23 14:25:08.486
Process Event:      4688
Process:            C:\Windows\System32\cmd.exe
Command Time:       2026-09-23 14:35:44.148
Time Difference:    635.66 seconds
Detection:          Administrator Privileged Command Shell Execution
~~~

The 635.66-second interval falls within the configured 15-minute correlation window.

### Evidence

**File:** `Day09-05-Controlled-Privileged-Cmd-Detection.png`

![Controlled Privileged Command Detection](../screenshots/Day09/Day09-05-Controlled-Privileged-Cmd-Detection.png)

---

## 10. Rule 008 Detection Logic

**Detection Name:** Windows Administrator Privileged Command Shell Execution

**Rule:** Rule 008

**Severity:** High

The detection requires:

1. Event ID 4672.
2. Administrator account context.
3. Event ID 4688.
4. `cmd.exe` process creation.
5. Matching Windows Logon ID.
6. Events occurring within the configured 15-minute window.

### Detection Flow

~~~text
Windows Security Event 4672
        ↓
Administrator privileged session
        ↓
Extract Windows Logon ID
        ↓
Windows Security Event 4688
        ↓
Identify cmd.exe
        ↓
Match Logon ID
        ↓
Calculate time difference
        ↓
≤ 15 minutes
        ↓
Rule 008 Alert
~~~

---

## 11. Splunk Detection

The production SPL query is stored at:

~~~text
splunk-queries/correlation/administrator-privileged-command-shell.spl
~~~

The detection performs:

- Windows Security event filtering
- Logon ID extraction
- Administrator identification
- `cmd.exe` identification
- Event correlation
- Time-window validation
- Detection labeling
- SOC-oriented result formatting

Detection label:

~~~text
Administrator Privileged Command Shell Execution
~~~

---

## 12. Sigma Detection Coverage

### Supporting Rule

~~~text
sigma-rules/windows/execution/windows-administrator-special-privileges.yml
~~~

Detects Administrator privileged-session activity using Event ID 4672.

### Supporting Rule

~~~text
sigma-rules/windows/execution/windows-administrator-command-shell.yml
~~~

Detects Administrator `cmd.exe` process creation using Event ID 4688.

### Primary Rule 008

~~~text
sigma-rules/windows/execution/windows-administrator-privileged-command-shell.yml
~~~

Correlates the two supporting detections using the Windows Logon ID and a 15-minute time window.

---

## 13. MITRE ATT&CK Mapping

**Technique:** T1059.003 — Windows Command Shell

**Tactic:** Execution

Rule 008 provides detection coverage for Windows Command Shell execution while adding privileged-session context.

The detection is mapped to T1059.003 because the observed execution involves:

~~~text
C:\Windows\System32\cmd.exe
~~~

MITRE coverage documentation:

~~~text
mitre-coverage/day09-privileged-command-shell-detection.md
~~~

---

## 14. False Positive Considerations

Legitimate activity may include:

- Authorized Administrator command-line administration
- IT support activity
- Endpoint troubleshooting
- Software deployment
- System maintenance
- Administrative automation

Therefore, the detection should be treated as an investigation signal rather than automatic proof of malicious activity.

A SOC analyst should review surrounding:

- Authentication activity
- Process ancestry
- Command-line arguments
- User activity
- Host context
- Administrative changes
- Related security events

---

## 15. Validation Results

| Metric | Result |
|---|---:|
| Windows Event IDs correlated | 2 |
| Controlled privileged session | 1 |
| Controlled `cmd.exe` execution | 1 |
| Matching Logon ID | 1 |
| Successful detection | 1 |
| Controlled validation success | 100% |
| Correlation window | 15 minutes |
| Primary Sigma detection | 1 |
| Supporting Sigma rules | 2 |
| Splunk correlation query | 1 |
| MITRE ATT&CK technique | T1059.003 |

### Validation Calculation

~~~text
Detection Success Rate
= Matching Detection Events / Controlled Test Events × 100

= 1 / 1 × 100

= 100%
~~~

---

## 16. Evidence Summary

| Evidence | Purpose |
|---|---|
| `Day09-01-Security-Event-Baseline.png` | Windows Security telemetry baseline |
| `Day09-02-Explicit-Credential-Use-Baseline.png` | Investigated alternative detection path |
| `Day09-03-Privileged-Command-Shell-Test.png` | Controlled benign test activity |
| `Day09-04-Privileged-Command-Shell-Correlation.png` | Existing 4672 → 4688 correlation |
| `Day09-05-Controlled-Privileged-Cmd-Detection.png` | Final controlled detection result |

The Explicit Credential evidence is retained as investigation history but is not part of the final Rule 008 detection logic.

---

## 17. Repository Artifacts

~~~text
docs/
└── Day09.md

sigma-rules/
└── windows/
    └── execution/
        ├── windows-administrator-special-privileges.yml
        ├── windows-administrator-command-shell.yml
        └── windows-administrator-privileged-command-shell.yml

splunk-queries/
└── correlation/
    └── administrator-privileged-command-shell.spl

validation/
└── rule-008-validation.md

mitre-coverage/
└── day09-privileged-command-shell-detection.md

screenshots/
└── Day09/
    ├── Day09-01-Security-Event-Baseline.png
    ├── Day09-02-Explicit-Credential-Use-Baseline.png
    ├── Day09-03-Privileged-Command-Shell-Test.png
    ├── Day09-04-Privileged-Command-Shell-Correlation.png
    └── Day09-05-Controlled-Privileged-Cmd-Detection.png
~~~

---

## 18. SOC Skills Demonstrated

Day 09 demonstrates practical experience with:

- Advanced SIEM correlation
- Windows Security Event analysis
- Event ID 4672 investigation
- Event ID 4688 process analysis
- Windows Logon ID correlation
- Administrator activity monitoring
- Splunk SPL development
- Sigma correlation rules
- Controlled detection validation
- False-positive analysis
- MITRE ATT&CK mapping
- Evidence-driven detection engineering
- SOC investigation workflow

---

## 19. Day 09 Outcome

Day 09 successfully expanded the Detection Engineering Lab from individual event-based detections into multi-event contextual correlation.

The final detection connects:

~~~text
Privileged Session
        +
Command Shell Execution
        +
Same Logon Context
        +
Temporal Correlation
        =
Contextual SOC Detection
~~~

The controlled validation produced **1 matching detection from 1 controlled test sequence**, resulting in a **100% controlled validation success rate**.

### Day 09 Status

**COMPLETE**

**Primary Detection:** Rule 008 — Windows Administrator Privileged Command Shell Execution

**MITRE ATT&CK:** T1059.003 — Windows Command Shell

