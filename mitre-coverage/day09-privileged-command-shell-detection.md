# MITRE ATT&CK Coverage — Day 09 Privileged Command Shell Detection

## 1. Detection Overview

**Detection:** Windows Administrator Privileged Command Shell Execution  
**Rule:** Rule 008  
**MITRE ATT&CK Technique:** T1059.003 — Windows Command Shell  
**Tactic:** Execution  
**Platform:** Windows  
**Detection Type:** Multi-event correlation  
**Primary Event IDs:** 4672, 4688  
**SIEM:** Splunk Cloud  
**Validation Status:** Validated

Day 09 extends the detection engineering coverage by correlating a privileged Administrator session with subsequent Windows Command Shell execution.

The detection uses Windows Security Event ID 4672 to establish privileged-session context and Event ID 4688 to identify `cmd.exe` process creation.

---

## 2. MITRE ATT&CK Mapping

### T1059.003 — Windows Command Shell

**Technique:** Command and Scripting Interpreter: Windows Command Shell

**Tactic:** Execution

**Technique ID:**

~~~text
T1059.003
~~~

The detection focuses specifically on Windows Command Shell execution through:

~~~text
C:\Windows\System32\cmd.exe
~~~

The detection does not classify every Administrator command-shell execution as malicious. Instead, it provides a contextual detection signal by correlating command-shell execution with a privileged Windows logon session.

---

## 3. Detection Strategy Alignment

MITRE ATT&CK's Windows Command Shell detection guidance includes process-creation telemetry and user-context analysis for identifying suspicious `cmd.exe` execution.

Rule 008 applies this concept by combining:

~~~text
User Context
      +
Privileged Session
      +
Process Creation
      +
Logon ID Correlation
      =
Contextual Command Shell Detection
~~~

The project uses Windows Security Event ID 4688 as the process-creation telemetry source and Event ID 4672 to establish privileged-session context.

---

## 4. Detection Logic

### Supporting Event 1 — Privileged Session

**Event ID:** 4672

~~~text
Special privileges assigned to new logon
~~~

The detection identifies:

~~~text
Account: Administrator
Logon ID: <correlation identifier>
~~~

### Supporting Event 2 — Process Creation

**Event ID:** 4688

The detection identifies:

~~~text
Process:
C:\Windows\System32\cmd.exe
~~~

### Correlation

The two events are correlated using the Windows Logon ID.

~~~text
Event 4672
Administrator privileged session
        |
        | Same Logon ID
        |
        v
Event 4688
cmd.exe process creation
        |
        v
Rule 008
Administrator Privileged Command Shell Execution
~~~

The production detection uses a 15-minute correlation window.

---

## 5. Sigma Detection Coverage

### Supporting Rule 1

~~~text
sigma-rules/windows/execution/windows-administrator-special-privileges.yml
~~~

Detects:

~~~text
Event ID 4672
Administrator privileged session
~~~

### Supporting Rule 2

~~~text
sigma-rules/windows/execution/windows-administrator-command-shell.yml
~~~

Detects:

~~~text
Event ID 4688
Administrator
cmd.exe
~~~

### Primary Rule 008

~~~text
sigma-rules/windows/execution/windows-administrator-privileged-command-shell.yml
~~~

Correlation:

~~~text
Administrator privileged session
        +
Windows Command Shell execution
        +
Same logon context
        +
15-minute correlation window
~~~

---

## 6. Splunk Detection Coverage

The corresponding SPL detection is stored at:

~~~text
splunk-queries/correlation/administrator-privileged-command-shell.spl
~~~

The query:

- Collects Event IDs 4672 and 4688.
- Extracts the Windows Logon ID.
- Identifies Administrator privileged sessions.
- Identifies `cmd.exe` process creation.
- Correlates both events by host and Logon ID.
- Calculates the time difference.
- Applies the 15-minute correlation window.
- Generates the detection label.

Detection name:

~~~text
Administrator Privileged Command Shell Execution
~~~

---

## 7. Validation Evidence

### Evidence 01 — Security Event Baseline

**File:**

~~~text
Day09-01-Security-Event-Baseline.png
~~~

![Day 09 Security Event Baseline](../screenshots/Day09/Day09-01-Security-Event-Baseline.png)

This establishes the Windows Security telemetry baseline used during the Day 09 investigation.

---

### Evidence 02 — Explicit Credential Investigation

**File:**

~~~text
Day09-02-Explicit-Credential-Use-Baseline.png
~~~

![Explicit Credential Use Baseline](../screenshots/Day09/Day09-02-Explicit-Credential-Use-Baseline.png)

This evidence documents an alternative detection path investigated during the development process.

The Explicit Credential Use approach was not selected as the final detection because the observed authentication relationships produced excessive normal Windows activity.

This evidence demonstrates that the final detection scenario was selected based on observed telemetry rather than assuming that every available event relationship represented a useful detection.

---

### Evidence 03 — Controlled Command Shell Activity

**File:**

~~~text
Day09-03-Privileged-Command-Shell-Test.png
~~~

![Controlled Privileged Command Shell Test](../screenshots/Day09/Day09-03-Privileged-Command-Shell-Test.png)

A benign command-shell test was executed from an Administrator Command Prompt.

Test command:

~~~cmd
cmd.exe /c echo Day09-Administrator-Cmd-Test
~~~

The activity was used to generate controlled Windows process-creation telemetry for validation.

---

### Evidence 04 — Privileged Command Shell Correlation

**File:**

~~~text
Day09-04-Privileged-Command-Shell-Correlation.png
~~~

![Privileged Command Shell Correlation](../screenshots/Day09/Day09-04-Privileged-Command-Shell-Correlation.png)

The evidence demonstrates an Administrator privileged session correlated with subsequent `cmd.exe` execution using the same Windows Logon ID.

Observed baseline correlation:

~~~text
Host:              WIN10-CLIENT
Account:           Administrator
Logon ID:          0xBDACF3
Privilege Event:   4672
Process Event:     4688
Process:           C:\Windows\System32\cmd.exe
Time Difference:   5.76 seconds
~~~

---

### Evidence 05 — Controlled Detection

**File:**

~~~text
Day09-05-Controlled-Privileged-Cmd-Detection.png
~~~

![Controlled Privileged Command Detection](../screenshots/Day09/Day09-05-Controlled-Privileged-Cmd-Detection.png)

The controlled validation produced a matching privileged-session and command-shell sequence.

Observed validation:

~~~text
Host:               WIN10-CLIENT
Account:            Administrator
Logon ID:           0x1B950D
Privilege Event:    4672
Privilege Time:     2026-09-23 14:25:08.486
Process Event:      4688
Process:            C:\Windows\System32\cmd.exe
Command Time:       2026-09-23 14:35:44.148
Time Difference:    635.66 seconds
Detection:          Administrator Privileged Command Shell Execution
~~~

The 635.66-second interval falls within the configured 15-minute validation window.

---

## 8. Validation Results

| Metric | Result |
|---|---:|
| Event IDs correlated | 2 |
| Privileged sessions validated | 1 |
| `cmd.exe` process creation validated | 1 |
| Matching Logon IDs | 1 |
| Successful controlled detections | 1 |
| Validation success rate | 100% |
| Correlation window | 15 minutes |

### Validation Result

~~~text
1 controlled sequence
        ↓
1 matching Event 4672
        ↓
1 matching Event 4688
        ↓
1 matching Logon ID
        ↓
1 detection
        ↓
100% controlled validation
~~~

---

## 9. Detection Engineering Significance

Rule 008 demonstrates contextual detection engineering rather than relying only on a single process event.

A standalone `cmd.exe` detection can generate legitimate administrative activity. Rule 008 adds privileged-session context by correlating Event ID 4672 with Event ID 4688.

This provides the SOC analyst with:

- Account context
- Privileged-session context
- Process context
- Windows Logon ID correlation
- Event timing
- Host context

The resulting alert can be investigated alongside surrounding authentication, process, and administrative activity.

---

## 10. False Positive Considerations

Potential legitimate activity includes:

- Authorized Administrator command-line administration
- IT support
- Endpoint troubleshooting
- Software deployment
- System maintenance
- Administrative automation

Therefore, the detection should be treated as a **contextual investigation signal**, not as automatic proof of malicious activity.

Analysts should review:

~~~text
Account activity
Process ancestry
Command-line arguments
Authentication events
Host activity
Administrative changes
Related security events
~~~

---

## 11. Day 09 Coverage

Day 09 adds the following detection-engineering coverage to the project:

~~~text
Windows Security Event Analysis
        ↓
Privileged Session Detection
        ↓
Process Creation Analysis
        ↓
Logon ID Correlation
        ↓
Windows Command Shell Detection
        ↓
MITRE ATT&CK T1059.003 Mapping
        ↓
Controlled Validation
~~~

### Project Artifacts

~~~text
Sigma Rules:
3

Primary Detection:
Rule 008

Windows Security Events:
2

Splunk Correlation Query:
1

MITRE ATT&CK Technique:
T1059.003

Controlled Validation:
1/1

Validation Success:
100%
~~~

---

## 12. Repository Mapping

~~~text
mitre-coverage/
└── day09-privileged-command-shell-detection.md

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

screenshots/
└── Day09/
    ├── Day09-01-Security-Event-Baseline.png
    ├── Day09-02-Explicit-Credential-Use-Baseline.png
    ├── Day09-03-Privileged-Command-Shell-Test.png
    ├── Day09-04-Privileged-Command-Shell-Correlation.png
    └── Day09-05-Controlled-Privileged-Cmd-Detection.png
~~~

---

## 13. Final MITRE Coverage Status

**Technique:** T1059.003 — Windows Command Shell

**Tactic:** Execution

**Detection:** Windows Administrator Privileged Command Shell Execution

**Status:** Validated

Rule 008 provides evidence-backed detection coverage for Windows Command Shell execution by correlating privileged Administrator-session telemetry with Windows process-creation telemetry.

The detection was validated using both existing telemetry and controlled benign activity, with a documented 1/1 controlled detection result.

**Day 09 MITRE ATT&CK coverage: COMPLETE**