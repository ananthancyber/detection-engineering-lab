# Rule 003 Validation — PowerShell Encoded Command Detection

## Detection Overview

| Field | Details |
|---|---|
| Rule | PowerShell Encoded Command Execution |
| Rule ID | `3c6b8f42-4688-4d71-a903-003fa1ed0a03` |
| Event ID | `4688` |
| Detection Category | Process Creation |
| Platform | Windows |
| SIEM | Splunk Cloud |
| Log Source | Windows Security Event Log |
| Host | `WIN10-CLIENT` |
| Account | `alice` |
| Detection Status | Validated |
| Validation Date | 19 September 2026 |

---

## 1. Validation Objective

The objective of this validation was to verify that Rule 003 can identify PowerShell process creation events containing encoded-command execution indicators.

The validation followed a controlled detection-engineering workflow:

1. Establish a baseline.
2. Search for suspicious PowerShell command-line indicators.
3. Confirm that the indicators were not already present in the baseline.
4. Generate a controlled PowerShell test event.
5. Verify that Windows Event ID `4688` captured the activity.
6. Search the event in Splunk.
7. Validate the final detection query.
8. Record measurable results.

---

## 2. Detection Logic

Rule 003 detects PowerShell process creation when the command line contains encoded-command indicators.

The detection focuses on:

- `powershell.exe`
- `pwsh.exe`
- `-EncodedCommand`
- `-enc`

The detection is intentionally more specific than simply detecting PowerShell execution.

This approach allows normal PowerShell activity, such as legitimate administrative and security tooling, to be distinguished from the specific command-line behavior being tested.

---

## 3. Sigma Rule

The Sigma rule used for validation is:

~~~yaml
title: PowerShell Encoded Command Execution
id: 3c6b8f42-4688-4d71-a903-003fa1ed0a03
status: experimental
description: Detects PowerShell process creation events where the command line contains encoded-command execution indicators.
author: Ananthan D
date: 2026/09/19

logsource:
  product: windows
  category: process_creation

detection:
  selection_process:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'

  selection_encoded:
    CommandLine|contains:
      - '-EncodedCommand'
      - '-EncodedCommand '
      - ' -enc '
      - ' -EncodedCommand'

  condition: selection_process and selection_encoded

level: medium

falsepositives:
  - Legitimate administrative PowerShell scripts using encoded commands
  - Security automation
  - Enterprise management tools
  - Software deployment systems

tags:
  - attack.execution
  - attack.t1059.001
~~~

---

## 4. Baseline Analysis

Before generating controlled test activity, an investigation was performed against the existing Windows Event ID `4688` telemetry.

The purpose was to determine whether suspicious PowerShell encoded-command indicators were already present in the environment.

### Baseline SPL Query

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell.exe"
| search (Process_Command_Line="*EncodedCommand*" OR Process_Command_Line="*-enc*" OR Process_Command_Line="*DownloadString*" OR Process_Command_Line="*IEX*" OR Process_Command_Line="*Invoke-Expression*")
| table _time host Account_Name New_Process_Name Process_Command_Line Creator_Process_Name
| sort - _time
~~~

### Baseline Result

The query returned:

**0 events**

This established that the selected suspicious PowerShell command-line indicators were not present in the existing telemetry before the controlled validation.

### Evidence

![PowerShell Suspicious Pattern Baseline](../screenshots/Day04/Day04-05-PowerShell-Suspicious-Pattern-Baseline.png)

**Evidence file:** `Day04-05-PowerShell-Suspicious-Pattern-Baseline.png`

---

## 5. Controlled Validation Activity

A controlled PowerShell process was executed on the Windows client to generate a known Event ID `4688`.

The test used a harmless encoded PowerShell command.

The decoded test payload was:

~~~text
Write-Output "DetectionEngineering-Day04"
~~~

The purpose of the activity was only to generate process-creation telemetry containing the `-EncodedCommand` indicator.

No download, persistence, credential access, or system modification was performed.

---

## 6. Controlled Event Generation

The controlled PowerShell execution generated a Windows Security Event ID `4688`.

The event was successfully collected by the Splunk Universal Forwarder and became searchable in Splunk Cloud.

### Observed Event Details

| Field | Observed Value |
|---|---|
| Event ID | `4688` |
| Host | `WIN10-CLIENT` |
| Account | `alice` |
| Process | `powershell.exe` |
| Command-line indicator | `-EncodedCommand` |
| Event count | `1` |
| Timestamp | `2026-09-19 06:42:04.766` |

### Evidence

![Controlled PowerShell Encoded Command](../screenshots/Day04/Day04-06-Controlled-PowerShell-EncodedCommand.png)

**Evidence file:** `Day04-06-Controlled-PowerShell-EncodedCommand.png`

---

## 7. SPL Detection Query

The final SPL query used to implement Rule 003 in Splunk was:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell.exe" OR New_Process_Name="*pwsh.exe"
| search Process_Command_Line="*-EncodedCommand*" OR Process_Command_Line="* -enc *"
| table _time host Account_Name New_Process_Name Process_Command_Line Creator_Process_Name
| sort - _time
~~~

### Query Purpose

The query:

1. Searches Windows Security Event ID `4688`.
2. Identifies PowerShell process creation.
3. Searches the command line for encoded-command indicators.
4. Displays the relevant investigation fields.
5. Sorts the newest matching events first.

---

## 8. Detection Result

The final SPL detection query successfully identified the controlled PowerShell event.

### Detection Result

**1 matching event**

The detected event corresponded to the controlled PowerShell execution generated during validation.

The result contained:

- `WIN10-CLIENT`
- Account `alice`
- `powershell.exe`
- `-EncodedCommand`
- Windows Event ID `4688`

### Evidence

![PowerShell Encoded Command Detection](../screenshots/Day04/Day04-07-PowerShell-EncodedCommand-Detection.png)

**Evidence file:** `Day04-07-PowerShell-EncodedCommand-Detection.png`

---

## 9. Sigma Rule Evidence

The completed Sigma rule was stored at:

~~~text
sigma-rules/windows/execution/windows-powershell-encoded-command.yml
~~~

### Evidence

![PowerShell Encoded Command Sigma Rule](../screenshots/Day04/Day04-08-PowerShell-EncodedCommand-Sigma-Rule.png)

**Evidence file:** `Day04-08-PowerShell-EncodedCommand-Sigma-Rule.png`

---

## 10. SPL Query File Evidence

The Splunk implementation was stored at:

~~~text
splunk-queries/process-creation/powershell-encoded-command.spl
~~~

### Evidence

![PowerShell Encoded Command SPL Query](../screenshots/Day04/Day04-09-PowerShell-EncodedCommand-SPL-Query.png)

**Evidence file:** `Day04-09-PowerShell-EncodedCommand-SPL-Query.png`

---

## 11. Validation Results

| Validation Metric | Result |
|---|---:|
| Baseline suspicious-pattern matches | `0` |
| Controlled test events generated | `1` |
| Event ID | `4688` |
| PowerShell events detected | `1` |
| Final detection matches | `1` |
| Controlled events successfully detected | `1/1` |
| Detection result | Successful |

---

## 12. Detection Validation Flow

~~~text
Existing Windows Telemetry
        ↓
PowerShell Baseline Search
        ↓
0 Suspicious Pattern Matches
        ↓
Controlled PowerShell Test
        ↓
Windows Event ID 4688
        ↓
Splunk Cloud
        ↓
Rule 003 SPL Detection
        ↓
1 Matching Event
        ↓
Successful Validation
~~~

---

## 13. Evidence Register

| Evidence ID | Description | Evidence File |
|---|---|---|
| Day04-05 | PowerShell suspicious-pattern baseline | `Day04-05-PowerShell-Suspicious-Pattern-Baseline.png` |
| Day04-06 | Controlled encoded-command event | `Day04-06-Controlled-PowerShell-EncodedCommand.png` |
| Day04-07 | Final SPL detection result | `Day04-07-PowerShell-EncodedCommand-Detection.png` |
| Day04-08 | Sigma rule | `Day04-08-PowerShell-EncodedCommand-Sigma-Rule.png` |
| Day04-09 | SPL query file | `Day04-09-PowerShell-EncodedCommand-SPL-Query.png` |

---

## 14. MITRE ATT&CK Mapping

| Detection | MITRE ATT&CK ID | Technique |
|---|---|---|
| PowerShell Encoded Command Execution | `T1059.001` | PowerShell |

The detection focuses on PowerShell execution through Windows process creation telemetry.

The encoded-command behavior provides additional command-line context to the PowerShell execution.

---

## 15. Validation Conclusion

Rule 003 was successfully validated against Windows Security Event ID `4688` telemetry collected in Splunk Cloud.

The baseline search produced `0` matching suspicious PowerShell command-line events.

A controlled PowerShell encoded-command event was then generated on `WIN10-CLIENT`.

The resulting Event ID `4688` was successfully collected and identified by the final SPL detection query.

The final validation produced:

**1 controlled event → 1 detection match**

This confirms that the detection logic successfully identifies the tested PowerShell encoded-command execution pattern in the lab environment.