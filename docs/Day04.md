# Day 04 — Windows Process Creation Detection Engineering

## Project

**Project:** Project 04 — Detection Engineering Lab  
**Day:** Day 04  
**Focus:** Windows Process Creation & PowerShell Detection  
**SIEM:** Splunk Cloud  
**Detection Format:** Sigma  
**Primary Event ID:** `4688` — A New Process Has Been Created  
**MITRE ATT&CK:** `T1059.001 — PowerShell`  
**Windows Host:** `WIN10-CLIENT`  
**Date:** 19 September 2026  

---

# 1. Objective

The objective of Day 04 was to develop and validate a Windows process-creation detection using Security Event ID `4688`.

The work focused on understanding process-creation telemetry, establishing a normal process baseline, analyzing PowerShell execution, investigating command-line visibility, and creating a detection for PowerShell encoded-command execution.

The detection engineering workflow followed was:

1. Analyze Windows Event ID `4688`.
2. Establish a process-creation baseline.
3. Analyze process command-line telemetry.
4. Investigate PowerShell execution.
5. Search for suspicious PowerShell command-line indicators.
6. Establish a clean baseline.
7. Generate controlled test activity.
8. Validate the resulting Windows event.
9. Create a Sigma detection.
10. Implement the detection in Splunk SPL.
11. Validate the detection against the controlled event.
12. Map the detection to MITRE ATT&CK.
13. Preserve evidence for reproducibility.

---

# 2. Lab Environment

| Component | Details |
|---|---|
| Host OS | Windows 11 |
| Windows Client | `WIN10-CLIENT` |
| Domain | `corp.local` |
| SIEM | Splunk Cloud |
| Log Collector | Splunk Universal Forwarder |
| Log Source | Windows Security Event Log |
| Splunk Index | `main` |
| Sourcetype | `WinEventLog:Security` |
| Primary Event | `4688` |
| Detection Format | Sigma |
| Query Language | Splunk SPL |

---

# 3. Windows Event ID 4688

## 3.1 Event Description

Windows Security Event ID `4688` is generated when a new process is created.

Process-creation telemetry is valuable for SOC investigations because it provides visibility into:

- Which process was executed.
- Which account executed the process.
- Which process created it.
- What command line was used.
- Process identifiers.
- Logon context.
- Token elevation information.
- Integrity level.

These fields can be correlated to identify unusual process execution and suspicious parent-child relationships.

---

# 4. Event ID 4688 Telemetry Analysis

The first investigation focused on the raw Event ID `4688` data available in Splunk.

The observed event contained fields including:

| Field | Availability |
|---|---|
| `EventCode` | Available |
| `New_Process_Name` | Available |
| `Process_Command_Line` | Available |
| `Creator_Process_Name` | Available |
| `Creator_Process_ID` | Available |
| `New_Process_ID` | Available |
| `Account_Name` | Available |
| `Account_Domain` | Available |
| `Logon_ID` | Available |
| `Token_Elevation_Type` | Available |
| `Mandatory_Label` | Available |

The presence of both process names and command-line telemetry provided sufficient visibility for behavior-based process detection.

## Evidence

![Event ID 4688 Analysis](../screenshots/Day04/Day04-01-Event-4688-Analysis.png)

**Evidence file:** `Day04-01-Event-4688-Analysis.png`

---

# 5. Process Creation Baseline

A baseline was established to understand normal process creation behavior on the Windows client.

## SPL Query

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| stats count by New_Process_Name, Creator_Process_Name
| sort - count
~~~

## Observed Results

The search returned:

- **11,956** Event ID `4688` events.
- **369** unique `New_Process_Name` and `Creator_Process_Name` combinations.

Examples of observed process relationships included:

| Child Process | Parent Process |
|---|---|
| `svchost.exe` | `services.exe` |
| `backgroundTaskHost.exe` | `svchost.exe` |
| `conhost.exe` | `auditpol.exe` |
| `conhost.exe` | `svchost.exe` |
| `RuntimeBroker.exe` | `svchost.exe` |

This baseline established the normal process-creation activity present in the lab.

## Evidence

![Process Creation Baseline](../screenshots/Day04/Day04-02-Process-Creation-Baseline.png)

**Evidence file:** `Day04-02-Process-Creation-Baseline.png`

---

# 6. Process Command-Line Baseline

The next investigation focused on command-line visibility within Event ID `4688`.

## SPL Query

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| stats count by New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort - count
~~~

## Observed Results

The search returned:

- **11,956** Event ID `4688` events.
- **2,673** unique combinations of process name, command line, and parent process.

The results confirmed that the Windows client was providing useful process command-line telemetry.

This was important because command-line data provides additional context beyond the process executable name.

## Evidence

![Process Command Line Baseline](../screenshots/Day04/Day04-03-Process-Command-Line-Baseline.png)

**Evidence file:** `Day04-03-Process-Command-Line-Baseline.png`

---

# 7. PowerShell Process Analysis

PowerShell process creation was analyzed separately because PowerShell is a legitimate Windows administration tool that can also be involved in malicious execution.

## SPL Query

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell.exe"
| stats count by New_Process_Name, Process_Command_Line, Creator_Process_Name, Account_Name, host
| sort - count
~~~

## Observed Results

The search returned:

- **402** PowerShell-related Event ID `4688` events.
- **31** distinct process and command-line combinations.

The baseline included legitimate PowerShell activity associated with:

- Splunk Universal Forwarder.
- Wazuh/security tooling.
- Windows administrative activity.

For example, legitimate process relationships included Splunk PowerShell activity and PowerShell commands used for security-policy analysis.

This demonstrated why simply detecting every `powershell.exe` execution would generate significant normal activity.

## Evidence

![PowerShell Process Analysis](../screenshots/Day04/Day04-04-PowerShell-Process-Analysis.png)

**Evidence file:** `Day04-04-PowerShell-Process-Analysis.png`

---

# 8. Suspicious PowerShell Pattern Baseline

A focused search was performed for selected PowerShell command-line indicators.

The indicators investigated were:

- `EncodedCommand`
- `-enc`
- `DownloadString`
- `IEX`
- `Invoke-Expression`

## SPL Query

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell.exe"
| search (Process_Command_Line="*EncodedCommand*" OR Process_Command_Line="*-enc*" OR Process_Command_Line="*DownloadString*" OR Process_Command_Line="*IEX*" OR Process_Command_Line="*Invoke-Expression*")
| table _time host Account_Name New_Process_Name Process_Command_Line Creator_Process_Name
| sort - _time
~~~

## Baseline Result

The search returned:

**0 events**

This established a clean baseline for the selected suspicious PowerShell indicators before controlled validation.

## Evidence

![PowerShell Suspicious Pattern Baseline](../screenshots/Day04/Day04-05-PowerShell-Suspicious-Pattern-Baseline.png)

**Evidence file:** `Day04-05-PowerShell-Suspicious-Pattern-Baseline.png`

---

# 9. Controlled PowerShell Test

Because the existing telemetry did not contain the selected encoded-command indicators, a controlled test was performed.

The purpose was to generate a known Event ID `4688` containing the detection indicator and then verify that the detection could identify it.

The controlled PowerShell payload executed:

~~~text
Write-Output "DetectionEngineering-Day04"
~~~

The activity was designed only for detection validation.

No downloading, persistence, credential access, or system modification was performed.

---

# 10. Controlled Event ID 4688

The controlled PowerShell execution successfully generated a Windows Security Event ID `4688`.

## Observed Event

| Field | Value |
|---|---|
| Event ID | `4688` |
| Host | `WIN10-CLIENT` |
| Account | `alice` |
| Process | `powershell.exe` |
| Indicator | `-EncodedCommand` |
| Event Count | `1` |
| Timestamp | `2026-09-19 06:42:04.766` |

The event confirmed that the command-line telemetry captured the encoded-command indicator.

## Evidence

![Controlled PowerShell Encoded Command](../screenshots/Day04/Day04-06-Controlled-PowerShell-EncodedCommand.png)

**Evidence file:** `Day04-06-Controlled-PowerShell-EncodedCommand.png`

---

# 11. Rule 003 — PowerShell Encoded Command Execution

## 11.1 Detection Objective

The third detection rule was designed to identify PowerShell process creation where the command line contains encoded-command execution indicators.

The detection does not treat every PowerShell process as suspicious.

Instead, it combines:

- PowerShell process identification.
- Command-line analysis.
- Encoded-command indicators.

This provides more specific behavioral detection logic.

---

# 12. Sigma Rule

## Rule Location

~~~text
sigma-rules/windows/execution/windows-powershell-encoded-command.yml
~~~

## Rule ID

~~~text
3c6b8f42-4688-4d71-a903-003fa1ed0a03
~~~

## Sigma Rule

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

## Evidence

![PowerShell Encoded Command Sigma Rule](../screenshots/Day04/Day04-08-PowerShell-EncodedCommand-Sigma-Rule.png)

**Evidence file:** `Day04-08-PowerShell-EncodedCommand-Sigma-Rule.png`

---

# 13. Splunk SPL Detection

The Sigma detection was implemented in Splunk Cloud using an equivalent SPL query.

## Query Location

~~~text
splunk-queries/process-creation/powershell-encoded-command.spl
~~~

## SPL Query

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell.exe" OR New_Process_Name="*pwsh.exe"
| search Process_Command_Line="*-EncodedCommand*" OR Process_Command_Line="* -enc *"
| table _time host Account_Name New_Process_Name Process_Command_Line Creator_Process_Name
| sort - _time
~~~

## Query Logic

| Component | Purpose |
|---|---|
| `EventCode=4688` | Searches process-creation events |
| `powershell.exe` | Identifies Windows PowerShell |
| `pwsh.exe` | Identifies PowerShell Core |
| `EncodedCommand` | Searches for encoded-command execution |
| `-enc` | Searches for abbreviated encoded-command syntax |
| `table` | Displays investigation fields |
| `sort - _time` | Shows newest events first |

## Evidence

![PowerShell Encoded Command SPL Query](../screenshots/Day04/Day04-09-PowerShell-EncodedCommand-SPL-Query.png)

**Evidence file:** `Day04-09-PowerShell-EncodedCommand-SPL-Query.png`

---

# 14. Final Detection Result

The final SPL detection query was executed against the Splunk Cloud environment.

The detection successfully identified the controlled PowerShell process-creation event.

## Detection Result

**1 matching event**

The detected event contained:

- Host: `WIN10-CLIENT`
- Account: `alice`
- Process: `powershell.exe`
- Command-line indicator: `-EncodedCommand`
- Event ID: `4688`

## Evidence

![PowerShell Encoded Command Detection](../screenshots/Day04/Day04-07-PowerShell-EncodedCommand-Detection.png)

**Evidence file:** `Day04-07-PowerShell-EncodedCommand-Detection.png`

---

# 15. Validation

The complete validation process consisted of:

~~~text
Existing Windows Telemetry
        ↓
Event ID 4688 Analysis
        ↓
Process Creation Baseline
        ↓
PowerShell Baseline
        ↓
Suspicious Pattern Search
        ↓
0 Existing Matches
        ↓
Controlled PowerShell Test
        ↓
Event ID 4688 Generated
        ↓
Splunk Collection
        ↓
SPL Detection
        ↓
1 Matching Event
        ↓
Successful Validation
~~~

---

# 16. Validation Results

| Metric | Result |
|---|---:|
| Event ID 4688 events analyzed | `11,956` |
| Unique process/parent combinations | `369` |
| Unique process/command-line/parent combinations | `2,673` |
| PowerShell-related events | `402` |
| PowerShell process/command combinations | `31` |
| Baseline suspicious-pattern matches | `0` |
| Controlled test events generated | `1` |
| Final detection matches | `1` |
| Controlled events detected | `1/1` |
| Validation result | Successful |

---

# 17. MITRE ATT&CK Mapping

## T1059.001 — PowerShell

| Field | Details |
|---|---|
| MITRE ATT&CK ID | `T1059.001` |
| Technique | PowerShell |
| Tactic | Execution |
| Detection | PowerShell Encoded Command Execution |
| Windows Event | `4688` |
| SIEM | Splunk Cloud |
| Detection Format | Sigma + SPL |

The detection provides visibility into PowerShell execution through Windows process-creation telemetry.

The command-line component adds behavioral context to PowerShell execution and allows the detection to focus on encoded-command indicators rather than all PowerShell activity.

## MITRE Coverage File

~~~text
mitre-coverage/day04-process-creation-detection.md
~~~

---

# 18. Evidence Register

| Evidence ID | Description | Evidence File |
|---|---|---|
| Day04-01 | Windows Event ID 4688 analysis | `Day04-01-Event-4688-Analysis.png` |
| Day04-02 | Process creation baseline | `Day04-02-Process-Creation-Baseline.png` |
| Day04-03 | Process command-line baseline | `Day04-03-Process-Command-Line-Baseline.png` |
| Day04-04 | PowerShell process analysis | `Day04-04-PowerShell-Process-Analysis.png` |
| Day04-05 | Suspicious PowerShell pattern baseline | `Day04-05-PowerShell-Suspicious-Pattern-Baseline.png` |
| Day04-06 | Controlled encoded-command event | `Day04-06-Controlled-PowerShell-EncodedCommand.png` |
| Day04-07 | Final SPL detection result | `Day04-07-PowerShell-EncodedCommand-Detection.png` |
| Day04-08 | Sigma Rule 003 | `Day04-08-PowerShell-EncodedCommand-Sigma-Rule.png` |
| Day04-09 | Splunk SPL query | `Day04-09-PowerShell-EncodedCommand-SPL-Query.png` |

All evidence is stored under:

~~~text
screenshots/Day04/
~~~

---

# 19. Repository Artifacts

## Sigma Rule

~~~text
sigma-rules/windows/execution/windows-powershell-encoded-command.yml
~~~

## Splunk Query

~~~text
splunk-queries/process-creation/powershell-encoded-command.spl
~~~

## Validation Report

~~~text
validation/rule-003-validation.md
~~~

## MITRE ATT&CK Coverage

~~~text
mitre-coverage/day04-process-creation-detection.md
~~~

## Day 04 Documentation

~~~text
docs/Day04.md
~~~

## Evidence

~~~text
screenshots/Day04/
~~~

---

# 20. Quantified Day 04 Outcomes

Day 04 produced the following measurable outcomes:

- **11,956** Windows process-creation events analyzed.
- **369** unique process-parent relationships identified.
- **2,673** unique process-command-line-parent combinations identified.
- **402** PowerShell-related events analyzed.
- **31** PowerShell process/command-line combinations identified.
- **0** suspicious encoded-command matches existed in the initial baseline.
- **1** controlled encoded-command event generated.
- **1** controlled event detected.
- **1** Sigma rule created.
- **1** Splunk detection query created.
- **1** validation report created.
- **1** MITRE ATT&CK technique mapped.
- **9** evidence screenshots captured.

---

# 21. Skills Demonstrated

Day 04 demonstrates practical experience in:

- Windows Event ID `4688` analysis.
- Windows process-creation monitoring.
- Process parent-child relationship analysis.
- PowerShell telemetry analysis.
- Command-line investigation.
- Splunk Cloud searching.
- SPL development.
- Sigma rule development.
- Detection-as-code methodology.
- Baseline analysis.
- Controlled detection validation.
- False-positive awareness.
- MITRE ATT&CK mapping.
- Evidence collection.
- SOC investigation documentation.

---

# 22. Detection Engineering Methodology Demonstrated

The work completed on Day 04 demonstrates a practical detection engineering lifecycle:

### 1. Telemetry Assessment

Determine whether the required Windows telemetry exists and contains useful fields.

### 2. Baseline Development

Understand normal process and PowerShell activity before defining suspicious behavior.

### 3. Detection Hypothesis

Identify a specific behavior that can be detected using available telemetry.

### 4. Controlled Validation

Generate known test activity instead of assuming the detection works.

### 5. Detection Implementation

Implement the detection using Sigma and Splunk SPL.

### 6. Evidence Collection

Capture screenshots and preserve the results.

### 7. ATT&CK Mapping

Map the observed behavior to the relevant MITRE ATT&CK technique.

This process makes the detection reproducible and evidence-driven.

---

# 23. Day 04 Completion Checklist

- [x] Event ID `4688` analyzed.
- [x] Process-creation telemetry fields identified.
- [x] Process creation baseline established.
- [x] Process command-line baseline established.
- [x] PowerShell activity analyzed.
- [x] Suspicious PowerShell indicators searched.
- [x] Baseline returned `0` suspicious matches.
- [x] Controlled PowerShell test performed.
- [x] Event ID `4688` captured the test.
- [x] Sigma Rule 003 created.
- [x] Splunk SPL detection created.
- [x] Detection successfully validated.
- [x] Validation report created.
- [x] MITRE ATT&CK mapping completed.
- [x] Evidence screenshots captured.
- [x] Quantified outcomes documented.
- [x] Day 04 documentation completed.

---

# 24. Final Day 04 Summary

Day 04 expanded the Detection Engineering Lab from authentication monitoring into Windows process-execution monitoring.

The investigation began with **11,956 Event ID `4688` events**, providing a broad baseline of process creation activity.

Process and command-line analysis established that the Windows client was providing detailed process telemetry.

PowerShell analysis identified **402 PowerShell-related events**, demonstrating that generic PowerShell detection would include significant legitimate activity.

A focused search for selected encoded-command indicators returned **0 baseline matches**.

A controlled PowerShell encoded-command execution was then generated to validate the detection.

The resulting Event ID `4688` was successfully collected by Splunk Cloud and identified by the final SPL detection.

The final validation produced:

~~~text
1 controlled test event
        ↓
1 Event ID 4688
        ↓
1 SPL detection match
        ↓
Successful validation
~~~

The detection was implemented in both **Sigma** and **Splunk SPL** and mapped to **MITRE ATT&CK T1059.001 — PowerShell**.

Day 04 therefore demonstrates an end-to-end process-creation detection workflow based on real Windows telemetry, controlled validation, detection-as-code, SIEM implementation, ATT&CK mapping, and evidence-based documentation.