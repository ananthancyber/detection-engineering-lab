# Day 07 — Account & Privilege Activity Detection

**Project:** Detection Engineering Lab  
**Focus:** Windows Account & Privilege Activity  
**Platform:** Windows 10 · Splunk Cloud · Sigma · Windows Security Logs  
**Detection:** Local Administrators Group Membership Change  
**MITRE ATT&CK:** T1098.007 — Account Manipulation: Additional Local or Domain Groups  
**Status:** Completed and Validated

---

## 1. Overview

Day 07 focused on detecting **account and privilege-related activity** within the Windows environment.

The primary detection scenario was the addition of a user to the local **Administrators** security group using Windows Security Event ID **4732**.

The objective was to follow a telemetry-driven detection engineering workflow:

1. Assess available Windows Security telemetry.
2. Identify relevant account and privilege-related events.
3. Analyze Event ID 4732.
4. Validate the event structure and available fields.
5. Perform a controlled privileged-group membership change.
6. Correlate the generated event with the test account's Security Identifier (SID).
7. Develop a Splunk detection query.
8. Implement the detection as a Sigma rule.
9. Validate the detection using real Windows telemetry.
10. Document the detection and map it to MITRE ATT&CK.

This approach demonstrates how a SOC analyst can move from **raw telemetry → detection logic → controlled validation → documented detection engineering evidence**.

---

## 2. Objectives

The objectives for Day 07 were:

- Analyze Windows Security Event ID 4732.
- Identify local security group membership changes.
- Assess whether account creation telemetry was available.
- Identify the local Administrators group as a privileged security target.
- Generate a controlled group membership change.
- Verify the resulting Windows security event in Splunk.
- Correlate the detected event with the test account SID.
- Develop a reusable SPL detection.
- Create Sigma Rule 006.
- Validate the detection with measurable results.
- Map the behavior to MITRE ATT&CK T1098.007.

---

## 3. Lab Environment

| Component | Configuration |
|---|---|
| Endpoint | WIN10-CLIENT |
| Operating System | Windows 10 |
| Domain | CORP |
| SIEM | Splunk Cloud |
| Log Source | Windows Security Event Log |
| Forwarder | Splunk Universal Forwarder |
| Primary Event | Event ID 4732 |
| Detection Format | Sigma |
| Query Language | SPL |
| ATT&CK Mapping | T1098.007 |

---

# 4. Telemetry Assessment

Before creating a detection, the available Windows Security telemetry was reviewed.

The following SPL query was used to identify the available Security Event IDs:

~~~spl
index=main sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort EventCode
~~~

The telemetry baseline showed multiple Windows Security events, including:

| Event ID | Count | Relevance |
|---:|---:|---|
| 4624 | 1,150 | Successful authentication |
| 4625 | 36 | Failed authentication |
| 4672 | 1,011 | Special privileges assigned |
| 4688 | 13,685 | Process creation |
| 4698 | 2 | Scheduled task creation |
| 4732 | 2 | Local security group membership change |
| 4798 | 410 | User local group membership enumeration |
| 4799 | 570 | Security-enabled local group enumeration |

The presence of **Event ID 4732** provided suitable telemetry for detecting local security group membership changes.

### Evidence

![Day 07 Windows Security Event Baseline](../screenshots/Day07/Day07-01-Local-Group-Membership-Change.png)

**Evidence:** `Day07-01-Local-Group-Membership-Change.png`

---

# 5. Event ID 4732 Analysis

Windows Security Event ID **4732** represents the addition of a member to a security-enabled local group.

The event was investigated using:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| table _time host Account_Name Member_Name Member_ID TargetUserName TargetDomainName SubjectUserName SubjectDomainName Group_Name EventCode Message
| sort - _time
~~~

The available events showed local security group membership changes on `WIN10-CLIENT`.

One observed event contained:

- Host: `WIN10-CLIENT`
- Subject Account: `WIN10-CLIENT$`
- Subject Domain: `CORP`
- Group: `Performance Monitor Users`
- Group Domain: `Builtin`
- Event ID: `4732`

This confirmed that Event ID 4732 was being successfully collected and could provide useful security group membership telemetry.

---

# 6. Raw Event Validation

The raw Windows Security event was reviewed to understand the original event structure before developing the detection.

Query:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| table _time host _raw Message
| sort - _time
~~~

The raw event contained important fields including:

- Subject Account Name
- Subject Account Domain
- Member Security ID
- Group Name
- Group Domain
- Event ID
- Event description

The raw event confirmed that the required information was present even when some normalized Splunk fields were not automatically populated.

### Evidence

![Day 07 Raw Event](../screenshots/Day07/Day07-02-Local-Group-Membership-Raw-Event.png)

**Evidence:** `Day07-02-Local-Group-Membership-Raw-Event.png`

---

# 7. Field Extraction

Because the required group and account fields were not consistently available as normalized Splunk fields, the relevant values were extracted directly from `_raw`.

The following SPL was used:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| rex field=_raw "Account Name:\s+(?<SubjectAccount>[^\r\n]+)"
| rex field=_raw "Account Domain:\s+(?<SubjectDomain>[^\r\n]+)"
| rex field=_raw "Group Name:\s+(?<GroupName>[^\r\n]+)"
| rex field=_raw "Group Domain:\s+(?<GroupDomain>[^\r\n]+)"
| rex field=_raw "Member:\s+Security ID:\s+(?<MemberSID>[^\r\n]+)"
| table _time host SubjectAccount SubjectDomain GroupName GroupDomain MemberSID EventCode
| sort - _time
~~~

The extraction successfully identified:

- Subject account
- Subject domain
- Group name
- Group domain
- Member SID
- Event ID

### Evidence

![Day 07 Field Extraction](../screenshots/Day07/Day07-03-Local-Group-Field-Extraction.png)

**Evidence:** `Day07-03-Local-Group-Field-Extraction.png`

---

# 8. Administrators Group Telemetry Assessment

The local `Administrators` group was selected as the primary detection target because membership in this group provides elevated local privileges.

The existing Event ID 4732 telemetry was filtered for the Administrators group:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| rex field=_raw "Account Name:\s+(?<SubjectAccount>[^\r\n]+)"
| rex field=_raw "Account Domain:\s+(?<SubjectDomain>[^\r\n]+)"
| rex field=_raw "Group Name:\s+(?<GroupName>[^\r\n]+)"
| rex field=_raw "Group Domain:\s+(?<GroupDomain>[^\r\n]+)"
| rex field=_raw "Member:\s+Security ID:\s+(?<MemberSID>[^\r\n]+)"
| search GroupName="Administrators"
| table _time host SubjectAccount SubjectDomain GroupName GroupDomain MemberSID EventCode
| sort - _time
~~~

The baseline returned **0 existing Administrators group membership changes**.

This established a clean baseline for the controlled validation.

---

# 9. Account Creation Telemetry Assessment

Account creation telemetry was also evaluated using Windows Security Event ID 4720.

Query:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4720
| table _time host Account_Name SubjectUserName SubjectDomainName TargetUserName TargetDomainName EventCode Message
| sort - _time
~~~

The query returned **0 events**.

This confirmed that account creation was not the most suitable detection scenario for the current validated telemetry.

### Evidence

![Day 07 Account Creation Baseline](../screenshots/Day07/Day07-04-User-Account-Creation-Baseline.png)

**Evidence:** `Day07-04-User-Account-Creation-Baseline.png`

---

# 10. Controlled Privileged Group Membership Test

A controlled test account was created on `WIN10-CLIENT` specifically for detection validation.

Test account:

~~~text
D7TestUser
~~~

The account was added to the local Administrators group using:

~~~powershell
net user D7TestUser "Temp-D7-Test-2026!" /add

net localgroup Administrators D7TestUser /add
~~~

Both operations completed successfully.

The purpose of this activity was strictly to generate a known Windows Security Event 4732 so that the detection could be validated against a controlled event.

### Evidence

![Day 07 Privileged Group Change Test](../screenshots/Day07/Day07-05-Privileged-Group-Change-Test.png)

**Evidence:** `Day07-05-Privileged-Group-Change-Test.png`

---

# 11. Test Account SID Correlation

The Security Identifier of the test account was retrieved from Windows:

~~~powershell
Get-LocalUser -Name D7TestUser | Select-Object Name,SID
~~~

The returned SID was:

~~~text
S-1-5-21-1757041310-2260995295-2021039635-1002
~~~

The same SID appeared in the `MemberSID` field of the corresponding Windows Security Event 4732.

This provided a direct correlation between:

**Controlled account → Windows SID → Security Event 4732 → Splunk detection**

### Evidence

![Day 07 Test Account SID Correlation](../screenshots/Day07/Day07-06-Test-Account-SID-Correlation.png)

**Evidence:** `Day07-06-Test-Account-SID-Correlation.png`

---

# 12. Event ID 4732 Detection

After the controlled test, the generated event was searched in Splunk.

The detection confirmed:

- Event ID: `4732`
- Host: `WIN10-CLIENT`
- Subject Account: `Administrator`
- Subject Domain: `CORP`
- Group Name: `Administrators`
- Group Domain: `Builtin`
- Member SID: `S-1-5-21-1757041310-2260995295-2021039635-1002`

The event message indicated:

~~~text
A member was added to a security-enabled local group.
~~~

The Member SID matched the SID previously retrieved from `D7TestUser`.

### Evidence

![Day 07 Administrators Group Detection](../screenshots/Day07/Day07-07-Administrators-Group-Detection.png)

**Evidence:** `Day07-07-Administrators-Group-Detection.png`

---

# 13. Rule 006 — SPL Detection

The final SPL detection was created at:

~~~text
splunk-queries/account-privilege/local-administrator-group-membership-change.spl
~~~

Detection logic:

~~~spl
index=main sourcetype="WinEventLog:Security" EventCode=4732
| rex field=_raw "Account Name:\s+(?<SubjectAccount>[^\r\n]+)"
| rex field=_raw "Account Domain:\s+(?<SubjectDomain>[^\r\n]+)"
| rex field=_raw "Group Name:\s+(?<GroupName>[^\r\n]+)"
| rex field=_raw "Group Domain:\s+(?<GroupDomain>[^\r\n]+)"
| rex field=_raw "Member:\s+Security ID:\s+(?<MemberSID>[^\r\n]+)"
| search GroupName="Administrators"
| eval Detection="Local Administrator Group Membership Change"
| table _time host SubjectAccount SubjectDomain GroupName GroupDomain MemberSID EventCode Detection
| sort - _time
~~~

The query returned **1 matching event** for the controlled validation.

The detection output identified:

| Field | Result |
|---|---|
| Host | WIN10-CLIENT |
| Subject Account | Administrator |
| Subject Domain | CORP |
| Group | Administrators |
| Group Domain | Builtin |
| Event ID | 4732 |
| Detection | Local Administrator Group Membership Change |

---

# 14. Rule 006 — Sigma Detection

The Sigma rule was created at:

~~~text
sigma-rules/windows/account-privilege/windows-local-administrator-group-membership-change.yml
~~~

Rule ID:

~~~text
84b6c2d7-4732-4e91-a306-008fa1ed0a08
~~~

Detection logic:

~~~yaml
title: Windows Local Administrator Group Membership Change
id: 84b6c2d7-4732-4e91-a306-008fa1ed0a08
status: experimental
description: Detects a member being added to the local Administrators security group using Windows Security Event ID 4732.
author: Ananthan D
date: 2026/09/21

logsource:
  product: windows
  service: security

detection:
  selection:
    EventID: 4732
    TargetUserName: Administrators
  condition: selection

level: high

falsepositives:
  - Legitimate administrative activity
  - Software installation or configuration
  - Endpoint management tools
  - Help desk or IT administration

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1098
~~~

The Sigma rule represents the detection in a platform-independent format, while the Splunk implementation performs the corresponding field extraction and filtering required by the current Splunk telemetry.

### Evidence

![Day 07 Local Administrator Sigma Rule](../screenshots/Day07/Day07-08-Local-Administrator-Sigma-Rule.png)

**Evidence:** `Day07-08-Local-Administrator-Sigma-Rule.png`

---

# 15. Detection Validation Results

The controlled validation produced the following result:

| Validation Item | Result |
|---|---|
| Test account created | Successful |
| Test account added to Administrators | Successful |
| Event ID 4732 generated | Yes |
| Event visible in Splunk | Yes |
| Administrators group identified | Yes |
| Test account SID identified | Yes |
| SID correlated with Event 4732 | Yes |
| SPL detection matched event | Yes |
| Sigma rule created | Yes |
| Detection result | 1 matching event |

### Detection Validation

**Controlled privileged-group membership change:** 1

**Matching Event ID 4732:** 1

**SPL detection matches:** 1

**Detection coverage for the controlled test:** 100%

The controlled validation therefore demonstrated that the detection logic successfully identified the intended activity.

---

# 16. Detection Engineering Workflow

Day 07 followed a practical detection engineering lifecycle:

~~~text
Windows Security Telemetry
          │
          ▼
Telemetry Assessment
          │
          ▼
Event ID 4732 Identification
          │
          ▼
Raw Event Analysis
          │
          ▼
Field Extraction
          │
          ▼
Administrators Group Targeting
          │
          ▼
Controlled Privileged-Group Change
          │
          ▼
Event 4732 Generated
          │
          ▼
SID Correlation
          │
          ▼
SPL Detection
          │
          ▼
Sigma Rule 006
          │
          ▼
Detection Validation
          │
          ▼
MITRE ATT&CK Mapping
~~~

This workflow demonstrates that the detection was developed from **verified telemetry rather than from assumptions about available log data**.

---

# 17. MITRE ATT&CK Mapping

## T1098.007 — Account Manipulation: Additional Local or Domain Groups

The observed behavior maps to:

**MITRE ATT&CK Technique:** T1098 — Account Manipulation

**Sub-technique:** T1098.007 — Account Manipulation: Additional Local or Domain Groups

**Tactics:**
- Persistence
- Privilege Escalation

The behavior observed during validation involved adding a user account to the local `Administrators` security group.

This is consistent with the ATT&CK behavior of modifying account group membership to obtain additional privileges.

### Detection Coverage

| ATT&CK ID | Technique | Detection |
|---|---|---|
| T1098.007 | Account Manipulation: Additional Local or Domain Groups | Event ID 4732 / Administrators group membership change |

---

# 18. SOC Investigation Perspective

From a SOC analyst perspective, an unexpected Event ID 4732 involving the local Administrators group should be investigated because it represents a potentially significant privilege change.

Relevant investigation questions include:

1. **Who performed the change?**
   - Subject account
   - Subject domain

2. **Which account was added?**
   - Member SID
   - Correlation with account information

3. **Which privileged group was modified?**
   - Group name
   - Group domain

4. **When did the change occur?**
   - Event timestamp

5. **Was the activity expected?**
   - Administrative change
   - Software deployment
   - Endpoint management
   - Help desk activity

6. **What happened afterward?**
   - Process creation
   - Authentication activity
   - Additional privilege changes
   - Other suspicious endpoint activity

The detection therefore provides an initial security signal that can be correlated with additional endpoint telemetry during a SOC investigation.

---

# 19. False Positive Considerations

Potential legitimate causes of local Administrators group membership changes include:

- Legitimate administrator activity
- Endpoint management operations
- Software installation
- System configuration
- IT support activity
- Help desk operations
- Automated administrative tooling

Detection output should therefore be investigated using surrounding telemetry and organizational context rather than automatically treated as malicious.

---

# 20. Evidence Register

All Day 07 evidence is stored under:

~~~text
screenshots/Day07/
~~~

| Evidence | Description |
|---|---|
| `Day07-01-Local-Group-Membership-Change.png` | Windows Security event baseline showing available Event IDs |
| `Day07-02-Local-Group-Membership-Raw-Event.png` | Raw Event ID 4732 analysis |
| `Day07-03-Local-Group-Field-Extraction.png` | Extracted Event 4732 fields |
| `Day07-04-User-Account-Creation-Baseline.png` | Event ID 4720 account creation baseline |
| `Day07-05-Privileged-Group-Change-Test.png` | Controlled Administrators group membership test |
| `Day07-06-Test-Account-SID-Correlation.png` | Test account SID correlation |
| `Day07-07-Administrators-Group-Detection.png` | Splunk detection of Administrators group membership change |
| `Day07-08-Local-Administrator-Sigma-Rule.png` | Sigma Rule 006 implementation |

---

# 21. Repository Artifacts

The following Day 07 artifacts were created:

### Detection Rule

~~~text
sigma-rules/windows/account-privilege/windows-local-administrator-group-membership-change.yml
~~~

### Splunk Detection

~~~text
splunk-queries/account-privilege/local-administrator-group-membership-change.spl
~~~

### Validation Report

~~~text
validation/rule-006-validation.md
~~~

### MITRE ATT&CK Documentation

~~~text
mitre-coverage/day07-account-privilege-detection.md
~~~

### Evidence

~~~text
screenshots/Day07/
~~~

---

# 22. Quantified Outcomes

| Metric | Result |
|---|---:|
| Windows Security events available in baseline | 21 event types |
| Event ID 4732 baseline events | 2 |
| Event ID 4720 baseline events | 0 |
| Controlled privileged-group changes | 1 |
| Event ID 4732 generated by test | 1 |
| SID correlations | 1 |
| SPL detection matches | 1 |
| Detection coverage for controlled test | 100% |
| Sigma detection rules added | 1 |
| MITRE ATT&CK sub-techniques mapped | 1 |

---

# 23. Skills Demonstrated

### Security Monitoring
- Windows Security Event Log analysis
- Account and privilege activity monitoring
- Security group membership analysis
- Privileged account activity investigation

### Detection Engineering
- Telemetry-driven detection development
- Raw event analysis
- SPL query development
- Field extraction using `rex`
- Sigma rule development
- Controlled detection validation

### Threat Detection
- Privilege-related activity detection
- Local Administrators group monitoring
- Account manipulation detection
- Event correlation using Security Identifiers

### SOC Investigation
- Baseline analysis
- Event investigation
- User/account correlation
- Detection validation
- False-positive assessment
- Follow-on investigation planning

### Framework Knowledge
- MITRE ATT&CK
- T1098 Account Manipulation
- T1098.007 Additional Local or Domain Groups
---

# 24. Final Day 07 Outcome

Day 07 successfully implemented and validated a **Windows local Administrators group membership detection** using Security Event ID 4732.

The detection engineering process progressed from **telemetry assessment and raw event analysis to controlled privilege-change validation, SID correlation, SPL detection, Sigma implementation, and MITRE ATT&CK mapping**.

The controlled test generated one Event ID 4732, the event was successfully identified in Splunk, the test account SID was correlated with the detected event, and the final SPL detection produced one matching result.

The resulting detection provides a practical SOC capability for identifying changes to the local Administrators group and investigating potential account manipulation and privilege-related activity.

**Day 07 Status: COMPLETE**