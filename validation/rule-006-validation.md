# Rule 006 Validation — Windows Local Administrator Group Membership Change

## 1. Validation Overview

**Rule:** Windows Local Administrator Group Membership Change  
**Rule ID:** `84b6c2d7-4732-4e91-a306-008fa1ed0a08`  
**Event ID:** `4732`  
**Detection Type:** Privilege / Account Manipulation  
**Severity:** High  
**Platform:** Windows  
**SIEM:** Splunk Cloud  
**Detection Format:** Sigma + SPL  
**Validation Date:** 2026-09-21  
**Host:** `WIN10-CLIENT`

### Validation Objective

Validate that a controlled addition of an account to the local Windows `Administrators` group:

1. Generates Windows Security Event ID 4732.
2. Is successfully ingested into Splunk Cloud.
3. Can be identified using extracted event fields.
4. Can be correlated to the controlled test account using its SID.
5. Is detected by the Rule 006 SPL implementation.
6. Is represented as a reusable Sigma detection rule.

---

## 2. Detection Scenario

Windows Security Event ID 4732 records a member being added to a security-enabled local group.

For this validation, the monitored security-sensitive group was:

`Administrators`

The controlled test account was:

`D7TestUser`

The objective was to demonstrate the complete detection lifecycle:

~~~text
Controlled Account Creation
        ↓
D7TestUser Added to Administrators
        ↓
Windows Security Event ID 4732
        ↓
Splunk Cloud Ingestion
        ↓
Member SID Correlation
        ↓
SPL Detection
        ↓
Sigma Detection Rule
~~~

---

## 3. Initial Telemetry Assessment

Before creating the detection, the Windows Security telemetry available in Splunk was reviewed.

The Event ID baseline confirmed the presence of Event ID `4732`.

The baseline contained two existing 4732 events.

The initial events included local group membership changes involving groups such as:

- `Performance Monitor Users`
- `Users`

This confirmed that Event ID 4732 was available in the environment and could be used as the telemetry source for the detection.

### Evidence

![Day 07 Local Group Membership Change](../screenshots/Day07/Day07-01-Local-Group-Membership-Change.png)

---

## 4. Raw Event Validation

The raw 4732 event was inspected before developing the detection.

The event contained relevant Windows Security information including:

- Event ID: `4732`
- Host: `WIN10-CLIENT`
- Subject account
- Subject domain
- Member Security ID
- Group Security ID
- Group Name
- Group Domain
- Event message

The raw event confirmed that the required security information was present even though some fields were not automatically extracted into Splunk.

### Evidence

![Day 07 Local Group Membership Raw Event](../screenshots/Day07/Day07-02-Local-Group-Membership-Raw-Event.png)

---

## 5. Field Extraction Validation

Because the initial Splunk field extraction did not expose all relevant 4732 fields, fields were extracted from `_raw` using SPL `rex` operations.

The following fields were extracted:

- `SubjectAccount`
- `SubjectDomain`
- `GroupName`
- `GroupDomain`
- `MemberSID`

The extraction successfully returned the expected values from the existing 4732 events.

### Example Extraction Logic

~~~spl
| rex field=_raw "Account Name:\s+(?<SubjectAccount>[^\r\n]+)"
| rex field=_raw "Account Domain:\s+(?<SubjectDomain>[^\r\n]+)"
| rex field=_raw "Group Name:\s+(?<GroupName>[^\r\n]+)"
| rex field=_raw "Group Domain:\s+(?<GroupDomain>[^\r\n]+)"
| rex field=_raw "Member:\s+Security ID:\s+(?<MemberSID>[^\r\n]+)"
~~~

### Evidence

![Day 07 Local Group Field Extraction](../screenshots/Day07/Day07-03-Local-Group-Field-Extraction.png)

---

## 6. Account Creation Telemetry Assessment

Event ID `4720` was also checked to determine whether Windows user-account creation events were available for a second Day 07 detection scenario.

The search returned:

**0 events**

Because account-creation telemetry was not present in the collected dataset, the project did not create an unvalidated 4720 detection.

The Day 07 detection was therefore focused on the verified Event ID 4732 telemetry.

This demonstrates a telemetry-driven detection engineering approach rather than assuming that every Windows security event is available.

### Evidence

![Day 07 User Account Creation Baseline](../screenshots/Day07/Day07-04-User-Account-Creation-Baseline.png)

---

## 7. Controlled Validation Activity

A temporary local Windows account was created specifically for detection validation:

`D7TestUser`

The account was then added to the local:

`Administrators`

group.

The activity was performed intentionally on the isolated Windows lab endpoint to generate a known Event ID 4732.

The controlled commands completed successfully.

### Controlled Test Actions

~~~powershell
net user D7TestUser "Temp-D7-Test-2026!" /add

net localgroup Administrators D7TestUser /add
~~~

The first command created the temporary account.

The second command added the account to the local Administrators group.

### Evidence

![Day 07 Privileged Group Change Test](../screenshots/Day07/Day07-05-Privileged-Group-Change-Test.png)

---

## 8. Test Account SID Correlation

The Security Event 4732 did not expose the test account name directly in the `Member Account Name` field.

Instead, Windows recorded the member's Security Identifier (SID).

The SID of `D7TestUser` was therefore retrieved directly from Windows:

~~~powershell
Get-LocalUser -Name D7TestUser | Select-Object Name,SID
~~~

The returned SID was:

~~~text
D7TestUser
S-1-5-21-1757041310-2260995295-2021039635-1002
~~~

The same SID appeared in the Event ID 4732 `Member` field in Splunk.

This established a direct correlation:

~~~text
D7TestUser
    ↓
S-1-5-21-1757041310-2260995295-2021039635-1002
    ↓
Event ID 4732
    ↓
Administrators group
~~~

### Evidence

![Day 07 Test Account SID Correlation](../screenshots/Day07/Day07-06-Test-Account-SID-Correlation.png)

---

## 9. Windows Event 4732 Detection

The generated Event ID 4732 was successfully ingested into Splunk Cloud.

Observed event details included:

| Field | Observed Value |
|---|---|
| Event ID | `4732` |
| Host | `WIN10-CLIENT` |
| Subject Account | `Administrator` |
| Subject Domain | `CORP` |
| Group Name | `Administrators` |
| Group Domain | `Builtin` |
| Member SID | `S-1-5-21-1757041310-2260995295-2021039635-1002` |
| Detection Scenario | Local Administrator Group Membership Change |

The event timestamp was:

`2026-09-21 14:49:57.358`

### Evidence

![Day 07 Administrators Group Detection](../screenshots/Day07/Day07-07-Administrators-Group-Detection.png)

---

## 10. SPL Detection Implementation

The validated Splunk detection was implemented in:

`../splunk-queries/account-privilege/local-administrator-group-membership-change.spl`

### Detection Logic

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

### SPL Validation Result

The query returned the controlled Event ID 4732 event.

Detection output included:

- `WIN10-CLIENT`
- `Administrator`
- `CORP`
- `Administrators`
- `Builtin`
- Controlled test account SID
- Event ID `4732`
- Detection label: `Local Administrator Group Membership Change`

### Quantified Result

**1 controlled privileged-group change → 1 matching SPL detection**

**Detection coverage for the controlled test: 100%**

---

## 11. Sigma Detection Rule

The Sigma implementation is stored at:

`../sigma-rules/windows/account-privilege/windows-local-administrator-group-membership-change.yml`

### Rule Details

| Attribute | Value |
|---|---|
| Rule | Windows Local Administrator Group Membership Change |
| UUID | `84b6c2d7-4732-4e91-a306-008fa1ed0a08` |
| Status | Experimental |
| Event ID | `4732` |
| Target Group | `Administrators` |
| Severity | High |
| Platform | Windows |
| Log Source | Windows Security |

### Sigma Detection Logic

~~~yaml
detection:
  selection:
    EventID: 4732
    TargetUserName: Administrators
  condition: selection
~~~

The Sigma rule represents the normalized Windows event logic, while the Splunk implementation uses the `GroupName` field extracted from the raw event.

### Evidence

![Day 07 Local Administrator Sigma Rule](../screenshots/Day07/Day07-08-Local-Administrator-Sigma-Rule.png)

---

## 12. Detection Validation Results

| Validation Step | Expected Result | Actual Result | Status |
|---|---|---|---|
| Event 4732 telemetry available | Event present | 2 baseline events observed | PASS |
| Controlled account creation | Account created | `D7TestUser` created | PASS |
| Administrator group modification | Account added | `D7TestUser` added | PASS |
| Windows Security event | Event 4732 generated | Event 4732 observed | PASS |
| Splunk ingestion | Event searchable | Event ingested | PASS |
| Group identification | Administrators identified | `Administrators` identified | PASS |
| SID correlation | Test account SID matches event | SID matched | PASS |
| SPL detection | Controlled event detected | 1 detection | PASS |
| Sigma implementation | Rule created | Rule 006 created | PASS |

---

## 13. Quantified Validation Outcome

The controlled validation produced the following measurable result:

- **1** temporary test account created
- **1** privileged local-group membership change performed
- **1** Event ID 4732 observed for the controlled change
- **1** matching Splunk detection
- **1** Sigma detection rule created
- **100%** detection rate for the controlled validation event

### Detection Chain

~~~text
1 Controlled Action
        ↓
1 Windows Security Event 4732
        ↓
1 Splunk Detection
        ↓
1 Sigma Detection Rule
~~~

---

## 14. SOC Investigation Perspective

From a SOC analyst perspective, an account being added to the local `Administrators` group is a security-relevant change that warrants investigation.

The detection provides the analyst with several useful investigation fields:

- Timestamp
- Host
- Account performing the change
- Account domain
- Target group
- Group domain
- Member SID

The `MemberSID` can also be correlated with endpoint account information when the member account name is not directly available in the Windows event.

For investigation, analysts should determine:

1. Who performed the group membership change?
2. Which account was added?
3. Was the change authorized?
4. Was the account expected to receive administrative privileges?
5. Was the change performed interactively or by an administrative tool?
6. Were additional suspicious events generated around the same timestamp?
7. Was the privileged access temporary or persistent?

This allows the detection to function as an investigation starting point rather than simply generating an isolated alert.

---

## 15. False-Positive Considerations

Legitimate administrative activity can generate Event ID 4732.

Potential benign sources include:

- Authorized IT administration
- Endpoint management platforms
- Software installation
- System configuration
- Help-desk activity
- Administrative troubleshooting

The detection should therefore be investigated in context rather than automatically treated as malicious.

Useful contextual fields include:

- Subject account
- Host
- Target group
- Member SID
- Event timestamp
- Related process or authentication activity

---

## 16. MITRE ATT&CK Mapping

### T1098 — Account Manipulation

The detection supports investigation of account manipulation involving membership changes that can alter the effective privileges of an account.

The observed behavior specifically involved adding an account to the local `Administrators` group.

The project does not classify the controlled activity itself as malicious. The controlled action was intentionally generated to validate detection coverage.

---

## 17. Evidence Register

| Evidence | Purpose |
|---|---|
| `Day07-01-Local-Group-Membership-Change.png` | Baseline Event 4732 telemetry |
| `Day07-02-Local-Group-Membership-Raw-Event.png` | Raw Windows Event 4732 validation |
| `Day07-03-Local-Group-Field-Extraction.png` | Splunk field extraction validation |
| `Day07-04-User-Account-Creation-Baseline.png` | Event 4720 telemetry assessment |
| `Day07-05-Privileged-Group-Change-Test.png` | Controlled privileged-group change |
| `Day07-06-Test-Account-SID-Correlation.png` | Test account SID correlation |
| `Day07-07-Administrators-Group-Detection.png` | Splunk detection result |
| `Day07-08-Local-Administrator-Sigma-Rule.png` | Sigma Rule 006 implementation |

All evidence is stored under:

`../screenshots/Day07/`

---

## 18. Repository Artifacts

### Sigma Rule

`../sigma-rules/windows/account-privilege/windows-local-administrator-group-membership-change.yml`

### SPL Query

`../splunk-queries/account-privilege/local-administrator-group-membership-change.spl`

### Validation Report

`rule-006-validation.md`

### Planned MITRE Coverage

`../mitre-coverage/day07-account-privilege-detection.md`

---

## 19. Final Validation Statement

Rule 006 was successfully validated using a controlled Windows security activity.

A temporary account named `D7TestUser` was added to the local `Administrators` group. Windows generated Security Event ID 4732, the event was successfully ingested into Splunk Cloud, and the member SID was correlated back to the controlled test account.

The validated SPL detection returned the expected event, producing **1 detection from 1 controlled privileged-group membership change**.

The detection logic was then formalized as a Sigma rule for reusable detection engineering.

**Final Result: PASS**

**Controlled Event:** 1  
**Detected Events:** 1  
**Detection Rate:** 100%  
**Sigma Rule:** Rule 006  
**MITRE ATT&CK:** T1098 — Account Manipulation