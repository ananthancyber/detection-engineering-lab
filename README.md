# Detection Engineering Lab

**Building and validating Sigma detection rules against live Windows telemetry in Splunk Cloud — from log pipeline to MITRE ATT&CK-mapped, controlled-test-proven detections.**

[![Platform](https://img.shields.io/badge/Platform-Splunk%20Cloud-black?logo=splunk)](https://www.splunk.com/)
[![Endpoint](https://img.shields.io/badge/Endpoint-Windows%2010-blue?logo=windows)](https://www.microsoft.com/windows)
[![Detection Format](https://img.shields.io/badge/Detection-Sigma-orange)](https://sigmahq.io/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Rules](https://img.shields.io/badge/Detections-7%20Validated-brightgreen)](#detection-coverage)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

---

## 30-Second Summary

| | |
|---|---|
| **What it is** | A self-built SOC lab: Windows endpoint → Splunk Cloud → Sigma detections, each one proven against a controlled attack simulation |
| **Detections shipped** | 7 validated rules (2 correlation-based, 5 event-based) across credential access, execution, persistence, lateral movement, privilege escalation, and discovery |
| **MITRE ATT&CK coverage** | T1110, T1059.001, T1053.005, T1078, T1098.007, T1069.001 |
| **Validation method** | Every rule: baseline → controlled attack → confirm detection fires → document false positives. Not "should detect" — **does detect**, with counts |
| **Biggest number** | Scoped a 1,019-event noisy discovery baseline down to a single, process-specific, low-noise detection rule |
| **Timeline** | 8 documented working days, each with narrative log, evidence screenshots, Sigma rule, SPL query, and validation report |

**If you only read one thing:** every detection in this repo was validated by *causing the exact behavior it's supposed to catch* and confirming a 1:1 match — not assumed to work.

---

## Table of Contents

- [Detection Engineering Lab](#detection-engineering-lab)
  - [30-Second Summary](#30-second-summary)
  - [Table of Contents](#table-of-contents)
  - [Why This Project](#why-this-project)
  - [Detection Coverage](#detection-coverage)
  - [How Every Rule Was Validated](#how-every-rule-was-validated)
  - [Lab Environment](#lab-environment)
  - [Repository Structure](#repository-structure)
  - [Day-by-Day Build Log](#day-by-day-build-log)
  - [Worked Example — Correlation Rule](#worked-example--correlation-rule)
  - [Skills Demonstrated](#skills-demonstrated)
  - [Author](#author)
  - [Disclaimer](#disclaimer)
  - [License](#license)

---

## Why This Project

Most beginner SIEM projects stop at "I installed Splunk and ran a search." This one exists to answer the question a SOC hiring manager actually asks: **can this person go from a security event log to a working, tested detection rule, and know why it might be wrong?**

Every rule here follows the same discipline a working detection engineer uses:

1. Look at what telemetry actually exists — don't assume it.
2. Baseline normal activity before writing a rule (a rule that fires on everything is useless).
3. Generate the exact malicious behavior in a controlled way.
4. Confirm the rule catches it — and only it.
5. Write down the false positives, because every rule has them.
6. Map to MITRE ATT&CK so the detection has language a SOC team already speaks.

Twice during this project (Day 05, Day 07) the originally planned detection had to be **abandoned** because the required telemetry wasn't actually present in the environment. Both pivots are documented in the day logs rather than hidden — that's a more useful signal of real engineering judgment than a repo where everything went according to plan.

---

## Detection Coverage

| # | Detection | Event ID(s) | MITRE ATT&CK | Type | Validated Result |
|---|---|---|---|---|---|
| 001 | Windows Failed Logon Attempt | 4625 | T1110 — Brute Force | Event | 36 events analyzed, detection confirmed |
| 002 | Multiple Failed Logons (5+ in 5 min) | 4625 | T1110 — Brute Force | Correlation | 3/3 correlation windows correctly matched |
| 003 | PowerShell Encoded Command Execution | 4688 | T1059.001 — PowerShell | Event | 402 PowerShell events baselined → 1/1 controlled detection |
| 004 | Windows Scheduled Task Created | 4698 | T1053.005 — Scheduled Task | Event | 1/1 controlled detection, 100% rate |
| 005 | Failed → Successful Network Logon Sequence | 4624 + 4625 | T1078 — Valid Accounts | Correlation | 62 events evaluated → 2 matching sequences found |
| 006 | Local Administrator Group Membership Change | 4732 | T1098.007 — Account Manipulation | Event | SID-correlated, 1/1 controlled detection |
| 007 | Administrators Group Enumeration via `net1.exe` | 4799 | T1069.001 — Permission Groups Discovery | Event (process-scoped) | 1,019-event baseline scoped to 1 precise match |

Every row links to a real Sigma rule, a real SPL query, and a real validation report with quantified results — see [Repository Structure](#repository-structure).

---

## How Every Rule Was Validated

```
Windows Security Telemetry
        ↓
Baseline: what's normal, what's noisy
        ↓
Sigma Rule + Matching SPL Query
        ↓
Controlled Attack Simulation (generate the exact behavior)
        ↓
Confirm Detection Fires — 1:1
        ↓
Document False Positives
        ↓
Map to MITRE ATT&CK
        ↓
Capture Evidence
```

This is not a design diagram — it's the literal sequence followed on all 8 days, with a validation report to prove each step for each rule.

---

## Lab Environment

| Component | Details |
|---|---|
| Host Operating System | Windows 11 |
| Monitored Endpoint | Windows 10 Client VM (`WIN10-CLIENT`) |
| Domain | `CORP` / `CORP.LOCAL` |
| SIEM Platform | Splunk Cloud |
| Log Collection Agent | Splunk Universal Forwarder 10.4.3 |
| Log Source | Windows Security Event Log |
| Splunk Index / Sourcetype | `main` / `WinEventLog:Security` |
| Forwarding | Port `9997` over SSL |
| Detection Format | Sigma (event + correlation rules) |
| Query Language | Splunk Processing Language (SPL) |
| Framework | MITRE ATT&CK |

**Tools:** Splunk Cloud · Splunk Universal Forwarder · Sigma · SPL (`rex`, `stats`, `eval`, correlation) · MITRE ATT&CK · PowerShell / `net` commands for controlled simulation · Git/GitHub

---

## Repository Structure

```
detection-engineering-lab/
│
├── docs/                    Day-by-day build logs (Day01–Day08)
│
├── sigma-rules/windows/
│   ├── credential-access/   Failed logon, repeated failed logon
│   ├── execution/           PowerShell encoded command
│   ├── persistence/         Scheduled task creation
│   ├── lateral-movement/    Network logon + failed→success correlation
│   ├── account-privilege/   Local admin group membership change
│   └── discovery/           Administrators group enumeration
│
├── splunk-queries/          One SPL file per detection, mirrors sigma-rules/
│
├── mitre-coverage/          Full ATT&CK-mapped writeup per detection day
│
├── validation/              rule-001 → rule-007, each with quantified pass/fail results
│
├── screenshots/             Evidence, organized by day
│
├── LICENSE
└── README.md
```

---

## Day-by-Day Build Log

| Day | Focus | Key Result |
|---|---|---|
| 01–02 | SIEM foundation | Splunk Cloud + Universal Forwarder live; 4624/4625/4688 confirmed indexed |
| 03 | Authentication detection | Rules 001–002 — failed logon + 5-in-5-min correlation |
| 04 | Process creation / PowerShell | 11,956 events baselined → Rule 003, 1/1 controlled detection |
| 05 | Persistence | Pivoted from registry (telemetry unavailable) to scheduled tasks → Rule 004 |
| 06 | Network authentication correlation | Rule 005 — temporal correlation across 62 events, 2 matches found |
| 07 | Account & privilege | Rule 006 — SID-correlated Administrators group change detection |
| 08 | Discovery | 1,019-event noisy baseline scoped to Rule 007, precision over recall |

Full detail for each day: [`docs/Day01.md`](docs/Day01.md) → [`docs/Day08.md`](docs/Day08.md) · Full MITRE writeups: [`mitre-coverage/`](mitre-coverage/) · Full validation data: [`validation/`](validation/)

---

## Worked Example — Correlation Rule

**Rule 002 — Multiple Failed Logon Attempts (5+ in 5 minutes)**

```yaml
title: Multiple Windows Failed Logon Attempts
id: 8a4e2f31-4625-4b7d-9c20-002fa1ed0a02
status: experimental
correlation:
  type: event_count
  rules:
    - 7f2c9d1e-4625-4a6b-9f31-001fa1ed0a01
  group-by:
    - Source_Network_Address
  timespan: 5m
  condition:
    gte: 5
level: medium
tags:
  - attack.credential_access
  - attack.t1110
```

```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625
| bin _time span=5m
| stats count dc(Account_Name) as unique_accounts values(Account_Name) as targeted_accounts values(Logon_Type) as logon_types by _time, Source_Network_Address, host
| where count >= 5
| sort - count
```

**Validated result:** 3 matching 5-minute windows, 8–10 failed logons each. The source resolved to the loopback interface — correctly flagged as "activity requiring investigation," **not** auto-classified as a confirmed attack. That distinction is documented in [`validation/rule-002-validation.md`](validation/rule-002-validation.md) and is exactly the kind of judgment call a SOC analyst has to make on every real alert.

---

## Skills Demonstrated

`SIEM pipeline setup` · `Sigma rule authoring (event + correlation)` · `SPL development & field extraction` · `Controlled attack simulation` · `Telemetry-driven scoping` · `False-positive analysis & tuning` · `SID-based identity correlation` · `MITRE ATT&CK mapping` · `Evidence-based technical documentation`

Maps directly to: **SOC Analyst L1** · **Detection Engineering Intern** · **Blue Team Analyst** · **Security Monitoring Analyst**

---

## Author

**Ananthan D**
B.Tech Information Technology Graduate — Cybersecurity & SOC Analyst Aspirant

- GitHub: [ananthancyber](https://github.com/ananthancyber)
- LinkedIn: [Ananthan D](https://www.linkedin.com/in/ananthan-d-ab295321b)

---

## Disclaimer

Educational, portfolio-purpose project in a controlled lab environment. All simulated attack activity (failed logons, encoded PowerShell, scheduled tasks, privilege changes, discovery commands) was performed only against an isolated, authorized Windows 10 VM owned by the author. No unauthorized systems, networks, or accounts were targeted.

## License

MIT License — see [LICENSE](LICENSE).