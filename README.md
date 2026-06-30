# NexaCorp DFIR: INC-2026-008 - Active Directory Reconnaissance and Kerberoasting

Investigation of an Active Directory credential-access incident against the NexaCorp Windows domain (`nexacorp.lab`). On the evening of Friday 3 July 2026 an attacker authenticated to the domain as a real but low-value helpdesk account (`t.remy`) from a single internal workstation (`bru-ws-01`), ran an automated directory enumeration (SharpHound), then requested a Kerberos service ticket for the service account `svc_report` while deliberately forcing the weak legacy RC4 cipher so the ticket can be cracked offline (Kerberoasting). No exploit and no malware were used: the attacker logged in and abused a by-design feature of Kerberos. Conducted as a solo engagement during the BeCode Brussels Blue & Red Team bootcamp (Mission 08), as the continuation of [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001), [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002), [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003), [INC-2026-004](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004), [INC-2026-005](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005), [INC-2026-006](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-006), and [INC-2026-007](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-007).

[![ci](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-008/actions/workflows/ci.yml/badge.svg)](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-008/actions/workflows/ci.yml)
[![Methodology](https://img.shields.io/badge/methodology-NIST%20SP%20800--61r2-blue.svg)](#methodology)
[![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red.svg)](https://attack.mitre.org/)
[![Detection](https://img.shields.io/badge/detection-Wazuh%20rule-blue.svg)](#detection-engineering)
[![Technique](https://img.shields.io/badge/technique-T1558.003%20Kerberoasting-orange.svg)](https://attack.mitre.org/techniques/T1558/003/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Johan--Emmanuel%20Hatchi-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/johan-emmanuel-hatchi/)

This repository documents a SOC analyst engagement carried out as part of the BeCode Cybersecurity Bootcamp (promotion 2025-2026). It has two deliverables: a Phase 1 forensic investigation and report, and a Phase 2 detection rule (a Wazuh rule for Kerberoasting). It is the eighth incident in the NexaCorp DFIR series and the first of Month 3 (Windows / Active Directory).

## Contents

- [Operational notice](#operational-notice)
- [At a glance](#at-a-glance)
- [Engagement context](#engagement-context)
- [Executive summary](#executive-summary)
- [Kill chain summary](#kill-chain-summary)
- [How to read this repository](#how-to-read-this-repository)
- [Methodology](#methodology)
- [Tools used](#tools-used)
- [Detection engineering](#detection-engineering)
- [Repository layout](#repository-layout)
- [Reproducibility](#reproducibility)
- [Known limits](#known-limits)
- [NexaCorp DFIR series](#nexacorp-dfir-series)
- [Acknowledgments](#acknowledgments)
- [About](#about)
- [License](#license)

---

## Operational notice

This is a training engagement against fictitious infrastructure. NexaCorp Industries is a fictional client used as the scenario for the BeCode Brussels bootcamp. The domain `nexacorp.lab` and its hosts are an isolated lab environment. No production system, customer data, or third party was involved.

All IP addresses, hostnames, and accounts referenced here (`192.168.10.30`, `192.168.10.31`, `t.remy`, `svc_report`, `p.renard`, `bru-ws-01`, and similar) are lab-local artifacts, not real-world threat intelligence. Do not feed them to a production SIEM as IOCs.

---

## At a glance

| Field                | Value                                                                                                                       |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Reference            | INC-2026-008                                                                                                                |
| Affected host        | bru-dc-01.nexacorp.lab (domain controller, 192.168.10.30)                                                                   |
| Workstation involved | bru-ws-01 (192.168.10.31)                                                                                                   |
| Root cause           | Kerberoasting (T1558.003): RC4 service ticket requested for a domain service account, crackable offline                     |
| Outcome              | Service account`svc_report` credential exposed (offline crack), a higher-value pivot                                      |
| Date of incident     | Friday 3 July 2026                                                                                                          |
| Evidence             | security_events.json, sysmon.json, kerberos_roast.pcap, wazuh-alerts.json, domain_spn_accounts.csv, ad_service_accounts.txt |
| Phases               | Phase 1 investigation + Phase 2 detection rule (Wazuh, deployed as rule.id 100011)                                          |
| Related incidents    | INC-2026-007 (Month 2 directory export, likely source of the reused credential)                                             |

| Investigation output    | Value                                                                                         |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| Foothold account        | t.remy (real helpdesk account, used out of hours)                                             |
| Source workstation      | bru-ws-01 (192.168.10.31)                                                                     |
| Technique event         | Windows Event 4769 (Kerberos service ticket requested)                                        |
| Distinguishing property | ticketEncryptionType 0x17 (RC4); 2 of 2697 4769 events, the rest AES 0x12                     |
| Roasted account         | svc_report                                                                                    |
| Targeted SPN            | HTTP/bru-app-01.nexacorp.lab                                                                  |
| Time of roast           | 03 July 2026 21:58:03 UTC (23:58:03 CEST)                                                     |
| Dwell time              | 10 min 50 s (logon to roast)                                                                  |
| SIEM detection gap      | 25 Wazuh alerts that night, all on a failed-logon decoy (rules 60122 / 60204), 0 on the roast |

---

## Engagement context

**Scenario (fictional).** NexaCorp Industries reported suspicious activity against its Active Directory. The engagement was reported by Marc Wauters (IT Infrastructure Manager); the incident occurred on Friday 3 July 2026. The Month 2 fixes (server-side authorization and removal of the `m.renard` backdoor) were real and effective, so the attacker changed surface: from the web application layer to the Windows domain.

**Scope.** A forensic analysis of the evidence bundle (domain controller Security log, Sysmon host telemetry, a Kerberos network capture, the Wazuh alert export, and the IT service-account register), plus a Phase 2 detection deliverable closing the SIEM gap.

**The bridge from Month 2.** Fixing a vulnerability does not un-leak the data that already escaped. The employee directory exported during INC-2026-007 is exactly the intelligence (who works there, what usernames look like) that lets an attacker reuse a low-value helpdesk credential like `t.remy`.

**Educational context.** Delivered during the BeCode Brussels Blue & Red Team bootcamp (November 2025 to September 2026) as Mission 08, the first incident of Month 3 (Windows / Active Directory).

---

## Executive summary

On Friday 3 July 2026 at 21:47 UTC, an attacker authenticated to the NexaCorp domain as `t.remy`, a genuine helpdesk account, from the workstation `bru-ws-01`, outside that operator's working hours. Within two minutes the session ran a heavy directory enumeration (40 directory-access events; SharpHound on the host), then at 21:58 UTC requested two Kerberos service tickets for the service account `svc_report`, both forced to the weak RC4 cipher. The whole sequence took under twelve minutes.

The attacker did not break in with an exploit; they logged in and abused a normal feature of Kerberos. Any authenticated domain user may request a service ticket; the only thing that made this malicious was forcing RC4 (`ticketEncryptionType 0x17`) instead of modern AES, because an RC4 ticket can be cracked offline to recover the service account password. That single property is the entire fingerprint of the attack, which is why the SIEM stayed silent on the part that mattered: of 25 Wazuh alerts that night, all concerned a noisy failed-logon burst from a different host, and none concerned the roast.

The consequence is a newly exposed credential: once cracked, `svc_report`'s password is a higher-value asset than the helpdesk login the attacker started with, and it sets up the next stage of a domain compromise. The incident is rated **High**. Phase 2 of this engagement delivers the Wazuh rule (deployed as rule.id 100011) that detects this class of attack going forward.

---

## Kill chain summary

The attacker moved from a low-value login to an offline-crackable service credential in under twelve minutes:

1. **Foothold**: `t.remy` logs in from `bru-ws-01` (192.168.10.31) at 21:47:13 UTC (Event 4624, type 3), out of hours. A normal TGT request (Event 4768, AES) precedes it; the account is genuine.
2. **Enumeration**: from 21:49:32 UTC, 40 directory-access events (Event 4662) map users, groups and service accounts. Host telemetry shows `SharpHound.exe -c All`.
3. **Kerberoast**: at 21:58:03 and 21:58:07 UTC, two service tickets for `svc_report` are issued with RC4 (Event 4769, `ticketEncryptionType 0x17`). Host telemetry shows `Rubeus.exe kerberoast /rc4opsec`; the capture confirms a TGS-REQ for `HTTP/bru-app-01.nexacorp.lab` with etype 23.
4. **Consequence**: the RC4 service ticket is crackable offline (hashcat mode 13100), exposing the `svc_report` password.

A failed-logon burst from a different host (192.168.10.66) is a separate decoy and is not the attack; the actual breach is the single clean roast from `bru-ws-01`.

---

## How to read this repository

| If you are a...                       | Start here                                                                                                                                                     | Time   |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **Recruiter or hiring manager** | This README + the[report](reports/INC-2026-008_Findings_Report.md) executive summary                                                                              | 5 min  |
| **Management / board**          | The[report](reports/INC-2026-008_Findings_Report.md) executive summary and remediation section (non-technical)                                                    | 10 min |
| **Detection engineer**          | [`detection/README.md`](detection/README.md) + [`detection/kerberoast_detection.xml`](detection/kerberoast_detection.xml)                                        | 15 min |
| **SOC analyst evaluating fit**  | [Report](reports/INC-2026-008_Findings_Report.md) technical analysis + [`detection/`](detection/) (the Wazuh rule)                                                 | 20 min |
| **DFIR practitioner**           | Full[report](reports/INC-2026-008_Findings_Report.md) + [`methodology/attack-timeline.md`](methodology/attack-timeline.md) + [`notes/journal.md`](notes/journal.md) | 30 min |

---

## Methodology

The engagement follows standard incident-response frameworks:

- **NIST SP 800-61r2** (incident handling) and **NIST SP 800-86** (forensic techniques): structure the Detection & Analysis work.
- **SANS PICERL**: the Identification stage is the core of the investigation (event-log, host-telemetry and capture correlation).
- **MITRE ATT&CK Enterprise v15**: every finding is mapped to one or more techniques (see [`methodology/attck-mapping.md`](methodology/attck-mapping.md)). This incident is one primary technique (Kerberoasting, T1558.003) preceded by Account Discovery (T1087.002).
- **Detection engineering**: the Phase 2 deliverable is a Wazuh rule, with a false-positive analysis (see [`detection/README.md`](detection/README.md)).

**Investigation approach.** Group the domain controller Security events by source host and account; isolate the one host that does more than log in (it also enumerates the directory and then requests tickets); use the ticket encryption type as the discriminator to separate the attack from normal Kerberos noise; join the SPN register to the malicious ticket to prove which account was actually targeted; corroborate with host telemetry and the network capture. See [`notes/journal.md`](notes/journal.md).

**Evidence and timestamps.** Log timestamps are UTC; local time is CEST (UTC+2). Timestamps are given in both where it aids the timeline.

---

## Tools used

- **jq**: querying and aggregating the Wazuh-format Security event export (Event ID distribution, encryption-type breakdown, per-host correlation).
- **tshark**: Kerberos network-capture analysis (confirming the TGS-REQ for the targeted SPN and the RC4 etype).
- **base64 / python3**: decoding an obfuscated PowerShell command observed in host telemetry.
- **grep / sort / uniq**: log triage and separating the attack from the failed-logon decoy.

---

## Detection engineering

This engagement includes a Phase 2 detection deliverable. The investigation proved not only the attack but that NexaCorp's SIEM said nothing about the part that mattered: of 25 Wazuh alerts that night, all concerned a noisy failed-logon burst (rules 60122 and 60204), and none concerned the Kerberoast, because a service-ticket request (Event 4769) is, on its own, completely normal.

The gap is closed by a Wazuh rule that keys on the encryption type, not the account name, so it catches any future roast rather than only `svc_report`:

```xml
<rule id="100800" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
  <description>Possible Kerberoasting: service ticket (4769) requested with weak RC4 encryption</description>
  <mitre><id>T1558.003</id></mitre>
</rule>
```

Submitted to the lab Wazuh manager and deployed as **rule.id 100011**. It fires on the RC4 4769 event and stays silent on normal AES (0x12) service tickets, validated live (five rule.id 100011 alerts on a controlled roast of all five SPN accounts, zero on AES). The full design, including a correlation rule for a mass roast, a false-positive analysis, and the dashboard screenshots, is in [`detection/README.md`](detection/README.md) and [`detection/screenshots/`](detection/screenshots/). Detection (this rule) and prevention (disable RC4 domain-wide, move service accounts to gMSA) are complementary controls.

---

## Repository layout

```
NexaCorp-DFIR-INC-2026-008/
├── README.md                      This file
├── LICENSE
├── .gitignore
├── .markdownlint.json
├── .github/
│   └── workflows/
│       └── ci.yml                 markdownlint + typography validation
├── reports/
│   └── INC-2026-008_Findings_Report.md    Markdown source of the findings report
├── detection/
│   ├── kerberoast_detection.xml   Wazuh rule (Phase 2), deployed as rule.id 100011
│   └── README.md                  Detection design, offline proof, false-positive analysis
├── evidence-summary/
│   └── ioc-summary.md             Indicators of compromise
├── methodology/
│   ├── attack-timeline.md         Event-level timeline (UTC and CEST)
│   └── attck-mapping.md           MITRE ATT&CK mapping table
└── notes/
    └── journal.md                 Investigation journal (post-analysis reconstruction)
```

The evidence bundle (event logs, Sysmon, capture, Wazuh alerts) is BeCode lab property and is not committed (see `.gitignore`).

---

## Reproducibility

The evidence bundle is BeCode lab property and is not redistributed. With your own copy, the core findings are reproducible from the domain controller Security log:

```bash
# The discriminator: encryption types across all service-ticket requests (4769)
jq -r '.[] | select(.data.win.system.eventID=="4769") | .data.win.eventdata.ticketEncryptionType' \
  logs/security_events.json | sort | uniq -c

# The attack: the only RC4 (0x17) service tickets, with target and source
jq -r '.[] | select(.data.win.system.eventID=="4769" and .data.win.eventdata.ticketEncryptionType=="0x17")
  | {ts:.timestamp, user:.data.win.eventdata.targetUserName, src:.data.win.eventdata.ipAddress}' \
  logs/security_events.json

# The foothold: the 4624 logon that gives the source workstation name
jq -r '.[] | select(.data.win.system.eventID=="4624" and .data.win.eventdata.targetUserName=="t.remy")
  | [.timestamp, .data.win.eventdata.ipAddress, .data.win.eventdata.workstationName] | @tsv' \
  logs/security_events.json
```

The targeted SPN (`HTTP/bru-app-01.nexacorp.lab`) reconciles `domain_spn_accounts.csv` with the RC4 ticket, and the capture confirms the TGS-REQ etype as 23 (RC4).

---

## Known limits

- **Credential origin is inferred.** The reuse of `t.remy` is most plausibly explained by the Month 2 directory export (INC-2026-007), but the evidence here proves the in-domain activity, not the exact moment the credential was obtained.
- **Offline cracking is out of band.** Recovering the `svc_report` password happens off-network and is not visible in this evidence set; the report states the exposure, not a confirmed crack.
- **Scope is the captured window.** The investigation covers the exported logs (late June to 3 July 2026); activity outside that window is out of scope.

---

## NexaCorp DFIR series

- [INC-2026-001](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-001): Linux infrastructure compromise (vsftpd backdoor, Caldera C2)
- [INC-2026-002](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-002): privilege escalation and persistence (Tor SSH, SUID, backdoor account)
- [INC-2026-003](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-003): month-1 cross-incident assessment
- [INC-2026-004](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-004): SQL injection (web portal)
- [INC-2026-005](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-005): OS command injection and web shell (web portal)
- [INC-2026-006](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-006): stored XSS and session hijacking (NexaPortal)
- [INC-2026-007](https://github.com/Jhatchi/NexaCorp-DFIR-INC-2026-007): IDOR and broken access control (Month 2 capstone)
- **INC-2026-008**: this repository (AD reconnaissance and Kerberoasting; first incident of Month 3)

---

## Acknowledgments

- **Thomas B.** (BeCode lab coach): scenario design and publication authorization for portfolio use.
- **MITRE** for the ATT&CK knowledge base used to map every finding.
- **The Wazuh project** for the SIEM and rule syntax used in the Phase 2 deliverable.

---

## About

Solo DFIR engagement delivered during the [BeCode Brussels](https://becode.org) Blue & Red Team bootcamp (November 2025 to September 2026), Mission 08.

Author: **[Johan-Emmanuel Hatchi](https://github.com/Jhatchi)** ([LinkedIn](https://www.linkedin.com/in/johan-emmanuel-hatchi/)).

Open to cybersecurity internship opportunities starting September 2026 in Belgium. Looking for SOC / DFIR / detection engineering roles where this kind of end-to-end work (Windows event-log and Kerberos forensics, Active Directory attack analysis, detection-rule authoring, formal client reporting) is in scope.

---

## License

[MIT](LICENSE), 2026 Johan-Emmanuel Hatchi.

The report text, methodology notes, and detection rule are released under MIT: free to copy, adapt, and reuse with attribution. The evidence bundle, lab infrastructure, and original engagement briefings remain BeCode Brussels property and are not redistributed.
