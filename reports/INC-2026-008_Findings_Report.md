# INC-2026-008 Findings Report: Active Directory Reconnaissance and Kerberoasting

**Engagement:** NexaCorp DFIR, AD reconnaissance and Kerberoasting against the NexaCorp domain
**Reference:** BCC-2026 / INC-2026-008
**Target system:** bru-dc-01.nexacorp.lab (Windows domain controller, 192.168.10.30); workstation involved bru-ws-01 (192.168.10.31)
**Reported by:** Marc Wauters, IT Infrastructure Manager, NexaCorp Industries
**Date reported:** 6 July 2026
**Analyst:** Johan-Emmanuel Hatchi, SOC Analyst L1, BeCode Corp
**Classification:** Confidential, do not distribute outside BeCode Corp

> Timezone note : log timestamps are UTC (+0000). Local time is CEST (UTC+02:00). Both are given where it aids the timeline.

---

## 1. Executive summary

On the evening of Friday 3 July 2026, an attacker authenticated to the NexaCorp Windows domain as a real but low-value helpdesk account, `t.remy`, from a single internal workstation (`bru-ws-01`). Within about two minutes they ran an automated enumeration of Active Directory, then requested a Kerberos service ticket for one service account, `svc_report`, deliberately forcing a weak, legacy encryption type so the ticket can be cracked offline. The whole sequence lasted under twelve minutes.

The most important point for management is that the attacker did not break in with an exploit. They **logged in** with a valid password and abused a normal, by-design feature of Kerberos. Any authenticated domain user is allowed to ask the domain controller for a service ticket; the only thing that made this request malicious was that it asked for the old RC4 cipher instead of modern AES. That single difference is the entire fingerprint of the attack, and it is why NexaCorp's monitoring stayed silent on the part that matters.

The consequence is a **newly exposed credential**. Once the `svc_report` ticket is cracked offline, the attacker holds that service account's password, which is a higher value than the helpdesk login they started with. This is the classic next step in a domain compromise and sets up the following incident. The incident is rated **High**.

A second, equally important finding is a detection gap: NexaCorp's Wazuh SIEM raised alerts on a noisy failed-logon burst the same night, but raised nothing on the Kerberoast itself. Section 5 documents the gap and the detection rule that closes it.

---

## 2. Incident timeline

| Time (UTC) | Time (CEST) | Event | Source |
|---|---|---|---|
| 03/Jul 21:47:12 | 23:47:12 | `t.remy` requests a Kerberos TGT (Event 4768, AES 0x12) from 192.168.10.31 | security_events.json |
| 03/Jul 21:47:13 | 23:47:13 | `t.remy` logon SUCCESS (Event 4624, type 3) from 192.168.10.31 = `bru-ws-01`, outside working hours | security_events.json |
| 03/Jul 21:49:32 onward | 23:49:32 onward | Heavy directory enumeration from `bru-ws-01` (40x Event 4662 on `CN=Users,DC=nexacorp,DC=lab`); SharpHound `-c All` on host | security_events.json, sysmon.json |
| 03/Jul 21:58:03 | 23:58:03 | Service ticket requested for `svc_report` with weak RC4 (Event 4769, ticketEncryptionType 0x17) from 192.168.10.31 | security_events.json, pcap |
| 03/Jul 21:58:07 | 23:58:07 | Second RC4 service ticket for `svc_report` (Event 4769, 0x17) | security_events.json |

The intrusion is tight: about eleven minutes from logon (21:47:13) to the Kerberoast (21:58:03). The dwell time between getting in and acting is **10 minutes 50 seconds**, consistent with an operator who logs in, runs a recon tool, reads the result, then roasts a chosen target.

---

## 3. Technical analysis

### 3.1 Finding 1 - Foothold via a real helpdesk account (Medium)

The domain controller records a successful network logon (Event 4624, logon type 3) for `t.remy` at 21:47:13 UTC, originating from 192.168.10.31, whose `workstationName` field resolves to `bru-ws-01`. The logon is outside that helpdesk operator's working hours. A TGT request (Event 4768) precedes it by one second with normal AES encryption (0x12), so the account itself is genuine; nothing about obtaining the ticket is anomalous.

The likely origin of the credential is the employee directory exported during INC-2026-007 (Month 2). Fixing the IDOR flaw did not un-leak the 47 records that already escaped; knowing who works at NexaCorp and what their usernames look like is exactly the intelligence that lets an attacker guess or reuse a low-value helpdesk password.

### 3.2 Finding 2 - Active Directory enumeration (Medium)

Starting at 21:49:32 UTC, the same workstation generates 40 directory-access events (Event 4662) against the `CN=Users` container, far more than a normal interactive user produces. Host telemetry confirms the tooling: `SharpHound.exe -c All` was executed on `bru-ws-01`. This is the reconnaissance step (BloodHound data collection) that maps users, groups and service accounts so the attacker can pick a worthwhile target. Enumeration alone is not the attack, but here it is performed by the same identity and host that then requests the malicious ticket.

### 3.3 Finding 3 - Kerberoasting of svc_report (High)

This is the core of the incident. At 21:58:03 and 21:58:07 UTC the domain controller issues two service tickets (Event 4769) for the service account `svc_report`, both with `ticketEncryptionType = 0x17` (RC4-HMAC), requested from 192.168.10.31.

The discriminator is decisive. Across the evidence window the DC issued **2697** service tickets (Event 4769); **2695** used strong AES (0x12) and only **2** used weak RC4 (0x17). Both RC4 tickets belong to this attack, target the same account, and come from the attacker's workstation. Modern Windows issues AES tickets by default; an attacker forces RC4 specifically because an RC4 service ticket can be cracked offline to recover the account password (hashcat mode 13100).

Host telemetry names the tool: `Rubeus.exe kerberoast /rc4opsec /nowrap /outfile:hash.txt`. The `/rc4opsec` flag is what downgrades the request to RC4, which is exactly what the DC logged.

The network capture corroborates this independently: from 192.168.10.31 to the DC (192.168.10.30), an AS-REQ/REP for the TGT followed by a **TGS-REQ for `HTTP/bru-app-01.nexacorp.lab` with etype 23 (RC4)**. `HTTP/bru-app-01.nexacorp.lab` is the registered SPN of `svc_report`, which joins the SPN reference list to the malicious ticket and proves which account was actually hit.

### 3.4 Tooling summary (from host telemetry)

| Stage | Tool observed (Sysmon, Event 1) | Effect |
|---|---|---|
| Enumeration | `SharpHound.exe -c All` | BloodHound collection of the domain |
| Kerberoast | `Rubeus.exe kerberoast /rc4opsec /nowrap /outfile:hash.txt` | Forces RC4 service ticket for offline cracking |

---

## 4. Impact

The attacker now holds an offline-crackable Kerberos ticket for `svc_report`. Once cracked, they recover that service account's clear-text password without ever touching the network again. This is a **new, higher-value credential** than the helpdesk login they started with, and it is the pivot that sets up the next stage of a domain compromise.

Five domain accounts carry a registered SPN and are therefore eligible to be roasted (see `evidence-summary/ioc-summary.md`). Only `svc_report` was actually attacked in this incident, but the exposure class is broader and is addressed in the remediation section. Notably `svc_backup_ad` is a member of `Backup Operators`, a sensitive group; it was not targeted here, but it is the highest-value roastable account and should be prioritised in hardening.

---

## 5. Detection gap and remediation (Phase 2)

NexaCorp's Wazuh SIEM produced 25 alerts that night, **all of them on a noisy failed-logon burst** (24x rule 60122 "Logon failure", 1x rule 60204 "Multiple Windows logon failures from same source"). It raised **nothing** on the Kerberoast, because a single service-ticket request (Event 4769) is, by itself, completely normal. That silence is the most important detection finding of the incident: the loud event was the decoy, and the quiet event was the attack.

The gap is closed by a Wazuh rule that keys on the encryption type rather than the account name, so it catches any future roast, not just this one:

```xml
<rule id="100800" level="12">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
  <description>Possible Kerberoasting: service ticket (4769) requested with weak RC4 encryption</description>
  <mitre><id>T1558.003</id></mitre>
</rule>
```

This rule was submitted to the lab Wazuh manager and deployed as **rule.id 100011** (see `detection/`). It fires on the RC4 4769 event and stays silent on normal AES (0x12) service tickets. This was validated live on the lab manager: a controlled roast of all five SPN accounts produced five rule.id 100011 alerts on the RC4 events and zero on AES, confirming no false positives.

**Prioritised recommendations:**

- **Immediate:** rotate the `svc_report` password now and treat it as compromised. Assume the ticket has been or will be cracked. Review what `svc_report` can access (the reporting web service on `bru-app-01`).
- **Medium-term:** remove the weakness class. Migrate service accounts to **group Managed Service Accounts (gMSA)** with long, automatically rotated passwords, and disable RC4 for Kerberos domain-wide (enforce AES). This makes offline cracking infeasible even if a ticket is requested.
- **Strategic / detection:** deploy the rule above (rule.id 100011) and add a correlation rule that escalates when one source requests several RC4 service tickets in a short window (mass roast). Detection (rule) and prevention (AES-only, gMSA) are complementary, not interchangeable.

---

## 6. Precision: what was NOT the attack

Three things looked suspicious that night and are explicitly cleared, because each defeats a lazy shortcut:

- **A legitimate administrator (`p.renard`, 192.168.10.36)** ran directory and service-principal queries (18x Event 4662) during normal activity. Enumeration alone is not the attack: `p.renard` never requested a weak-cipher ticket. The same account also performed a legitimate RDP logon from the jump box `bru-jump-01` and created a scheduled backup task, both normal admin work.
- **A host at 192.168.10.66** generated a burst of 24 failed logons (Event 4625) against six usernames (`administrator`, `admin`, `helpdesk`, `backup`, `svc_admin`, `t.remy`) and never succeeded. This is the noisy decoy the SIEM did alert on; it is not the attacker's clean single success from `bru-ws-01`.
- **An SPN is exposure, not proof.** Five accounts hold a registered SPN; only the one for which a weak-cipher ticket was actually requested (`svc_report`) is reported as attacked.

The single discriminator that cuts through all three is the **ticket encryption type**: only the attack used RC4 (0x17).

---

## 7. Appendix - MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Discovery | Account Discovery: Domain Account | T1087.002 | 40x Event 4662, `SharpHound.exe -c All` |
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | 2x Event 4769 RC4 (0x17) for `svc_report`, `Rubeus.exe kerberoast /rc4opsec` |

This incident is primarily one technique (Kerberoasting, T1558.003) with a reconnaissance step (Account Discovery, T1087.002) immediately preceding it.

---

## 8. Indicators of compromise

See `evidence-summary/ioc-summary.md` for the full IOC table. Key indicators: account `t.remy` used out of hours, source host `bru-ws-01` (192.168.10.31), target `svc_report` (SPN `HTTP/bru-app-01.nexacorp.lab`), Event 4769 with `ticketEncryptionType = 0x17`, tooling `SharpHound.exe` and `Rubeus.exe`.

> No live credentials appear in this versioned report. The helpdesk and service-account passwords referenced during the engagement are kept out of version control and retained only in the evidence bundle, as in any real DFIR report.
