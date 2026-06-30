# Indicators of Compromise: INC-2026-008

Active Directory reconnaissance and Kerberoasting against the NexaCorp domain (`nexacorp.lab`), 3 July 2026. Credentials are redacted in this versioned summary.

## Network indicators

| Type | Value | Source |
|---|---|---|
| Attacker workstation IP | 192.168.10.31 | Event 4624 / 4769, pcap |
| Domain controller | 192.168.10.30 (bru-dc-01.nexacorp.lab) | security_events.json |
| Kerberos message | TGS-REQ for `HTTP/bru-app-01.nexacorp.lab`, etype 23 (RC4) | kerberos_roast.pcap |
| Failed-logon decoy host | 192.168.10.66 (not the attacker) | Event 4625 |

## Host and account indicators

| Type | Value | Source |
|---|---|---|
| Foothold account | t.remy (used out of hours) | Event 4624 type 3 |
| Source host name | bru-ws-01 | Event 4624 workstationName |
| Targeted service account | svc_report | Event 4769 |
| Targeted SPN | HTTP/bru-app-01.nexacorp.lab | domain_spn_accounts.csv, pcap |
| Recon tool | SharpHound.exe -c All | sysmon.json (Event 1) |
| Kerberoast tool | Rubeus.exe kerberoast /rc4opsec /nowrap | sysmon.json (Event 1) |

## Behavioral indicators

| Type | Value | Source |
|---|---|---|
| Malicious event | Event 4769 with ticketEncryptionType 0x17 (RC4) | security_events.json |
| Discriminator | 2 RC4 (0x17) tickets out of 2697 total 4769 (rest AES 0x12) | security_events.json |
| Enumeration burst | 40x Event 4662 on CN=Users,DC=nexacorp,DC=lab | security_events.json |
| Dwell time | 10 min 50 s (logon 21:47:13 to roast 21:58:03 UTC) | security_events.json |

## Roastable service accounts (exposure, not proof of attack)

| sAMAccountName | SPN | Note |
|---|---|---|
| svc_report | HTTP/bru-app-01.nexacorp.lab | ATTACKED in this incident |
| svc_sql | MSSQLSvc/bru-db-01.nexacorp.lab:1433 | eligible only |
| svc_web | HTTP/bru-web-01.nexacorp.lab | eligible only |
| svc_mail | SMTP/bru-smtp-01.nexacorp.lab | eligible only |
| svc_backup_ad | CIFS/bru-files-01.nexacorp.lab | eligible only, member of Backup Operators (high value) |

Note: only `svc_report` was confirmed roasted (a weak-cipher 4769 was requested for it from the attacker host in the attack window). The other four are exposure to be hardened, not evidence of compromise.
