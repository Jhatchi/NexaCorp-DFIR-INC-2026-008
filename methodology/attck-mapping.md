# MITRE ATT&CK Mapping: INC-2026-008

This incident is primarily one credential-access technique (Kerberoasting) with a reconnaissance step immediately preceding it.

| Tactic | Technique | ID | Evidence in this incident |
|---|---|---|---|
| Discovery | Account Discovery: Domain Account | T1087.002 | 40x Event 4662 on `CN=Users`; `SharpHound.exe -c All` on `bru-ws-01` |
| Credential Access | Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | 2x Event 4769 with RC4 (0x17) for `svc_report`; `Rubeus.exe kerberoast /rc4opsec`; TGS-REQ etype 23 in pcap |

## Notes

- **T1087.002** is the reconnaissance that lets the attacker choose a worthwhile SPN to roast. Enumeration on its own is not malicious; it is mapped here because it was performed by the same identity and host that then roasted.
- **T1558.003** is the heart of the incident. The defining artifact is the deliberate downgrade to RC4 (`ticketEncryptionType = 0x17`), which makes the service ticket crackable offline (hashcat mode 13100). A modern AES (0x11 / 0x12) ticket would not be cracked this way.
- Offline cracking of the recovered ticket would be **T1110.002 (Brute Force: Password Cracking)**, performed off-network and therefore not visible in this evidence set.
