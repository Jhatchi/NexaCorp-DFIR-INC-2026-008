# Attack Timeline: INC-2026-008

Reconstructed from the domain controller Security log, Sysmon host telemetry and the network capture. Timestamps are UTC (+0000); CEST (UTC+02:00) is given alongside.

| # | Time (UTC) | Time (CEST) | Phase | Event |
|---|---|---|---|---|
| 1 | 03/Jul 21:47:12 | 23:47:12 | Foothold | `t.remy` requests a TGT (Event 4768, AES 0x12) from 192.168.10.31 |
| 2 | 03/Jul 21:47:13 | 23:47:13 | Foothold | `t.remy` network logon SUCCESS (Event 4624, type 3) from `bru-ws-01`, out of hours |
| 3 | 03/Jul 21:49:32 | 23:49:32 | Enumeration | First of 40 directory-access events (Event 4662, `CN=Users,DC=nexacorp,DC=lab`); `SharpHound.exe -c All` on host |
| 4 | 03/Jul 21:58:03 | 23:58:03 | Kerberoast | Service ticket for `svc_report` with RC4 (Event 4769, 0x17); `Rubeus.exe kerberoast /rc4opsec` |
| 5 | 03/Jul 21:58:07 | 23:58:07 | Kerberoast | Second RC4 service ticket for `svc_report` (Event 4769, 0x17) |

## Reading the timeline

- The TGT request (step 1) one second before the logon is normal Kerberos behavior and confirms the account is genuine.
- The 40 directory-access events (step 3) are the BloodHound collection; a normal interactive user does not query the directory this way.
- The dwell time between getting in (step 2) and acting (step 4) is **10 minutes 50 seconds**, the window in which the operator ran recon and chose a target.
- The roast is two service-ticket requests four seconds apart, both forced to RC4, both for the same account.
