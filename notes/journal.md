# Investigation Journal: INC-2026-008

> Honesty note: this is a reconstruction written after the analysis, from the exported evidence bundle (Windows Security log, Sysmon, network capture, Wazuh alerts). The bundle spans several days; most of it is ordinary domain activity. No live access to the domain was used for Phase 1.

## Phase 1 - Investigation

1. **Inventory.** Extracted the bundle and catalogued the files without interpreting: 3562 Security events (Wazuh `windows_eventchannel` format), Sysmon, a small Kerberos pcap, a SPN reference list and the SIEM's own alerts.
2. **Find the signal.** Distribution of Event IDs showed 2697 service-ticket events (4769). Grouping them by `ticketEncryptionType` gave the break: 2695 AES (0x12) and only 2 RC4 (0x17). The two RC4 tickets are the attack.
3. **Pivot from the discriminator.** Both RC4 tickets were for `svc_report`, requested from 192.168.10.31. The 4624 logon from that IP gave the foothold account (`t.remy`) and the host name (`bru-ws-01`).
4. **Join SPN list to the ticket.** The SPN reference lists five eligible accounts; only `svc_report` (`HTTP/bru-app-01.nexacorp.lab`) had a weak-cipher ticket actually requested. That join is what turns "eligible" into "attacked".
5. **Corroborate.** Sysmon named the tools (`SharpHound.exe -c All`, `Rubeus.exe kerberoast /rc4opsec`); the pcap showed the TGS-REQ for `HTTP/bru-app-01` with etype 23. Three independent sources agree.
6. **Clear the decoys.** Confirmed `p.renard` (legitimate admin enumeration, AES only) and the 192.168.10.66 failed-logon burst were not the attack, using the encryption-type discriminator.

## Phase 2 - Detection

Confirmed from `wazuh-alerts.json` that the SIEM alerted only on the failed-logon burst (rules 60122 / 60204) and nothing on the roast. Wrote a Wazuh rule keyed on `ticketEncryptionType = 0x17` for Event 4769, submitted it, and it deployed as rule.id 100011.

## Lessons learned

- **Volume is not signal.** The loud failed-logon burst was the decoy; the attack was two quiet, legitimate-looking ticket requests. Precision, not volume, identified the attacker.
- **One field decides everything.** The entire case rests on one property, the ticket encryption type. Both the detection and the attribution hinge on RC4 vs AES.
- **Fixing a vulnerability does not un-leak data.** The Month 2 directory export is the most likely source of the reused helpdesk credential, even though the IDOR flaw itself was patched.
- **Detection and prevention are different deliverables.** The rule catches the next roast; only AES-only plus gMSA removes the weakness.
