# Incident Report: S01

## Summary
An email titled "Microsoft account unusual signin activity" claims to come from the Microsoft account team but was sent from a Polish hosting server with no authentication. Three different domains appear in From, Return-Path and Reply-To, and the body links to an unrelated tracking domain. The verdict is Malicious.

## Verdict
**Malicious.** Evidence: brand impersonation, lookalike sender domain, no SPF or DKIM, DMARC permerror, mismatched sender domains. URL result: 10/93 flagged (mostly Phishing, community score -79) on VirusTotal, URLScan: not scanned. The linked domain is flagged by 5 or more VirusTotal engines, which meets the playbook section 4 rule for Malicious.

## Timeline
- Email received / reported: Fri, 8 Sep 2023 05:47:04 +0000 (Date header of the sample)
- Analysis started: 25 Oct 2026
- Verdict reached: 25 Oct 2026, after header, IP and URL checks

## Header analysis
| Check | Value | Finding |
|---|---|---|
| From | Microsoft account team <no-reply@access-accsecurity.com> | Display name impersonates Microsoft; domain is a lookalike |
| Return-Path | bounce@thcultarfdes.co.uk | Different domain from From |
| Reply-To | sotrecognizd@gmail.com | Free Gmail address; replies go to the attacker |
| SPF / DKIM / DMARC | none / none / permerror | No authorised sender, unsigned, broken DMARC record |
| Received hops / origin IP | 4 hops / 89.144.44.2 | MSCode.pl hosting, Poland. AbuseIPDB 0% (1 report); a clean score is not evidence of safety |

## IOCs (defanged)
| Type | Value | Enrichment result |
|---|---|---|
| IP | 89.144.44.2 | AbuseIPDB 0%, Poland, hosting provider |
| Domain | access-accsecurity[.]com | Lookalike sender domain |
| Email | sotrecognizd@gmail[.]com | Reply-To address |
| URL | hxxp://thebandalisty[.]com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176 | VirusTotal 10/93 flagged (mostly Phishing, community score -79); URLScan not scanned; domain flagged on VirusTotal, scan 2026-10-25 |

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| T1566.002 Spearphishing Link | Body links to an unrelated tracking domain |
| T1036 Masquerading | Display name and subject imitate Microsoft account security |

## Impact
A user who clicks the link could be taken to a fake Microsoft sign-in page, exposing Microsoft 365 credentials.

## Recommended actions
- Block access-accsecurity[.]com, thcultarfdes[.]co[.]uk, thebandalisty[.]com and 89.144.44.2
- Purge the message from all mailboxes
- Check proxy and mail logs for clicks on the URL
- Reset credentials for any user who clicked or entered data
- Notify the reporting user and add the IOCs to the blocklist
