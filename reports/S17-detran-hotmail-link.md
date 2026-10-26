# Incident Report: S17

## Summary
An email titled "DETRAN: Suspensão de CNH em processamento - Regularize Urgente" impersonates the Brazilian traffic authority and threatens a driving licence suspension. It was sent with no authentication from a Linode VPS and contains a link that displays a Hotmail address but actually resolves to a Google Cloud Run host. The verdict is Malicious.

## Verdict
**Malicious.** Evidence: authority impersonation with urgency, no SPF, DKIM or DMARC, invalid sender domain, and a deceptive link using the userinfo trick. VirusTotal result for the destination host: 13/93 flagged, mostly Phishing; page returns 404, taken down.

## Timeline
- Email received / reported: Tue, 30 Jun 2026 10:39:27 +0000 (Date header of the sample)
- Analysis started: 26 Oct 2026
- Verdict reached: 26 Oct 2026, after header, IP and URL checks

## Header analysis
| Check | Value | Finding |
|---|---|---|
| From | Detran - Aviso Urgente <detran@sistemadeinfracao198373> | Government impersonation; sender domain has no TLD and is not a valid domain |
| Return-Path | detran@sistemadeinfracao198373 | Matches From |
| Reply-To | None | n/a |
| SPF / DKIM / DMARC | none / none / none | No authentication at all |
| Received hops / origin IP | 4 hops / 172.238.39.126 | Linode VPS, USA. AbuseIPDB 0% (0 reports); new infrastructure, a clean score is not evidence of safety |

## IOCs (defanged)
| Type | Value | Enrichment result |
|---|---|---|
| IP | 172.238.39.126 | AbuseIPDB 0%, Linode VPS, USA |
| URL | hxxps://www[.]hotmail[.]com-pt-br987628260contapremium@dt3-161255673571[.]southamerica-east1[.]run[.]app | Userinfo trick: shows a Hotmail name, real host is the Cloud Run domain after the @ |
| Domain | dt3-161255673571[.]southamerica-east1[.]run[.]app | VirusTotal: 13/93 flagged, mostly Phishing; page returns 404, taken down |

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| T1566.002 Spearphishing Link | Body contains a deceptive link, no attachment |
| T1036 Masquerading | Impersonates the DETRAN authority and a Hotmail address |

## Impact
A user who clicks would reach an attacker-controlled page, likely a credential or payment harvesting form, risking account takeover or financial loss.

## Limitations
The landing page was not visited and no URLScan result was captured, so the page content is unconfirmed.

## Recommended actions
- Block the run[.]app host and 172.238.39.126
- Purge the message from all mailboxes
- Check proxy logs for clicks on the URL
- Reset credentials for any user who clicked or entered data
- Notify the reporting user and add the IOCs to the blocklist
