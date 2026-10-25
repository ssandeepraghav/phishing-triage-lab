# Incident Report: S02

## Summary
An email with the subject "[Important] Unauthorized access; Your Amazon account has been lock..." carried a PDF named "StatementAmazon#CASE-3987187467.pdf". It imitates an Amazon security notice and threatens account lockout within 24 hours to push the reader to a "Verify Now" button. The attachment is flagged malicious by 25 of 62 VirusTotal engines, so the verdict is Malicious.

## Verdict
**Malicious.** Playbook section 4 rule applies: attachment hash flagged by 5+ VirusTotal engines (25/62).

## Timeline
- Email received / reported: Wed, 26 Jul 2023 19:26:24 +0700 (Date header of the sample)
- Analysis started: 25 Oct 2026
- Verdict reached: 25 Oct 2026, after the VirusTotal hash lookup

## Header analysis
| Check | Value | Finding |
|---|---|---|
| From | Obfuscated display name (base64 with inserted Unicode characters) <cs-noreplygrusakgrusuk0384911323@arulnotes.com> | Domain arulnotes.com has no link to Amazon. Display name obfuscation is a filter-evasion sign. |
| Return-Path | cs-noreplygrusakgrusuk0384911323@arulnotes.com | Matches From, no mismatch |
| Reply-To | None | n/a |
| SPF / DKIM / DMARC | pass / pass / pass for arulnotes.com | Authentication passed for the attacker's own domain, not Amazon. Passing authentication does not make an email safe. |
| Received hops / origin IP | 5 hops / 209.85.221.193 | Google mail relay, so IP reputation is not a useful signal |

## IOCs (defanged)
| Type | Value | Enrichment result |
|---|---|---|
| SHA-256 | 73a0e5d5582ec223d1d4216df506c5ce6961948f76d39f73a84e966b607ea1b7 | VirusTotal 25/62 malicious, community score -17 |
| Filename | StatementAmazon#CASE-3987187467.pdf (80.77 KB) | VirusTotal AI summary: Amazon impersonation lure, generic greeting, "Verify Now" button, no embedded JavaScript |
| Sender domain | arulnotes[.]com | Not looked up; unrelated to Amazon |

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| T1566.001 Spearphishing Attachment | Malicious PDF delivered as an email attachment |
| T1036 Masquerading | PDF, filename and display name imitate Amazon |

## Impact
A user who opens the PDF and clicks "Verify Now" would likely reach a fake login page. Entered credentials would give the attacker access to the Amazon account and to any account that reuses the password.

## Recommended actions
- Block the sender address, the domain arulnotes[.]com and the attachment hash
- Purge the message from all mailboxes
- Check who received, opened or clicked the PDF
- Reset credentials for any user who clicked or entered data
- Notify the reporting user and add the IOCs to the blocklist
