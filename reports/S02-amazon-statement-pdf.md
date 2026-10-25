# Incident Report: S02

## Summary
A user-reported email carried a PDF named "StatementAmazon#CASE-3987187467.pdf" that imitates an Amazon account security notice. The PDF pressures the reader with a 24-hour account lockout threat and a "Verify Now" button designed to lead to a credential-harvesting site. The attachment is confirmed malicious on VirusTotal, so the verdict is Malicious.

## Verdict
**Malicious.** Playbook section 4 rule applies: attachment hash flagged by 5+ VirusTotal engines (25/62).

## Timeline
- Email received / reported: FILL (use the Date header)
- Analysis started: FILL (today's date)
- Verdict reached: FILL (same day, after VirusTotal lookup)

## Header analysis
| Check | Value | Finding |
|---|---|---|
| From | FILL | FILL (does the domain match Amazon?) |
| Return-Path | FILL | FILL |
| Reply-To | FILL | FILL |
| SPF / DKIM / DMARC | pass / pass / pass (parser output) | Authentication passed, but this only proves the sending domain is genuine for itself, not that the email is safe |
| Received hops / origin IP | 5 hops / FILL | FILL |

## IOCs (defanged)
| Type | Value | Enrichment result |
|---|---|---|
| SHA-256 | 73a0e5d5582ec223d1d4216df506c5ce6961948f76d39f73a84e966b607ea1b7 | VirusTotal 25/62 malicious, community score -17 |
| Filename | StatementAmazon#CASE-3987187467.pdf (80.77 KB) | VirusTotal AI summary: Amazon impersonation lure, generic greeting, "Verify Now" button, no embedded JavaScript |

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| T1566.001 Spearphishing Attachment | Malicious PDF delivered as an email attachment |
| T1036 Masquerading | PDF and filename imitate an Amazon statement |

## Impact
A user who opens the PDF and clicks "Verify Now" would reach a fake login page. Entered credentials would give the attacker access to the Amazon account and any account that reuses the password.

## Recommended actions
- Block the sender address and the attachment hash
- Purge the message from all mailboxes
- Check who received, opened or clicked the PDF
- Reset credentials for any user who clicked or entered data
- Notify the reporting user and add the IOCs to the blocklist
