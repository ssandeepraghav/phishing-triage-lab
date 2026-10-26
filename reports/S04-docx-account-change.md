# Incident Report: S04

## Summary
An email with an obfuscated base64 subject, apparently "Your Account Security Settings Change", arrived with four attachments: a Word document, a small PNG, and two files with document-style names and no extension. The sender domain is unrelated to any brand and passes all authentication checks. The Word document is unknown to VirusTotal and two payloads were stripped from the dataset, so no IOC is confirmed malicious. The verdict is Suspicious.

## Verdict
**Suspicious.** Many red flags but no confirmed bad IOC, which matches playbook section 4 for Suspicious. Blocking is still recommended.

## Timeline
- Email received / reported: Wed, 8 Jul 2026 17:00:27 +0000 (Date header of the sample)
- Analysis started: 26 Oct 2026
- Verdict reached: 26 Oct 2026, after header, attachment and VirusTotal checks

## Header analysis
| Check | Value | Finding |
|---|---|---|
| From | Base64 display name with mixed Unicode characters <kb@202330648.dptinfoalma.ca> | Obfuscated display name and numeric subdomain; no link to a known brand |
| Return-Path | kb@202330648.dptinfoalma.ca | Matches From, no mismatch |
| Reply-To | None | n/a |
| SPF / DKIM / DMARC | pass / pass / pass for dptinfoalma.ca | Authentication passed for the sender's own domain; this does not make the email safe |
| Received hops / origin IP | 4 hops / 209.85.221.53 | Google mail relay, so IP reputation is not a useful signal. An earlier hop, 41.31.13.34, is Vodacom (South Africa), AbuseIPDB 0% |

## IOCs (defanged)
| Type | Value | Enrichment result |
|---|---|---|
| SHA-256 | c8aae837b8187fba9075666e70c7b78e0895127ccb25890756ede549c1e113e9 | Regulation Wed, July 08, 2026.docx (41,883 B). VirusTotal: not found. Not evidence of safety |
| SHA-256 | 8ae9bfe9b4d2701ba7de0904e5efca621d42b8b0a32c3e1a400b02876a0febc3 | KR0001 (PNG, 34,270 B). VirusTotal 0/61, benign inline image |
| Attachments | "E-Statement Wed, July 08, 2026" and "Privacy & Policy Wed, July 08, 2026" | 0 bytes: payloads stripped in the dataset, not enrichable. No file extension, type application/octet-stream |
| Domain | dptinfoalma[.]ca | Sender domain, not looked up |

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| T1566.001 Spearphishing Attachment | Word document and two document-style attachments delivered by email |
| T1036 Masquerading | Attachments named like statements and policies, with no extension, to hide their type |

## Impact
If the Word document were weaponised, opening it could lead to macro or exploit-based code execution. Because the payload could not be assessed, the actual impact is unconfirmed.

## Limitations
Two attachment payloads were stripped from the dataset, the .docx was never submitted to VirusTotal, and the URLs in the body were not looked up, so the verdict rests on header and naming evidence.

## Recommended actions
- Block dptinfoalma[.]ca and the attachment hashes
- Hold or purge the message from mailboxes and ask recipients not to open the attachments
- Detonate the .docx in a sandbox (for example Any.Run or Hybrid Analysis) to upgrade or downgrade the verdict
- Re-check the hashes on VirusTotal after 24 hours
