# Incident Report: S11

## Summary
An email titled "Invoice 73_RSJZ896543 purchase confirmation P9M4-KWX3X-WTZ903R" was sent from a free Gmail account under the name [display name redacted] with a PDF attachment. It imitates a purchase confirmation to make the recipient worry about an unexpected charge and open the file or contact the sender. The PDF is unknown to VirusTotal, so no indicator is confirmed malicious. The verdict is Suspicious.

## Verdict
**Suspicious.** Several red flags but no confirmed bad IOC, which matches playbook section 4 for Suspicious. Blocking is still recommended.

## Timeline
- Email received / reported: Thu, 2 Jul 2026 14:05:04 -0400 (Date header of the sample)
- Analysis started: 26 Oct 2026
- Verdict reached: 26 Oct 2026, after header and VirusTotal checks

## Header analysis
| Check | Value | Finding |
|---|---|---|
| From | [display name redacted] <i*****36@gmail.com> | Free Gmail address with a random-looking handle sending a business invoice |
| Return-Path | i*****36@gmail.com | Matches From, no mismatch |
| Reply-To | None | n/a |
| SPF / DKIM / DMARC | pass / pass / pass for gmail.com | Passes because the mail truly came from Gmail. Authentication proves the sender domain, not honest intent |
| Received hops / origin IP | 7 hops / 209.85.218.50 | Google mail relay, so IP reputation is not a useful signal |

## IOCs (defanged)
| Type | Value | Enrichment result |
|---|---|---|
| SHA-256 | a7b2f6fb4382726b51da18abe49e4a34bf45651e90a456aebb6488903c542da7 | U3XYDBV2X7AIS3VULT0.pdf. VirusTotal: not found. Not evidence of safety |
| Email | i*****36@gmail[.]com | Sender account |
| Subject token | Invoice 73_RSJZ896543 / P9M4-KWX3X-WTZ903R | Random order and invoice numbers |

## MITRE ATT&CK mapping
| Technique | Evidence |
|---|---|
| T1566.001 Spearphishing Attachment | PDF delivered as an email attachment |
| T1036 Masquerading | Imitates a purchase confirmation from a billing system |

## Impact
A recipient who opens the PDF may be pushed to call a fake support number or click a link, leading to payment fraud, remote-access scams or credential theft. The real impact is unconfirmed because the PDF content was not assessed.

## Limitations
The PDF was never submitted to VirusTotal and its contents were not examined in a sandbox, so the verdict rests on sender and subject evidence.

## Recommended actions
- Block the sender address and the attachment hash
- Purge the message from mailboxes and tell recipients not to open the PDF
- Detonate the PDF in a sandbox (Any.Run or Hybrid Analysis) to confirm or upgrade the verdict
- Re-check the hash on VirusTotal after 24 hours
- Report the Gmail account to Google
