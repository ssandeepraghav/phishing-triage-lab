# MITRE ATT&CK Mapping

Only techniques with evidence in the analysed samples are listed.

| Sample | Technique | Evidence |
|---|---|---|
| S02 | T1566.001 Spearphishing Attachment | PDF "StatementAmazon#CASE-...pdf", 25/62 on VirusTotal |
| S02 | T1036 Masquerading | PDF and display name imitate Amazon |
| S04 | T1566.001 Spearphishing Attachment | .docx plus two extensionless attachments (payloads stripped) |
| S04 | T1036 Masquerading | Document-style names with no extension, application/octet-stream |
| S11 | T1566.001 Spearphishing Attachment | PDF invoice from a free Gmail account |
| S11 | T1036 Masquerading | Fake purchase confirmation |
| S01 | T1566.002 Spearphishing Link | Tracking link to thebandalisty[.]com, flagged 10/93 |
| S01 | T1036 Masquerading | Microsoft account team display name, lookalike domain |
| S17 | T1566.002 Spearphishing Link | Userinfo-trick URL resolving to a run[.]app host, flagged 13/93 |
| S17 | T1036 Masquerading | DETRAN authority and Hotmail impersonation |

## Not mapped
T1204 User Execution and T1598 Phishing for Information are not listed because no sample showed a user action or a confirmed credential page.

## Coverage note
Link-based phishing (S01, S17) and attachment-based phishing (S02, S04, S11) are both represented.
