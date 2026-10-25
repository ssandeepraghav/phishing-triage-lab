

## 1. Purpose and scope
This playbook describes how a SOC L1 analyst triages user-reported suspicious emails. It covers header, authentication, URL and attachment checks, assigning a verdict, and the response actions for each verdict.

## 2. Safety rules
- Never click links or open attachments
- Analyse headers and raw source only
- Defang all IOCs before sharing them
- Hash attachments, never execute them

## 3. Triage checklist
### 3.1 Sender checks
- [ ] From vs Return-Path vs Reply-To domains match?
- [ ] Display name impersonating a known brand or person?
- [ ] Lookalike domain (paypa1.com, micros0ft-support.com)?

### 3.2 Authentication checks
- [ ] SPF result
- [ ] DKIM result
- [ ] DMARC result
- [ ] Does the authenticated domain match the From domain?

### 3.3 Routing checks
- [ ] Received chain: hop count, origin IP, any odd country or hosting provider?

### 3.4 Content checks
- [ ] Urgency, threats or rewards in the wording?
- [ ] Generic greeting?
- [ ] Link text different from the real URL?
- [ ] Credential form or login page?

### 3.5 Attachment checks
- [ ] Extension (html, iso, zip, docm, exe, lnk, pdf with link)
- [ ] SHA-256 looked up on VirusTotal

## 4. Verdict criteria
| Verdict | Rule |
|---|---|
| Malicious | Any one: URL or hash flagged by 5+ VT engines; credential-harvesting page confirmed in URLScan; DMARC fail + lookalike domain + login link |
| Suspicious | Some red flags but no confirmed bad IOC (e.g. SPF fail only, or new unknown domain) |
| Benign / Spam | Auth passes, no malicious IOC, marketing or unwanted bulk mail |

## 5. Response actions
| Verdict | Actions |
|---|---|
| Malicious | Block sender, domain and URL; purge from all mailboxes; check who clicked; reset credentials if clicked; notify user; add IOCs to blocklist |
| Suspicious | Hold for review; add to watchlist; ask user not to interact; re-check after 24h |
| Benign / Spam | Close ticket; tell user; tune spam filter if needed |

## 6. Escalation
Escalate to L2 if a user entered credentials or ran an attachment, if more than one mailbox received the email, or if a malicious IOC already appears in other logs.

## 7. Documentation
Each investigated email gets a report using reports/TEMPLATE.md.
