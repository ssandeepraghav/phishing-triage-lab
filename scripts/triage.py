#!/usr/bin/env python3
"""Parse .eml files: auth results, header mismatches, IOCs, attachment hashes."""
import csv, hashlib, ipaddress, re, sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

URL_RE = re.compile(r'https?://[^\s<>"\')\]]+', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def public_ips(text):
    out = []
    for ip in IP_RE.findall(text):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_global:
            out.append(ip)
    return out

def defang(s):
    return s.replace("http", "hxxp").replace(".", "[.]")

def domain(addr):
    return parseaddr(addr)[1].rpartition("@")[2].lower()

def auth_result(auth, key):
    m = re.search(rf"\b{key}=(\w+)", auth, re.I)
    return m.group(1).lower() if m else "none"

def analyze(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)
    auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    from_d = domain(str(msg.get("From", "")))
    rp_d = domain(str(msg.get("Return-Path", "")))
    reply_d = domain(str(msg.get("Reply-To", "")))

    urls, hashes, names = set(), [], []
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                urls.update(URL_RE.findall(part.get_content()))
            except Exception:
                pass
        fn = part.get_filename()
        if fn:
            data = part.get_payload(decode=True) or b""
            names.append(fn)
            hashes.append(hashlib.sha256(data).hexdigest())

    received = [str(r) for r in msg.get_all("Received", [])]
    hop_ips = [ip for r in reversed(received) for ip in public_ips(r)]

    return {
        "sample_id": Path(path).stem,
        "from": str(msg.get("From", "")),
        "subject": str(msg.get("Subject", "")).replace("\n", " "),
        "spf": auth_result(auth, "spf"),
        "dkim": auth_result(auth, "dkim"),
        "dmarc": auth_result(auth, "dmarc"),
        "from_returnpath_mismatch": bool(rp_d and rp_d != from_d),
        "from_replyto_mismatch": bool(reply_d and reply_d != from_d),
        "hops": len(received),
        "origin_ip_candidates": ";".join(dict.fromkeys(hop_ips)),
        "urls_defanged": ";".join(defang(u) for u in sorted(urls)),
        "attachments": ";".join(names),
        "attachment_sha256": ";".join(hashes),
    }

if __name__ == "__main__":
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "samples")
    rows = [analyze(p) for p in sorted(src.glob("S*.eml"))]
    if not rows:
        sys.exit("No S*.eml files found. Add your own .eml files and re-run.")
    out = Path("output/parsed_results.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader(); w.writerows(rows)
    print(f"Parsed {len(rows)} samples -> {out}")
