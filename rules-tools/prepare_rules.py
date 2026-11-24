#!/usr/bin/env python3
"""Build an offline policy from real sources; native bundlecheck validates it."""
import hashlib
import json
from pathlib import Path
import sys
import time
import socket
import urllib.request
import urllib.error

SOURCES = {
    "oisd": "https://raw.githubusercontent.com/sjhgvr/oisd/main/abp_big.txt",
    "hagezi": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "adguard_dns": "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/gh-pages/Filters/filter.txt",
    "1hosts": "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/adblock.txt",
    "adguard_popup": "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/gh-pages/Filters/adguard_popup_filter.txt",
}
DIRECT_URL = "https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/whitelist/domains.lst"
LIMIT = 16 * 1024 * 1024


def download(url):
    last_error = None
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(url, timeout=90) as response:
                if response.status != 200:
                    raise ValueError(f"HTTP {response.status}: {url}")
                raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError(f"source exceeds size limit: {url}")
            text = raw.decode("utf-8-sig")
            if not text.strip() or "<html" in text[:1024].lower() or "<!doctype" in text[:1024].lower():
                raise ValueError(f"empty or HTML response: {url}")
            return text
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            last_error = exc
            print(f"Download attempt {attempt}/3 failed for {url}: {exc}", flush=True)
            if isinstance(exc, urllib.error.HTTPError) and exc.code in (400, 401, 403, 404, 410):
                break
            if attempt < 3:
                time.sleep(attempt * 2)
    raise ValueError(f"DNS filter download failed: {url}: {last_error}") from last_error


def build():
    sources = {}
    for name, url in SOURCES.items():
        print(f"Downloading DNS block source {name}: {url}", flush=True)
        sources[name] = download(url)
    smart_url = "https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/main/lists/hosts/smart-no-crutch.adguard.txt"
    smart_rewrites = download(smart_url)
    direct = {"whitelist_domains": download(DIRECT_URL)}
    popup_rewrites = "\n".join(line for line in sources["adguard_popup"].splitlines() if "$dnsrewrite=" in line)
    rewrites = smart_rewrites + "\n" + popup_rewrites
    popup_blocks = "\n".join(line for line in sources["adguard_popup"].splitlines() if "$dnsrewrite=" not in line)
    blocks = "\n".join(value for name, value in sources.items() if name != "adguard_popup") + "\n" + popup_blocks
    if len((blocks + rewrites).encode()) > 64 * 1024 * 1024:
        raise ValueError("combined rules exceed size limit")
    return {"direct": direct, "sources": sources, "blocks": blocks, "smartRewrites": smart_rewrites, "rewrites": rewrites,
            "updatedAt": int(time.time() * 1000),
            "provenance": {"blockSources": SOURCES, "smartNoCrutch": smart_url, "directSource": DIRECT_URL,
                           "sha256": hashlib.sha256((blocks + rewrites).encode()).hexdigest()}}


if __name__ == "__main__":
    target = Path(sys.argv[1])
    payload = build()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False))
    print(json.dumps(payload["provenance"], indent=2))
