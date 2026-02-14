#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

try:
    import yaml  # pyyaml
except Exception:
    print("❌ Missing dependency: pyyaml. Please install it.", flush=True)
    sys.exit(1)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "remote-rules.json"
WORK = ROOT / ".work"
DIST = ROOT / "dist"

SING_BOX_BIN = os.getenv("SINGBOX_BIN", "sing-box")


def log(msg: str) -> None:
    print(msg, flush=True)


def http_get(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=60) as r:
        return r.read()


def parse_clash_rules(raw_text: str) -> list[str]:
    """
    Accepts:
      - YAML with payload: [...]
      - YAML with rules: [...]
      - YAML list: [...]
      - Plain text lines: - DOMAIN-SUFFIX,xx
    Returns list of rule lines like "DOMAIN-SUFFIX,google.com" (action part removed if any)
    """
    txt = raw_text.strip()

    # 1) Try YAML
    try:
        data = yaml.safe_load(txt)
        if isinstance(data, dict):
            rules = data.get("payload") or data.get("rules") or []
            if isinstance(rules, list):
                return [str(x).strip().lstrip("-").strip() for x in rules if str(x).strip()]
        if isinstance(data, list):
            return [str(x).strip().lstrip("-").strip() for x in data if str(x).strip()]
    except Exception:
        pass

    # 2) Fallback plain lines
    lines = []
    for line in txt.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lstrip("-").strip()
        if s:
            lines.append(s)
    return lines


def strip_action(rule_line: str) -> str:
    """
    Clash rule lines may be:
      DOMAIN-SUFFIX,google.com,PROXY
      IP-CIDR,1.1.1.1/32,DIRECT,no-resolve
    For conversion, we keep only the matcher parts:
      DOMAIN-SUFFIX,google.com
      IP-CIDR,1.1.1.1/32
    """
    parts = [p.strip() for p in rule_line.split(",")]
    if len(parts) >= 2:
        return f"{parts[0]},{parts[1]}"
    return rule_line.strip()


def add_rule(bucket: dict, key: str, value: str):
    if not value:
        return
    bucket.setdefault(key, [])
    if value not in bucket[key]:
        bucket[key].append(value)


def clash_to_singbox_source(rules: list[str]) -> dict:
    """
    Map common Clash types -> sing-box rule-set source fields.
    """
    b = {}  # buckets

    for line in rules:
        base = strip_action(line)
        if "," not in base:
            continue
        t, v = [x.strip() for x in base.split(",", 1)]
        t_up = t.upper()

        if t_up == "DOMAIN":
            add_rule(b, "domain", v)
        elif t_up == "DOMAIN-SUFFIX":
            # sing-box keeps suffix without leading dot; that's fine
            add_rule(b, "domain_suffix", v.lstrip("."))
        elif t_up == "DOMAIN-KEYWORD":
            add_rule(b, "domain_keyword", v)
        elif t_up == "DOMAIN-REGEX":
            add_rule(b, "domain_regex", v)
        elif t_up == "PROCESS-NAME":
            add_rule(b, "process_name", v)
        elif t_up == "PROCESS-PATH":
            add_rule(b, "process_path", v)
        elif t_up == "IP-CIDR":
            add_rule(b, "ip_cidr", v)
        elif t_up == "IP-CIDR6":
            add_rule(b, "ip_cidr6", v)
        elif t_up == "IP-ASN":
            add_rule(b, "ip_asn", v)
        elif t_up == "GEOIP":
            add_rule(b, "geoip", v)
        elif t_up == "GEOSITE":
            add_rule(b, "geosite", v)
        else:
            # ignore unknown types to avoid breaking build
            pass

    # Build sing-box rule-set source JSON
    rule_obj = {}
    for k, arr in b.items():
        if arr:
            rule_obj[k] = arr

    return {
        "version": 1,
        "rules": [rule_obj] if rule_obj else []
    }


def run(cmd: list[str]) -> None:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        log(p.stdout)
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    if p.stdout.strip():
        log(p.stdout.rstrip())


def main():
    if not MANIFEST.exists():
        log(f"❌ Missing manifest: {MANIFEST}")
        sys.exit(1)

    WORK.mkdir(parents=True, exist_ok=True)
    DIST.mkdir(parents=True, exist_ok=True)

    items = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(items, list) or not items:
        log("❌ remote-rules.json is empty or invalid.")
        sys.exit(1)

    # sanity: sing-box exists
    try:
        run([SING_BOX_BIN, "version"])
    except Exception as e:
        log(f"❌ sing-box not available: {e}")
        sys.exit(1)

    for it in items:
        name = it.get("name")
        url = it.get("url")
        fmt = (it.get("format") or "clash").lower()

        if not name or not url:
            log(f"⚠️ Skip invalid item: {it}")
            continue

        log(f"\n==> {name}\n    url: {url}\n    format: {fmt}")

        raw = http_get(url).decode("utf-8", errors="ignore")

        if fmt == "clash":
            rule_lines = parse_clash_rules(raw)
            src = clash_to_singbox_source(rule_lines)
        else:
            log(f"⚠️ Unknown format '{fmt}', skip: {name}")
            continue

        json_path = WORK / f"{name}.json"
        mrs_path = DIST / f"{name}.mrs"

        json_path.write_text(json.dumps(src, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"    ✅ write source: {json_path}")

        # compile to mrs
        run([SING_BOX_BIN, "rule-set", "compile", str(json_path), "-o", str(mrs_path)])
        log(f"    ✅ compiled: {mrs_path}")

    log("\n✅ Done.")


if __name__ == "__main__":
    main()