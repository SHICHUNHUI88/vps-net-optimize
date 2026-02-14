#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "remote-rules.json"

REMOTE_SRC = ROOT / "remote-src"
REMOTE_MRS = ROOT / "remote-mrs"
REMOTE_SRS = ROOT / "remote-srs"

SINGBOX_BIN = "./sing-box"
MIHOMO_BIN = "./mihomo"


def log(msg):
    print(msg, flush=True)


def http_get(url):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="ignore")


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        log(p.stdout)
        raise RuntimeError("Command failed")
    if p.stdout.strip():
        log(p.stdout.strip())


def parse_lines(text):
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lstrip("-").strip()
        if s:
            lines.append(s)
    return lines


def extract_rules(lines):
    buckets = {
        "domain": set(),
        "domain_suffix": set(),
        "domain_keyword": set(),
        "domain_regex": set(),
        "ip_cidr": set(),
        "ip_cidr6": set(),
        "process_name": set(),
    }

    for line in lines:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue

        t = parts[0].upper()
        v = parts[1]

        if t == "DOMAIN":
            buckets["domain"].add(v)
        elif t == "DOMAIN-SUFFIX":
            buckets["domain_suffix"].add(v.lstrip("."))
        elif t == "DOMAIN-KEYWORD":
            buckets["domain_keyword"].add(v)
        elif t == "DOMAIN-REGEX":
            buckets["domain_regex"].add(v)
        elif t == "IP-CIDR":
            buckets["ip_cidr"].add(v)
        elif t == "IP-CIDR6":
            buckets["ip_cidr6"].add(v)
        elif t == "PROCESS-NAME":
            buckets["process_name"].add(v)

    return buckets


def build_singbox_json(b):
    rule = {"type": "default"}
    for k, v in b.items():
        if v:
            rule[k] = sorted(v)

    if len(rule) == 1:
        return {"version": 1, "rules": []}

    return {"version": 1, "rules": [rule]}


def build_mihomo_payload(b):
    payload = []

    for v in sorted(b["domain"]):
        payload.append(f"DOMAIN,{v}")
    for v in sorted(b["domain_suffix"]):
        payload.append(f"DOMAIN-SUFFIX,{v}")
    for v in sorted(b["domain_keyword"]):
        payload.append(f"DOMAIN-KEYWORD,{v}")
    for v in sorted(b["domain_regex"]):
        payload.append(f"DOMAIN-REGEX,{v}")
    for v in sorted(b["ip_cidr"]):
        payload.append(f"IP-CIDR,{v}")
    for v in sorted(b["ip_cidr6"]):
        payload.append(f"IP-CIDR6,{v}")
    for v in sorted(b["process_name"]):
        payload.append(f"PROCESS-NAME,{v}")

    return {"payload": payload}


def main():
    if not MANIFEST.exists():
        log("❌ remote-rules.json not found")
        sys.exit(1)

    REMOTE_SRC.mkdir(exist_ok=True)
    REMOTE_MRS.mkdir(exist_ok=True)
    REMOTE_SRS.mkdir(exist_ok=True)

    items = json.loads(MANIFEST.read_text(encoding="utf-8"))

    run([SINGBOX_BIN, "version"])
    run([MIHOMO_BIN, "-v"])

    for item in items:
        name = item["name"]
        url = item["url"]

        log(f"\n==> {name}")

        raw = http_get(url)
        lines = parse_lines(raw)
        buckets = extract_rules(lines)

        # ---------- sing-box ----------
        sbox_json = build_singbox_json(buckets)
        sbox_json_path = REMOTE_SRC / f"{name}.json"
        sbox_json_path.write_text(json.dumps(sbox_json, ensure_ascii=False, indent=2), encoding="utf-8")

        srs_path = REMOTE_SRS / f"{name}.srs"
        run([SINGBOX_BIN, "rule-set", "compile", str(sbox_json_path), "-o", str(srs_path)])
        log(f"    ✅ SRS: {srs_path}")

        # ---------- mihomo ----------
        mihomo_yaml = build_mihomo_payload(buckets)
        mihomo_yaml_path = REMOTE_SRC / f"{name}.yaml"
        mihomo_yaml_path.write_text(yaml.safe_dump(mihomo_yaml, allow_unicode=True), encoding="utf-8")

        mrs_path = REMOTE_MRS / f"{name}.mrs"
        run([MIHOMO_BIN, "rule-set", "compile", str(mihomo_yaml_path), "-o", str(mrs_path)])
        log(f"    ✅ MRS: {mrs_path}")

    log("\n🎉 Done")


if __name__ == "__main__":
    main()