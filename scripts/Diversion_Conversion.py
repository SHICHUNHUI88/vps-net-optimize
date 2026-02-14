#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

try:
    import yaml  # pip install pyyaml
except Exception:
    print("❌ Missing dependency: pyyaml (pip install pyyaml)", flush=True)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "remote-rules.json"

# ======= Isolated output dirs =======
MIHOMO_SRC_DIR = ROOT / "remote-mihomo-src"
MIHOMO_MRS_DIR = ROOT / "remote-mihomo-mrs"
SBOX_SRC_DIR   = ROOT / "remote-singbox-src"
SBOX_SRS_DIR   = ROOT / "remote-singbox-srs"

# ======= bins (env overridable) =======
MIHOMO_BIN = os.getenv("MIHOMO_BIN", "./mihomo")
SINGBOX_BIN = os.getenv("SINGBOX_BIN", "./sing-box")

def log(msg: str) -> None:
    print(msg, flush=True)

def http_get(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="ignore")

def run(cmd: list[str]) -> None:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        if p.stdout.strip():
            log(p.stdout.rstrip())
        raise RuntimeError("Command failed: " + " ".join(cmd))
    if p.stdout.strip():
        log(p.stdout.rstrip())

def load_struct(text: str):
    t = (text or "").strip()
    if not t:
        return None
    if t[0] in "{[":
        try:
            return json.loads(t)
        except Exception:
            pass
    try:
        return yaml.safe_load(t)
    except Exception:
        return None

def is_singbox_source(obj) -> bool:
    return isinstance(obj, dict) and obj.get("version") == 1 and isinstance(obj.get("rules"), list)

def strip_action(rule_line: str) -> str:
    parts = [p.strip() for p in (rule_line or "").split(",")]
    if len(parts) >= 2:
        return f"{parts[0]},{parts[1]}"
    return (rule_line or "").strip()

def parse_clash_lines(raw_text: str) -> list[str]:
    """
    支持：
      - YAML/JSON dict: payload/rules
      - YAML/JSON list
      - TXT lines
    输出：list[str] 规则行（可能含 action，后续会 strip）
    """
    txt = (raw_text or "").strip()
    data = load_struct(txt)

    if isinstance(data, dict):
        rules = data.get("payload") or data.get("rules") or []
        if isinstance(rules, list):
            return [str(x).strip().lstrip("-").strip() for x in rules if str(x).strip()]
        return []

    if isinstance(data, list):
        return [str(x).strip().lstrip("-").strip() for x in data if str(x).strip()]

    # txt fallback
    out = []
    for line in txt.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lstrip("-").strip()
        if s:
            out.append(s)
    return out

def buckets_from_clash(rule_lines: list[str]) -> dict:
    """
    只提取“可提取”的常用类型（域名/IP/进程），忽略其它类型，避免误伤/编译失败。
    """
    b = {
        "domain": set(),
        "domain_suffix": set(),
        "domain_keyword": set(),
        "domain_regex": set(),
        "ip_cidr": set(),
        "ip_cidr6": set(),
        "process_name": set(),
    }

    for line in rule_lines:
        base = strip_action(line)
        if "," not in base:
            continue
        t, v = [x.strip() for x in base.split(",", 1)]
        t = t.upper()
        if not v:
            continue

        if t == "DOMAIN":
            b["domain"].add(v)
        elif t == "DOMAIN-SUFFIX":
            b["domain_suffix"].add(v.lstrip("."))
        elif t == "DOMAIN-KEYWORD":
            b["domain_keyword"].add(v)
        elif t == "DOMAIN-REGEX":
            b["domain_regex"].add(v)
        elif t == "IP-CIDR":
            b["ip_cidr"].add(v)
        elif t == "IP-CIDR6":
            b["ip_cidr6"].add(v)
        elif t == "PROCESS-NAME":
            b["process_name"].add(v)

    return b

def singbox_source_from_buckets(b: dict) -> dict:
    rule = {"type": "default"}  # sing-box headless rule
    if b["domain"]:
        rule["domain"] = sorted(b["domain"])
    if b["domain_suffix"]:
        rule["domain_suffix"] = sorted(b["domain_suffix"])
    if b["domain_keyword"]:
        rule["domain_keyword"] = sorted(b["domain_keyword"])
    if b["domain_regex"]:
        rule["domain_regex"] = sorted(b["domain_regex"])
    # sing-box 可同时保存 v4/v6
    cidr_all = sorted(b["ip_cidr"])
    cidr6_all = sorted(b["ip_cidr6"])
    if cidr_all:
        rule["ip_cidr"] = cidr_all
    if cidr6_all:
        rule["ip_cidr6"] = cidr6_all
    if b["process_name"]:
        rule["process_name"] = sorted(b["process_name"])

    if len(rule) == 1:
        return {"version": 1, "rules": []}
    return {"version": 1, "rules": [rule]}

def mihomo_payload_from_buckets(b: dict) -> list[str]:
    payload = []
    for d in sorted(b["domain"]):
        payload.append(f"DOMAIN,{d}")
    for s in sorted(b["domain_suffix"]):
        payload.append(f"DOMAIN-SUFFIX,{s}")
    for k in sorted(b["domain_keyword"]):
        payload.append(f"DOMAIN-KEYWORD,{k}")
    for r in sorted(b["domain_regex"]):
        payload.append(f"DOMAIN-REGEX,{r}")
    for c in sorted(b["ip_cidr"]):
        payload.append(f"IP-CIDR,{c}")
    for c6 in sorted(b["ip_cidr6"]):
        payload.append(f"IP-CIDR6,{c6}")
    for p in sorted(b["process_name"]):
        payload.append(f"PROCESS-NAME,{p}")
    return payload

def buckets_from_singbox_source(obj: dict) -> dict:
    """
    如果远程本身就是 sing-box source JSON，也能反向“提取可提取项”再产出 mihomo/sing-box 二进制。
    """
    b = {
        "domain": set(),
        "domain_suffix": set(),
        "domain_keyword": set(),
        "domain_regex": set(),
        "ip_cidr": set(),
        "ip_cidr6": set(),
        "process_name": set(),
    }
    rules = obj.get("rules", [])
    for r in rules:
        if not isinstance(r, dict):
            continue
        for k in ["domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "ip_cidr6", "process_name"]:
            v = r.get(k)
            if isinstance(v, str):
                b[k].add(v.strip())
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, str) and x.strip():
                        b[k].add(x.strip())
    return b

def ensure_dirs():
    for d in [MIHOMO_SRC_DIR, MIHOMO_MRS_DIR, SBOX_SRC_DIR, SBOX_SRS_DIR]:
        d.mkdir(parents=True, exist_ok=True)

def main():
    if not MANIFEST.exists():
        log(f"❌ Missing manifest: {MANIFEST}")
        sys.exit(1)

    items = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(items, list) or not items:
        log("❌ remote-rules.json is empty or invalid.")
        sys.exit(1)

    ensure_dirs()

    # sanity
    run([SINGBOX_BIN, "version"])
    run([MIHOMO_BIN, "-v"])

    for it in items:
        name = (it.get("name") or "").strip()
        url = (it.get("url") or "").strip()
        fmt = (it.get("format") or "clash").lower().strip()  # clash / singbox / auto

        if not name or not url:
            log(f"⚠️ Skip invalid item: {it}")
            continue

        log(f"\n==> {name}\n    url: {url}\n    format: {fmt}")

        raw = http_get(url)
        if not raw.strip():
            raise RuntimeError(f"{name}: empty content from {url}")

        struct = load_struct(raw)

        # 统一先得到 buckets（只保留可提取）
        if fmt == "singbox" or is_singbox_source(struct):
            if not is_singbox_source(struct):
                raise RuntimeError(f"{name}: format=singbox but content not sing-box source JSON")
            b = buckets_from_singbox_source(struct)
        else:
            lines = parse_clash_lines(raw)
            b = buckets_from_clash(lines)

        # 生成 sing-box source json
        sbox_src = singbox_source_from_buckets(b)
        if not sbox_src["rules"]:
            raise RuntimeError(f"{name}: extracted 0 rules (no supported domain/ip/process items?)")

        sbox_json_path = SBOX_SRC_DIR / f"{name}.json"
        sbox_json_path.write_text(json.dumps(sbox_src, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"    ✅ sing-box source: {sbox_json_path}")

        # 编译 sing-box srs
        srs_path = SBOX_SRS_DIR / f"{name}.srs"
        run([SINGBOX_BIN, "rule-set", "compile", str(sbox_json_path), "-o", str(srs_path)])
        log(f"    ✅ sing-box SRS: {srs_path}")

        # 生成 mihomo payload yaml
        payload = mihomo_payload_from_buckets(b)
        mihomo_yaml_path = MIHOMO_SRC_DIR / f"{name}.yaml"
        mihomo_yaml_path.write_text(yaml.safe_dump({"payload": payload}, allow_unicode=True, sort_keys=False), encoding="utf-8")
        log(f"    ✅ mihomo source: {mihomo_yaml_path}")

        # 编译 mihomo mrs
        mrs_path = MIHOMO_MRS_DIR / f"{name}.mrs"
        run([MIHOMO_BIN, "rule-set", "compile", str(mihomo_yaml_path), "-o", str(mrs_path)])
        log(f"    ✅ mihomo MRS: {mrs_path}")

    log("\n✅ Done.")

if __name__ == "__main__":
    main()