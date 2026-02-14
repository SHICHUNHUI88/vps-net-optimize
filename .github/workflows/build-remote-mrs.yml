#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
scripts/Diversion_Conversion.py

功能：
- 从 remote-rules.json 读取远程规则链接
- 拉取远程内容（支持 Clash YAML / txt 行 / YAML list / YAML dict payload/rules）
- 只提取“可提取”的规则：DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX / IP-CIDR / IP-CIDR6 / PROCESS-NAME
- 同时输出：
  1) sing-box 可用二进制：remote-srs/*.srs
  2) mihomo  可用二进制：remote-mrs/*.mrs
- 中间源文件输出到：remote-tmp/*.json + remote-tmp/*.yaml（可选择不提交）

要求：
- workflow 中已下载并放置 ./sing-box 与 ./mihomo
- pip install pyyaml
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen

try:
    import yaml  # pyyaml
except Exception:
    print("❌ Missing dependency: pyyaml (pip install pyyaml).", flush=True)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "remote-rules.json"

REMOTE_TMP = ROOT / "remote-tmp"   # 中间文件（json/yaml）
REMOTE_SRS = ROOT / "remote-srs"   # sing-box 二进制产物
REMOTE_MRS = ROOT / "remote-mrs"   # mihomo  二进制产物

SINGBOX_BIN = os.getenv("SINGBOX_BIN", "./sing-box")
MIHOMO_BIN = os.getenv("MIHOMO_BIN", "./mihomo")


def log(msg: str) -> None:
    print(msg, flush=True)


def run(cmd: list[str]) -> None:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        if p.stdout.strip():
            log(p.stdout.rstrip())
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    if p.stdout.strip():
        log(p.stdout.rstrip())


def http_get(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="ignore")


def safe_load_struct(text: str):
    t = (text or "").strip()
    if not t:
        return None

    # try json first when it looks like json
    if t[:1] in "{[":
        try:
            return json.loads(t)
        except Exception:
            pass

    # try yaml
    try:
        return yaml.safe_load(t)
    except Exception:
        return None


def parse_rule_lines(raw_text: str) -> list[str]:
    """
    支持输入：
      - YAML dict: payload / rules
      - YAML list
      - txt lines（可能带 '-' 开头）
    输出：原始规则行（可能含 action/no-resolve）
    """
    txt = (raw_text or "").strip()
    data = safe_load_struct(txt)

    # dict with payload/rules
    if isinstance(data, dict):
        rules = data.get("payload") or data.get("rules") or []
        if isinstance(rules, list):
            out = []
            for x in rules:
                s = str(x).strip()
                if not s or s.startswith("#"):
                    continue
                out.append(s.lstrip("-").strip())
            return out
        return []

    # list directly
    if isinstance(data, list):
        out = []
        for x in data:
            s = str(x).strip()
            if not s or s.startswith("#"):
                continue
            out.append(s.lstrip("-").strip())
        return out

    # fallback plain text
    out = []
    for line in txt.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lstrip("-").strip()
        if s:
            out.append(s)
    return out


def strip_action(rule_line: str) -> str:
    """
    只保留 TYPE,VALUE
    例：
      DOMAIN-SUFFIX,google.com,PROXY -> DOMAIN-SUFFIX,google.com
      IP-CIDR,1.1.1.1/32,DIRECT,no-resolve -> IP-CIDR,1.1.1.1/32
    """
    parts = [p.strip() for p in (rule_line or "").split(",")]
    if len(parts) >= 2:
        return f"{parts[0]},{parts[1]}"
    return (rule_line or "").strip()


def add_set(bucket: dict, key: str, value: str) -> None:
    if not value:
        return
    bucket.setdefault(key, set())
    bucket[key].add(value)


def extract_supported_buckets(rule_lines: list[str]) -> dict:
    """
    只提取可编译/可移植的规则类型：
    DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX / IP-CIDR / IP-CIDR6 / PROCESS-NAME
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
            add_set(b, "domain", v)
        elif t == "DOMAIN-SUFFIX":
            add_set(b, "domain_suffix", v.lstrip("."))
        elif t == "DOMAIN-KEYWORD":
            add_set(b, "domain_keyword", v)
        elif t == "DOMAIN-REGEX":
            add_set(b, "domain_regex", v)
        elif t == "IP-CIDR":
            add_set(b, "ip_cidr", v)
        elif t == "IP-CIDR6":
            add_set(b, "ip_cidr6", v)
        elif t == "PROCESS-NAME":
            add_set(b, "process_name", v)

    return b


def build_singbox_source_json(b: dict) -> dict:
    """
    sing-box rule-set 源格式：{ "version": 1, "rules": [ { ... } ] }
    """
    rule = {"type": "default"}

    if b["domain"]:
        rule["domain"] = sorted(b["domain"])
    if b["domain_suffix"]:
        rule["domain_suffix"] = sorted(b["domain_suffix"])
    if b["domain_keyword"]:
        rule["domain_keyword"] = sorted(b["domain_keyword"])
    if b["domain_regex"]:
        rule["domain_regex"] = sorted(b["domain_regex"])
    if b["ip_cidr"]:
        rule["ip_cidr"] = sorted(b["ip_cidr"])
    if b["ip_cidr6"]:
        rule["ip_cidr6"] = sorted(b["ip_cidr6"])
    if b["process_name"]:
        rule["process_name"] = sorted(b["process_name"])

    if len(rule) == 1:
        return {"version": 1, "rules": []}

    return {"version": 1, "rules": [rule]}


def build_mihomo_payload_yaml(b: dict) -> dict:
    """
    mihomo rule-set 源 YAML：{ payload: [ "DOMAIN,xx", ... ] }
    """
    payload: list[str] = []
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


def ensure_dirs() -> None:
    REMOTE_TMP.mkdir(parents=True, exist_ok=True)
    REMOTE_SRS.mkdir(parents=True, exist_ok=True)
    REMOTE_MRS.mkdir(parents=True, exist_ok=True)


def main() -> None:
    if not MANIFEST.exists():
        log(f"❌ Missing manifest: {MANIFEST}")
        sys.exit(1)

    ensure_dirs()

    items = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(items, list) or not items:
        log("❌ remote-rules.json is empty or invalid.")
        sys.exit(1)

    # sanity: binaries exist
    run([SINGBOX_BIN, "version"])
    run([MIHOMO_BIN, "-v"])

    for it in items:
        name = (it.get("name") or "").strip()
        url = (it.get("url") or "").strip()
        fmt = (it.get("format") or "clash").strip().lower()

        if not name or not url:
            log(f"⚠️ Skip invalid item: {it}")
            continue

        log(f"\n==> {name}\n    url: {url}\n    format: {fmt}")

        raw = http_get(url)
        if not raw.strip():
            log("    ❌ empty content, skip")
            continue

        # 目前按 clash 解析；如果你以后要支持 sing-box 源 JSON，也可以扩展 fmt == "singbox"
        rule_lines = parse_rule_lines(raw)
        b = extract_supported_buckets(rule_lines)

        # stats
        cnt = (
            len(b["domain"]) + len(b["domain_suffix"]) + len(b["domain_keyword"]) +
            len(b["domain_regex"]) + len(b["ip_cidr"]) + len(b["ip_cidr6"]) +
            len(b["process_name"])
        )
        log(f"    ✅ extracted items: {cnt} (domain={len(b['domain'])}, suffix={len(b['domain_suffix'])}, "
            f"keyword={len(b['domain_keyword'])}, regex={len(b['domain_regex'])}, "
            f"cidr={len(b['ip_cidr'])}, cidr6={len(b['ip_cidr6'])}, process={len(b['process_name'])})")

        if cnt == 0:
            log("    ⚠️ extracted 0 supported rules, skip compiling")
            continue

        # ---- sing-box: write source json -> compile srs ----
        sbox_src = build_singbox_source_json(b)
        sbox_json_path = REMOTE_TMP / f"{name}.json"
        sbox_json_path.write_text(json.dumps(sbox_src, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"    ✅ write sing-box source: {sbox_json_path}")

        srs_path = REMOTE_SRS / f"{name}.srs"
        run([SINGBOX_BIN, "rule-set", "compile", str(sbox_json_path), "-o", str(srs_path)])
        log(f"    ✅ SRS: {srs_path}")

        # ---- mihomo: write payload yaml -> compile mrs ----
        mh_src = build_mihomo_payload_yaml(b)
        mh_yaml_path = REMOTE_TMP / f"{name}.yaml"
        mh_yaml_path.write_text(
            yaml.safe_dump(mh_src, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        log(f"    ✅ write mihomo source: {mh_yaml_path}")

        mrs_path = REMOTE_MRS / f"{name}.mrs"
        run([MIHOMO_BIN, "rule-set", "compile", str(mh_yaml_path), "-o", str(mrs_path)])
        log(f"    ✅ MRS: {mrs_path}")

    log("\n✅ Done.")


if __name__ == "__main__":
    main()