#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

REMOTE_TMP = ROOT / "remote-tmp"
REMOTE_SRS = ROOT / "remote-srs"
REMOTE_MRS = ROOT / "remote-mrs"

SINGBOX_BIN = os.getenv("SINGBOX_BIN", "./sing-box")
MIHOMO_BIN = os.getenv("MIHOMO_BIN", "./mihomo")


def log(msg: str) -> None:
    print(msg, flush=True)


def http_get(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="ignore")


def run(cmd: list[str], timeout: int = 120) -> str:
    log(f"    ▶ Run: {' '.join(cmd)}")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out_lines = []
    try:
        for line in iter(p.stdout.readline, ''):
            if not line:
                break
            line = line.rstrip()
            if line:
                log(line)
                out_lines.append(line)
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        raise RuntimeError(f"Timeout after {timeout}s: {' '.join(cmd)}")

    if p.returncode != 0:
        raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(cmd)}\n" + "\n".join(out_lines))

    return "\n".join(out_lines)


def safe_load_struct(text: str):
    t = (text or "").strip()
    if not t:
        return None
    if t[:1] in "{[":
        try:
            return json.loads(t)
        except Exception:
            pass
    try:
        return yaml.safe_load(t)
    except Exception:
        return None


def parse_rule_lines(raw_text: str) -> list[str]:
    """
    支持：
    - YAML dict: payload / rules
    - YAML list
    - txt lines
    """
    txt = (raw_text or "").strip()
    data = safe_load_struct(txt)

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

    if isinstance(data, list):
        out = []
        for x in data:
            s = str(x).strip()
            if not s or s.startswith("#"):
                continue
            out.append(s.lstrip("-").strip())
        return out

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
    parts = [p.strip() for p in (rule_line or "").split(",")]
    if len(parts) >= 2:
        return f"{parts[0]},{parts[1]}"
    return (rule_line or "").strip()


def extract_supported(rule_lines: list[str]) -> dict:
    """
    当前支持（可提取/可编译）：
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


def build_singbox_source_json(b: dict) -> dict:
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


def fsize(path: Path) -> str:
    if not path.exists():
        return "missing"
    return f"{path.stat().st_size} bytes"


def main() -> None:
    if not MANIFEST.exists():
        log(f"❌ Missing manifest: {MANIFEST}")
        sys.exit(1)

    REMOTE_TMP.mkdir(parents=True, exist_ok=True)
    REMOTE_SRS.mkdir(parents=True, exist_ok=True)
    REMOTE_MRS.mkdir(parents=True, exist_ok=True)

    items = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(items, list) or not items:
        log("❌ remote-rules.json is empty or invalid.")
        sys.exit(1)

    # sanity
    run([SINGBOX_BIN, "version"], timeout=60)
    run([MIHOMO_BIN, "-v"], timeout=60)

    for it in items:
        name = (it.get("name") or "").strip()
        url = (it.get("url") or "").strip()
        fmt = (it.get("format") or "clash").strip().lower()

        if not name or not url:
            log(f"⚠️ Skip invalid item: {it}")
            continue

        log(f"\n==> {name}\n    url: {url}\n    format: {fmt}")

        raw = http_get(url)
        rule_lines = parse_rule_lines(raw)
        b = extract_supported(rule_lines)

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

        # ---- sing-box -> srs ----
        sbox_src = build_singbox_source_json(b)
        sbox_json_path = REMOTE_TMP / f"{name}.json"
        sbox_json_path.write_text(json.dumps(sbox_src, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"    ✅ write sing-box source: {sbox_json_path} ({fsize(sbox_json_path)})")

        srs_path = REMOTE_SRS / f"{name}.srs"
        run([SINGBOX_BIN, "rule-set", "compile", str(sbox_json_path), "-o", str(srs_path)], timeout=180)
        log(f"    ✅ SRS: {srs_path} ({fsize(srs_path)})")

        # ---- mihomo -> mrs ----
        mh_src = build_mihomo_payload_yaml(b)
        mh_yaml_path = REMOTE_TMP / f"{name}.yaml"
        mh_yaml_path.write_text(
            yaml.safe_dump(mh_src, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        log(f"    ✅ write mihomo source: {mh_yaml_path} ({fsize(mh_yaml_path)})")

        mrs_path = REMOTE_MRS / f"{name}.mrs"
        # 关键：给更长 timeout，并且必打印输出
        run([MIHOMO_BIN, "rule-set", "compile", str(mh_yaml_path), "-o", str(mrs_path)], timeout=300)
        log(f"    ✅ MRS: {mrs_path} ({fsize(mrs_path)})")

    log("\n✅ Done.")


if __name__ == "__main__":
    main()