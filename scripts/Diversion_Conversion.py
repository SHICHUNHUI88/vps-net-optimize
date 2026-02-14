#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import sys
import subprocess
import ipaddress
from pathlib import Path
from urllib.request import Request, urlopen

try:
    import yaml
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
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    )
    out = (p.stdout or "").rstrip()
    if out:
        log(out)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed ({p.returncode}): {' '.join(cmd)}\n{out}")
    return out


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
    输出：原始规则行（可能含 action/no-resolve）
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
    """
    只保留 TYPE,VALUE
    """
    parts = [p.strip() for p in (rule_line or "").split(",")]
    if len(parts) >= 2:
        return f"{parts[0]},{parts[1]}"
    return (rule_line or "").strip()


def extract_supported(rule_lines: list[str]) -> dict:
    """
    只提取远程里“可提取”的常用规则（保持你现在的范围，不乱扩展）：
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
            # 校验 CIDR
            try:
                ipaddress.ip_network(v, strict=False)
                b["ip_cidr"].add(v)
            except ValueError:
                pass
        elif t == "IP-CIDR6":
            try:
                ipaddress.ip_network(v, strict=False)
                b["ip_cidr6"].add(v)
            except ValueError:
                pass
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


def write_mihomo_domain_yaml(domains: list[str], path: Path) -> None:
    # mihomo convert-ruleset(domain) 需要 “payload: - xxx” 的纯域名列表
    with open(path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for d in domains:
            f.write(f"  - {d}\n")


def write_mihomo_ip_yaml(cidrs: list[str], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for c in cidrs:
            f.write(f"  - {c}\n")


def convert_with_mihomo(behavior: str, src_yaml: Path, dst_mrs: Path) -> None:
    """
    用你老脚本的稳定命令：
      mihomo convert-ruleset <behavior> yaml <src_yaml> <dst_mrs>
    behavior: domain / ipcidr
    """
    cmd = [MIHOMO_BIN, "convert-ruleset", behavior, "yaml", str(src_yaml), str(dst_mrs)]
    run(cmd, timeout=120)


def ensure_dirs():
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

        # 统计
        cnt = (
            len(b["domain"]) + len(b["domain_suffix"]) + len(b["domain_keyword"]) +
            len(b["domain_regex"]) + len(b["ip_cidr"]) + len(b["ip_cidr6"]) +
            len(b["process_name"])
        )
        log(f"    ✅ extracted items: {cnt} (domain={len(b['domain'])}, suffix={len(b['domain_suffix'])}, "
            f"keyword={len(b['domain_keyword'])}, regex={len(b['domain_regex'])}, "
            f"cidr={len(b['ip_cidr'])}, cidr6={len(b['ip_cidr6'])}, process={len(b['process_name'])})")

        if cnt == 0:
            log("    ⚠️ extracted 0 supported rules, skip")
            continue

        # ---- sing-box: json -> srs ----
        sbox_src = build_singbox_source_json(b)
        sbox_json_path = REMOTE_TMP / f"{name}.json"
        sbox_json_path.write_text(json.dumps(sbox_src, ensure_ascii=False, indent=2), encoding="utf-8")
        log(f"    ✅ write sing-box source: {sbox_json_path}")

        srs_path = REMOTE_SRS / f"{name}.srs"
        run([SINGBOX_BIN, "rule-set", "compile", str(sbox_json_path), "-o", str(srs_path)], timeout=180)
        log(f"    ✅ SRS: {srs_path} ({srs_path.stat().st_size} bytes)")

        # ---- mihomo: 用 convert-ruleset 生成 mrs（domain/ipcidr 分开）----
        # 把可提取的域名项合并成“纯域名列表”
        # 规则类型不乱扩展：DOMAIN+SUFFIX+KEYWORD+REGEX+PROCESS-NAME 里只有 DOMAIN/SUFFIX/KEYWORD 能转为 domain 行为
        domain_entries = sorted(set(list(b["domain"]) + list(b["domain_suffix"]) + list(b["domain_keyword"])))
        ip_entries = sorted(set(list(b["ip_cidr"]) + list(b["ip_cidr6"])))

        # domain mrs
        if domain_entries:
            tmp_domain_yaml = REMOTE_TMP / f"{name}_domain.yaml"
            out_domain_mrs = REMOTE_MRS / f"{name}_domain.mrs"
            write_mihomo_domain_yaml(domain_entries, tmp_domain_yaml)
            log(f"    ✅ write mihomo domain source: {tmp_domain_yaml}")
            convert_with_mihomo("domain", tmp_domain_yaml, out_domain_mrs)
            log(f"    ✅ MRS(domain): {out_domain_mrs} ({out_domain_mrs.stat().st_size} bytes)")
        else:
            log("    ℹ️ no domain entries, skip domain.mrs")

        # ipcidr mrs
        if ip_entries:
            tmp_ip_yaml = REMOTE_TMP / f"{name}_ipcidr.yaml"
            out_ip_mrs = REMOTE_MRS / f"{name}_ipcidr.mrs"
            write_mihomo_ip_yaml(ip_entries, tmp_ip_yaml)
            log(f"    ✅ write mihomo ipcidr source: {tmp_ip_yaml}")
            convert_with_mihomo("ipcidr", tmp_ip_yaml, out_ip_mrs)
            log(f"    ✅ MRS(ipcidr): {out_ip_mrs} ({out_ip_mrs.stat().st_size} bytes)")
        else:
            log("    ℹ️ no ipcidr entries, skip ipcidr.mrs")

    log("\n✅ Done.")


if __name__ == "__main__":
    main()