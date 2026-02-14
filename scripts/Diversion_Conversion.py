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
    print("❌ Missing dependency: pyyaml. Please install it (pip install pyyaml).", flush=True)
    sys.exit(1)

# =========================
# Paths (HARD ISOLATION)
# =========================
ROOT = Path(__file__).resolve().parents[1]

# 远程规则清单（放仓库根目录）
MANIFEST = ROOT / "remote-rules.json"

# 中间产物：sing-box 源 JSON（独立文件夹）
WORK = ROOT / "remote-src"

# 最终产物：.mrs（二进制规则，独立文件夹）
DIST = ROOT / "remote-mrs"

# sing-box 可执行文件路径，可用环境变量覆盖
SING_BOX_BIN = os.getenv("SINGBOX_BIN", "sing-box")


def log(msg: str) -> None:
    print(msg, flush=True)


def http_get(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=60) as r:
        return r.read()


def run(cmd: list[str]) -> None:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if p.returncode != 0:
        if p.stdout.strip():
            log(p.stdout.rstrip())
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    if p.stdout.strip():
        log(p.stdout.rstrip())


def is_singbox_source(obj) -> bool:
    """sing-box rule-set 源 JSON 判定：{"version":1,"rules":[...]}"""
    return isinstance(obj, dict) and obj.get("version") == 1 and isinstance(obj.get("rules"), list)


def load_as_struct(text: str):
    """
    尝试解析为结构体：
      1) JSON（严格）
      2) YAML（兼容 YAML/JSON）
    """
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


def parse_clash_rules(raw_text: str) -> list[str]:
    """
    支持输入：
      - YAML/JSON dict: {"payload":[...]} or {"rules":[...]}
      - YAML/JSON list: ["DOMAIN-SUFFIX,xx", ...]
      - TXT: 每行一条规则（支持前导 - ）
    返回：
      - list[str]，元素形如 "DOMAIN-SUFFIX,google.com,PROXY"（动作后续会剥离）
    """
    txt = (raw_text or "").strip()
    if not txt:
        return []

    data = load_as_struct(txt)

    if isinstance(data, dict):
        rules = data.get("payload") or data.get("rules") or []
        if isinstance(rules, list):
            return [str(x).strip().lstrip("-").strip() for x in rules if str(x).strip()]
        return []

    if isinstance(data, list):
        return [str(x).strip().lstrip("-").strip() for x in data if str(x).strip()]

    # plain text fallback
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
    Clash 规则可能带策略/参数：
      DOMAIN-SUFFIX,google.com,PROXY
      IP-CIDR,1.1.1.1/32,DIRECT,no-resolve
    转换只保留前两段：
      DOMAIN-SUFFIX,google.com
      IP-CIDR,1.1.1.1/32
    """
    parts = [p.strip() for p in (rule_line or "").split(",")]
    if len(parts) >= 2:
        return f"{parts[0]},{parts[1]}"
    return (rule_line or "").strip()


def add_rule(bucket: dict, key: str, value: str):
    if not value:
        return
    bucket.setdefault(key, [])
    if value not in bucket[key]:
        bucket[key].append(value)


def clash_to_singbox_source(rule_lines: list[str]) -> dict:
    """
    将 Clash 规则行映射为 sing-box rule-set 源 JSON（version=1）
    仅处理常见类型（域名/IP/进程/geo）。
    """
    b = {}

    for line in rule_lines:
        base = strip_action(line)
        if "," not in base:
            continue

        t, v = [x.strip() for x in base.split(",", 1)]
        t_up = t.upper()

        if t_up == "DOMAIN":
            add_rule(b, "domain", v)
        elif t_up == "DOMAIN-SUFFIX":
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
            # 未知类型直接忽略，避免构建失败
            pass

    rule_obj = {k: arr for k, arr in b.items() if arr}
    return {"version": 1, "rules": [rule_obj] if rule_obj else []}


def main():
    if not MANIFEST.exists():
        log(f"❌ Missing manifest: {MANIFEST}")
        sys.exit(1)

    # Create isolated dirs
    WORK.mkdir(parents=True, exist_ok=True)
    DIST.mkdir(parents=True, exist_ok=True)

    items = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(items, list) or not items:
        log("❌ remote-rules.json is empty or invalid.")
        sys.exit(1)

    # Ensure sing-box exists
    run([SING_BOX_BIN, "version"])

    for it in items:
        name = (it.get("name") or "").strip()
        url = (it.get("url") or "").strip()
        fmt = (it.get("format") or "auto").lower().strip()  # auto / clash / singbox

        if not name or not url:
            log(f"⚠️ Skip invalid item: {it}")
            continue

        log(f"\n==> {name}\n    url: {url}\n    format: {fmt}")

        raw_text = http_get(url).decode("utf-8", errors="ignore").strip()
        if not raw_text:
            raise RuntimeError(f"{name}: empty content from {url}")

        struct = load_as_struct(raw_text)

        json_path = WORK / f"{name}.json"
        mrs_path = DIST / f"{name}.mrs"

        # 1) sing-box 源：直接编译
        if fmt == "singbox" or is_singbox_source(struct):
            if not is_singbox_source(struct):
                raise RuntimeError(f"{name}: format=singbox but content is not sing-box source JSON")
            json_path.write_text(json.dumps(struct, ensure_ascii=False, indent=2), encoding="utf-8")
            log(f"    ✅ sing-box source saved: {json_path}")

        # 2) clash：解析并转换
        else:
            rule_lines = parse_clash_rules(raw_text)
            src = clash_to_singbox_source(rule_lines)

            # 解析到 0 条规则，直接失败（避免假成功）
            if not src.get("rules"):
                raise RuntimeError(f"{name}: parsed 0 rules (maybe unsupported format?) url={url}")

            json_path.write_text(json.dumps(src, ensure_ascii=False, indent=2), encoding="utf-8")
            log(f"    ✅ converted source saved: {json_path}")

        # compile to mrs
        run([SING_BOX_BIN, "rule-set", "compile", str(json_path), "-o", str(mrs_path)])
        log(f"    ✅ compiled: {mrs_path}")

    log("\n✅ Done.")


if __name__ == "__main__":
    main()