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

# 严格模式：只要本次构建失败/无规则，就删除旧产物，避免“假更新”
STRICT_MODE = True


def log(msg: str) -> None:
    print(msg, flush=True)


def safe_unlink(path: Path) -> None:
    """安全删除文件（不存在就忽略）。"""
    try:
        if path.exists():
            path.unlink()
    except Exception as e:
        log(f"    ⚠️ 删除失败: {path} -> {e}")


def http_get(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="ignore")


def run(cmd, timeout: int = 180) -> str:
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


def ensure_dirs() -> None:
    REMOTE_TMP.mkdir(parents=True, exist_ok=True)
    REMOTE_SRS.mkdir(parents=True, exist_ok=True)
    REMOTE_MRS.mkdir(parents=True, exist_ok=True)


def safe_load_struct(text: str):
    t = (text or "").strip()
    if not t:
        return None
    # 先尝试 JSON
    if t[:1] in "{[":
        try:
            return json.loads(t)
        except Exception:
            pass
    # 再尝试 YAML
    try:
        return yaml.safe_load(t)
    except Exception:
        return None


def first_nonempty_line(text: str) -> str:
    for line in (text or "").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return s
    return ""


# ========= 类型识别 =========

CLASH_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
}


def looks_like_clash_rule_line(s: str) -> bool:
    if not s or "," not in s:
        return False
    t = s.split(",", 1)[0].strip().upper()
    return t in CLASH_TYPES


def is_singbox_ruleset_json(obj) -> bool:
    # sing-box 规则源：{"version":1,"rules":[{...}]}
    return isinstance(obj, dict) and isinstance(obj.get("version"), int) and isinstance(
        obj.get("rules"), list
    )


def detect_format(fmt: str, raw_text: str) -> str:
    """
    规范化 / 自动识别源格式：
      - clash         : Clash YAML / JSON / 文本规则
      - domain-text   : 纯域名 txt（一行一个）
      - ip-text       : 纯 CIDR txt（一行一个）
      - singbox-json  : sing-box 规则源 JSON
      - auto          : 自动判断
    """
    fmt = (fmt or "auto").strip().lower()
    if fmt in (
        "clash",
        "domain-text",
        "domain_text",
        "ip-text",
        "ip_text",
        "singbox-json",
        "singbox_json",
        "auto",
    ):
        pass
    else:
        fmt = "auto"

    # 用户明确指定就直接用
    if fmt != "auto":
        if fmt == "domain_text":
            return "domain-text"
        if fmt == "ip_text":
            return "ip-text"
        if fmt == "singbox_json":
            return "singbox-json"
        return fmt

    # 自动检测
    t = (raw_text or "").strip()
    obj = safe_load_struct(t)
    if is_singbox_ruleset_json(obj):
        return "singbox-json"

    # YAML/JSON dict 里有 payload/rules，大概率是 Clash 规则
    if isinstance(obj, dict) and ("payload" in obj or "rules" in obj):
        return "clash"

    # 第一行长得像 Clash 规则行
    s0 = first_nonempty_line(t)
    if looks_like_clash_rule_line(s0):
        return "clash"

    # 看看是不是纯 CIDR / 纯域名列表
    cidr_hits = 0
    domain_hits = 0
    total = 0
    for line in t.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lstrip("-").strip()
        if not s:
            continue
        total += 1
        if "/" in s:
            try:
                ipaddress.ip_network(s, strict=False)
                cidr_hits += 1
                continue
            except Exception:
                pass
        if "." in s and " " not in s and "," not in s and "/" not in s:
            domain_hits += 1
        if total >= 50:
            break

    if total > 0 and cidr_hits >= max(3, int(total * 0.6)):
        return "ip-text"
    if total > 0 and domain_hits >= max(3, int(total * 0.6)):
        return "domain-text"

    return "clash"


# ========= Clash 规则解析 =========

def parse_rule_lines_from_clash_like(raw_text: str) -> list:
    """
    支持：
      - YAML dict: payload / rules
      - YAML list
      - JSON dict/list
      - 文本行
    输出：规则行列表（字符串）
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
                out.append(str(s).lstrip("-").strip())
            return out
        return []

    if isinstance(data, list):
        out = []
        for x in data:
            s = str(x).strip()
            if not s or s.startswith("#"):
                continue
            out.append(str(s).lstrip("-").strip())
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
    把 "DOMAIN,example.com,PROXY" 裁成 "DOMAIN,example.com"
    """
    parts = [p.strip() for p in (rule_line or "").split(",")]
    if len(parts) >= 2:
        return f"{parts[0]},{parts[1]}"
    return (rule_line or "").strip()


def extract_supported_from_clash_lines(rule_lines: list) -> dict:
    """
    从 Clash 规则里提取：
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
            # sing-box 这边习惯保留前导点
            vv = v if v.startswith(".") else "." + v
            b["domain_suffix"].add(vv)
        elif t == "DOMAIN-KEYWORD":
            b["domain_keyword"].add(v)
        elif t == "DOMAIN-REGEX":
            b["domain_regex"].add(v)
        elif t == "IP-CIDR":
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


# ========= 纯列表解析（域名 / CIDR） =========

def parse_domain_list(raw_text: str) -> list:
    """
    解析 Loy 那种一行一个域名 / .域名 的 txt 列表，
    也兼容 "DOMAIN,xxx" / "DOMAIN-SUFFIX,xxx" 这种写法。
    """
    out = []
    for line in (raw_text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lstrip("-").strip()
        if not s:
            continue

        # 兼容 TYPE,VALUE 格式
        if looks_like_clash_rule_line(s):
            t, v = [x.strip() for x in strip_action(s).split(",", 1)]
            # 只吃 DOMAIN / DOMAIN-SUFFIX，其它（PROCESS-NAME 等）直接丢掉
            if t.upper() in ("DOMAIN", "DOMAIN-SUFFIX"):
                s = v
            else:
                continue

        # 必须像域名：至少有一个点
        if "." not in s:
            continue

        if " " in s or "/" in s:
            continue

        if ":" in s:
            continue

        out.append(s.lstrip("."))

    return sorted(set(out))


def parse_cidr_list(raw_text: str):
    """
    解析纯 CIDR 列表，也兼容 "IP-CIDR,xxx" / "IP-CIDR6,xxx"
    """
    v4 = set()
    v6 = set()
    for line in (raw_text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lstrip("-").strip()
        if not s:
            continue

        if looks_like_clash_rule_line(s):
            t, v = [x.strip() for x in strip_action(s).split(",", 1)]
            if t.upper() in ("IP-CIDR", "IP-CIDR6"):
                s = v
            else:
                continue

        try:
            net = ipaddress.ip_network(s, strict=False)
            if net.version == 4:
                v4.add(s)
            else:
                v6.add(s)
        except Exception:
            pass

    return sorted(v4), sorted(v6)


# ========= sing-box & mihomo 输出 =========

def build_singbox_source_json(b: dict) -> dict:
    """
    构造 sing-box rule-set 源 JSON：
      {"version":1,"rules":[{...}]}
    注意：为了兼容当前版本，只输出 ip_cidr，不再单独写 ip_cidr6。
    """
    rule = {"type": "default"}

    if b.get("domain"):
        rule["domain"] = sorted(b["domain"])
    if b.get("domain_suffix"):
        rule["domain_suffix"] = sorted(b["domain_suffix"])
    if b.get("domain_keyword"):
        rule["domain_keyword"] = sorted(b["domain_keyword"])
    if b.get("domain_regex"):
        rule["domain_regex"] = sorted(b["domain_regex"])

    ip_cidr_merged = set(b.get("ip_cidr") or [])
    ip_cidr_merged.update(b.get("ip_cidr6") or [])
    if ip_cidr_merged:
        rule["ip_cidr"] = sorted(ip_cidr_merged)

    if b.get("process_name"):
        rule["process_name"] = sorted(b["process_name"])

    if len(rule) == 1:
        return {"version": 1, "rules": []}
    return {"version": 1, "rules": [rule]}


def write_mihomo_payload_yaml(lines: list, path: Path) -> None:
    """
    写成 mihomo convert-ruleset 需要的：
      payload:
        - xxx
        - yyy
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for x in lines:
            f.write(f"  - {x}\n")


def output_paths_for_name(name: str):
    """给定 name，返回该 name 对应的 SRS 与 MRS 路径。"""
    srs_path = REMOTE_SRS / f"{name}.srs"
    domain_mrs = REMOTE_MRS / f"{name}_domain.mrs"
    ip_mrs = REMOTE_MRS / f"{name}_ipcidr.mrs"
    return srs_path, domain_mrs, ip_mrs


def cleanup_outputs_for_name(name: str) -> None:
    """严格增删同步：删除一个 name 对应的所有产物。"""
    srs_path, domain_mrs, ip_mrs = output_paths_for_name(name)
    safe_unlink(srs_path)
    safe_unlink(domain_mrs)
    safe_unlink(ip_mrs)


def cleanup_orphan_outputs(valid_names) -> None:
    """
    manifest 删除的 name 对应的 SRS/MRS 也要同步删除。
    """
    valid_names = set(valid_names)

    # remote-srs/*.srs
    if REMOTE_SRS.exists():
        for p in REMOTE_SRS.glob("*.srs"):
            name = p.stem
            if name not in valid_names:
                log(f"🧹 STRICT: 删除孤儿 SRS: {p}")
                safe_unlink(p)

    # remote-mrs/*_domain.mrs / *_ipcidr.mrs
    if REMOTE_MRS.exists():
        for p in REMOTE_MRS.glob("*.mrs"):
            fname = p.name
            base = None
            if fname.endswith("_domain.mrs"):
                base = fname[: -len("_domain.mrs")]
            elif fname.endswith("_ipcidr.mrs"):
                base = fname[: -len("_ipcidr.mrs")]
            if base and base not in valid_names:
                log(f"🧹 STRICT: 删除孤儿 MRS: {p}")
                safe_unlink(p)


# ========= 严格模式：sing-box SRS 编译 =========

def compile_singbox_srs_strict(src_json: dict, name: str) -> bool:
    """
    严格模式编译 SRS：
    - 源 JSON 写到 remote-tmp/{name}.json
    - 编译输出到 remote-srs/{name}.srs.tmp
    - 成功且非空：替换 remote-srs/{name}.srs
    - 失败/空：删除 tmp，并在 STRICT_MODE 下删除旧 srs
    """
    srs_path, _, _ = output_paths_for_name(name)
    tmp_srs = srs_path.with_suffix(".srs.tmp")

    # 写源 JSON
    sbox_json_path = REMOTE_TMP / f"{name}.json"
    sbox_json_path.write_text(
        json.dumps(src_json, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log(f"    ✅ write sing-box source: {sbox_json_path}")

    safe_unlink(tmp_srs)

    cmd = [SINGBOX_BIN, "rule-set", "compile", str(sbox_json_path), "-o", str(tmp_srs)]

    try:
        run(cmd, timeout=240)
    except Exception as e:
        log(f"    ❌ 编译 SRS 出错: {e}")
        safe_unlink(tmp_srs)
        if STRICT_MODE:
            log("    🧹 STRICT: 删除旧 SRS 以避免用到脏产物")
            safe_unlink(srs_path)
        # 源 JSON 只作为中间产物，可以保留或删除，这里保留，便于调试
        return False

    if not tmp_srs.exists():
        log("    ❌ 临时 SRS 文件未生成")
        if STRICT_MODE:
            log("    🧹 STRICT: 删除旧 SRS 以避免用到脏产物")
            safe_unlink(srs_path)
        return False

    size = tmp_srs.stat().st_size
    log(f"    ✅ 临时 SRS 生成成功: {tmp_srs} ({size} bytes)")

    if size == 0:
        log("    ⚠️ 临时 SRS 大小为 0，视为失败")
        safe_unlink(tmp_srs)
        if STRICT_MODE:
            log("    🧹 STRICT: 删除旧 SRS 以避免用到脏产物")
            safe_unlink(srs_path)
        return False

    # 原子替换
    try:
        os.replace(tmp_srs, srs_path)
    except Exception as e:
        log(f"    ❌ 替换正式 SRS 失败: {e}")
        safe_unlink(tmp_srs)
        if STRICT_MODE:
            log("    🧹 STRICT: 删除旧 SRS 以避免用到脏产物")
            safe_unlink(srs_path)
        return False

    final_size = srs_path.stat().st_size
    log(f"    ✅ SRS 更新成功: {srs_path} ({final_size} bytes)")
    return True


# ========= 严格模式：MRS 编译 =========

def convert_with_mihomo_strict(behavior: str, src_yaml: Path, dst_mrs: Path) -> bool:
    """
    严格模式编译 MRS：
    - 输出先写到 dst_mrs.tmp
    - 成功且非空再替换 dst_mrs
    - 失败/空时删除 tmp，并在 STRICT_MODE 下删除旧 mrs
    """
    tmp_mrs = dst_mrs.with_suffix(dst_mrs.suffix + ".tmp")
    safe_unlink(tmp_mrs)

    cmd = [
        MIHOMO_BIN,
        "convert-ruleset",
        behavior,
        "yaml",
        str(src_yaml),
        str(tmp_mrs),
    ]

    try:
        run(cmd, timeout=180)
    except Exception as e:
        log(f"    ❌ mihomo 转换出错: {e}")
        safe_unlink(tmp_mrs)
        if STRICT_MODE:
            log("    🧹 STRICT: 删除旧 MRS 以避免用到脏产物")
            safe_unlink(dst_mrs)
        return False

    if not tmp_mrs.exists():
        log("    ❌ 临时 MRS 文件未生成")
        if STRICT_MODE:
            log("    🧹 STRICT: 删除旧 MRS 以避免用到脏产物")
            safe_unlink(dst_mrs)
        return False

    size = tmp_mrs.stat().st_size
    log(f"    ✅ 临时 MRS 生成成功: {tmp_mrs} ({size} bytes)")

    if size == 0:
        log("    ⚠️ 临时 MRS 大小为 0，视为失败")
        safe_unlink(tmp_mrs)
        if STRICT_MODE:
            log("    🧹 STRICT: 删除旧 MRS 以避免用到脏产物")
            safe_unlink(dst_mrs)
        return False

    try:
        os.replace(tmp_mrs, dst_mrs)
    except Exception as e:
        log(f"    ❌ 替换正式 MRS 失败: {e}")
        safe_unlink(tmp_mrs)
        if STRICT_MODE:
            log("    🧹 STRICT: 删除旧 MRS 以避免用到脏产物")
            safe_unlink(dst_mrs)
        return False

    final_size = dst_mrs.stat().st_size
    log(f"    ✅ MRS 更新成功: {dst_mrs} ({final_size} bytes)")
    return True


def build_mrs_domain_from_list(domains: list, name: str) -> bool:
    """
    严格模式：
    - 有域名：编译到 name_domain.mrs（严格模式 + 原子写）
    - 无域名：删除 name_domain.mrs（增删同步）
    """
    _, domain_mrs, _ = output_paths_for_name(name)

    if not domains:
        log("    ℹ️ no domain entries, delete domain.mrs if exists (sync)")
        safe_unlink(domain_mrs)
        return False

    tmp_domain_yaml = REMOTE_TMP / f"{name}_domain.yaml"
    write_mihomo_payload_yaml(domains, tmp_domain_yaml)
    log(f"    ✅ write mihomo domain source: {tmp_domain_yaml}")

    ok = convert_with_mihomo_strict("domain", tmp_domain_yaml, domain_mrs)
    safe_unlink(tmp_domain_yaml)
    if ok:
        log(f"    ✅ MRS(domain): {domain_mrs} ({domain_mrs.stat().st_size} bytes)")
    return ok


def build_mrs_ip_from_list(cidrs: list, name: str) -> bool:
    """
    严格模式：
    - 有 CIDR：编译到 name_ipcidr.mrs
    - 无 CIDR：删除 name_ipcidr.mrs
    """
    _, _, ip_mrs = output_paths_for_name(name)

    if not cidrs:
        log("    ℹ️ no ipcidr entries, delete ipcidr.mrs if exists (sync)")
        safe_unlink(ip_mrs)
        return False

    tmp_ip_yaml = REMOTE_TMP / f"{name}_ipcidr.yaml"
    write_mihomo_payload_yaml(cidrs, tmp_ip_yaml)
    log(f"    ✅ write mihomo ipcidr source: {tmp_ip_yaml}")

    ok = convert_with_mihomo_strict("ipcidr", tmp_ip_yaml, ip_mrs)
    safe_unlink(tmp_ip_yaml)
    if ok:
        log(f"    ✅ MRS(ipcidr): {ip_mrs} ({ip_mrs.stat().st_size} bytes)")
    return ok


# ========= main =========

def main() -> None:
    if not MANIFEST.exists():
        log(f"❌ Missing manifest: {MANIFEST}")
        sys.exit(1)

    ensure_dirs()

    items = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(items, list) or not items:
        log("❌ remote-rules.json is empty or invalid.")
        sys.exit(1)

    # 先检查二进制
    run([SINGBOX_BIN, "version"], timeout=60)
    run([MIHOMO_BIN, "-v"], timeout=60)

    # 先清理已不存在于 manifest 中的孤儿产物
    valid_names = [ (it.get("name") or "").strip() for it in items if (it.get("name") or "").strip() ]
    cleanup_orphan_outputs(valid_names)

    for it in items:
        name = (it.get("name") or "").strip()
        url = (it.get("url") or "").strip()
        fmt_in = (it.get("format") or "auto").strip().lower()

        if not name or not url:
            log(f"⚠️ Skip invalid item: {it}")
            continue

        log(f"\n==> {name}\n    url: {url}\n    format: {fmt_in}")

        # 默认认为失败时要清理对应 name 的所有产物
        try:
            # 拉取远程内容
            raw = http_get(url)
        except Exception as e:
            log(f"    ❌ HTTP 拉取失败: {e}")
            if STRICT_MODE:
                log("    🧹 STRICT: HTTP 失败 -> 删除该 name 的所有产物")
                cleanup_outputs_for_name(name)
            continue

        fmt = detect_format(fmt_in, raw)
        log(f"    🔍 detected format: {fmt_in} -> {fmt}")

        obj = safe_load_struct(raw)

        # ---- 1) singbox-json 源（有就原样编译）----
        if fmt == "singbox-json" and is_singbox_ruleset_json(obj):
            src_json = obj or {}
            rules = src_json.get("rules") or []
            if not rules:
                log("    ⚠️ singbox-json 中 rules 为空 -> 删除该 name 的所有产物（增删同步）")
                cleanup_outputs_for_name(name)
                continue

            # 编译 SRS
            compile_singbox_srs_strict(src_json, name)

            # 顺手从 sing-box JSON 抽 domain/ip 生成 mrs
            domains = []
            cidrs = []
            for r in rules:
                if not isinstance(r, dict):
                    continue
                for d in r.get("domain") or []:
                    if isinstance(d, str) and d.strip():
                        domains.append(d.strip().lstrip("."))
                for ds in r.get("domain_suffix") or []:
                    if isinstance(ds, str) and ds.strip():
                        domains.append(ds.strip().lstrip("."))
                for c in r.get("ip_cidr") or []:
                    if isinstance(c, str) and c.strip():
                        cidrs.append(c.strip())

            domains = sorted(set(domains))
            cidrs = sorted(set(cidrs))
            build_mrs_domain_from_list(domains, name)
            build_mrs_ip_from_list(cidrs, name)
            continue

        # ---- 2) 纯域名 txt ----
        if fmt == "domain-text":
            domains = parse_domain_list(raw)
            log(f"    ✅ parsed domain lines: {len(domains)}")
            if not domains:
                log("    ⚠️ domain-text parsed 0 -> 删除该 name 的所有产物（增删同步）")
                cleanup_outputs_for_name(name)
                continue

            # mrs(domain)
            build_mrs_domain_from_list(domains, name)

            # srs：把这些全当 domain_suffix 来用（带前导点）
            b = {
                "domain": set(),
                "domain_suffix": {("." + d) for d in domains},
                "domain_keyword": set(),
                "domain_regex": set(),
                "ip_cidr": set(),
                "ip_cidr6": set(),
                "process_name": set(),
            }
            compile_singbox_srs_strict(build_singbox_source_json(b), name)
            continue

        # ---- 3) 纯 CIDR txt ----
        if fmt == "ip-text":
            v4, v6 = parse_cidr_list(raw)
            log(f"    ✅ parsed cidr lines: v4={len(v4)} v6={len(v6)}")
            if not v4 and not v6:
                log("    ⚠️ ip-text parsed 0 -> 删除该 name 的所有产物（增删同步）")
                cleanup_outputs_for_name(name)
                continue

            all_cidrs = sorted(set(v4 + v6))

            # mrs(ipcidr)：v4+v6 一起
            build_mrs_ip_from_list(all_cidrs, name)

            # srs：v4+v6 全塞 ip_cidr
            b = {
                "domain": set(),
                "domain_suffix": set(),
                "domain_keyword": set(),
                "domain_regex": set(),
                "ip_cidr": set(all_cidrs),
                "ip_cidr6": set(),
                "process_name": set(),
            }
            compile_singbox_srs_strict(build_singbox_source_json(b), name)
            continue

        # ---- 4) Clash 类规则（默认）----
        rule_lines = parse_rule_lines_from_clash_like(raw)
        b = extract_supported_from_clash_lines(rule_lines)

        cnt = (
            len(b["domain"])
            + len(b["domain_suffix"])
            + len(b["domain_keyword"])
            + len(b["domain_regex"])
            + len(b["ip_cidr"])
            + len(b["ip_cidr6"])
            + len(b["process_name"])
        )
        log(
            f"    ✅ extracted items: {cnt} "
            f"(domain={len(b['domain'])}, suffix={len(b['domain_suffix'])}, "
            f"keyword={len(b['domain_keyword'])}, regex={len(b['domain_regex'])}, "
            f"cidr={len(b['ip_cidr'])}, cidr6={len(b['ip_cidr6'])}, process={len(b['process_name'])})"
        )

        if cnt == 0:
            log("    ⚠️ extracted 0 supported rules -> 删除该 name 的所有产物（增删同步）")
            cleanup_outputs_for_name(name)
            continue

        # 先给 sing-box 出 SRS
        compile_singbox_srs_strict(build_singbox_source_json(b), name)

        # 再给 mihomo 出 MRS（domain / ipcidr）
        domains_for_mrs = []
        for d in b["domain"]:
            domains_for_mrs.append(d.lstrip("."))
        for ds in b["domain_suffix"]:
            domains_for_mrs.append(ds.lstrip("."))

        domains_for_mrs = sorted(set(domains_for_mrs))
        ip_for_mrs = sorted(set(list(b["ip_cidr"]) + list(b["ip_cidr6"])))

        build_mrs_domain_from_list(domains_for_mrs, name)
        build_mrs_ip_from_list(ip_for_mrs, name)

    log("\n✅ Done.")


if __name__ == "__main__":
    main()