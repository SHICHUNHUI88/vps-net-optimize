#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess
from typing import Any, Dict, List, Optional, Set, Union

# 源目录 & sing-box 可执行文件，可用环境变量覆盖
SBOX_DIR = os.getenv("SBOX_DIR", "singbox")
SINGBOX_BIN = os.getenv("SINGBOX_BIN", "./sing-box")

# sing-box rule-set 源格式版本（对应 1.11.x 用 3，1.13+ 可以用 4）
RULESET_VERSION = int(os.getenv("RULESET_VERSION", "3"))


def log(msg: str) -> None:
    print(msg, flush=True)


# ================== 通用 JSON 读取 ==================

def load_json(path: str) -> Optional[Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        log(f"    ❌ JSON 语法错误: {e}")
        return None
    except Exception as e:
        log(f"    ❌ 读取文件失败: {e}")
        return None


# ================== 结构判断 ==================

def is_ruleset_json(data: Any) -> bool:
    """
    判断是否是 sing-box rule-set 源格式:
    1) {"version":x,"rules":[...]}
    2) {"rules":[...]}
    3) 根节点就是一个数组: [ {...}, {...} ]
    """
    if isinstance(data, dict) and isinstance(data.get("rules"), list):
        return True
    if isinstance(data, list):
        return True
    return False


# ================== 工具：把字段统一转成 list[str]（兼容 str/list）==================

def as_str_list(val: Any) -> List[str]:
    """
    允许输入:
      - "1.1.1.1/32"
      - ["1.1.1.1/32", "8.8.8.8/32"]
    输出统一为 list[str]，并去掉空白/空串。
    """
    out: List[str] = []
    if isinstance(val, str):
        s = val.strip()
        if s:
            out.append(s)
    elif isinstance(val, list):
        for x in val:
            if isinstance(x, str):
                s = x.strip()
                if s:
                    out.append(s)
    return out


# ================== 对已有 rule-set 进行“提纯” ==================

# 允许从规则里提取并写入 SRS 的字段（headless rule）
ALLOWED_HEADLESS_KEYS = {
    "type",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "port",
    "port_range",
    "source_port",
    "source_port_range",
    "process_name",
    "process_path",
    "package_name",
    "network_type",
    "invert",
}

def normalize_ruleset(data: Any) -> Dict[str, Any]:
    """
    传入一个“看起来像 rule-set”的 JSON,
    只提取 sing-box 支持的 Headless Rule 字段，构造一个干净的 rule-set 源对象:
        { "version": RULESET_VERSION, "rules": [ {...}, ... ] }

    关键增强：
    - ip_cidr/ip_cidr6 支持 str 或 list[str]；
    - ip_cidr6 会并入 ip_cidr（保证 IPv6 也能进 SRS）；
    - 其余无法表达的字段（如 ip_asn/geoip）不会写入 rule-set。
    """
    if isinstance(data, list):
        rules_src = data
    elif isinstance(data, dict):
        rules_src = data.get("rules", [])
    else:
        rules_src = []

    clean_rules: List[Dict[str, Any]] = []

    for idx, rule in enumerate(rules_src):
        if not isinstance(rule, dict):
            log(f"    ⚠️ 跳过非对象规则 rules[{idx}]")
            continue

        clean_rule: Dict[str, Any] = {}

        # 规则类型，缺省就用 default
        r_type = rule.get("type", "default")
        if not isinstance(r_type, str) or not r_type.strip():
            r_type = "default"
        clean_rule["type"] = r_type

        # 直接允许透传的字段
        for key in ALLOWED_HEADLESS_KEYS:
            if key == "type":
                continue

            # ip_cidr 单独处理（因为要合并 ip_cidr6）
            if key == "ip_cidr":
                continue

            v = rule.get(key)
            if v is None:
                continue

            # domain / domain_suffix / ... 通常是 list[str]
            if isinstance(v, (list, str, int, bool)):
                clean_rule[key] = v

        # ip_cidr / ip_cidr6: 合并进 ip_cidr（同时兼容 str / list）
        cidrs = as_str_list(rule.get("ip_cidr"))
        cidrs6 = as_str_list(rule.get("ip_cidr6"))
        all_cidrs = cidrs + cidrs6
        if all_cidrs:
            clean_rule["ip_cidr"] = sorted(set(all_cidrs))

        # 如果除了 type 之外完全没留下任何字段，就没必要写入这条 rule
        if len(clean_rule) > 1:
            clean_rules.append(clean_rule)
        else:
            log(f"    ℹ️ rules[{idx}] 没有可用字段，跳过")

    return {
        "version": RULESET_VERSION,
        "rules": clean_rules,
    }


# ================== 从 payload (Clash 样式) 抽规则，构造 rule-set ==================

def build_ruleset_from_payload(data: Any) -> Dict[str, Any]:
    """
    支持从类似：
      { "payload": ["DOMAIN-SUFFIX,github.com", "IP-CIDR,1.1.1.1/32,no-resolve", ...] }
    中提取规则，并构造 rule-set 源对象。

    注意：
    - 只取第二段为值（域名/IP/进程名），后面的 action/no-resolve 等忽略；
    - 支持 IP-CIDR / IP-CIDR6；
    """
    if not isinstance(data, dict):
        return {"version": RULESET_VERSION, "rules": []}

    payload = data.get("payload")
    if not isinstance(payload, list):
        return {"version": RULESET_VERSION, "rules": []}

    domains: Set[str] = set()
    domain_suffix: Set[str] = set()
    domain_keyword: Set[str] = set()
    domain_regex: Set[str] = set()
    ip_cidr: Set[str] = set()
    process_name: Set[str] = set()

    for item in payload:
        if not isinstance(item, str):
            continue

        line = item.strip()
        if not line or line.startswith("#"):
            continue

        # 去掉 ['xxx'] 这种包起来的写法
        if line.startswith("['") and line.endswith("']"):
            line = line.strip("[]'\"").strip()

        # 允许出现多段：TYPE,VALUE,ACTION,no-resolve...
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue

        t = parts[0].upper()
        v = parts[1].strip()

        if not v:
            continue

        if t == "DOMAIN":
            domains.add(v)
        elif t == "DOMAIN-SUFFIX":
            domain_suffix.add(v)
        elif t == "DOMAIN-KEYWORD":
            domain_keyword.add(v)
        elif t == "DOMAIN-REGEX":
            domain_regex.add(v)
        elif t in ("IP-CIDR", "IP-CIDR6"):
            ip_cidr.add(v)
        elif t == "PROCESS-NAME":
            process_name.add(v)
        # 其它类型暂时忽略

    rule: Dict[str, Any] = {"type": "default"}

    if domains:
        rule["domain"] = sorted(domains)
    if domain_suffix:
        rule["domain_suffix"] = sorted(domain_suffix)
    if domain_keyword:
        rule["domain_keyword"] = sorted(domain_keyword)
    if domain_regex:
        rule["domain_regex"] = sorted(domain_regex)
    if ip_cidr:
        rule["ip_cidr"] = sorted(ip_cidr)
    if process_name:
        rule["process_name"] = sorted(process_name)

    if len(rule) == 1:  # 只有 type，说明啥都没提到
        return {"version": RULESET_VERSION, "rules": []}

    return {
        "version": RULESET_VERSION,
        "rules": [rule],
    }


def write_temp_ruleset_json(base_name: str, ruleset_obj: Dict[str, Any]) -> str:
    temp_path = os.path.join(SBOX_DIR, f"temp_ruleset_{base_name}.json")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(ruleset_obj, f, ensure_ascii=False, indent=2)
    return temp_path


# ================== 调用 sing-box 编译 SRS ==================

def compile_to_srs(json_path: str, base_name: str) -> bool:
    output_srs = os.path.join(SBOX_DIR, f"{base_name}.srs")
    cmd = [SINGBOX_BIN, "rule-set", "compile", "--output", output_srs, json_path]
    log(f"    ▶ Run: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        log("    ❌ 命令超时")
        return False
    except Exception as e:
        log(f"    ❌ 调用 sing-box 出错: {e}")
        return False

    if result.stdout.strip():
        log(f"    stdout: {result.stdout.strip()}")
    if result.stderr.strip():
        log(f"    stderr: {result.stderr.strip()}")

    if result.returncode != 0:
        log(f"    ❌ sing-box 退出码: {result.returncode}")
        return False

    if not os.path.exists(output_srs):
        log("    ❌ SRS 文件未生成")
        return False

    size = os.path.getsize(output_srs)
    log(f"    ✅ SRS 生成成功: {output_srs} ({size} 字节)")
    if size == 0:
        log("    ⚠️ SRS 文件大小为 0，请检查上面的 stderr 输出")
    return size > 0


# ================== 主流程 ==================

def main() -> None:
    if not os.path.isdir(SBOX_DIR):
        log(f"❌ 目录不存在: {SBOX_DIR}")
        sys.exit(1)

    if not os.path.exists(SINGBOX_BIN):
        log(f"❌ sing-box 二进制未找到: {SINGBOX_BIN}")
        sys.exit(1)

    json_files = [f for f in os.listdir(SBOX_DIR) if f.endswith(".json")]
    if not json_files:
        log(f"⚠️ {SBOX_DIR} 中没有 .json 文件")
        return

    log(f"🔧 工作目录: {SBOX_DIR}")
    log(f"🔧 发现 {len(json_files)} 个 JSON 文件")

    success, fail = 0, 0

    for json_file in sorted(json_files):
        full_path = os.path.join(SBOX_DIR, json_file)
        base_name = os.path.splitext(json_file)[0]
        log(f"\n🔍 处理: {json_file}")

        data = load_json(full_path)
        if data is None:
            fail += 1
            continue

        # ===== 决定用哪种方式构造 rule-set =====
        if is_ruleset_json(data):
            rs_obj = normalize_ruleset(data)
            if rs_obj["rules"]:
                # 自检：统计 ip_cidr 条目数
                ip_cnt = 0
                for r in rs_obj.get("rules", []):
                    ip_cnt += len(r.get("ip_cidr", [])) if isinstance(r.get("ip_cidr"), list) else 0
                log(f"  ✅ 识别为 rule-set JSON，已提取有效字段（ip_cidr 条目数: {ip_cnt}）")
            else:
                log("  ⚠️ 识别为 rule-set JSON，但没有提取到任何可用规则，将生成空 SRS 文件")
        else:
            rs_obj = build_ruleset_from_payload(data)
            if rs_obj["rules"]:
                ip_cnt = 0
                for r in rs_obj.get("rules", []):
                    ip_cnt += len(r.get("ip_cidr", [])) if isinstance(r.get("ip_cidr"), list) else 0
                log(f"  ✅ 从 payload 中提取并构造 rule-set JSON（ip_cidr 条目数: {ip_cnt}）")
            else:
                log("  ⚠️ 不是 rule-set，且从 payload 中未提取到任何规则，将生成空 SRS 文件")

        temp_json = write_temp_ruleset_json(base_name, rs_obj)

        try:
            ok = compile_to_srs(temp_json, base_name)
        finally:
            if temp_json and os.path.exists(temp_json):
                os.remove(temp_json)

        if ok:
            success += 1
        else:
            fail += 1

    log(f"\n📊 统计: 成功 {success} 个, 失败 {fail} 个")


if __name__ == "__main__":
    main()