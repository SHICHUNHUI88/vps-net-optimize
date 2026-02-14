#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import subprocess

# 源目录 & sing-box 可执行文件，可用环境变量覆盖
SBOX_DIR = os.getenv("SBOX_DIR", "singbox")
SINGBOX_BIN = os.getenv("SINGBOX_BIN", "./sing-box")

# sing-box rule-set 源格式版本（对应 1.11.x 用 3，1.13+ 可以用 4）
RULESET_VERSION = 3


def log(msg: str) -> None:
    print(msg, flush=True)


# ================== 通用 JSON 读取 ==================

def load_json(path: str):
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

def is_ruleset_json(data) -> bool:
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


# ================== 对已有 rule-set 进行“提纯” ==================

# 允许从规则里提取并写入 SRS 的字段
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

def normalize_ruleset(data):
    """
    传入一个“看起来像 rule-set”的 JSON,
    只提取 sing-box 支持的 Headless Rule 字段，构造一个干净的 rule-set 源对象:
        { "version": RULESET_VERSION, "rules": [ {...}, ... ] }

    注意：
    - 原始 data 不会被修改；
    - ip_cidr6 会被并入 ip_cidr，保证 IPv6 也能进 SRS；
    - ip_asn 等无法直接表达的字段：只保留在原 JSON，不写入 rule-set。
    """
    if isinstance(data, list):
        rules_src = data
    elif isinstance(data, dict):
        rules_src = data.get("rules", [])
    else:
        rules_src = []

    clean_rules = []

    for idx, rule in enumerate(rules_src):
        if not isinstance(rule, dict):
            log(f"    ⚠️ 跳过非对象规则 rules[{idx}]")
            continue

        clean_rule = {}

        # 规则类型，缺省就用 default
        r_type = rule.get("type", "default")
        if not isinstance(r_type, str) or not r_type:
            r_type = "default"
        clean_rule["type"] = r_type

        # 直接允许透传的字段
        for key in ALLOWED_HEADLESS_KEYS:
            if key == "type":
                continue
            if key in rule and isinstance(rule[key], (list, str, int, bool)):
                clean_rule[key] = rule[key]

        # ip_cidr6: 合并进 ip_cidr
        ip_cidr_list = []

        # 原本就有 ip_cidr 的
        if "ip_cidr" in rule and isinstance(rule["ip_cidr"], list):
            for item in rule["ip_cidr"]:
                if isinstance(item, str):
                    ip_cidr_list.append(item)

        # 如果有 ip_cidr6，把 IPv6 CIDR 一并塞进 ip_cidr
        if "ip_cidr6" in rule and isinstance(rule["ip_cidr6"], list):
            for item in rule["ip_cidr6"]:
                if isinstance(item, str):
                    ip_cidr_list.append(item)

        if ip_cidr_list:
            # 去重一下
            clean_rule["ip_cidr"] = sorted(set(ip_cidr_list))

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

def build_ruleset_from_payload(data):
    """
    支持从类似：
      { "payload": ["DOMAIN-SUFFIX,github.com", "IP-CIDR,1.1.1.1/32", ...] }
    中提取规则，并构造 rule-set 源对象。
    """
    if not isinstance(data, dict):
        return {"version": RULESET_VERSION, "rules": []}

    payload = data.get("payload")
    if not isinstance(payload, list):
        return {"version": RULESET_VERSION, "rules": []}

    domains = set()
    domain_suffix = set()
    domain_keyword = set()
    domain_regex = set()
    ip_cidr = set()
    process_name = set()

    for item in payload:
        if not isinstance(item, str):
            continue

        line = item.strip()
        if not line or line.startswith("#"):
            continue

        # 去掉 ['xxx'] 这种包起来的写法
        if line.startswith("['") and line.endswith("']"):
            line = line.strip("[]'\"")

        parts = [p.strip() for p in line.split(",") if p.strip()]
        if len(parts) < 2:
            continue

        t = parts[0].upper()
        v = parts[1]

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

    rule = {"type": "default"}

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


def write_temp_ruleset_json(base_name: str, ruleset_obj) -> str:
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

def main():
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
            # 已经是 rule-set，提取有用字段、抛弃其它无用字段（仅在临时 JSON 中）
            rs_obj = normalize_ruleset(data)
            if rs_obj["rules"]:
                log("  ✅ 识别为 rule-set JSON，已提取有效字段")
            else:
                log("  ⚠️ 识别为 rule-set JSON，但没有提取到任何可用规则，将生成空 SRS 文件")
        else:
            # 尝试从 payload 里抽规则
            rs_obj = build_ruleset_from_payload(data)
            if rs_obj["rules"]:
                log("  ✅ 从 payload 中提取并构造 rule-set JSON")
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