#!/usr/bin/env python3
import os
import sys
import json
import subprocess

# 源目录 & sing-box 可执行文件，可用环境变量覆盖
SBOX_DIR = os.getenv("SBOX_DIR", "singbox")
SINGBOX_BIN = os.getenv("SINGBOX_BIN", "./sing-box")


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
    判断是否已经是 sing-box rule-set 源格式：
    1) {"version":1,"rules":[...]}
    2) {"rules":[...]} (没有 version 也算)
    3) 根节点就是一个数组：[ {...}, {...} ]
    """
    if isinstance(data, dict) and isinstance(data.get("rules"), list):
        return True
    if isinstance(data, list):
        return True
    return False


# ================== 从 payload (Clash 样式) 抽规则，构造 rule-set ==================

def build_ruleset_from_payload(data):
    """
    支持从类似：
      { "payload": ["DOMAIN-SUFFIX,github.com", "IP-ASN,138667", "PROCESS-NAME,xxx", ...] }
    里提取规则，并构造 sing-box rule-set 对象。
    即使没有提取到任何规则，也返回一个包含空 rules 列表的对象。
    """
    # 如果不是字典，直接返回空规则集
    if not isinstance(data, dict):
        return {"version": 1, "rules": []}

    payload = data.get("payload")
    # 如果没有 payload 或 payload 不是列表，返回空规则集
    if not isinstance(payload, list):
        return {"version": 1, "rules": []}

    domains = set()
    domain_suffix = set()
    domain_keyword = set()
    domain_regex = set()
    ip_cidr = set()
    ip_asn = set()
    process_name = set()

    for item in payload:
        if not isinstance(item, str):
            continue

        line = item.strip()
        if not line or line.startswith("#"):
            continue

        # 处理类似 "['DOMAIN-SUFFIX,github.com']" 这种包起来的写法
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
        elif t == "IP-ASN":
            try:
                asn = int(v)
                ip_asn.add(asn)
            except ValueError:
                continue
        elif t == "PROCESS-NAME":
            process_name.add(v)
        # 其他未识别的类型直接忽略

    rule = {}

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
    if ip_asn:
        rule["ip_asn"] = sorted(ip_asn)
    if process_name:
        rule["process_name"] = sorted(process_name)

    # 无论 rule 是否为空，都返回一个有效的规则集对象
    return {
        "version": 1,
        "rules": [rule] if rule else []
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

        temp_json = None

        if is_ruleset_json(data):
            # 已经是 sing-box rule-set 格式，直接使用
            if isinstance(data, dict):
                rs_obj = data
                if "version" not in rs_obj:
                    rs_obj["version"] = 1
            else:  # 根是数组
                rs_obj = {"version": 1, "rules": data}
            temp_json = write_temp_ruleset_json(base_name, rs_obj)
            log("  ✅ 已是 sing-box rule-set JSON，直接编译")
        else:
            # 尝试从 payload 提取 Clash 风格规则
            rs_obj = build_ruleset_from_payload(data)
            temp_json = write_temp_ruleset_json(base_name, rs_obj)
            if rs_obj["rules"]:
                log("  ✅ 从 payload 中提取并构造 rule-set JSON")
            else:
                log("  ⚠️ 从 payload 中未提取到任何有效规则，将生成空 SRS 文件")

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