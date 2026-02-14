#!/usr/bin/env python3
import os
import sys
import json
import subprocess

SBOX_DIR = os.getenv("SBOX_DIR", "singbox")
SINGBOX_BIN = "./sing-box"


def log(msg: str) -> None:
    print(msg, flush=True)


# ---------- 工具函数 ----------

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


def is_ruleset_json(data) -> bool:
    """
    判断是否已经是 sing-box rule-set 源格式：
    1) {"version":1,"rules":[...]}
    2) 或者根节点就是一个 rules 数组：[ {...}, {...} ]
    """
    # 形式 1：包含 version + rules
    if isinstance(data, dict) and "rules" in data and isinstance(data["rules"], list):
        return True

    # 形式 2：根就是一个规则数组
    if isinstance(data, list):
        return True

    return False


def build_ruleset_from_payload(data):
    """
    从 Clash 风格 payload 里提取规则，构造 sing-box rule-set JSON。
    支持的类型：
      - DOMAIN
      - DOMAIN-SUFFIX
      - DOMAIN-KEYWORD
      - DOMAIN-REGEX
      - IP-CIDR / IP-CIDR6
    """
    if not isinstance(data, dict):
        return None
    payload = data.get("payload")
    if not isinstance(payload, list):
        return None

    domains = []
    domain_suffix = []
    domain_keyword = []
    domain_regex = []
    ip_cidr = []

    for item in payload:
        if not isinstance(item, str):
            continue
        line = item.strip()
        if not line or line.startswith("#"):
            continue

        # 去掉奇怪的包裹写法：['DOMAIN-SUFFIX,github.com']
        if line.startswith("['") and line.endswith("']"):
            line = line.strip("[]'\"")

        parts = [p.strip() for p in line.split(",") if p.strip()]
        if len(parts) < 2:
            continue

        t = parts[0].upper()
        v = parts[1]

        if t == "DOMAIN":
            domains.append(v)
        elif t == "DOMAIN-SUFFIX":
            domain_suffix.append(v)
        elif t == "DOMAIN-KEYWORD":
            domain_keyword.append(v)
        elif t == "DOMAIN-REGEX":
            domain_regex.append(v)
        elif t in ("IP-CIDR", "IP-CIDR6"):
            # sing-box ip_cidr 同时支持 v4/v6，这里统一塞进去
            ip_cidr.append(v)

    rule = {}
    if domains:
        rule["domain"] = sorted(set(domains))
    if domain_suffix:
        rule["domain_suffix"] = sorted(set(domain_suffix))
    if domain_keyword:
        rule["domain_keyword"] = sorted(set(domain_keyword))
    if domain_regex:
        rule["domain_regex"] = sorted(set(domain_regex))
    if ip_cidr:
        rule["ip_cidr"] = sorted(set(ip_cidr))

    if not rule:
        return None

    # 按 sing-box classical 源格式拼装
    return {
        "version": 1,
        "rules": [rule]
    }


def write_temp_ruleset_json(base_name: str, ruleset_obj) -> str:
    temp_path = os.path.join(SBOX_DIR, f"temp_ruleset_{base_name}.json")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(ruleset_obj, f, ensure_ascii=False, indent=2)
    return temp_path


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


# ---------- 主流程 ----------

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

    success_count = 0
    fail_count = 0

    for json_file in sorted(json_files):
        full_path = os.path.join(SBOX_DIR, json_file)
        base_name = os.path.splitext(json_file)[0]
        log(f"\n🔍 处理: {json_file}")

        data = load_json(full_path)
        if data is None:
            fail_count += 1
            continue

        temp_json = None

        if is_ruleset_json(data):
            # 已经是 rule-set 源格式，最多给没有 version 的补一个
            if isinstance(data, dict):
                rs_obj = data
                if "version" not in rs_obj:
                    rs_obj["version"] = 1
            else:  # 根是一个数组
                rs_obj = {"version": 1, "rules": data}
            temp_json = write_temp_ruleset_json(base_name, rs_obj)
            log("  ✅ 检测到已是 sing-box rule-set 源格式，直接编译")
        else:
            # 尝试从 payload 提取 clash 规则，生成 rule-set
            rs_obj = build_ruleset_from_payload(data)
            if rs_obj:
                temp_json = write_temp_ruleset_json(base_name, rs_obj)
                log("  ✅ 从 payload 中提取出可转换规则，已自动构造 rule-set 源 JSON")
            else:
                log("  ⏭ 不支持的 JSON 结构，无法提取规则，跳过")
                fail_count += 1
                continue

        try:
            ok = compile_to_srs(temp_json, base_name)
        finally:
            if temp_json and os.path.exists(temp_json):
                os.remove(temp_json)

        if ok:
            success_count += 1
        else:
            fail_count += 1

    log(f"\n📊 统计: 成功 {success_count} 个, 失败 {fail_count} 个")


if __name__ == "__main__":
    main()