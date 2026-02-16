#!/usr/bin/env python3
import os
import sys
import yaml
import ipaddress
import subprocess

# 从环境变量读取，默认 clash
SRC_DIR = os.getenv("SRC_DIR", "clash")
MIHOMO_BIN = os.getenv("MIHOMO_BIN", "./mihomo")

# 严格模式：转换失败就删除旧产物，避免误用旧 mrs
STRICT_MODE = True


def log(msg: str) -> None:
    print(msg, flush=True)


def safe_unlink(path: str) -> None:
    """删除文件（不存在就忽略）"""
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except Exception as e:
        log(f"    ⚠️ Failed to delete {path}: {e}")


def extract_rules_from_payload(payload):
    """
    从 payload 列表里提取：
    - 纯域名列表 domains
    - 纯 CIDR 列表 cidrs
    """
    domains = set()
    cidrs = set()

    if not isinstance(payload, list):
        return [], []

    for item in payload:
        if not isinstance(item, str):
            continue

        line = item.strip()
        if not line or line.startswith("#"):
            continue

        stripped = line.lstrip()

        # ---------- 域名规则 ----------
        # 收集 DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-WILDCARD 等
        # 排除 DOMAIN-REGEX（regex 不适合丢给 behavior=domain）
        if stripped.startswith("DOMAIN") and not stripped.startswith("DOMAIN-REGEX"):
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if len(parts) >= 2:
                domains.add(parts[1])
            continue

        # ---------- IP 规则 ----------
        # IP-CIDR / IP-CIDR6 都收集
        if stripped.startswith("IP-CIDR"):
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if len(parts) >= 2:
                cidr = parts[1]
                try:
                    ipaddress.ip_network(cidr, strict=False)
                    cidrs.add(cidr)
                except ValueError:
                    pass
            continue

    return sorted(domains), sorted(cidrs)


def write_temp_payload_yaml(temp_path: str, items) -> None:
    """写一个 payload: 列表给 mihomo 用（纯值列表）"""
    with open(temp_path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for it in items:
            f.write(f"  - {it}\n")


def convert_with_mihomo_atomic_strict(behavior: str, src_yaml: str, dst_mrs: str) -> bool:
    """
    原子写入 + 严格模式：
    - 输出到 dst_mrs.tmp
    - 成功且非空：os.replace 覆盖 dst_mrs
    - 失败/空：删除 tmp；严格模式下删除 dst_mrs（防止继续用旧文件）
    """
    tmp_out = dst_mrs + ".tmp"
    safe_unlink(tmp_out)

    cmd = [MIHOMO_BIN, "convert-ruleset", behavior, "yaml", src_yaml, tmp_out]
    log(f"    ▶ Run: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stdout.strip():
        log(f"    stdout: {result.stdout.strip()}")
    if result.stderr.strip():
        log(f"    stderr: {result.stderr.strip()}")

    # 失败：删 tmp，严格模式删旧产物
    if result.returncode != 0:
        log(f"    ❌ mihomo exit code: {result.returncode}")
        safe_unlink(tmp_out)
        if STRICT_MODE:
            log("    🧹 STRICT: delete old output to avoid stale mrs")
            safe_unlink(dst_mrs)
        return False

    if not os.path.exists(tmp_out):
        log("    ❌ tmp MRS file not created")
        if STRICT_MODE:
            log("    🧹 STRICT: delete old output to avoid stale mrs")
            safe_unlink(dst_mrs)
        return False

    size = os.path.getsize(tmp_out)
    log(f"    ✅ tmp MRS generated: {tmp_out} ({size} bytes)")

    # 空文件：当作失败处理
    if size == 0:
        log("    ⚠️ tmp MRS is empty -> treat as failure")
        safe_unlink(tmp_out)
        if STRICT_MODE:
            log("    🧹 STRICT: delete old output to avoid stale mrs")
            safe_unlink(dst_mrs)
        return False

    # 原子替换
    try:
        os.replace(tmp_out, dst_mrs)
    except Exception as e:
        log(f"    ❌ Failed to replace {dst_mrs}: {e}")
        safe_unlink(tmp_out)
        if STRICT_MODE:
            log("    🧹 STRICT: delete old output to avoid stale mrs")
            safe_unlink(dst_mrs)
        return False

    final_size = os.path.getsize(dst_mrs)
    log(f"    ✅ MRS updated: {dst_mrs} ({final_size} bytes)")
    return True


def process_yaml_file(yaml_path: str, base_name: str) -> None:
    log(f"\n🔍 Processing {yaml_path} ...")

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        log(f"  ❌ Failed to load YAML: {e}")
        # 严格模式：YAML 解析失败也不要留旧产物（防止假更新）
        if STRICT_MODE:
            out_domain = os.path.join(SRC_DIR, f"{base_name}_domain.mrs")
            out_ip = os.path.join(SRC_DIR, f"{base_name}_ip.mrs")
            log("  🧹 STRICT: YAML parse failed -> delete old outputs")
            safe_unlink(out_domain)
            safe_unlink(out_ip)
        return

    if not isinstance(data, dict) or "payload" not in data:
        log("  ⚠️ No payload found or payload is not a list")
        if STRICT_MODE:
            out_domain = os.path.join(SRC_DIR, f"{base_name}_domain.mrs")
            out_ip = os.path.join(SRC_DIR, f"{base_name}_ip.mrs")
            log("  🧹 STRICT: invalid structure -> delete old outputs")
            safe_unlink(out_domain)
            safe_unlink(out_ip)
        return

    payload = data["payload"]
    domains, cidrs = extract_rules_from_payload(payload)

    log(f"  Found {len(domains)} domain entries, {len(cidrs)} IP CIDR entries")

    out_domain = os.path.join(SRC_DIR, f"{base_name}_domain.mrs")
    out_ip = os.path.join(SRC_DIR, f"{base_name}_ip.mrs")

    # ---------- 域名规则 ----------
    if domains:
        temp_domain = os.path.join(SRC_DIR, f"temp_domain_{base_name}.yaml")
        try:
            write_temp_payload_yaml(temp_domain, domains)
            log(f"  🚀 Converting domain rules ({len(domains)}) ...")
            ok = convert_with_mihomo_atomic_strict("domain", temp_domain, out_domain)
            if not ok:
                log("  ❌ Domain conversion failed")
        finally:
            safe_unlink(temp_domain)
    else:
        # 增删同步：没规则就删产物
        if os.path.exists(out_domain):
            log("  🧹 No domain rules -> delete *_domain.mrs for sync")
        safe_unlink(out_domain)

    # ---------- IP 规则 ----------
    if cidrs:
        temp_ip = os.path.join(SRC_DIR, f"temp_ip_{base_name}.yaml")
        try:
            write_temp_payload_yaml(temp_ip, cidrs)
            log(f"  🚀 Converting IP rules ({len(cidrs)}) ...")
            ok = convert_with_mihomo_atomic_strict("ipcidr", temp_ip, out_ip)
            if not ok:
                log("  ❌ IP conversion failed")
        finally:
            safe_unlink(temp_ip)
    else:
        # 增删同步：没规则就删产物
        if os.path.exists(out_ip):
            log("  🧹 No IP rules -> delete *_ip.mrs for sync")
        safe_unlink(out_ip)


def main():
    if not os.path.isdir(SRC_DIR):
        log(f"❌ SRC_DIR '{SRC_DIR}' not found")
        sys.exit(1)

    if not os.path.exists(MIHOMO_BIN):
        log(f"❌ mihomo binary '{MIHOMO_BIN}' not found")
        sys.exit(1)

    yaml_files = [f for f in os.listdir(SRC_DIR) if f.endswith(".yaml")]
    if not yaml_files:
        log(f"⚠️ No .yaml files found in {SRC_DIR}")
        return

    log(f"🔧 Using SRC_DIR = {SRC_DIR}")
    log(f"🔧 MIHOMO_BIN = {MIHOMO_BIN}")
    log(f"🔧 STRICT_MODE = {STRICT_MODE}")
    log(f"🔧 Found {len(yaml_files)} yaml files")

    for yaml_file in sorted(yaml_files):
        full_path = os.path.join(SRC_DIR, yaml_file)
        base_name = os.path.splitext(yaml_file)[0]
        process_yaml_file(full_path, base_name)


if __name__ == "__main__":
    main()