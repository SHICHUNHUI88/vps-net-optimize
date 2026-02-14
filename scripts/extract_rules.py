#!/usr/bin/env python3
import os
import sys
import yaml
import ipaddress
import subprocess

# 从环境变量读取，默认 clash
SRC_DIR = os.getenv("SRC_DIR", "clash")
MIHOMO_BIN = "./mihomo"


def log(msg: str) -> None:
    print(msg, flush=True)


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
        # 只处理字符串规则
        if not isinstance(item, str):
            continue

        line = item.strip()
        if not line or line.startswith("#"):
            continue

        stripped = line.lstrip()

        # ---------- 域名规则 ----------
        if stripped.startswith("DOMAIN") and not stripped.startswith("DOMAIN-REGEX"):
            # 例如：DOMAIN-SUFFIX,google.com,no-resolve
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if len(parts) >= 2:
                # type = parts[0]  # DOMAIN / DOMAIN-SUFFIX / ...
                value = parts[1]
                # 直接收集域名字符串，交给 mihomo 去做行为判断
                domains.add(value)
            continue

        # ---------- IP 规则 ----------
        if stripped.startswith("IP-CIDR"):
            # 例如：IP-CIDR,1.1.1.0/24,no-resolve
            parts = [p.strip() for p in line.split(",") if p.strip()]
            if len(parts) >= 2:
                cidr = parts[1]
                try:
                    # 校验一下是不是合法网段
                    ipaddress.ip_network(cidr, strict=False)
                    cidrs.add(cidr)
                except ValueError:
                    # 非法就丢掉
                    pass
            continue

    # 排好序返回
    return sorted(domains), sorted(cidrs)


def convert_with_mihomo(behavior: str, src_yaml: str, dst_mrs: str) -> bool:
    """
    调用 mihomo convert-ruleset 进行转换。
    behavior: "domain" / "ipcidr"
    """
    cmd = [MIHOMO_BIN, "convert-ruleset", behavior, "yaml", src_yaml, dst_mrs]
    log(f"    ▶ Run: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stdout.strip():
        log(f"    stdout: {result.stdout.strip()}")
    if result.stderr.strip():
        log(f"    stderr: {result.stderr.strip()}")

    if result.returncode != 0:
        log(f"    ❌ mihomo exit code: {result.returncode}")
        return False

    if not os.path.exists(dst_mrs):
        log("    ❌ MRS file not created")
        return False

    size = os.path.getsize(dst_mrs)
    log(f"    ✅ MRS generated: {dst_mrs} ({size} bytes)")
    if size == 0:
        log("    ⚠️  MRS file is empty!")
    return size > 0


def process_yaml_file(yaml_path: str, base_name: str) -> None:
    log(f"\n🔍 Processing {yaml_path} ...")

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        log(f"  ❌ Failed to load YAML: {e}")
        return

    if not isinstance(data, dict) or "payload" not in data:
        log("  ⚠️ No payload found or payload is not a list")
        return

    payload = data["payload"]
    domains, cidrs = extract_rules_from_payload(payload)

    log(f"  Found {len(domains)} domain entries, {len(cidrs)} IP CIDR entries")

    # ---------- 域名规则 -> _domain.mrs ----------
    if domains:
        temp_domain = os.path.join(SRC_DIR, f"temp_domain_{base_name}.yaml")
        out_domain = os.path.join(SRC_DIR, f"{base_name}_domain.mrs")

        try:
            with open(temp_domain, "w", encoding="utf-8") as f:
                f.write("payload:\n")
                for d in domains:
                    # 这里直接写纯域名字符串
                    f.write(f"  - {d}\n")
            log(f"  🚀 Converting domain rules ({len(domains)}) ...")
            ok = convert_with_mihomo("domain", temp_domain, out_domain)
            if not ok:
                log("  ❌ Domain rules conversion failed")
        finally:
            if os.path.exists(temp_domain):
                os.remove(temp_domain)
    else:
        log("  ℹ️ No domain rules, skip domain.mrs")

    # ---------- IP 规则 -> _ip.mrs ----------
    if cidrs:
        temp_ip = os.path.join(SRC_DIR, f"temp_ip_{base_name}.yaml")
        out_ip = os.path.join(SRC_DIR, f"{base_name}_ip.mrs")

        try:
            with open(temp_ip, "w", encoding="utf-8") as f:
                f.write("payload:\n")
                for c in cidrs:
                    # 只写纯 CIDR，例如 1.1.1.0/24
                    f.write(f"  - {c}\n")
            log(f"  🚀 Converting IP rules ({len(cidrs)}) ...")
            ok = convert_with_mihomo("ipcidr", temp_ip, out_ip)
            if not ok:
                log("  ❌ IP rules conversion failed")
        finally:
            if os.path.exists(temp_ip):
                os.remove(temp_ip)
    else:
        log("  ℹ️ No IP rules, skip _ip.mrs")


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
    log(f"🔧 Found {len(yaml_files)} yaml files")

    for yaml_file in sorted(yaml_files):
        full_path = os.path.join(SRC_DIR, yaml_file)
        base_name = os.path.splitext(yaml_file)[0]
        process_yaml_file(full_path, base_name)


if __name__ == "__main__":
    main()