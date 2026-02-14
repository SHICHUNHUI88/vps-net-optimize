#!/usr/bin/env python3
import yaml
import os
import subprocess

SRC_DIR = os.getenv('SRC_DIR', 'clash')

for yaml_file in os.listdir(SRC_DIR):
    if not yaml_file.endswith('.yaml'):
        continue
    full_path = os.path.join(SRC_DIR, yaml_file)
    base_name = os.path.splitext(yaml_file)[0]

    print(f"\n🔍 Processing {yaml_file}...")

    with open(full_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    domain_rules = []
    ip_rules = []

    if data and 'payload' in data:
        payload = data['payload']
        print(f"  Payload contains {len(payload)} items.")
        # 打印前几条规则，便于检查原始内容
        for i, item in enumerate(payload[:3]):
            print(f"    Example item {i}: {repr(item)}")

        for item in payload:
            if not isinstance(item, str):
                print(f"    ⚠️ Skipping non-string item: {repr(item)}")
                continue
            # 去除前导空白后判断
            stripped = item.lstrip()
            # 域名规则（排除正则）
            if stripped.startswith('DOMAIN') and not stripped.startswith('DOMAIN-REGEX'):
                domain_rules.append(item)
                print(f"    ➕ Domain rule: {repr(item)}")
            # IP 规则（同时匹配 IP-CIDR 和 IP-CIDR6）
            elif stripped.startswith('IP-CIDR'):
                ip_rules.append(item)
                print(f"    ➕ IP rule: {repr(item)}")
    else:
        print("  ⚠️ No payload found or empty")

    print(f"  Found {len(domain_rules)} domain rules, {len(ip_rules)} IP rules")

    # 转换域名规则
    if domain_rules:
        temp_domain = os.path.join(SRC_DIR, f"temp_domain_{base_name}.yaml")
        with open(temp_domain, 'w') as f:
            f.write("payload:\n")
            for rule in domain_rules:
                # 保持原样写入（域名规则不需要修改）
                f.write(f"  - {rule}\n")
        # 执行转换，捕获输出
        result = subprocess.run(
            ["./mihomo", "convert-ruleset", "domain", "yaml", temp_domain, f"{SRC_DIR}/{base_name}_domain.mrs"],
            capture_output=True, text=True
        )
        print(f"    Domain convert stdout: {result.stdout.strip()}")
        if result.stderr:
            print(f"    Domain convert stderr: {result.stderr.strip()}")
        os.remove(temp_domain)
        # 检查生成的文件
        domain_file = f"{SRC_DIR}/{base_name}_domain.mrs"
        if os.path.exists(domain_file):
            size = os.path.getsize(domain_file)
            print(f"    ✅ Domain MRS generated, size: {size} bytes")
        else:
            print(f"    ❌ Domain MRS not generated")
    else:
        print(f"  ℹ️ No domain rules")

    # 转换 IP 规则
    if ip_rules:
        temp_ip = os.path.join(SRC_DIR, f"temp_ip_{base_name}.yaml")
        with open(temp_ip, 'w') as f:
            f.write("payload:\n")
            for rule in ip_rules:
                # 去掉可能存在的 ,no-resolve 部分，只保留 IP-CIDR,xxx
                # 按逗号分割，取前两部分
                parts = rule.split(',')
                if len(parts) >= 2:
                    clean_rule = f"{parts[0]},{parts[1]}"
                else:
                    clean_rule = rule  # 保底
                f.write(f"  - {clean_rule}\n")
        print(f"  🚀 Converting {len(ip_rules)} IP rules (cleaned of no-resolve)...")
        result = subprocess.run(
            ["./mihomo", "convert-ruleset", "ipcidr", "yaml", temp_ip, f"{SRC_DIR}/{base_name}_ip.mrs"],
            capture_output=True, text=True
        )
        print(f"    IP convert stdout: {result.stdout.strip()}")
        if result.stderr:
            print(f"    IP convert stderr: {result.stderr.strip()}")
        os.remove(temp_ip)
        ip_file = f"{SRC_DIR}/{base_name}_ip.mrs"
        if os.path.exists(ip_file):
            size = os.path.getsize(ip_file)
            print(f"    ✅ IP MRS generated, size: {size} bytes")
            if size == 0:
                print("    ⚠️  IP MRS is empty! Check mihomo output above.")
        else:
            print(f"    ❌ IP MRS not generated")
    else:
        print(f"  ℹ️ No IP rules")