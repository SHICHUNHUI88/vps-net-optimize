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
        for i, item in enumerate(payload[:5]):
            print(f"    First few items: {repr(item)}")

        for item in payload:
            if isinstance(item, str):
                if item.startswith('DOMAIN') and not item.startswith('DOMAIN-REGEX'):
                    domain_rules.append(item)
                elif item.startswith('IP-CIDR') or item.startswith('IP-CIDR6'):
                    ip_rules.append(item)
                    print(f"    ✅ Matched IP rule: {repr(item)}")  # 打印匹配到的每一条 IP 规则
    else:
        print("  ⚠️ No payload found or empty")

    print(f"  Found {len(domain_rules)} domain rules, {len(ip_rules)} IP rules")

    # 转换域名规则
    if domain_rules:
        temp_domain = os.path.join(SRC_DIR, f"temp_domain_{base_name}.yaml")
        with open(temp_domain, 'w') as f:
            f.write("payload:\n")
            for rule in domain_rules:
                f.write(f"  - {rule}\n")
        os.system(f"./mihomo convert-ruleset domain yaml {temp_domain} {SRC_DIR}/{base_name}_domain.mrs")
        os.remove(temp_domain)
        print(f"  ✅ Converted domain rules: {base_name}_domain.mrs")
    else:
        print(f"  ℹ️ No domain rules")

    # 转换 IP 规则
    if ip_rules:
        temp_ip = os.path.join(SRC_DIR, f"temp_ip_{base_name}.yaml")
        with open(temp_ip, 'w') as f:
            f.write("payload:\n")
            for rule in ip_rules:
                f.write(f"  - {rule}\n")
        print(f"  🚀 Converting {len(ip_rules)} IP rules...")
        # 使用 subprocess 捕获输出
        result = subprocess.run(
            ["./mihomo", "convert-ruleset", "ipcidr", "yaml", temp_ip, f"{SRC_DIR}/{base_name}_ip.mrs"],
            capture_output=True,
            text=True
        )
        print(f"  Command stdout: {result.stdout.strip()}")
        print(f"  Command stderr: {result.stderr.strip()}")
        print(f"  Exit code: {result.returncode}")
        os.remove(temp_ip)
        # 检查生成的文件
        ip_file = f"{SRC_DIR}/{base_name}_ip.mrs"
        if os.path.exists(ip_file):
            size = os.path.getsize(ip_file)
            print(f"  ✅ Generated {base_name}_ip.mrs, size: {size} bytes")
            if size == 0:
                print("  ⚠️  File is empty!")
        else:
            print(f"  ❌ File {base_name}_ip.mrs not generated!")
    else:
        print(f"  ℹ️ No IP rules")