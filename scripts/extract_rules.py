#!/usr/bin/env python3
import yaml
import os
import sys

SRC_DIR = os.getenv('SRC_DIR', 'clash')  # 从环境变量读取

for yaml_file in os.listdir(SRC_DIR):
    if not yaml_file.endswith('.yaml'):
        continue
    full_path = os.path.join(SRC_DIR, yaml_file)
    base_name = os.path.splitext(yaml_file)[0]

    with open(full_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    domain_rules = []
    ip_rules = []

    if data and 'payload' in data:
        for item in data['payload']:
            if isinstance(item, str):
                if item.startswith('DOMAIN') and not item.startswith('DOMAIN-REGEX'):
                    domain_rules.append(item)
                # ✅ 修复：同时匹配 IP-CIDR 和 IP-CIDR6
                elif item.startswith('IP-CIDR') or item.startswith('IP-CIDR6'):
                    ip_rules.append(item)

    # 转换域名规则
    if domain_rules:
        temp_domain = os.path.join(SRC_DIR, f"temp_domain_{base_name}.yaml")
        with open(temp_domain, 'w') as f:
            f.write("payload:\n")
            for rule in domain_rules:
                f.write(f"  - {rule}\n")
        os.system(f"./mihomo convert-ruleset domain yaml {temp_domain} {SRC_DIR}/{base_name}_domain.mrs")
        os.remove(temp_domain)
        print(f"✓ Converted domain rules: {base_name}_domain.mrs")
    else:
        print(f"ℹ️ No domain rules in {base_name}.yaml")

    # 转换 IP 规则
    if ip_rules:
        temp_ip = os.path.join(SRC_DIR, f"temp_ip_{base_name}.yaml")
        with open(temp_ip, 'w') as f:
            f.write("payload:\n")
            for rule in ip_rules:
                f.write(f"  - {rule}\n")
        os.system(f"./mihomo convert-ruleset ipcidr yaml {temp_ip} {SRC_DIR}/{base_name}_ip.mrs")
        os.remove(temp_ip)
        print(f"✓ Converted IP rules: {base_name}_ip.mrs")
    else:
        print(f"ℹ️ No IP rules in {base_name}.yaml")