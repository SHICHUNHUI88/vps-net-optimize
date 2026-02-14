#!/usr/bin/env python3
import yaml
import os

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
        print(f"  Payload contains {len(payload)} items. First 5 items as raw strings:")
        for i, item in enumerate(payload[:5]):
            # 打印每个条目的 repr，可以看到隐藏字符
            print(f"    {i}: {repr(item)}")

        for item in payload:
            if isinstance(item, str):
                # 打印每个被检查的规则的前缀，便于追踪
                if item.startswith('IP-CIDR'):
                    print(f"    ➡️ Matched IP-CIDR: {repr(item)}")
                    ip_rules.append(item)
                elif item.startswith('IP-CIDR6'):
                    print(f"    ➡️ Matched IP-CIDR6: {repr(item)}")
                    ip_rules.append(item)
                elif item.startswith('DOMAIN') and not item.startswith('DOMAIN-REGEX'):
                    domain_rules.append(item)
    else:
        print("  ⚠️ No payload found or empty")

    print(f"  Found {len(domain_rules)} domain rules, {len(ip_rules)} IP rules")

    # 转换域名规则...
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

    if ip_rules:
        temp_ip = os.path.join(SRC_DIR, f"temp_ip_{base_name}.yaml")
        with open(temp_ip, 'w') as f:
            f.write("payload:\n")
            for rule in ip_rules:
                f.write(f"  - {rule}\n")
        print(f"  🚀 Converting {len(ip_rules)} IP rules...")
        # 执行转换并捕获输出，便于调试
        result = os.system(f"./mihomo convert-ruleset ipcidr yaml {temp_ip} {SRC_DIR}/{base_name}_ip.mrs")
        print(f"  Conversion command exited with code: {result}")
        os.remove(temp_ip)
        # 检查生成的文件大小
        if os.path.exists(f"{SRC_DIR}/{base_name}_ip.mrs"):
            size = os.path.getsize(f"{SRC_DIR}/{base_name}_ip.mrs")
            print(f"  ✅ Generated {base_name}_ip.mrs, size: {size} bytes")
        else:
            print(f"  ❌ File {base_name}_ip.mrs not generated!")
    else:
        print(f"  ℹ️ No IP rules")