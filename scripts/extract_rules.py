#!/usr/bin/env python3
import os
import yaml

SRC_DIR = os.getenv("SRC_DIR", "clash")  # 从环境变量读取，默认 clash

for yaml_file in os.listdir(SRC_DIR):
    if not yaml_file.endswith(".yaml"):
        continue

    full_path = os.path.join(SRC_DIR, yaml_file)
    base_name = os.path.splitext(yaml_file)[0]

    with open(full_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    domain_rules = []
    ip_rules = []

    # 只处理 payload 是列表的情况，防止奇怪结构
    if isinstance(data, dict) and isinstance(data.get("payload"), list):
        for item in data["payload"]:
            if not isinstance(item, str):
                continue

            # 域名规则：DOMAIN 系，排除 DOMAIN-REGEX
            if item.startswith("DOMAIN") and not item.startswith("DOMAIN-REGEX"):
                domain_rules.append(item)

            # IP 规则：IP-CIDR / IP-CIDR6
            elif item.startswith("IP-CIDR"):
                parts = item.split(",")
                if len(parts) >= 2:
                    # 只保留「类型 + CIDR」，去掉 no-resolve 等尾巴
                    rule_type = parts[0].strip()      # IP-CIDR / IP-CIDR6
                    cidr = parts[1].strip()           # 101.227.0.0/16 / 2409:...
                    ip_rules.append(f"{rule_type},{cidr}")

    # ===== 域名规则转 MRS =====
    if domain_rules:
        temp_domain = os.path.join(SRC_DIR, f"temp_domain_{base_name}.yaml")
        with open(temp_domain, "w", encoding="utf-8") as f:
            f.write("payload:\n")
            for rule in domain_rules:
                f.write(f"  - {rule}\n")

        os.system(f"./mihomo convert-ruleset domain yaml {temp_domain} {SRC_DIR}/{base_name}_domain.mrs")
        os.remove(temp_domain)
        print(f"✓ Converted domain rules: {base_name}_domain.mrs")
    else:
        print(f"ℹ️ No domain rules in {base_name}.yaml")

    # ===== IP 规则转 MRS =====
    if ip_rules:
        temp_ip = os.path.join(SRC_DIR, f"temp_ip_{base_name}.yaml")
        with open(temp_ip, "w", encoding="utf-8") as f:
            f.write("payload:\n")
            for rule in ip_rules:
                f.write(f"  - {rule}\n")

        os.system(f"./mihomo convert-ruleset ipcidr yaml {temp_ip} {SRC_DIR}/{base_name}_ip.mrs")
        os.remove(temp_ip)
        print(f"✓ Converted IP rules: {base_name}_ip.mrs")
    else:
        print(f"ℹ️ No IP rules in {base_name}.yaml")