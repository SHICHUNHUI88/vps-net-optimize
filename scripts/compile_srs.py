#!/usr/bin/env python3
import os
import sys
import subprocess
import json

SBOX_DIR = os.getenv("SBOX_DIR", "singbox")
SINGBOX_BIN = "./sing-box"

def log(msg: str) -> None:
    print(msg, flush=True)

def is_valid_json(file_path: str) -> bool:
    """检查JSON文件语法是否有效"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            json.load(f)
        return True
    except json.JSONDecodeError as e:
        log(f"    ❌ JSON语法错误: {e}")
        return False
    except Exception as e:
        log(f"    ❌ 读取文件失败: {e}")
        return False

def compile_json_to_srs(json_path: str, base_name: str) -> bool:
    """编译有效JSON，返回是否成功"""
    output_srs = os.path.join(SBOX_DIR, f"{base_name}.srs")
    cmd = [SINGBOX_BIN, "rule-set", "compile", "--output", output_srs, json_path]
    log(f"    ▶ Run: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        log("    ❌ 命令超时")
        return False
    except Exception as e:
        log(f"    ❌ 异常: {e}")
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
    return size > 0

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

        if not is_valid_json(full_path):
            fail_count += 1
            continue

        ok = compile_json_to_srs(full_path, base_name)
        if ok:
            success_count += 1
        else:
            fail_count += 1

    log(f"\n📊 统计: 成功 {success_count} 个, 失败 {fail_count} 个")

if __name__ == "__main__":
    main()