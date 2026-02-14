#!/usr/bin/env python3
import os
import sys
import subprocess
import json

SBOX_DIR = os.getenv("SBOX_DIR", "singbox")
SINGBOX_BIN = "./sing-box"

def log(msg: str) -> None:
    print(msg, flush=True)

def compile_json_to_srs(json_path: str, base_name: str) -> bool:
    """将单个 JSON 文件编译为 SRS，返回是否成功"""
    output_srs = os.path.join(SBOX_DIR, f"{base_name}.srs")
    cmd = [SINGBOX_BIN, "rule-set", "compile", "--output", output_srs, json_path]
    log(f"    ▶ Run: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        log("    ❌ Command timed out")
        return False
    except Exception as e:
        log(f"    ❌ Exception: {e}")
        return False

    if result.stdout.strip():
        log(f"    stdout: {result.stdout.strip()}")
    if result.stderr.strip():
        log(f"    stderr: {result.stderr.strip()}")

    if result.returncode != 0:
        log(f"    ❌ sing-box exit code: {result.returncode}")
        return False

    if not os.path.exists(output_srs):
        log("    ❌ SRS file not created")
        return False

    size = os.path.getsize(output_srs)
    log(f"    ✅ SRS generated: {output_srs} ({size} bytes)")
    return size > 0

def main():
    if not os.path.isdir(SBOX_DIR):
        log(f"❌ SBOX_DIR '{SBOX_DIR}' not found")
        sys.exit(1)

    if not os.path.exists(SINGBOX_BIN):
        log(f"❌ sing-box binary '{SINGBOX_BIN}' not found")
        sys.exit(1)

    json_files = [f for f in os.listdir(SBOX_DIR) if f.endswith(".json")]
    if not json_files:
        log(f"⚠️ No .json files found in {SBOX_DIR}")
        return

    log(f"🔧 Using SBOX_DIR = {SBOX_DIR}")
    log(f"🔧 Found {len(json_files)} json files")

    success_count = 0
    fail_count = 0

    for json_file in sorted(json_files):
        full_path = os.path.join(SBOX_DIR, json_file)
        base_name = os.path.splitext(json_file)[0]
        log(f"\n🔍 Processing {json_file} ...")
        ok = compile_json_to_srs(full_path, base_name)
        if ok:
            success_count += 1
        else:
            fail_count += 1
            log(f"    ❌ Failed to compile {json_file}")

    log(f"\n📊 Summary: {success_count} succeeded, {fail_count} failed")

if __name__ == "__main__":
    main()