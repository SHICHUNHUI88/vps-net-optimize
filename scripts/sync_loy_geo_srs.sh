#!/usr/bin/env bash
set -euo pipefail

# ===== 你给的来源 =====
GEOIP_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'
GEOSITE_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'

# ===== 输出目录：你要求的两个新文件夹 =====
OUT_GEOIP_DIR='singbox/Loy-geoip'
OUT_GEOSITE_DIR='singbox/Loy-geosite'

WORKDIR="$(mktemp -d)"
cleanup(){ rm -rf "$WORKDIR"; }
trap cleanup EXIT

mkdir -p "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"

echo "[1/4] Download geoip.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOIP_URL" -o "$WORKDIR/geoip.dat"

echo "[2/4] Download geosite.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOSITE_URL" -o "$WORKDIR/geosite.dat"

# 可选：避免旧文件残留（强烈建议开）
rm -f "$OUT_GEOIP_DIR"/*.srs 2>/dev/null || true
rm -f "$OUT_GEOSITE_DIR"/*.srs 2>/dev/null || true

echo "[3/4] Convert geoip.dat -> SRS (no prefix, output to $OUT_GEOIP_DIR)"
geodat2srs geoip -i "$WORKDIR/geoip.dat" -o "$OUT_GEOIP_DIR"

echo "[4/4] Convert geosite.dat -> SRS (no prefix, output to $OUT_GEOSITE_DIR)"
geodat2srs geosite -i "$WORKDIR/geosite.dat" -o "$OUT_GEOSITE_DIR"

echo "Done."