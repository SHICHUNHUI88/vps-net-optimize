#!/usr/bin/env bash
set -euo pipefail

# ===== 你给的来源 =====
GEOIP_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'
GEOSITE_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'

# ===== 你的仓库目录结构（按你截图）=====
OUT_GEOIP_DIR='singbox/geoip'
OUT_GEOSITE_DIR='singbox/geosite'

# 临时目录
WORKDIR="$(mktemp -d)"
cleanup(){ rm -rf "$WORKDIR"; }
trap cleanup EXIT

mkdir -p "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"

echo "[1/4] Download geoip.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOIP_URL" -o "$WORKDIR/geoip.dat"

echo "[2/4] Download geosite.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOSITE_URL" -o "$WORKDIR/geosite.dat"

echo "[3/4] Convert geoip.dat -> SRS (prefix: Loy-)"
# 生成一堆：Loy-cn.srs / Loy-telegram.srs ...（具体取决于 dat 内的 list）
geodat2srs geoip -i "$WORKDIR/geoip.dat" -o "$OUT_GEOIP_DIR" --prefix "Loy-"

echo "[4/4] Convert geosite.dat -> SRS (prefix: Loy-)"
geodat2srs geosite -i "$WORKDIR/geosite.dat" -o "$OUT_GEOSITE_DIR" --prefix "Loy-"

echo "Done."