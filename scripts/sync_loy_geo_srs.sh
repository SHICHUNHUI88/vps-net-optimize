#!/usr/bin/env bash
set -euo pipefail

GEOIP_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'
GEOSITE_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'

OUT_GEOIP_DIR='singbox/Loy-geoip'
OUT_GEOSITE_DIR='singbox/Loy-geosite'

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"

curl -fsSL --retry 3 --retry-delay 2 "$GEOIP_URL" -o "$WORKDIR/geoip.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOSITE_URL" -o "$WORKDIR/geosite.dat"

# 清空旧文件，避免残留
rm -f "$OUT_GEOIP_DIR"/*.srs 2>/dev/null || true
rm -f "$OUT_GEOSITE_DIR"/*.srs 2>/dev/null || true

geodat2srs geoip   -i "$WORKDIR/geoip.dat"   -o "$OUT_GEOIP_DIR"
geodat2srs geosite -i "$WORKDIR/geosite.dat" -o "$OUT_GEOSITE_DIR"