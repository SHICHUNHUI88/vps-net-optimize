#!/usr/bin/env bash
set -euo pipefail

URL="https://raw.githubusercontent.com/SHICHUNHUI88/vps-net-optimize/main/net-optimize-ultimate.sh"
DST="/usr/local/sbin/net-optimize-ultimate.sh"

tmp="$(mktemp)"
curl -fsSL "$URL" -o "$tmp"
bash -n "$tmp"   # 语法检查，防止你又提交了“压扁版”直接炸机
install -Dm755 "$tmp" "$DST"
rm -f "$tmp"

exec "$DST" "$@"