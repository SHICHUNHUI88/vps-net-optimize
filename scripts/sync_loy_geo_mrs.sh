#!/usr/bin/env bash
set -euo pipefail

# ===== 上游 DAT =====
GEOIP_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'
GEOSITE_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'

# ===== 输出目录（固定）=====
OUT_GEOIP_DIR='geo/geoip'
OUT_GEOSITE_DIR='geo/geosite'

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$WORKDIR" "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"

echo "[1/5] Download dat..."
curl -fsSL --retry 3 --retry-delay 2 "$GEOIP_URL"   -o "$WORKDIR/geoip.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOSITE_URL" -o "$WORKDIR/geosite.dat"

echo "[2/5] Unpack dat -> split txt..."
mkdir -p "$WORKDIR/geoip_txt" "$WORKDIR/geosite_txt"
v2dat unpack geoip   -d "$WORKDIR/geoip_txt"   "$WORKDIR/geoip.dat"
v2dat unpack geosite -d "$WORKDIR/geosite_txt" "$WORKDIR/geosite.dat"

echo "[3/5] Rebuild output dirs (clean sync)..."
rm -rf "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"
mkdir -p "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"

echo "[4/5] Compile geoip -> split mrs..."
shopt -s nullglob
for f in "$WORKDIR/geoip_txt"/*.txt; do
  base="$(basename "$f")"           # geoip_<TAG>.txt
  tag="${base#geoip_}"
  tag="${tag%.txt}"
  ./mihomo convert-ruleset ipcidr text "$f" "${OUT_GEOIP_DIR}/${tag}.mrs"
done

echo "[5/5] Compile geosite -> split mrs (domain/full only)..."
mkdir -p "$WORKDIR/geosite_domain_only"

for f in "$WORKDIR/geosite_txt"/*.txt; do
  base="$(basename "$f")"           # geosite_<TAG>.txt
  tag="${base#geosite_}"
  tag="${tag%.txt}"

  out="$WORKDIR/geosite_domain_only/${tag}.txt"
  : > "$out"

  # v2dat geosite 输出：
  # - 普通行：domain（省略 domain: 前缀）
  # - full:xxx
  # - keyword:xxx
  # - regexp:xxx
  #
  # mrs 的 domain ruleset 不支持 keyword/regexp，所以丢弃它们
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    case "$line" in
      keyword:*|regexp:*)
        continue
        ;;
      full:*)
        echo "${line#full:}" >> "$out"
        ;;
      *)
        # domain：转成后缀匹配 .example.com
        if [[ "$line" == .* || "$line" == *"*"* ]]; then
          echo "$line" >> "$out"
        else
          echo ".$line" >> "$out"
        fi
        ;;
    esac
  done < "$f"

  # 过滤后为空就跳过
  [[ -s "$out" ]] || continue

  ./mihomo convert-ruleset domain text "$out" "${OUT_GEOSITE_DIR}/${tag}.mrs"
done

ls -lah geo || true
find geo -maxdepth 2 -type f | head -n 20 || true

echo "Done."