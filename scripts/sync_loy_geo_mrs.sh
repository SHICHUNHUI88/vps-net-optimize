#!/usr/bin/env bash
set -euo pipefail

GEOIP_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'
GEOSITE_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'

# 你要的输出目录（像截图那样）
OUT_GEOIP_DIR='geo/geoip'
OUT_GEOSITE_DIR='geo/geosite'

MIHOMO_BIN="${MIHOMO_BIN:-./mihomo}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# --- 检查依赖 ---
command -v v2dat >/dev/null 2>&1 || { echo "ERROR: v2dat not found"; exit 1; }
[ -x "$MIHOMO_BIN" ] || { echo "ERROR: mihomo not found at $MIHOMO_BIN"; exit 1; }

mkdir -p "$WORKDIR"

echo "[1/5] Download dat..."
curl -fsSL --retry 3 --retry-delay 2 "$GEOIP_URL"   -o "$WORKDIR/geoip.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOSITE_URL" -o "$WORKDIR/geosite.dat"

echo "[2/5] Unpack dat -> txt..."
mkdir -p "$WORKDIR/geoip_txt" "$WORKDIR/geosite_txt"
v2dat unpack geoip   -d "$WORKDIR/geoip_txt"   "$WORKDIR/geoip.dat"
v2dat unpack geosite -d "$WORKDIR/geosite_txt" "$WORKDIR/geosite.dat"

echo "[3/5] Clean output (sync add/del)..."
rm -rf "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"
mkdir -p "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR" geo

# 报告（可选）
REPORT_FILTERED="geo/REPORT-loy-geosite-filtered.txt"
REPORT_SKIPPED="geo/REPORT-loy-geosite-skipped-keyword-regexp.txt"
: > "$REPORT_FILTERED"
: > "$REPORT_SKIPPED"

echo "[4/5] Compile geoip -> mrs..."
while IFS= read -r f; do
  base="$(basename "$f")"
  tag="${base#geoip_}"; tag="${tag%.txt}"
  [[ "$tag" == "$base" ]] && tag="${base%.txt}"
  "$MIHOMO_BIN" convert-ruleset ipcidr text "$f" "${OUT_GEOIP_DIR}/${tag}.mrs"
done < <(find "$WORKDIR/geoip_txt" -type f -name '*.txt' | sort)

echo "[5/5] Compile geosite -> mrs (domain/full only)..."
mkdir -p "$WORKDIR/geosite_domain_only"

while IFS= read -r f; do
  base="$(basename "$f")"
  tag="${base#geosite_}"; tag="${tag%.txt}"
  [[ "$tag" == "$base" ]] && tag="${base%.txt}"

  out="$WORKDIR/geosite_domain_only/${tag}.txt"
  : > "$out"

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    case "$line" in
      keyword:*|regexp:*)
        echo "${tag}  ${line}" >> "$REPORT_SKIPPED"
        continue
        ;;
      full:*)
        echo "${line#full:}" >> "$out"
        ;;
      *)
        # domain -> suffix match
        if [[ "$line" == .* || "$line" == *"*"* ]]; then
          echo "$line" >> "$out"
        else
          echo ".$line" >> "$out"
        fi
        ;;
    esac
  done < "$f"

  if [[ ! -s "$out" ]]; then
    echo "$tag" >> "$REPORT_FILTERED"
    continue
  fi

  "$MIHOMO_BIN" convert-ruleset domain text "$out" "${OUT_GEOSITE_DIR}/${tag}.mrs"
done < <(find "$WORKDIR/geosite_txt" -type f -name '*.txt' | sort)

echo "Done. Counts:"
echo "geoip mrs:   $(find "$OUT_GEOIP_DIR" -type f -name '*.mrs' | wc -l)"
echo "geosite mrs: $(find "$OUT_GEOSITE_DIR" -type f -name '*.mrs' | wc -l)"