#!/usr/bin/env bash
set -euo pipefail

# ---------------------------
# Loyalsoldier DAT -> Split MRS (geo/)
# Output:
#   geo/geoip/*.mrs
#   geo/geosite/*.mrs
# Reports:
#   geo/REPORT-loy-geosite-filtered.txt
#   geo/REPORT-loy-geosite-skipped-keyword-regexp.txt
#
# Requirements:
#   - v2dat in PATH
#   - ./mihomo exists in repo root (or set MIHOMO_BIN)
# Notes:
#   - geosite.dat contains keyword/regexp which cannot be represented in .mrs domain ruleset.
#     We keep only:
#       - domain (suffix)  => ".example.com"
#       - full (exact)     => "www.example.com"
#     Skip:
#       - keyword:*
#       - regexp:*
# ---------------------------

GEOIP_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'
GEOSITE_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'

OUT_GEOIP_DIR='geo/geoip'
OUT_GEOSITE_DIR='geo/geosite'
REPORT_DIR='geo'

MIHOMO_BIN="${MIHOMO_BIN:-./mihomo}"

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }

# Ensure run at repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

log "Repo root: $(pwd)"

log "Check tools..."
command -v v2dat >/dev/null 2>&1 || { echo "ERROR: v2dat not found in PATH"; exit 1; }
[ -x "$MIHOMO_BIN" ] || { echo "ERROR: mihomo not executable at: $MIHOMO_BIN"; ls -lah; exit 1; }

log "mihomo version:"
"$MIHOMO_BIN" -v || true

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

mkdir -p "$WORKDIR"

log "1) Download DAT..."
curl -fsSL --retry 3 --retry-delay 2 "$GEOIP_URL"   -o "$WORKDIR/geoip.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOSITE_URL" -o "$WORKDIR/geosite.dat"

log "2) Unpack DAT -> split txt..."
mkdir -p "$WORKDIR/geoip_txt" "$WORKDIR/geosite_txt"

# v2dat 输出结构可能是：直接一堆 txt，或者多层子目录
v2dat unpack geoip   -d "$WORKDIR/geoip_txt"   "$WORKDIR/geoip.dat"
v2dat unpack geosite -d "$WORKDIR/geosite_txt" "$WORKDIR/geosite.dat"

log "DEBUG: show unpack outputs (first 80 files)"
find "$WORKDIR/geoip_txt"   -maxdepth 4 -type f | head -n 40 || true
find "$WORKDIR/geosite_txt" -maxdepth 4 -type f | head -n 40 || true

log "3) Rebuild output dirs (clean sync)..."
rm -rf "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"
mkdir -p "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR" "$REPORT_DIR"

REPORT_FILTERED="${REPORT_DIR}/REPORT-loy-geosite-filtered.txt"
REPORT_SKIPPED="${REPORT_DIR}/REPORT-loy-geosite-skipped-keyword-regexp.txt"
: > "$REPORT_FILTERED"
: > "$REPORT_SKIPPED"

log "4) Compile geoip -> split mrs..."
geoip_count=0
# 用 find 抓所有 txt，避免 v2dat 输出在子目录导致匹配不到
while IFS= read -r f; do
  base="$(basename "$f")"
  tag="${base#geoip_}"
  tag="${tag%.txt}"
  # 如果命名不是 geoip_xxx.txt，就用文件名本体
  if [[ "$tag" == "$base" ]]; then
    tag="${base%.txt}"
  fi

  "$MIHOMO_BIN" convert-ruleset ipcidr text "$f" "${OUT_GEOIP_DIR}/${tag}.mrs"
  geoip_count=$((geoip_count+1))
done < <(find "$WORKDIR/geoip_txt" -type f -name '*.txt' | sort)

log "geoip mrs generated: ${geoip_count}"

log "5) Compile geosite -> split mrs (domain/full only)..."
mkdir -p "$WORKDIR/geosite_domain_only"

geosite_count=0
filtered_empty_count=0
skipped_kw_re_count=0

while IFS= read -r f; do
  base="$(basename "$f")"
  tag="${base#geosite_}"
  tag="${tag%.txt}"
  if [[ "$tag" == "$base" ]]; then
    tag="${base%.txt}"
  fi

  out="$WORKDIR/geosite_domain_only/${tag}.txt"
  : > "$out"

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    case "$line" in
      keyword:*|regexp:*)
        echo "${tag}  ${line}" >> "$REPORT_SKIPPED"
        skipped_kw_re_count=$((skipped_kw_re_count+1))
        continue
        ;;
      full:*)
        echo "${line#full:}" >> "$out"
        ;;
      *)
        # 普通 domain：转后缀匹配 .example.com
        if [[ "$line" == .* || "$line" == *"*"* ]]; then
          echo "$line" >> "$out"
        else
          echo ".$line" >> "$out"
        fi
        ;;
    esac
  done < "$f"

  # 过滤后为空（这个 tag 全是 keyword/regexp）就记录并跳过
  if [[ ! -s "$out" ]]; then
    echo "${tag}" >> "$REPORT_FILTERED"
    filtered_empty_count=$((filtered_empty_count+1))
    continue
  fi

  "$MIHOMO_BIN" convert-ruleset domain text "$out" "${OUT_GEOSITE_DIR}/${tag}.mrs"
  geosite_count=$((geosite_count+1))
done < <(find "$WORKDIR/geosite_txt" -type f -name '*.txt' | sort)

log "geosite mrs generated: ${geosite_count}"
log "geosite tags filtered empty: ${filtered_empty_count}"
log "geosite lines skipped (keyword/regexp): ${skipped_kw_re_count}"

log "6) Final debug listing..."
log "geo folder:"
ls -lah geo || true

echo "geoip .mrs count:"
find "$OUT_GEOIP_DIR" -type f -name '*.mrs' | wc -l || true
echo "geosite .mrs count:"
find "$OUT_GEOSITE_DIR" -type f -name '*.mrs' | wc -l || true

log "Sample outputs (first 40):"
find geo -maxdepth 2 -type f | head -n 40 || true

log "Done."