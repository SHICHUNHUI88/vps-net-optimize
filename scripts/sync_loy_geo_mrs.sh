#!/usr/bin/env bash
set -euo pipefail

GEOIP_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'
GEOSITE_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'

OUT_GEOIP_DIR='geo/geoip'
OUT_GEOSITE_DIR='geo/geosite'

MIHOMO_BIN="${MIHOMO_BIN:-./mihomo}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$REPO_ROOT"

echo "[INFO] repo root: $(pwd)"

command -v v2dat >/dev/null 2>&1 || { echo "ERROR: v2dat not found in PATH"; exit 1; }
[ -x "$MIHOMO_BIN" ] || { echo "ERROR: mihomo not executable at $MIHOMO_BIN"; ls -lah; exit 1; }

echo "[INFO] mihomo version:"
"$MIHOMO_BIN" -v || true

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "[1/6] Download dat..."
curl -fsSL --retry 3 --retry-delay 2 "$GEOIP_URL"   -o "$WORKDIR/geoip.dat"
curl -fsSL --retry 3 --retry-delay 2 "$GEOSITE_URL" -o "$WORKDIR/geosite.dat"

echo "[2/6] Unpack dat -> txt..."
mkdir -p "$WORKDIR/geoip_txt" "$WORKDIR/geosite_txt"

# ✅ 关键修复：urlesistiana/v2dat 用 -o/--out，不支持 -d
v2dat unpack geoip   -o "$WORKDIR/geoip_txt"   "$WORKDIR/geoip.dat"
v2dat unpack geosite -o "$WORKDIR/geosite_txt" "$WORKDIR/geosite.dat"

echo "[DEBUG] unpack samples:"
echo "  geoip_txt:"
find "$WORKDIR/geoip_txt" -type f | head -n 20 || true
echo "  geosite_txt:"
find "$WORKDIR/geosite_txt" -type f | head -n 20 || true

GEOIP_TXT_COUNT="$(find "$WORKDIR/geoip_txt" -type f -name '*.txt' | wc -l | tr -d ' ')"
GEOSITE_TXT_COUNT="$(find "$WORKDIR/geosite_txt" -type f -name '*.txt' | wc -l | tr -d ' ')"
echo "[DEBUG] geoip txt count   = $GEOIP_TXT_COUNT"
echo "[DEBUG] geosite txt count = $GEOSITE_TXT_COUNT"

if [ "$GEOIP_TXT_COUNT" -eq 0 ] || [ "$GEOSITE_TXT_COUNT" -eq 0 ]; then
  echo "ERROR: unpack produced 0 txt files."
  echo "Hint: check v2dat output files (maybe not .txt) or permissions."
  exit 1
fi

echo "[3/6] Clean output (sync add/del)..."
rm -rf "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"
mkdir -p "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR" geo

REPORT_FILTERED="geo/REPORT-loy-geosite-filtered.txt"
REPORT_SKIPPED="geo/REPORT-loy-geosite-skipped-keyword-regexp.txt"
: > "$REPORT_FILTERED"
: > "$REPORT_SKIPPED"

convert_atomic() {
  local behavior="$1"   # domain / ipcidr
  local src_text="$2"   # input text file
  local dst_mrs="$3"    # output mrs file
  local tmp_out="${dst_mrs}.tmp"

  rm -f "$tmp_out" 2>/dev/null || true
  "$MIHOMO_BIN" convert-ruleset "$behavior" text "$src_text" "$tmp_out"

  if [ ! -s "$tmp_out" ]; then
    echo "WARN: tmp output empty -> $tmp_out"
    rm -f "$tmp_out" 2>/dev/null || true
    return 1
  fi

  mv -f "$tmp_out" "$dst_mrs"
  return 0
}

echo "[4/6] Compile geoip -> mrs..."
geoip_mrs_count=0
while IFS= read -r f; do
  base="$(basename "$f")"
  tag="${base#geoip_}"; tag="${tag%.txt}"
  [[ "$tag" == "$base" ]] && tag="${base%.txt}"

  out="${OUT_GEOIP_DIR}/${tag}.mrs"
  if convert_atomic ipcidr "$f" "$out"; then
    geoip_mrs_count=$((geoip_mrs_count+1))
  fi
done < <(find "$WORKDIR/geoip_txt" -type f -name '*.txt' | sort)

echo "[INFO] geoip mrs generated: $geoip_mrs_count"

echo "[5/6] Compile geosite -> mrs (domain/full only)..."
mkdir -p "$WORKDIR/geosite_domain_only"

geosite_mrs_count=0
filtered_tags=0

while IFS= read -r f; do
  base="$(basename "$f")"
  tag="${base#geosite_}"; tag="${tag%.txt}"
  [[ "$tag" == "$base" ]] && tag="${base%.txt}"

  out_txt="$WORKDIR/geosite_domain_only/${tag}.txt"
  : > "$out_txt"

  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    case "$line" in
      keyword:*|regexp:*)
        echo "${tag}  ${line}" >> "$REPORT_SKIPPED"
        continue
        ;;
      full:*)
        echo "${line#full:}" >> "$out_txt"
        ;;
      *)
        if [[ "$line" == .* || "$line" == *"*"* ]]; then
          echo "$line" >> "$out_txt"
        else
          echo ".$line" >> "$out_txt"
        fi
        ;;
    esac
  done < "$f"

  if [[ ! -s "$out_txt" ]]; then
    echo "$tag" >> "$REPORT_FILTERED"
    filtered_tags=$((filtered_tags+1))
    continue
  fi

  out_mrs="${OUT_GEOSITE_DIR}/${tag}.mrs"
  if convert_atomic domain "$out_txt" "$out_mrs"; then
    geosite_mrs_count=$((geosite_mrs_count+1))
  fi
done < <(find "$WORKDIR/geosite_txt" -type f -name '*.txt' | sort)

echo "[INFO] geosite mrs generated: $geosite_mrs_count"
echo "[INFO] geosite filtered empty tags: $filtered_tags"

echo "[6/6] Done. Final counts:"
echo "geoip mrs:   $(find "$OUT_GEOIP_DIR" -type f -name '*.mrs' | wc -l | tr -d ' ')"
echo "geosite mrs: $(find "$OUT_GEOSITE_DIR" -type f -name '*.mrs' | wc -l | tr -d ' ')"

echo "[DEBUG] geo tree sample:"
find geo -maxdepth 2 -type f | head -n 30 || true