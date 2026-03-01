#!/usr/bin/env bash
set -euo pipefail

# ---------------------------
# Loy DAT -> Split MRS (geo/)
# Requirements:
#   - v2dat in PATH
#   - ./mihomo in repo root (or MIHOMO_BIN env)
# Output:
#   geo/geoip/*.mrs
#   geo/geosite/*.mrs
# Notes:
#   - geosite supports domain/full only; keyword/regexp are skipped (mrs can't represent them)
# ---------------------------

GEOIP_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat'
GEOSITE_URL='https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat'

OUT_GEOIP_DIR='geo/geoip'
OUT_GEOSITE_DIR='geo/geosite'

# allow override
MIHOMO_BIN="${MIHOMO_BIN:-./mihomo}"

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }

# Ensure we are at repo root (script may be called from anywhere)
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
# v2dat output filenames are typically geoip_<tag>.txt and geosite_<tag>.txt
v2dat unpack geoip   -d "$WORKDIR/geoip_txt"   "$WORKDIR/geoip.dat"
v2dat unpack geosite -d "$WORKDIR/geosite_txt" "$WORKDIR/geosite.dat"

log "3) Rebuild output dirs (clean sync)..."
rm -rf "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"
mkdir -p "$OUT_GEOIP_DIR" "$OUT_GEOSITE_DIR"

log "4) Compile geoip -> split mrs..."
shopt -s nullglob
geoip_count=0
for f in "$WORKDIR/geoip_txt"/*.txt; do
  base="$(basename "$f")"   # geoip_<TAG>.txt (normally)
  tag="${base#geoip_}"
  tag="${tag%.txt}"
  # If naming doesn't match expected, fall back to base name without ext
  if [[ "$tag" == "$base" ]]; then
    tag="${base%.txt}"
  fi
  "$MIHOMO_BIN" convert-ruleset ipcidr text "$f" "${OUT_GEOIP_DIR}/${tag}.mrs"
  geoip_count=$((geoip_count+1))
done
log "geoip mrs generated: ${geoip_count}"

log "5) Compile geosite -> split mrs (domain/full only)..."
mkdir -p "$WORKDIR/geosite_domain_only"

# Report files
REPORT_DIR="geo"
REPORT_FILTERED="${REPORT_DIR}/REPORT-loy-geosite-filtered.txt"
REPORT_SKIPPED="${REPORT_DIR}/REPORT-loy-geosite-skipped-keyword-regexp.txt"
: > "$REPORT_FILTERED"
: > "$REPORT_SKIPPED"

geosite_count=0
filtered_empty_count=0
skipped_kw_re_count=0

for f in "$WORKDIR/geosite_txt"/*.txt; do
  base="$(basename "$f")"   # geosite_<TAG>.txt
  tag="${base#geosite_}"
  tag="${tag%.txt}"
  if [[ "$tag" == "$base" ]]; then
    tag="${base%.txt}"
  fi

  out="$WORKDIR/geosite_domain_only/${tag}.txt"
  : > "$out"

  # Convert lines:
  #   - keyword:* / regexp:*  -> skip (mrs can't represent)
  #   - full:example.com      -> keep as exact domain
  #   - example.com (domain)  -> convert to ".example.com" (suffix match)
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
        # domain line => suffix rule
        # keep wildcard or already-dot lines
        if [[ "$line" == .* || "$line" == *"*"* ]]; then
          echo "$line" >> "$out"
        else
          echo ".$line" >> "$out"
        fi
        ;;
    esac
  done < "$f"

  if [[ ! -s "$out" ]]; then
    echo "${tag}" >> "$REPORT_FILTERED"
    filtered_empty_count=$((filtered_empty_count+1))
    continue
  fi

  "$MIHOMO_BIN" convert-ruleset domain text "$out" "${OUT_GEOSITE_DIR}/${tag}.mrs"
  geosite_count=$((geosite_count+1))
done

log "geosite mrs generated: ${geosite_count}"
log "geosite tags filtered empty (all keyword/regexp): ${filtered_empty_count}"
log "geosite lines skipped (keyword/regexp total): ${skipped_kw_re_count}"

log "6) Debug listing..."
log "Repo root files:"
ls -lah | sed -n '1,120p' || true

log "geo tree:"
ls -lah geo || true
echo "geoip .mrs count:"
find "$OUT_GEOIP_DIR" -type f -name '*.mrs' | wc -l || true
echo "geosite .mrs count:"
find "$OUT_GEOSITE_DIR" -type f -name '*.mrs' | wc -l || true

log "Sample output files (first 30):"
find geo -maxdepth 2 -type f | head -n 30 || true

log "Done."