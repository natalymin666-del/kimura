#!/usr/bin/env bash
set -Eeuo pipefail

# ====== SIMPLE API BASELINE SCANNER (safe) ======
# Usage:
#   ./coinbase_scan.sh
#   ./coinbase_scan.sh https://api.exchange.coinbase.com/products

DEFAULT_URL="https://api.exchange.coinbase.com/products"
API_URL="${1:-$DEFAULT_URL}"

OUT_DIR="./api_scans"
TS="$(date +%Y%m%d_%H%M%S)"
SCAN_ID="scan_${TS}"
FULL="${OUT_DIR}/${SCAN_ID}_full.txt"
HEADERS="${OUT_DIR}/${SCAN_ID}_headers.txt"
BODY="${OUT_DIR}/${SCAN_ID}_body.txt"
REPORT="${OUT_DIR}/${SCAN_ID}_report.md"

mkdir -p "$OUT_DIR"

banner() {
  echo "=============================================="
  echo " API BASELINE SCANNER"
  echo " Scan ID : $SCAN_ID"
  echo " Target  : $API_URL"
  echo " Out dir : $OUT_DIR"
  echo "=============================================="
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[ERROR] Missing command: $1"; exit 1; }
}

validate_url() {
  if [[ ! "$API_URL" =~ ^https?:// ]]; then
    echo "[ERROR] Invalid URL: $API_URL"
    echo "Example: ./coinbase_scan.sh https://api.exchange.coinbase.com/products"
    exit 1
  fi
}

req() {
  local method="$1"
  local url="$2"
  curl -sS -i -X "$method" "$url" \
    -H "User-Agent: KimuraBaselineScanner/1.0" \
    -H "Accept: application/json, text/plain, */*" \
    --max-time 20
}

extract_status() {
  # First HTTP status code in response
  grep -m1 -Eo 'HTTP/[0-9.]+\s+[0-9]+' "$HEADERS" | awk '{print $2}' || true
}

is_json() {
  # quick check: body starts with { or [
  head -c 1 "$BODY" | grep -qE '(\{|\[)'
}

write_report() {
  local status="$1"
  local server="$(grep -i '^server:' "$HEADERS" | head -n1 | cut -d: -f2- | xargs || true)"
  local ctype="$(grep -i '^content-type:' "$HEADERS" | head -n1 | cut -d: -f2- | xargs || true)"
  local cf_ray="$(grep -i '^cf-ray:' "$HEADERS" | head -n1 | cut -d: -f2- | xargs || true)"
  local cache="$(grep -i '^cf-cache-status:' "$HEADERS" | head -n1 | cut -d: -f2- | xargs || true)"

  local rl_present="absent"
  if grep -qiE '^(x-ratelimit|ratelimit)' "$HEADERS"; then rl_present="present"; fi

  cat > "$REPORT" <<EOF
# API Baseline Report

- **Target:** \`$API_URL\`
- **Scan ID:** \`$SCAN_ID\`
- **Time:** \`$(date)\`

## HTTP
- **Status:** \`$status\`
- **Content-Type:** \`${ctype:-unknown}\`
- **Server:** \`${server:-unknown}\`
- **cf-ray:** \`${cf_ray:-none}\`
- **cf-cache-status:** \`${cache:-none}\`
- **Rate-limit headers:** **$rl_present**

## Quick notes
- If status is **401** → endpoint requires auth (expected for private endpoints)
- If status is **403** with HTML/“Just a moment” → WAF/Cloudflare challenge (expected for browser-protected pages)
- If status is **200** and JSON → public endpoint

## Files
- Full response: \`$FULL\`
- Headers: \`$HEADERS\`
- Body: \`$BODY\`
EOF
}

test_methods() {
  echo ""
  echo "[*] Testing methods (gentle):"
  for m in GET HEAD OPTIONS POST PUT DELETE PATCH; do
    code="$(curl -sS -o /dev/null -w "%{http_code}" -X "$m" "$API_URL" \
      -H "User-Agent: KimuraBaselineScanner/1.0" \
      -H "Accept: application/json, text/plain, */*" \
      --max-time 15 || true)"
    echo "  $m -> $code"
  done
}

main() {
  need_cmd curl
  banner
  validate_url

  echo "[*] Sending GET request..."
  req GET "$API_URL" | tee "$FULL" >/dev/null

  # split headers/body: first empty line separates them
  awk 'BEGIN{h=1} {print > (h?"'"$HEADERS"'":"'"$BODY"'")} /^(\r)?$/{h=0}' "$FULL"

  local status
  status="$(extract_status)"
  status="${status:-0}"

  echo "[+] Saved:"
  echo "  Full    : $FULL"
  echo "  Headers : $HEADERS"
  echo "  Body    : $BODY"
  echo ""
  echo "[*] Status: $status"

  if is_json; then
    echo "[+] Body looks like JSON (starts with { or [)"
  else
    echo "[!] Body may be HTML/WAF or empty"
    echo "    First 120 chars:"
    head -c 120 "$BODY" | tr '\n' ' ' ; echo ""
  fi

  test_methods
  write_report "$status"

  echo ""
  echo "[+] Report saved: $REPORT"
  echo "Tip: open report -> less \"$REPORT\""
}

main "$@"
