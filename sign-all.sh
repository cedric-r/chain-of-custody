#!/usr/bin/env bash
#
# sign-all.sh — Batch-sign image files via the Chain of Custody API
#
# Scans the current directory recursively for compatible image and raw
# files (jpg, jpeg, png, tif, tiff, cr2, cr3, nef), signs each one via
# the remote API, and saves the signed copies into the "signed" folder.
#
# Usage:
#   ./sign-all.sh <api-url> <api-key>
#
# Examples:
#   ./sign-all.sh https://api.photo-verify.org coc_abc123...
#   ./sign-all.sh http://localhost:8001 coc_def456...
#
# Requires: curl, bash 4+

if [ $# -lt 2 ]; then
    echo "Usage: $0 <api-url> <api-key>"
    echo "  <api-url>  Base URL of the signing API (e.g. https://api.photo-verify.org)"
    echo "  <api-key>  API key with Bearer prefix (e.g. coc_abc123...)"
    exit 1
fi

API_URL="${1%/}"
API_KEY="$2"
SIGNED_DIR="${PWD}/signed"

mkdir -p "$SIGNED_DIR"

TOTAL=0
OK=0
FAIL=0
SKIP=0

echo "Scanning for compatible files in ${PWD} ..."
echo "API:   ${API_URL}/sign"
echo "Out:   ${SIGNED_DIR}"
echo ""

# Build file list
FILES=()
while IFS= read -r f; do
    FILES+=("$f")
done < <(find "${PWD}" -type f ! -path "${SIGNED_DIR}/*" \
    -regextype posix-extended -regex '.*\.(jpg|jpeg|png|tif|tiff|cr2|cr3|nef)$' \
    2>/dev/null | sort)

TOTAL=${#FILES[@]}

if [ "$TOTAL" -eq 0 ]; then
    echo "No compatible files found."
    exit 0
fi

echo "Found ${TOTAL} file(s)."
echo ""

for src in "${FILES[@]}"; do
    base=$(basename "$src")
    name=${base%.*}
    ext=${base##*.}
    dst="${SIGNED_DIR}/${name}-signed.${ext}"

    if [ -f "$dst" ]; then
        echo "  SKIP  ${base}  (signed copy already exists)"
        SKIP=$((SKIP + 1))
        continue
    fi

    printf "  SIGN  %s ... " "$base"

    # Temp file for curl output
    tmpf=$(mktemp /tmp/coc-sign-XXXXXX)

    # Upload and sign — write HTTP body directly to temp file,
    # capture HTTP status code separately
    http_code=$(curl -s -S -X POST \
        "${API_URL}/sign" \
        -H "Authorization: Bearer ${API_KEY}" \
        -F "file=@${src}" \
        --connect-timeout 30 \
        --max-time 300 \
        --output "$tmpf" \
        --write-out '%{http_code}' \
        2>/dev/null)

    curl_rc=$?

    if [ "$curl_rc" -ne 0 ]; then
        echo "FAIL  (curl error $curl_rc)"
        rm -f "$tmpf"
        FAIL=$((FAIL + 1))
        continue
    fi

    # Check for HTTP errors
    if [ "$http_code" -ne 200 ]; then
        msg=$(tr -d '\n\r' < "$tmpf" | sed -n 's~.*"message":"\([^"]*\)".*~\1~p')
        echo "FAIL  (HTTP ${http_code}: ${msg:-unknown})"
        rm -f "$tmpf"
        FAIL=$((FAIL + 1))
        continue
    fi

    # Check API status
    if ! grep -q '"status":"ok"' "$tmpf" 2>/dev/null; then
        msg=$(tr -d '\n\r' < "$tmpf" | sed -n 's~.*"message":"\([^"]*\)".*~\1~p')
        echo "FAIL  (${msg:-API error})"
        rm -f "$tmpf"
        FAIL=$((FAIL + 1))
        continue
    fi

    # Extract base64 signed data (using the temp file directly, no variable for large data)
    if ! grep -q '"signed"' "$tmpf" 2>/dev/null; then
        echo "FAIL  (no signed data in response)"
        # Save the raw response for debugging
        cp "$tmpf" "${SIGNED_DIR}/${name}-response.json" 2>/dev/null
        echo "  Saved response to ${SIGNED_DIR}/${name}-response.json" >&2
        rm -f "$tmpf"
        FAIL=$((FAIL + 1))
        continue
    fi

    # Decode and save: extract base64 from JSON and pipe straight to decoder
    tr -d '\n\r' < "$tmpf" \
        | sed -n 's~.*"signed":"\([^"]*\)".*~\1~p' \
        | base64 -d > "$dst" 2>/dev/null

    if [ -s "$dst" ]; then
        rm -f "$tmpf"
        size=$(stat -c%s "$dst" 2>/dev/null || stat -f%z "$dst" 2>/dev/null)
        echo "done  (${size} bytes)"
        OK=$((OK + 1))
    else
        echo "FAIL  (decoded file is empty)"
        # Save the raw response for debugging
        cp "$tmpf" "${SIGNED_DIR}/${name}-response.json" 2>/dev/null
        echo "  Response saved: ${SIGNED_DIR}/${name}-response.json" >&2
        rm -f "$tmpf" "$dst"
        FAIL=$((FAIL + 1))
    fi
done

echo ""
echo "──────────────────────────────"
echo "  Total:  ${TOTAL}"
echo "  Signed: ${OK}"
echo "  Failed: ${FAIL}"
echo "  Skipped: ${SKIP}"
echo "──────────────────────────────"
echo "Signed files saved to: ${SIGNED_DIR}"
