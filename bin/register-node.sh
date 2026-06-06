#!/usr/bin/env bash
#
# register-node.sh — Generate and verify a Chain of Custody node identifier
#
# This script helps register a new node in the distributed verification
# network. It generates a node ID, checks that the /.well-known endpoint
# is properly serving metadata, and prints the DNS CNAME configuration.
#
# Usage:
#   ./register-node.sh <api-url>
#
# Examples:
#   ./register-node.sh https://api.mynode.org
#   ./register-node.sh http://localhost:8001
#
# Requires: curl, php, bash 4+

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <api-url>"
    echo "  <api-url>  Base URL of your node's API (e.g. https://api.mynode.org)"
    exit 1
fi

API_URL="${1%/}"

echo "Chain of Custody — Node Registration"
echo "====================================="
echo ""

# Generate a node ID
NODE_ID=$(php -r "echo bin2hex(random_bytes(8));")
echo "Generated node ID: ${NODE_ID}"
echo ""

# Check the well-known endpoint
WELL_KNOWN="${API_URL}/.well-known/chain-of-custody"
echo "Testing: ${WELL_KNOWN}"
echo ""

HTTP_CODE=$(curl -s -o /tmp/coc_wellknown.json -w "%{http_code}" --connect-timeout 10 "${WELL_KNOWN}" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" = "200" ]]; then
    echo "✅ Well-known endpoint responds OK"
    echo ""
    echo "Response:"
    cat /tmp/coc_wellknown.json | python3 -m json.tool 2>/dev/null || cat /tmp/coc_wellknown.json
    echo ""
else
    echo "⚠️  Well-known endpoint returned HTTP ${HTTP_CODE}"
    echo ""
    echo "To set it up, create a static file at your API's document root:"
    echo "  /.well-known/chain-of-custody"
    echo "with content:"
    echo "  {"
    echo "    \"node_id\": \"${NODE_ID}\","
    echo "    \"algorithm\": \"SHA-256\""
    echo "  }"
    echo ""
    echo "Or ensure api/index.php handles the route."
fi

rm -f /tmp/coc_wellknown.json

echo ""
echo "DNS Configuration"
echo "=================="
echo "Add the following CNAME record to your DNS zone (photo-verify.org):"
echo ""
echo "  ${NODE_ID}.photo-verify.org  IN  CNAME  $(hostname -f 2>/dev/null || echo 'your-server.com')"
echo ""
echo "Once the DNS record propagates, other nodes will be able to"
echo "discover your node and forward verification requests to it."
echo ""
echo "Add this to your config.php:"
echo ""
echo "  'node_id' => '${NODE_ID}',"
echo ""
