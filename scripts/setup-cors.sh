#!/bin/sh
# Configure CORS via the wafctl API.
# Run once after deploying plugin v0.17.0 to replace the Caddyfile (cors) snippet.
#
# Usage: ./scripts/setup-cors.sh [WAFCTL_URL]
# Default: http://localhost:8080

WAFCTL_URL="${1:-http://localhost:8080}"

echo "Configuring CORS on ${WAFCTL_URL}..."

curl -s -X PUT "${WAFCTL_URL}/api/cors" \
  -H 'Content-Type: application/json' \
  -d '{
  "enabled": true,
  "global": {
    "allowed_origins": ["^https://[a-z0-9-]+\\.erfi\\.io$"],
    "allowed_methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
    "allowed_headers": ["Content-Type", "Authorization"],
    "max_age": 3600
  }
}' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"

echo ""
echo "Deploying..."
curl -s -X POST "${WAFCTL_URL}/api/deploy" \
  -H 'Content-Type: application/json' \
  -d '{}' | python3 -m json.tool 2>/dev/null || echo "(raw response above)"

echo ""
echo "CORS configured. Plugin will hot-reload within seconds."
