#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f .env.local ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env.local
  set +a
elif [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [[ -z "${VIRUSTOTAL_API_KEY:-}" ]]; then
  echo "WARN: VIRUSTOTAL_API_KEY is empty — VirusTotal Public API will report error (no bypass)."
fi

PORT="${PORT:-3000}"
echo "Building…"
npm run build

echo "Starting Next.js on :$PORT"
npm run start -- -p "$PORT" &
APP_PID=$!

cleanup() {
  kill "$APP_PID" 2>/dev/null || true
  kill "$TUNNEL_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

for i in $(seq 1 60); do
  if curl -sf "http://127.0.0.1:$PORT/api/engines" >/dev/null; then
    break
  fi
  sleep 1
done

echo "Starting Cloudflare quick tunnel…"
cloudflared tunnel --url "http://127.0.0.1:$PORT" --no-autoupdate 2>&1 | tee /tmp/cloudflared-vibe.log &
TUNNEL_PID=$!

echo "Waiting for trycloudflare URL…"
for i in $(seq 1 45); do
  URL=$(grep -oE 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' /tmp/cloudflared-vibe.log 2>/dev/null | head -1 || true)
  if [[ -n "${URL:-}" ]]; then
    echo ""
    echo "============================================"
    echo " Public Vibe Store: $URL"
    echo " Engines:           $URL/api/engines"
    echo "============================================"
    echo "$URL" > /tmp/vibestore-public-url.txt
    break
  fi
  sleep 1
done

wait
