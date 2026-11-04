#!/usr/bin/env bash
# Container entrypoint: prepares ClamAV (signatures + clamd daemon), then starts Next.js.
# Scans use clamdscan (fast, DB stays in memory) and fall back to clamscan if clamd is down.
set -euo pipefail

export VIBE_DATA_DIR="${VIBE_DATA_DIR:-/data}"
mkdir -p "$VIBE_DATA_DIR/uploads" "$VIBE_DATA_DIR/media"

CLAM_DB_DIR=/var/lib/clamav
CLAM_SOCKET=/run/clamav/clamd.ctl

start_clamav() {
  mkdir -p /run/clamav
  chown clamav:clamav /run/clamav 2>/dev/null || true

  # Signatures must exist before clamd can start. Only block on download if missing.
  if [[ ! -f "$CLAM_DB_DIR/main.cvd" && ! -f "$CLAM_DB_DIR/main.cld" ]]; then
    echo "[entrypoint] ClamAV DB missing, downloading (may take a minute)…"
    timeout 600 freshclam --quiet || echo "[entrypoint] WARN: freshclam failed; scans will report ClamAV errors"
  fi

  # Keep signatures fresh in the background (freshclam daemon mode).
  freshclam -d --quiet || echo "[entrypoint] WARN: freshclam daemon not started"

  if clamd; then
    echo "[entrypoint] clamd started, waiting for socket…"
    for _ in $(seq 1 120); do
      [[ -S "$CLAM_SOCKET" ]] && break
      sleep 1
    done
    [[ -S "$CLAM_SOCKET" ]] && echo "[entrypoint] clamd ready" || echo "[entrypoint] WARN: clamd socket not ready yet"
  else
    echo "[entrypoint] WARN: clamd failed to start; falling back to clamscan"
  fi
}

if [[ "${SKIP_CLAMAV:-0}" != "1" ]]; then
  start_clamav
else
  echo "[entrypoint] SKIP_CLAMAV=1 — ClamAV engines will report errors"
fi

echo "[entrypoint] starting Next.js on 0.0.0.0:${PORT:-3000} (data: $VIBE_DATA_DIR)"
# -H is explicit on purpose: Next reads HOSTNAME, which Docker sets to the container id.
exec ./node_modules/.bin/next start -H 0.0.0.0 -p "${PORT:-3000}"
