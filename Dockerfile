# Vibe Apps for Railway (or any Docker host).
# ClamAV is installed natively: without it every scan would be "unavailable"
# and the store would block all uploads (by design — no emulation fallback).
FROM node:22-bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    NEXT_TELEMETRY_DISABLED=1

# ClamAV signatures are warmed into the image so the first boot is fast.
# Runtime freshclam keeps them updated, so a failure here is non-fatal.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      clamav clamav-daemon clamav-freshclam ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && (freshclam --quiet || echo "freshclam warm-up skipped; entrypoint will retry")

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build \
 && npm prune --omit=dev \
 && npm cache clean --force \
 && mkdir -p /data \
 && chmod +x scripts/railway-entrypoint.sh

ENV NODE_ENV=production \
    VIBE_DATA_DIR=/data \
    PORT=3000

EXPOSE 3000

ENTRYPOINT ["/usr/bin/tini", "--", "bash", "/app/scripts/railway-entrypoint.sh"]
