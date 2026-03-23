#!/bin/bash
set -e

mkdir -p /data/.picoclaw/workspace
mkdir -p /data/.picoclaw/sessions
mkdir -p /data/.picoclaw/cron

if [ ! -f /data/.picoclaw/config.json ]; then
    picoclaw onboard 2>/dev/null || echo "[warn] picoclaw onboard failed (expected on ephemeral FS), continuing..."
fi

exec python /app/server.py
