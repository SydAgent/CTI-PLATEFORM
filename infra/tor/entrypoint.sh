#!/bin/bash
# ============================================================================
# ONYX CTI — Tor Proxy Entrypoint
# Initializes Tor with hashed control password, starts Privoxy, and launches
# the circuit rotator daemon for automated IP rotation.
# ============================================================================
set -euo pipefail

echo "[ONYX] =========================================="
echo "[ONYX] Tor Proxy Initialization — ONYX CTI v3.0"
echo "[ONYX] =========================================="

# --- Generate hashed control password ---
HASHED_PW=$(tor --hash-password "${TOR_CONTROL_PASSWORD:-onyx_tor_control_2026}" 2>/dev/null | tail -1)
echo "HashedControlPassword ${HASHED_PW}" >> /etc/tor/torrc
echo "[ONYX] Control password hashed and injected into torrc"

# --- Start Privoxy in background ---
echo "[ONYX] Starting Privoxy HTTP bridge on :8118"
privoxy --no-daemon /etc/privoxy/config &
PRIVOXY_PID=$!

# --- Start circuit rotator in background ---
echo "[ONYX] Starting circuit rotator (interval: ${TOR_CIRCUIT_ROTATION_SECONDS:-300}s)"
python3 /usr/local/bin/circuit_rotator.py \
    --interval "${TOR_CIRCUIT_ROTATION_SECONDS:-300}" \
    --control-port 9051 \
    --password "${TOR_CONTROL_PASSWORD:-onyx_tor_control_2026}" &
ROTATOR_PID=$!

# --- Graceful shutdown handler ---
cleanup() {
    echo "[ONYX] Shutting down Tor proxy stack..."
    kill "${PRIVOXY_PID}" "${ROTATOR_PID}" 2>/dev/null || true
    wait
    echo "[ONYX] Shutdown complete."
}
trap cleanup SIGTERM SIGINT

# --- Start Tor in foreground ---
echo "[ONYX] Starting Tor SOCKS5 proxy on :9050"
exec tor -f /etc/tor/torrc
