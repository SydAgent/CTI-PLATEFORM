# ============================================================================
# ONYX CTI — Tor SOCKS5 Proxy with Privoxy HTTP Relay
# Provides anonymized .onion access for dark web crawlers.
# Features: circuit rotation, control port, kill-switch, non-root execution.
# ============================================================================
FROM alpine:3.19

LABEL maintainer="ONYX CTI Platform"
LABEL description="Tor proxy with Privoxy HTTP bridge and circuit rotation"

# Install Tor + Privoxy + control utilities
RUN apk add --no-cache \
    tor \
    privoxy \
    curl \
    python3 \
    bash \
    && rm -rf /var/cache/apk/*

# Create non-root onyx user
RUN addgroup -S onyx && adduser -S onyx -G onyx

# ------ Tor Configuration ------
RUN mkdir -p /var/lib/tor /var/log/tor && \
    chown -R onyx:onyx /var/lib/tor /var/log/tor

COPY torrc /etc/tor/torrc
COPY entrypoint.sh /entrypoint.sh
COPY circuit_rotator.py /usr/local/bin/circuit_rotator.py

RUN chmod +x /entrypoint.sh /usr/local/bin/circuit_rotator.py

# ------ Privoxy Configuration ------
COPY privoxy.conf /etc/privoxy/config
RUN chown -R onyx:onyx /etc/privoxy /var/log/privoxy || true

# Expose SOCKS5 (9050) + HTTP (8118) + Control (9051)
EXPOSE 9050 8118 9051

USER onyx

ENTRYPOINT ["/entrypoint.sh"]
