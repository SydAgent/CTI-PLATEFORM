"""
ONYX CTI — Tor Circuit Manager
Manages Tor SOCKS5 proxy connections, circuit rotation, identity isolation,
and kill-switch enforcement.

Pattern source: AIL Framework bin/crawlers/Crawler.py — circuit management,
timeout handling, and onion filtering logic adapted to async Python.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

import httpx

from onyx_core.config import get_config

logger = logging.getLogger("onyx.tor")


class TorStatus(str, Enum):
    """Tor proxy operational status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    ROTATING = "rotating"
    KILLED = "killed"


@dataclass
class CircuitInfo:
    """Information about the current Tor circuit."""
    exit_ip: str = ""
    country: str = ""
    is_tor: bool = False
    circuit_id: int = 0
    established_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    requests_count: int = 0


class TorManager:
    """
    Manages Tor proxy lifecycle, circuit rotation, and health monitoring.
    
    Adapted from AIL Framework's crawler circuit management:
    - Automatic circuit rotation after N requests or T seconds
    - Identity isolation per crawl target (IsolateDestAddr)
    - Kill-switch: immediately drops all Tor traffic on activation
    - Health check via check.torproject.org API
    """

    def __init__(self) -> None:
        cfg = get_config().tor
        self._socks_proxy = cfg.socks_proxy
        self._http_proxy = cfg.http_proxy
        self._control_port = cfg.control_port
        self._control_password = cfg.control_password
        self._rotation_interval = cfg.circuit_rotation_seconds
        self._kill_switch = cfg.kill_switch
        self._status = TorStatus.DISCONNECTED
        self._circuit = CircuitInfo()
        self._max_requests_per_circuit = 50
        self._lock = asyncio.Lock()

    @property
    def status(self) -> TorStatus:
        return self._status

    @property
    def circuit(self) -> CircuitInfo:
        return self._circuit

    @property
    def is_alive(self) -> bool:
        return self._status == TorStatus.CONNECTED

    @property
    def is_killed(self) -> bool:
        return self._kill_switch or self._status == TorStatus.KILLED

    def get_proxy_client(self, timeout: float = 30.0) -> httpx.AsyncClient:
        """
        Create an httpx AsyncClient configured to route through Tor SOCKS5.
        Each client gets circuit isolation via IsolateDestAddr in torrc.
        """
        if self.is_killed:
            raise RuntimeError("Tor kill-switch is ACTIVE. All .onion traffic blocked.")

        return httpx.AsyncClient(
            proxy=self._socks_proxy,
            timeout=httpx.Timeout(timeout, connect=15.0),
            follow_redirects=True,
            max_redirects=5,
            verify=False,  # .onion sites rarely have valid SSL
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
            },
        )

    async def check_connection(self) -> CircuitInfo:
        """
        Verify Tor connectivity by querying the Tor Project's check API.
        Adapted from AIL's lacus health check pattern.
        """
        try:
            async with self.get_proxy_client(timeout=20.0) as client:
                resp = await client.get("https://check.torproject.org/api/ip")
                data = resp.json()
                self._circuit.exit_ip = data.get("IP", "")
                self._circuit.is_tor = data.get("IsTor", False)
                self._circuit.established_at = datetime.now(timezone.utc)
                self._circuit.requests_count = 0

                if self._circuit.is_tor:
                    self._status = TorStatus.CONNECTED
                    logger.info(
                        "Tor connected — exit IP: %s, IsTor: %s",
                        self._circuit.exit_ip,
                        self._circuit.is_tor,
                    )
                else:
                    self._status = TorStatus.DISCONNECTED
                    logger.warning("Tor check failed — traffic is NOT routed through Tor")

        except Exception as e:
            self._status = TorStatus.DISCONNECTED
            logger.error("Tor connection check failed: %s", str(e))

        return self._circuit

    async def rotate_circuit(self) -> str:
        """
        Request a new Tor circuit (NEWNYM signal).
        Adapted from AIL Framework's circuit rotation with control port auth.
        
        The NEWNYM signal tells Tor to build new circuits for future requests,
        effectively changing the exit IP address.
        """
        async with self._lock:
            if self.is_killed:
                raise RuntimeError("Tor kill-switch is ACTIVE")

            self._status = TorStatus.ROTATING
            logger.info("Rotating Tor circuit (NEWNYM)...")

            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("tor-proxy", self._control_port),
                    timeout=10.0,
                )

                # Read banner
                await reader.readline()

                # Authenticate
                writer.write(f'AUTHENTICATE "{self._control_password}"\r\n'.encode())
                await writer.drain()
                response = await reader.readline()
                if b"250" not in response:
                    raise ConnectionError(f"Tor auth failed: {response.decode().strip()}")

                # Send NEWNYM
                writer.write(b"SIGNAL NEWNYM\r\n")
                await writer.drain()
                response = await reader.readline()

                writer.close()
                await writer.wait_closed()

                if b"250" in response:
                    # Wait for new circuit to establish
                    await asyncio.sleep(3)
                    await self.check_connection()
                    logger.info("Circuit rotated — new exit IP: %s", self._circuit.exit_ip)
                    return self._circuit.exit_ip
                else:
                    raise ConnectionError(f"NEWNYM failed: {response.decode().strip()}")

            except Exception as e:
                self._status = TorStatus.DISCONNECTED
                logger.error("Circuit rotation failed: %s", str(e))
                raise

    async def maybe_rotate(self) -> None:
        """
        Auto-rotate circuit if request count exceeds threshold.
        Adapted from AIL's capture-based rotation heuristics.
        """
        self._circuit.requests_count += 1
        if self._circuit.requests_count >= self._max_requests_per_circuit:
            await self.rotate_circuit()

    def activate_kill_switch(self) -> None:
        """
        Emergency kill-switch: immediately blocks all Tor traffic.
        Sets status to KILLED, preventing any new proxy clients from being created.
        """
        self._kill_switch = True
        self._status = TorStatus.KILLED
        logger.critical("TOR KILL-SWITCH ACTIVATED — All .onion traffic blocked")

    def deactivate_kill_switch(self) -> None:
        """Deactivate kill-switch and restore Tor connectivity."""
        self._kill_switch = False
        self._status = TorStatus.DISCONNECTED
        logger.warning("Tor kill-switch deactivated — connectivity will resume on next check")

    async def get_status_report(self) -> dict:
        """Full Tor status report for the dashboard."""
        return {
            "status": self._status.value,
            "kill_switch": self._kill_switch,
            "exit_ip": self._circuit.exit_ip,
            "is_tor": self._circuit.is_tor,
            "country": self._circuit.country,
            "circuit_established": self._circuit.established_at.isoformat(),
            "requests_on_circuit": self._circuit.requests_count,
            "rotation_interval_sec": self._rotation_interval,
            "max_requests_per_circuit": self._max_requests_per_circuit,
        }
