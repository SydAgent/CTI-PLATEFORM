#!/usr/bin/env python3
"""
ONYX CTI — Tor Circuit Rotator
Periodically sends NEWNYM signals to Tor to rotate circuits (change IP).
Includes jitter to avoid predictable timing patterns.
"""

import argparse
import random
import signal
import socket
import sys
import time
from typing import NoReturn


class CircuitRotator:
    """Manages periodic Tor circuit rotation via the control port."""

    def __init__(self, control_port: int, password: str, interval: int) -> None:
        self.control_port = control_port
        self.password = password
        self.interval = interval
        self._running = True
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum: int, frame: object) -> None:
        """Handle graceful shutdown signals."""
        print(f"[ROTATOR] Received signal {signum}, shutting down...")
        self._running = False

    def _send_newnym(self) -> bool:
        """Send NEWNYM signal to Tor control port to rotate circuit."""
        try:
            with socket.create_connection(("127.0.0.1", self.control_port), timeout=10) as sock:
                # Read banner
                response = sock.recv(1024).decode("utf-8", errors="replace")
                if "250" not in response and "220" not in response:
                    print(f"[ROTATOR] Unexpected banner: {response.strip()}")

                # Authenticate
                sock.sendall(f'AUTHENTICATE "{self.password}"\r\n'.encode())
                response = sock.recv(1024).decode("utf-8", errors="replace")
                if "250" not in response:
                    print(f"[ROTATOR] Authentication failed: {response.strip()}")
                    return False

                # Send NEWNYM (new identity)
                sock.sendall(b"SIGNAL NEWNYM\r\n")
                response = sock.recv(1024).decode("utf-8", errors="replace")
                if "250" in response:
                    print("[ROTATOR] Circuit rotated successfully (NEWNYM)")
                    return True
                else:
                    print(f"[ROTATOR] NEWNYM failed: {response.strip()}")
                    return False

        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            print(f"[ROTATOR] Control port connection error: {e}")
            return False

    def run(self) -> NoReturn:
        """Main loop: rotate circuits at configured interval with jitter."""
        print(f"[ROTATOR] Starting circuit rotation every {self.interval}s (±15% jitter)")

        # Wait for Tor to finish bootstrapping
        time.sleep(30)

        while self._running:
            self._send_newnym()

            # Add jitter: ±15% of interval to avoid timing fingerprinting
            jitter = random.uniform(-0.15, 0.15) * self.interval
            sleep_time = max(30, self.interval + jitter)  # Minimum 30s between rotations

            # Sleep in small increments to respond to shutdown signals quickly
            elapsed = 0.0
            while elapsed < sleep_time and self._running:
                time.sleep(1.0)
                elapsed += 1.0

        print("[ROTATOR] Stopped.")
        sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="ONYX Tor Circuit Rotator")
    parser.add_argument("--interval", type=int, default=300, help="Rotation interval in seconds")
    parser.add_argument("--control-port", type=int, default=9051, help="Tor control port")
    parser.add_argument("--password", type=str, default="onyx_tor_control_2026", help="Control password")
    args = parser.parse_args()

    rotator = CircuitRotator(
        control_port=args.control_port,
        password=args.password,
        interval=args.interval,
    )
    rotator.run()


if __name__ == "__main__":
    main()
