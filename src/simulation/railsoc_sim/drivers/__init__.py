"""Real-protocol client drivers (HC-23): genuine HTTP/Modbus/SSH traffic, never fabricated.

Each driver here makes a real network call with a real library (``requests``, ``pymodbus``,
``paramiko``) against a real server, and - where the server itself does not already log a
schema event (Modbus, SSH) - writes the matching event right after the real call returns, never
before and never independently of it.
"""

from __future__ import annotations

__version__ = "0.1.0"
