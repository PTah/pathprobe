from __future__ import annotations

import errno
import socket
from typing import Any

from pathprobe.models import Availability, CauseCode, Layer, ProbeResult


def probe_tcp(peer: str, host: str, port: int, timeout: float) -> ProbeResult:
    target = f"{host}:{port}"
    evidence: dict[str, Any] = {"host": host, "port": port}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        evidence["connected"] = True
        return ProbeResult(
            Layer.TCP, peer, target, "tcp", port,
            Availability.AVAILABLE, CauseCode.TCP_OPEN,
            detail="connect OK", evidence=evidence,
        )
    except TimeoutError:
        return ProbeResult(
            Layer.TCP, peer, target, "tcp", port,
            Availability.UNAVAILABLE, CauseCode.TCP_TIMEOUT,
            detail=f"таймаут {timeout}s", evidence=evidence,
        )
    except socket.timeout:
        return ProbeResult(
            Layer.TCP, peer, target, "tcp", port,
            Availability.UNAVAILABLE, CauseCode.TCP_TIMEOUT,
            detail=f"таймаут {timeout}s", evidence=evidence,
        )
    except ConnectionRefusedError:
        return ProbeResult(
            Layer.TCP, peer, target, "tcp", port,
            Availability.UNAVAILABLE, CauseCode.TCP_REFUSED,
            detail="Connection refused", evidence=evidence,
        )
    except OSError as exc:
        evidence["errno"] = getattr(exc, "errno", None)
        evidence["winerror"] = getattr(exc, "winerror", None)
        # Windows: WSAECONNRESET=10054; Linux: ECONNRESET
        if exc.errno in (errno.ECONNRESET, 10054) or "reset" in str(exc).lower():
            return ProbeResult(
                Layer.TCP, peer, target, "tcp", port,
                Availability.UNAVAILABLE, CauseCode.TCP_RST,
                detail=str(exc), evidence=evidence,
            )
        if exc.errno in (errno.ETIMEDOUT, 10060):
            return ProbeResult(
                Layer.TCP, peer, target, "tcp", port,
                Availability.UNAVAILABLE, CauseCode.TCP_TIMEOUT,
                detail=str(exc), evidence=evidence,
            )
        if exc.errno in (errno.ECONNREFUSED, 10061):
            return ProbeResult(
                Layer.TCP, peer, target, "tcp", port,
                Availability.UNAVAILABLE, CauseCode.TCP_REFUSED,
                detail=str(exc), evidence=evidence,
            )
        return ProbeResult(
            Layer.TCP, peer, target, "tcp", port,
            Availability.UNKNOWN, CauseCode.ERROR,
            detail=str(exc), evidence=evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(
            Layer.TCP, peer, target, "tcp", port,
            Availability.UNKNOWN, CauseCode.ERROR,
            detail=str(exc), evidence=evidence,
        )
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_peer_tcp(peer: str, peer_cfg: dict[str, Any], timeout: float) -> list[ProbeResult]:
    host = peer_cfg.get("host")
    if not host:
        return []
    ports = peer_cfg.get("tcp_ports") or []
    return [probe_tcp(peer, host, int(p), timeout) for p in ports]
