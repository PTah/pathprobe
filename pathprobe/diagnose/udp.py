from __future__ import annotations

import errno
import socket
from typing import Any

from pathprobe.models import Availability, CauseCode, Layer, ProbeResult

# Маркер для совместимости с echo/udp_echo.py
PROBE_MAGIC = b"PATHPROBE1"


def probe_udp(peer: str, host: str, port: int, timeout: float) -> ProbeResult:
    target = f"{host}:{port}"
    evidence: dict[str, Any] = {"host": host, "port": port}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(PROBE_MAGIC, (host, port))
        data, addr = sock.recvfrom(2048)
        evidence["reply_from"] = list(addr)
        evidence["reply_len"] = len(data)
        evidence["reply_startswith_magic"] = data.startswith(PROBE_MAGIC) or data == PROBE_MAGIC
        return ProbeResult(
            Layer.UDP, peer, target, "udp", port,
            Availability.AVAILABLE, CauseCode.UDP_OK,
            detail=f"ответ {len(data)} байт от {addr[0]}:{addr[1]}",
            evidence=evidence,
        )
    except (socket.timeout, TimeoutError):
        return ProbeResult(
            Layer.UDP, peer, target, "udp", port,
            Availability.UNAVAILABLE, CauseCode.UDP_TIMEOUT,
            detail=f"таймаут {timeout}s (блок UDP, нет echo или drop)",
            evidence=evidence,
        )
    except ConnectionRefusedError:
        # На части ОС ICMP port unreachable проявляется так
        return ProbeResult(
            Layer.UDP, peer, target, "udp", port,
            Availability.UNAVAILABLE, CauseCode.UDP_ICMP_UNREACH,
            detail="ICMP/refused", evidence=evidence,
        )
    except OSError as exc:
        evidence["errno"] = getattr(exc, "errno", None)
        if exc.errno in (errno.ECONNREFUSED, 10061, 10054):
            return ProbeResult(
                Layer.UDP, peer, target, "udp", port,
                Availability.UNAVAILABLE, CauseCode.UDP_ICMP_UNREACH,
                detail=str(exc), evidence=evidence,
            )
        return ProbeResult(
            Layer.UDP, peer, target, "udp", port,
            Availability.UNKNOWN, CauseCode.ERROR,
            detail=str(exc), evidence=evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(
            Layer.UDP, peer, target, "udp", port,
            Availability.UNKNOWN, CauseCode.ERROR,
            detail=str(exc), evidence=evidence,
        )
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_peer_udp(peer: str, peer_cfg: dict[str, Any], timeout: float) -> list[ProbeResult]:
    host = peer_cfg.get("host")
    if not host:
        return []
    ports = peer_cfg.get("udp_ports") or []
    return [probe_udp(peer, host, int(p), timeout) for p in ports]
