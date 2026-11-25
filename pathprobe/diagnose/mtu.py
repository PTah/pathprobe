from __future__ import annotations

import platform
import re
import subprocess
from typing import Any

from pathprobe.models import Availability, CauseCode, Layer, ProbeResult


def _ping_df(host: str, size: int, timeout: float) -> tuple[bool, str]:
    """ICMP ping с DF. size — размер payload (байты данных ping)."""
    system = platform.system().lower()
    if system == "windows":
        # -f DF, -l size, -n 1, -w timeout_ms
        cmd = ["ping", "-n", "1", "-f", "-l", str(size), "-w", str(int(timeout * 1000)), host]
    else:
        # Linux: -M do, -s size, -c 1, -W timeout_sec
        cmd = ["ping", "-c", "1", "-M", "do", "-s", str(size), "-W", str(max(1, int(timeout))), host]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0
        return ok, out.strip()[:500]
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _find_max_payload(host: str, min_size: int, max_size: int, timeout: float) -> tuple[int | None, list[dict[str, Any]]]:
    """Двоичный поиск максимального ICMP payload с DF."""
    log: list[dict[str, Any]] = []
    lo, hi = min_size, max_size
    best: int | None = None
    # сначала проверим минимум
    ok_min, out_min = _ping_df(host, min_size, timeout)
    log.append({"size": min_size, "ok": ok_min, "sample": out_min[:200]})
    if not ok_min:
        return None, log

    while lo <= hi:
        mid = (lo + hi) // 2
        ok, out = _ping_df(host, mid, timeout)
        log.append({"size": mid, "ok": ok, "sample": out[:200]})
        if ok:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return best, log


def probe_mtu(peer: str, peer_cfg: dict[str, Any], timeout: float) -> list[ProbeResult]:
    mtu_cfg = peer_cfg.get("mtu") or {}
    host = mtu_cfg.get("target") or peer_cfg.get("host")
    if not host:
        return []
    min_size = int(mtu_cfg.get("min_size", 500))
    max_size = int(mtu_cfg.get("max_size", 1472))  # 1500 - 28 IP/ICMP hdr typ.
    evidence: dict[str, Any] = {
        "host": host,
        "min_size": min_size,
        "max_size": max_size,
        "platform": platform.system(),
    }

    best, log = _find_max_payload(host, min_size, max_size, timeout)
    evidence["probe_log"] = log[-8:]  # хвост
    evidence["best_payload"] = best

    # Приблизительный L3 MTU ≈ payload + 28
    approx_mtu = (best + 28) if best is not None else None
    evidence["approx_ip_mtu"] = approx_mtu

    target = f"{host}/mtu"
    if best is None:
        return [
            ProbeResult(
                Layer.MTU, peer, target, "icmp", None,
                Availability.UNAVAILABLE, CauseCode.MTU_BLACKHOLE,
                detail=f"даже payload={min_size} с DF не проходит (ICMP блок или blackhole)",
                evidence=evidence,
            )
        ]

    if best >= max_size - 8:
        return [
            ProbeResult(
                Layer.MTU, peer, target, "icmp", None,
                Availability.AVAILABLE, CauseCode.MTU_OK,
                detail=f"payload до ~{best} (≈MTU {approx_mtu})",
                evidence=evidence,
            )
        ]

    # Ограниченный MTU
    frag_hint = ""
    joined = " ".join(x.get("sample", "") for x in log).lower()
    if "fragment" in joined or "df" in joined or re.search(r"needs?\s*frag", joined):
        frag_hint = "; есть признаки need-frag"
    return [
        ProbeResult(
            Layer.MTU, peer, target, "icmp", None,
            Availability.DEGRADED, CauseCode.MTU_LIMITED,
            detail=f"макс. payload с DF ≈{best} (≈MTU {approx_mtu}){frag_hint}",
            evidence=evidence,
        )
    ]
