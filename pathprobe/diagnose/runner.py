from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from pathprobe.config import peer_items
from pathprobe.diagnose.classify import classify_all
from pathprobe.diagnose.dns import probe_peer_dns
from pathprobe.diagnose.matrix import build_matrix
from pathprobe.diagnose.mtu import probe_mtu
from pathprobe.diagnose.tcp import probe_peer_tcp
from pathprobe.diagnose.tls import probe_peer_tls
from pathprobe.diagnose.udp import probe_peer_udp
from pathprobe.models import DiagnosisReport, ProbeResult

# peer, stage_id, event: start|done|error, detail
ProgressCb = Callable[[str, str, str, str], None]

STAGES: tuple[tuple[str, str], ...] = (
    ("dns", "DNS"),
    ("tcp", "TCP"),
    ("tls", "TLS / SNI"),
    ("udp", "UDP"),
    ("mtu", "MTU"),
)


def _emit(cb: ProgressCb | None, peer: str, stage: str, event: str, detail: str = "") -> None:
    if cb:
        cb(peer, stage, event, detail)


def run_peer_probes(
    peer: str,
    peer_cfg: dict[str, Any],
    timeouts: dict[str, Any],
    on_progress: ProgressCb | None = None,
) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    steps: list[tuple[str, Callable[[], list[ProbeResult]]]] = [
        ("dns", lambda: probe_peer_dns(peer, peer_cfg, float(timeouts["dns_sec"]))),
        ("tcp", lambda: probe_peer_tcp(peer, peer_cfg, float(timeouts["tcp_sec"]))),
        ("tls", lambda: probe_peer_tls(peer, peer_cfg, float(timeouts["tls_sec"]))),
        ("udp", lambda: probe_peer_udp(peer, peer_cfg, float(timeouts["udp_sec"]))),
        ("mtu", lambda: probe_mtu(peer, peer_cfg, float(timeouts["mtu_sec"]))),
    ]
    for stage_id, fn in steps:
        _emit(on_progress, peer, stage_id, "start")
        try:
            chunk = fn()
            results.extend(chunk)
            bad = sum(
                1
                for r in chunk
                if r.availability.value in ("недоступен", "деградирован")
            )
            _emit(
                on_progress,
                peer,
                stage_id,
                "done",
                f"проб={len(chunk)}, проблем={bad}",
            )
        except Exception as exc:  # noqa: BLE001
            _emit(on_progress, peer, stage_id, "error", str(exc))
            raise
    return results


def run_diagnosis(
    cfg: dict[str, Any],
    config_path: str = "",
    on_progress: ProgressCb | None = None,
) -> DiagnosisReport:
    timeouts = cfg.get("timeouts") or {}
    results: list[ProbeResult] = []
    for name, peer_cfg in peer_items(cfg):
        _emit(on_progress, name, "peer", "start", "начало диагностики peer")
        results.extend(run_peer_probes(name, peer_cfg, timeouts, on_progress=on_progress))
        _emit(on_progress, name, "peer", "done", "peer завершён")
    matrix = build_matrix(results)
    classifications = classify_all(results)
    _emit(on_progress, "*", "classify", "done", "классификация готова")
    return DiagnosisReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        config_path=config_path,
        results=results,
        matrix=matrix,
        classifications=classifications,
    )
