from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pathprobe.config import peer_items
from pathprobe.diagnose.classify import classify_all
from pathprobe.diagnose.dns import probe_peer_dns
from pathprobe.diagnose.matrix import build_matrix
from pathprobe.diagnose.mtu import probe_mtu
from pathprobe.diagnose.tcp import probe_peer_tcp
from pathprobe.diagnose.tls import probe_peer_tls
from pathprobe.diagnose.udp import probe_peer_udp
from pathprobe.models import DiagnosisReport, ProbeResult


def run_peer_probes(peer: str, peer_cfg: dict[str, Any], timeouts: dict[str, Any]) -> list[ProbeResult]:
    results: list[ProbeResult] = []
    results.extend(probe_peer_dns(peer, peer_cfg, float(timeouts["dns_sec"])))
    results.extend(probe_peer_tcp(peer, peer_cfg, float(timeouts["tcp_sec"])))
    results.extend(probe_peer_tls(peer, peer_cfg, float(timeouts["tls_sec"])))
    results.extend(probe_peer_udp(peer, peer_cfg, float(timeouts["udp_sec"])))
    results.extend(probe_mtu(peer, peer_cfg, float(timeouts["mtu_sec"])))
    return results


def run_diagnosis(cfg: dict[str, Any], config_path: str = "") -> DiagnosisReport:
    timeouts = cfg.get("timeouts") or {}
    results: list[ProbeResult] = []
    for name, peer_cfg in peer_items(cfg):
        results.extend(run_peer_probes(name, peer_cfg, timeouts))
    matrix = build_matrix(results)
    classifications = classify_all(results)
    return DiagnosisReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        config_path=config_path,
        results=results,
        matrix=matrix,
        classifications=classifications,
    )
