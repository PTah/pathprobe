from pathprobe.diagnose.matrix import build_matrix, matrix_summary_counts
from pathprobe.models import Availability, CauseCode, Layer, ProbeResult


def test_build_matrix_dedup_tcp():
    results = [
        ProbeResult(Layer.TCP, "p", "1.2.3.4:443", "tcp", 443, Availability.AVAILABLE, CauseCode.TCP_OPEN),
        ProbeResult(Layer.TCP, "p", "1.2.3.4:443", "tcp", 443, Availability.AVAILABLE, CauseCode.TCP_OPEN),
        ProbeResult(Layer.UDP, "p", "1.2.3.4:51820", "udp", 51820, Availability.UNAVAILABLE, CauseCode.UDP_TIMEOUT),
    ]
    cells = build_matrix(results)
    tcp = [c for c in cells if c.protocol == "tcp"]
    assert len(tcp) == 1
    assert len(cells) == 2


def test_matrix_counts():
    results = [
        ProbeResult(Layer.TCP, "p", "h:22", "tcp", 22, Availability.AVAILABLE, CauseCode.TCP_OPEN),
        ProbeResult(Layer.TCP, "p", "h:80", "tcp", 80, Availability.UNAVAILABLE, CauseCode.TCP_TIMEOUT),
    ]
    cells = build_matrix(results)
    counts = matrix_summary_counts(cells)
    assert counts[Availability.AVAILABLE.value] == 1
    assert counts[Availability.UNAVAILABLE.value] == 1
