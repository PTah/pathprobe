from pathprobe.diagnose.destination import classify_destination
from pathprobe.models import Availability, CauseCode, Layer, ProbeResult


def _dns(peer, proto, cause, avail, answers=None):
    return ProbeResult(
        Layer.DNS, peer, "t", proto, 53, avail, cause,
        evidence={"answers": answers or []},
    )


def _tcp(peer, cause, avail, ip="1.2.3.4"):
    return ProbeResult(
        Layer.TCP, peer, f"{ip}:443", "tcp", 443, avail, cause,
        evidence={"host": ip, "port": 443},
    )


def _tls(peer, cause, avail, ip="1.2.3.4"):
    return ProbeResult(
        Layer.TLS, peer, f"{ip}:443", "tls", 443, avail, cause,
        evidence={"host": ip},
    )


def _http(peer, cause, avail):
    return ProbeResult(
        Layer.TLS, peer, "h:443", "http", 443, avail, cause,
        evidence={"status": 403 if cause == CauseCode.HTTP_DENY else 200},
    )


def test_dns_spoof_vs_control():
    control = [_dns("canva", "dns-control", CauseCode.OK, Availability.AVAILABLE, ["1.2.3.4"])]
    local = [_dns("canva", "dns-local", CauseCode.DNS_SPOOF_A, Availability.UNAVAILABLE, ["9.9.9.9"])]
    cl = classify_destination(
        "canva", "www.canva.com", control, local, [], [], [], ["1.2.3.4"], ["9.9.9.9"]
    )
    assert cl.kind == "destination"
    assert cl.verdict == "dns_spoof_local"
    assert "DNS" in cl.who_blocks_ru or "dns" in cl.who_blocks_ru.lower() or "локальн" in cl.who_blocks_ru


def test_tls_dpi_verdict():
    control = [_dns("canva", "dns-control", CauseCode.OK, Availability.AVAILABLE, ["1.2.3.4"])]
    local = [_dns("canva", "dns-local", CauseCode.OK, Availability.AVAILABLE, ["1.2.3.4"])]
    tcp = [_tcp("canva", CauseCode.TCP_OPEN, Availability.AVAILABLE)]
    tls = [_tls("canva", CauseCode.TLS_CLIENTHELLO_DROP, Availability.UNAVAILABLE)]
    cl = classify_destination(
        "canva", "www.canva.com", control, local, tcp, tls, [], ["1.2.3.4"], ["1.2.3.4"]
    )
    assert cl.verdict == "path_tls_sni_dpi"


def test_service_http_deny():
    control = [_dns("canva", "dns-control", CauseCode.OK, Availability.AVAILABLE, ["1.2.3.4"])]
    local = [_dns("canva", "dns-local", CauseCode.OK, Availability.AVAILABLE, ["1.2.3.4"])]
    tcp = [_tcp("canva", CauseCode.TCP_OPEN, Availability.AVAILABLE)]
    tls = [_tls("canva", CauseCode.TLS_OK, Availability.AVAILABLE)]
    http = [_http("canva", CauseCode.HTTP_DENY, Availability.DEGRADED)]
    cl = classify_destination(
        "canva", "www.canva.com", control, local, tcp, tls, http, ["1.2.3.4"], ["1.2.3.4"]
    )
    assert cl.verdict == "service_http_deny"
    assert "сервис" in cl.who_blocks_ru.lower() or "WAF" in cl.who_blocks_ru
