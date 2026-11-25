from pathprobe.diagnose.classify import classify_peer, suggest_profiles
from pathprobe.models import Availability, CauseCode, Layer, ProbeResult


def _r(peer, layer, cause, avail, protocol="tcp", port=443):
    return ProbeResult(
        layer=layer,
        peer=peer,
        target="t",
        protocol=protocol,
        port=port,
        availability=avail,
        cause=cause,
    )


def test_suggest_openvpn_on_tls_dpi_and_udp_block():
    causes = {CauseCode.TLS_CLIENTHELLO_DROP, CauseCode.UDP_TIMEOUT}
    profiles = suggest_profiles(causes, {Layer.TLS, Layer.UDP})
    names = [p["profile"] for p in profiles]
    assert "openvpn_tcp443" in names


def test_classify_tls_dpi_summary():
    results = [
        _r("work", Layer.TLS, CauseCode.TLS_CLIENTHELLO_DROP, Availability.UNAVAILABLE, "tls", 443),
        _r("work", Layer.TCP, CauseCode.TCP_OPEN, Availability.AVAILABLE, "tcp", 443),
        _r("work", Layer.UDP, CauseCode.UDP_TIMEOUT, Availability.UNAVAILABLE, "udp", 51820),
    ]
    cl = classify_peer("work", results)
    assert "tls" in cl.layers_affected
    assert any(p["profile"] == "openvpn_tcp443" for p in cl.suggested_profiles)
    assert "TLS" in cl.summary_ru or "tls" in cl.layers_affected


def test_classify_clean_path():
    results = [
        _r("work", Layer.TCP, CauseCode.TCP_OPEN, Availability.AVAILABLE, "tcp", 22),
        _r("work", Layer.UDP, CauseCode.UDP_OK, Availability.AVAILABLE, "udp", 51820),
    ]
    cl = classify_peer("work", results)
    assert cl.layers_affected == []
    assert "не обнаружено" in cl.summary_ru
