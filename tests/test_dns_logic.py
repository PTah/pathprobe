from unittest.mock import MagicMock, patch

import dns.rcode
import dns.rdatatype

from pathprobe.diagnose.dns import probe_dns
from pathprobe.models import CauseCode


def test_dns_spoof_detection():
    resp = MagicMock()
    resp.rcode.return_value = dns.rcode.NOERROR
    rr = MagicMock()
    rr.address = "9.9.9.9"
    rrset = MagicMock()
    rrset.rdtype = dns.rdatatype.A
    rrset.__iter__ = lambda self: iter([rr])
    resp.answer = [rrset]

    with patch("pathprobe.diagnose.dns.dns.message.make_query"), patch(
        "pathprobe.diagnose.dns.dns.query.udp", return_value=resp
    ):
        result = probe_dns("p", "1.1.1.1", "probe.example", ["10.10.10.1"], 1.0)
    assert result.cause == CauseCode.DNS_SPOOF_A


def test_dns_nxdomain():
    resp = MagicMock()
    resp.rcode.return_value = dns.rcode.NXDOMAIN
    resp.answer = []
    with patch("pathprobe.diagnose.dns.dns.message.make_query"), patch(
        "pathprobe.diagnose.dns.dns.query.udp", return_value=resp
    ):
        result = probe_dns("p", "1.1.1.1", "no.example", None, 1.0)
    assert result.cause == CauseCode.DNS_NXDOMAIN
