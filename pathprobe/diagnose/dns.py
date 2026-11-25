from __future__ import annotations

from typing import Any

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from pathprobe.models import Availability, CauseCode, Layer, ProbeResult


def probe_dns(
    peer: str,
    resolver: str,
    name: str,
    expected_a: list[str] | None,
    timeout: float,
) -> ProbeResult:
    target = f"{resolver}/{name}"
    evidence: dict[str, Any] = {"resolver": resolver, "qname": name, "expected_a": expected_a or []}
    try:
        q = dns.message.make_query(name, dns.rdatatype.A)
        resp = dns.query.udp(q, resolver, timeout=timeout)
        rcode = resp.rcode()
        evidence["rcode"] = dns.rcode.to_text(rcode)
        answers: list[str] = []
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.A:
                for rr in rrset:
                    answers.append(rr.address)
        evidence["answers"] = answers

        if rcode == dns.rcode.NXDOMAIN:
            return ProbeResult(
                Layer.DNS, peer, target, "dns", 53,
                Availability.UNAVAILABLE, CauseCode.DNS_NXDOMAIN,
                detail="rcode=NXDOMAIN", evidence=evidence,
            )
        if rcode == dns.rcode.SERVFAIL:
            return ProbeResult(
                Layer.DNS, peer, target, "dns", 53,
                Availability.UNAVAILABLE, CauseCode.DNS_SERVFAIL,
                detail="rcode=SERVFAIL", evidence=evidence,
            )
        if rcode == dns.rcode.REFUSED:
            return ProbeResult(
                Layer.DNS, peer, target, "dns", 53,
                Availability.UNAVAILABLE, CauseCode.DNS_REFUSED,
                detail="rcode=REFUSED", evidence=evidence,
            )
        if rcode != dns.rcode.NOERROR:
            return ProbeResult(
                Layer.DNS, peer, target, "dns", 53,
                Availability.UNAVAILABLE, CauseCode.DNS_OTHER,
                detail=f"rcode={dns.rcode.to_text(rcode)}", evidence=evidence,
            )

        if expected_a:
            expected_set = set(expected_a)
            got_set = set(answers)
            if not got_set:
                return ProbeResult(
                    Layer.DNS, peer, target, "dns", 53,
                    Availability.UNAVAILABLE, CauseCode.DNS_OTHER,
                    detail="NOERROR без A-записей", evidence=evidence,
                )
            if got_set != expected_set and not got_set.issubset(expected_set):
                return ProbeResult(
                    Layer.DNS, peer, target, "dns", 53,
                    Availability.UNAVAILABLE, CauseCode.DNS_SPOOF_A,
                    detail=f"ожидали {sorted(expected_set)}, получили {sorted(got_set)}",
                    evidence=evidence,
                )

        return ProbeResult(
            Layer.DNS, peer, target, "dns", 53,
            Availability.AVAILABLE, CauseCode.OK,
            detail=f"A={answers}", evidence=evidence,
        )
    except dns.exception.Timeout:
        return ProbeResult(
            Layer.DNS, peer, target, "dns", 53,
            Availability.UNAVAILABLE, CauseCode.DNS_TIMEOUT,
            detail=f"таймаут {timeout}s", evidence=evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(
            Layer.DNS, peer, target, "dns", 53,
            Availability.UNKNOWN, CauseCode.ERROR,
            detail=str(exc), evidence=evidence,
        )


def probe_peer_dns(peer: str, peer_cfg: dict[str, Any], timeout: float) -> list[ProbeResult]:
    dns_cfg = peer_cfg.get("dns") or {}
    resolvers = dns_cfg.get("resolvers") or []
    queries = dns_cfg.get("queries") or []
    out: list[ProbeResult] = []
    for resolver in resolvers:
        for q in queries:
            name = q.get("name")
            if not name:
                continue
            expected = q.get("expected_a")
            out.append(probe_dns(peer, resolver, name, expected, timeout))
    return out
