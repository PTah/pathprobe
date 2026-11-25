from __future__ import annotations

import errno
import socket
import ssl
from typing import Any

from pathprobe.models import Availability, CauseCode, Layer, ProbeResult


def probe_tls(
    peer: str,
    host: str,
    port: int,
    sni: str | None,
    timeout: float,
    expect_cert_cn: str | None = None,
) -> ProbeResult:
    target = f"{host}:{port}"
    if sni:
        target = f"{target}/SNI={sni}"
    evidence: dict[str, Any] = {"host": host, "port": port, "sni": sni}

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    tls: ssl.SSLSocket | None = None
    ctx = ssl.create_default_context()
    # Self-hosted / IP peers: не валим пробу только из‑за недоверенного CA
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        raw.connect((host, port))
        evidence["tcp_connected"] = True
        server_hostname = sni or host
        try:
            tls = ctx.wrap_socket(raw, server_hostname=server_hostname)
            evidence["tls_version"] = tls.version()
            evidence["cipher"] = tls.cipher()
            cert = tls.getpeercert(binary_form=False) or {}
            if not cert:
                der = tls.getpeercert(binary_form=True)
                evidence["peer_cert_der_len"] = len(der) if der else 0
            else:
                evidence["peer_cert"] = cert
                if expect_cert_cn:
                    subject = {k: v for tup in cert.get("subject", ()) for k, v in tup}
                    cn = subject.get("commonName")
                    evidence["cert_cn"] = cn
                    if cn and cn != expect_cert_cn:
                        return ProbeResult(
                            Layer.TLS, peer, target, "tls", port,
                            Availability.DEGRADED, CauseCode.TLS_CERT_MISMATCH,
                            detail=f"CN={cn}, ожидали {expect_cert_cn}",
                            evidence=evidence,
                        )
            return ProbeResult(
                Layer.TLS, peer, target, "tls", port,
                Availability.AVAILABLE, CauseCode.TLS_OK,
                detail="handshake OK", evidence=evidence,
            )
        except (socket.timeout, TimeoutError):
            return ProbeResult(
                Layer.TLS, peer, target, "tls", port,
                Availability.UNAVAILABLE, CauseCode.TLS_CLIENTHELLO_DROP,
                detail="таймаут после TCP connect (вероятный drop ClientHello/SNI)",
                evidence=evidence,
            )
        except ConnectionResetError:
            return ProbeResult(
                Layer.TLS, peer, target, "tls", port,
                Availability.UNAVAILABLE, CauseCode.TLS_RST_AFTER_CH,
                detail="RST во время TLS handshake", evidence=evidence,
            )
        except OSError as exc:
            evidence["errno"] = getattr(exc, "errno", None)
            if exc.errno in (errno.ECONNRESET, 10054) or "reset" in str(exc).lower():
                return ProbeResult(
                    Layer.TLS, peer, target, "tls", port,
                    Availability.UNAVAILABLE, CauseCode.TLS_RST_AFTER_CH,
                    detail=str(exc), evidence=evidence,
                )
            return ProbeResult(
                Layer.TLS, peer, target, "tls", port,
                Availability.UNAVAILABLE, CauseCode.TLS_HANDSHAKE_FAIL,
                detail=str(exc), evidence=evidence,
            )
        except ssl.SSLError as exc:
            return ProbeResult(
                Layer.TLS, peer, target, "tls", port,
                Availability.UNAVAILABLE, CauseCode.TLS_HANDSHAKE_FAIL,
                detail=str(exc), evidence=evidence,
            )
    except (socket.timeout, TimeoutError):
        return ProbeResult(
            Layer.TLS, peer, target, "tls", port,
            Availability.UNAVAILABLE, CauseCode.TCP_TIMEOUT,
            detail="TCP connect timeout до TLS", evidence=evidence,
        )
    except ConnectionRefusedError:
        return ProbeResult(
            Layer.TLS, peer, target, "tls", port,
            Availability.UNAVAILABLE, CauseCode.TCP_REFUSED,
            detail="TCP refused до TLS", evidence=evidence,
        )
    except ConnectionResetError:
        return ProbeResult(
            Layer.TLS, peer, target, "tls", port,
            Availability.UNAVAILABLE, CauseCode.TCP_RST,
            detail="TCP RST до TLS", evidence=evidence,
        )
    except OSError as exc:
        evidence["errno"] = getattr(exc, "errno", None)
        if exc.errno in (errno.ECONNRESET, 10054):
            return ProbeResult(
                Layer.TLS, peer, target, "tls", port,
                Availability.UNAVAILABLE, CauseCode.TCP_RST,
                detail=str(exc), evidence=evidence,
            )
        return ProbeResult(
            Layer.TLS, peer, target, "tls", port,
            Availability.UNKNOWN, CauseCode.ERROR,
            detail=str(exc), evidence=evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(
            Layer.TLS, peer, target, "tls", port,
            Availability.UNKNOWN, CauseCode.ERROR,
            detail=str(exc), evidence=evidence,
        )
    finally:
        for s in (tls, raw):
            if s is None:
                continue
            try:
                s.close()
            except OSError:
                pass


def probe_peer_tls(peer: str, peer_cfg: dict[str, Any], timeout: float) -> list[ProbeResult]:
    out: list[ProbeResult] = []
    for item in peer_cfg.get("tls") or []:
        host = item.get("host") or peer_cfg.get("host")
        port = int(item.get("port", 443))
        if not host:
            continue
        out.append(
            probe_tls(
                peer,
                host,
                port,
                item.get("sni"),
                timeout,
                item.get("expect_cert_cn"),
            )
        )
    return out
