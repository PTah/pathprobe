from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from typing import Any, Callable

from pathprobe.diagnose.dns import probe_dns
from pathprobe.diagnose.tcp import probe_tcp
from pathprobe.diagnose.tls import probe_tls
from pathprobe.models import (
    CIRCUMVOLVE_LAYER_MAP,
    Availability,
    CauseCode,
    Classification,
    Layer,
    ProbeResult,
)

ProgressCb = Callable[[str, str, str, str], None]

DEST_STAGES: tuple[tuple[str, str], ...] = (
    ("dns_control", "DNS эталон"),
    ("dns_local", "DNS локальный"),
    ("tcp", "TCP"),
    ("tls", "TLS / SNI"),
    ("http", "HTTP"),
)


def _emit(cb: ProgressCb | None, name: str, stage: str, event: str, detail: str = "") -> None:
    if cb:
        cb(name, stage, event, detail)


def _resolve_ips(results: list[ProbeResult]) -> list[str]:
    ips: list[str] = []
    for r in results:
        if r.availability != Availability.AVAILABLE:
            continue
        for ip in r.evidence.get("answers") or []:
            if ip not in ips:
                ips.append(ip)
    return ips


def _http_probe(dest_id: str, host: str, ip: str, port: int, timeout: float) -> ProbeResult:
    # Ходим по имени (SNI/Host корректны). IP — справочно из предыдущих проб.
    url = f"https://{host}/" if port == 443 else f"https://{host}:{port}/"
    target = f"{host}:{port}"
    evidence: dict[str, Any] = {"url": url, "ref_ip": ip, "sni_host": host}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "pathprobe/0.3",
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            code = getattr(resp, "status", None) or resp.getcode()
            body = resp.read(4096).decode("utf-8", errors="replace").lower()
            evidence["status"] = code
            evidence["body_sample"] = body[:400]
            if 200 <= int(code) < 400:
                return ProbeResult(
                    Layer.TLS, dest_id, target, "http", port,
                    Availability.AVAILABLE, CauseCode.HTTP_OK,
                    detail=f"HTTP {code}", evidence=evidence,
                )
            if int(code) in (401, 403, 451):
                return ProbeResult(
                    Layer.TLS, dest_id, target, "http", port,
                    Availability.DEGRADED, CauseCode.HTTP_DENY,
                    detail=f"HTTP {code} (отказ сервиса/WAF/гео)", evidence=evidence,
                )
            return ProbeResult(
                Layer.TLS, dest_id, target, "http", port,
                Availability.DEGRADED, CauseCode.HTTP_DENY,
                detail=f"HTTP {code}", evidence=evidence,
            )
    except urllib.error.HTTPError as exc:
        code = exc.code
        body = ""
        try:
            body = exc.read(4096).decode("utf-8", errors="replace").lower()
        except Exception:  # noqa: BLE001
            pass
        evidence["status"] = code
        evidence["body_sample"] = body[:400]
        markers = (
            "blocked", "access denied", "заблок", "дост", "forbidden",
            "rkn", "роском", "provider", "фильтрац", "censorship",
        )
        if any(m in body for m in markers) or code in (451,):
            return ProbeResult(
                Layer.TLS, dest_id, target, "http", port,
                Availability.UNAVAILABLE, CauseCode.HTTP_BLOCK_PAGE,
                detail=f"HTTP {code}, признаки страницы блокировки", evidence=evidence,
            )
        if code in (401, 403):
            return ProbeResult(
                Layer.TLS, dest_id, target, "http", port,
                Availability.DEGRADED, CauseCode.HTTP_DENY,
                detail=f"HTTP {code}", evidence=evidence,
            )
        return ProbeResult(
            Layer.TLS, dest_id, target, "http", port,
            Availability.DEGRADED, CauseCode.HTTP_DENY,
            detail=f"HTTP {code}", evidence=evidence,
        )
    except TimeoutError:
        return ProbeResult(
            Layer.TLS, dest_id, target, "http", port,
            Availability.UNAVAILABLE, CauseCode.TCP_TIMEOUT,
            detail="HTTP timeout", evidence=evidence,
        )
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(
            Layer.TLS, dest_id, target, "http", port,
            Availability.UNKNOWN, CauseCode.ERROR,
            detail=str(exc), evidence=evidence,
        )


def probe_destination(
    dest: dict[str, Any],
    local_resolvers: list[str],
    control_resolvers: list[str],
    timeouts: dict[str, Any],
    on_progress: ProgressCb | None = None,
) -> tuple[list[ProbeResult], Classification]:
    dest_id = str(dest.get("id") or dest.get("name") or dest.get("host"))
    host = str(dest.get("host") or dest.get("name"))
    ports = [int(p) for p in (dest.get("ports") or [443])]
    do_http = bool(dest.get("http", True))
    results: list[ProbeResult] = []

    # 1) Эталонный DNS (публичные резолверы)
    _emit(on_progress, dest_id, "dns_control", "start")
    control_dns_results: list[ProbeResult] = []
    for resolver in control_resolvers:
        r = probe_dns(dest_id, resolver, host, None, float(timeouts["dns_sec"]))
        r.protocol = "dns-control"
        r.detail = f"эталон@{resolver}; {r.detail}"
        control_dns_results.append(r)
        results.append(r)
    control_ips = _resolve_ips(control_dns_results)
    _emit(
        on_progress,
        dest_id,
        "dns_control",
        "done",
        f"A={control_ips or 'нет'}",
    )

    # 2) Локальный DNS (DC / офисный резолвер)
    _emit(on_progress, dest_id, "dns_local", "start")
    local_dns_results: list[ProbeResult] = []
    expected = control_ips if control_ips else None
    for resolver in local_resolvers:
        r = probe_dns(dest_id, resolver, host, expected, float(timeouts["dns_sec"]))
        r.protocol = "dns-local"
        r.detail = f"локальный@{resolver}; {r.detail}"
        # Если эталона нет — не ставим spoof
        local_dns_results.append(r)
        results.append(r)
    local_ips = _resolve_ips(local_dns_results)
    _emit(on_progress, dest_id, "dns_local", "done", f"A={local_ips or 'нет'}")

    # Для TCP/TLS берём эталонные IP (что «должно» быть в мире), иначе локальные
    path_ips = control_ips or local_ips
    tcp_results: list[ProbeResult] = []
    tls_results: list[ProbeResult] = []
    http_results: list[ProbeResult] = []

    _emit(on_progress, dest_id, "tcp", "start")
    if not path_ips:
        _emit(on_progress, dest_id, "tcp", "done", "нет IP — пропуск")
    else:
        for ip in path_ips[:3]:
            for port in ports:
                tr = probe_tcp(dest_id, ip, port, float(timeouts["tcp_sec"]))
                tr.detail = f"{host} via {ip}; {tr.detail}"
                tcp_results.append(tr)
                results.append(tr)
        _emit(
            on_progress,
            dest_id,
            "tcp",
            "done",
            f"ok={sum(1 for r in tcp_results if r.availability == Availability.AVAILABLE)}",
        )

    _emit(on_progress, dest_id, "tls", "start")
    open_targets = [
        (r.evidence.get("host"), r.port)
        for r in tcp_results
        if r.availability == Availability.AVAILABLE and r.port is not None
    ]
    # если TCP не открылся — всё равно пробуем TLS на control IP (иногда mid-path странно)
    if not open_targets and path_ips:
        open_targets = [(ip, ports[0]) for ip in path_ips[:2]]
    for ip, port in open_targets[:4]:
        if not ip:
            continue
        tr = probe_tls(dest_id, str(ip), int(port), host, float(timeouts["tls_sec"]))
        tr.detail = f"SNI={host} via {ip}; {tr.detail}"
        tls_results.append(tr)
        results.append(tr)
    _emit(
        on_progress,
        dest_id,
        "tls",
        "done",
        f"ok={sum(1 for r in tls_results if r.cause == CauseCode.TLS_OK)}",
    )

    if do_http:
        _emit(on_progress, dest_id, "http", "start")
        tls_ok_ips = []
        for r in tls_results:
            if r.cause == CauseCode.TLS_OK:
                # target вида host:port/SNI=...
                ip = r.evidence.get("host")
                if ip:
                    tls_ok_ips.append((ip, r.port or 443))
        if not tls_ok_ips and path_ips:
            # попробуем HTTP только если TCP открыт
            for r in tcp_results:
                if r.availability == Availability.AVAILABLE:
                    tls_ok_ips.append((r.evidence.get("host"), r.port or 443))
        for ip, port in tls_ok_ips[:2]:
            if not ip:
                continue
            hr = _http_probe(dest_id, host, str(ip), int(port), float(timeouts.get("http_sec", 10)))
            http_results.append(hr)
            results.append(hr)
        _emit(
            on_progress,
            dest_id,
            "http",
            "done",
            f"проб={len(http_results)}",
        )
    else:
        _emit(on_progress, dest_id, "http", "done", "пропуск")

    classification = classify_destination(
        dest_id,
        host,
        control_dns_results,
        local_dns_results,
        tcp_results,
        tls_results,
        http_results,
        control_ips,
        local_ips,
    )
    return results, classification


def classify_destination(
    dest_id: str,
    host: str,
    control_dns: list[ProbeResult],
    local_dns: list[ProbeResult],
    tcp: list[ProbeResult],
    tls: list[ProbeResult],
    http: list[ProbeResult],
    control_ips: list[str],
    local_ips: list[str],
) -> Classification:
    layers: set[Layer] = set()
    causes: list[CauseCode] = []

    control_ok = any(r.availability == Availability.AVAILABLE for r in control_dns)
    local_fail = [
        r for r in local_dns
        if r.cause in (
            CauseCode.DNS_NXDOMAIN,
            CauseCode.DNS_SERVFAIL,
            CauseCode.DNS_TIMEOUT,
            CauseCode.DNS_REFUSED,
            CauseCode.DNS_SPOOF_A,
            CauseCode.DNS_OTHER,
        )
    ]
    local_spoof = any(r.cause == CauseCode.DNS_SPOOF_A for r in local_dns)
    local_ok = any(r.availability == Availability.AVAILABLE for r in local_dns) and not local_spoof

    tcp_ok = any(r.availability == Availability.AVAILABLE for r in tcp)
    tcp_rst = any(r.cause == CauseCode.TCP_RST for r in tcp)
    tcp_timeout = any(r.cause == CauseCode.TCP_TIMEOUT for r in tcp)

    tls_ok = any(r.cause == CauseCode.TLS_OK for r in tls)
    tls_dpi = any(
        r.cause in (CauseCode.TLS_CLIENTHELLO_DROP, CauseCode.TLS_RST_AFTER_CH) for r in tls
    )

    http_ok = any(r.cause == CauseCode.HTTP_OK for r in http)
    http_deny = any(r.cause == CauseCode.HTTP_DENY for r in http)
    http_block = any(r.cause == CauseCode.HTTP_BLOCK_PAGE for r in http)

    verdict = "inconclusive"
    who = "недостаточно данных"
    summary = ""
    recs: list[dict[str, str]] = []
    confidence = "medium"

    if control_ok and local_fail and not local_ok:
        layers.add(Layer.DNS)
        causes.extend(r.cause for r in local_fail)
        if local_spoof or any(r.cause == CauseCode.DNS_SPOOF_A for r in local_fail):
            verdict = "dns_spoof_local"
            who = "локальный DNS / фильтрация DNS на пути (не сам сервис)"
        elif any(r.cause == CauseCode.DNS_NXDOMAIN for r in local_fail):
            verdict = "dns_nxdomain_local"
            who = "локальный DNS / цензура DNS"
        elif any(r.cause == CauseCode.DNS_SERVFAIL for r in local_fail):
            verdict = "dns_servfail_local"
            who = "локальный DNS / фильтр (SERVFAIL)"
        else:
            verdict = "dns_block_local"
            who = "локальный DNS / путь до резолвера"
        summary = (
            f"«{host}»: эталонный DNS A={control_ips or '—'}; локальный DNS "
            f"A={local_ips or '—'} / ошибки. Блок или подмена на DNS в вашей сети, "
            f"а не отказ конечного сервиса."
        )
        recs.append({
            "profile": "fix_dns_or_doh",
            "reason_ru": (
                "Сменить DNS (DoH/DoT) или резолвить через туннель; "
                "сайт сам по себе тут ни при чём."
            ),
        })
        confidence = "high"

    if control_ok and (tcp_timeout or tcp_rst) and not tcp_ok:
        layers.add(Layer.TCP)
        causes.extend([CauseCode.TCP_TIMEOUT if tcp_timeout else CauseCode.TCP_RST])
        if verdict == "inconclusive":
            verdict = "path_tcp_block"
            who = "фильтр/DPI/firewall на пути (провайдер или периметр офиса)"
            summary = (
                f"«{host}»: DNS эталона знает IP {control_ips}, но TCP до них "
                f"{'таймаут' if tcp_timeout else 'RST'}. Типично блок на пути, "
                f"не «Canva отключила вас» на уровне приложения."
            )
            confidence = "high"
        recs.append({
            "profile": "tunnel_or_bypass",
            "reason_ru": "Нужен обход пути (VPN/туннель) или исключение в периметровом фильтре.",
        })

    if tls_dpi and not tls_ok:
        layers.add(Layer.TLS)
        causes.append(CauseCode.TLS_CLIENTHELLO_DROP)
        if verdict in ("inconclusive", "path_tcp_block") or verdict.startswith("dns_"):
            # TLS DPI may be primary if TCP somehow ok or alongside
            if tcp_ok or verdict == "inconclusive":
                verdict = "path_tls_sni_dpi"
                who = "DPI/фильтр по SNI на пути (провайдер или офисный шлюз)"
                summary = (
                    f"«{host}»: TCP до IP есть (или частично), но TLS с SNI={host} "
                    f"обрывается (ClientHello drop/RST). Это классический DPI по SNI, "
                    f"а не бан аккаунта на стороне сервиса."
                )
                confidence = "high"
        recs.append({
            "profile": "tunnel_tls_bypass",
            "reason_ru": "Обход DPI (туннель/VPN). Сам сервис здесь, скорее всего, ни при чём.",
        })

    if tls_ok and http_block:
        layers.add(Layer.TLS)
        causes.append(CauseCode.HTTP_BLOCK_PAGE)
        verdict = "provider_http_block_page"
        who = "провайдер/фильтр (HTTP-заглушка), сеть до сервиса в целом проходит"
        summary = (
            f"«{host}»: TLS установлен, но HTTP похож на страницу блокировки. "
            f"Скорее фильтр на пути, чем отказ приложения Canva."
        )
        confidence = "high"
        recs.append({
            "profile": "tunnel_or_bypass",
            "reason_ru": "Обход фильтра; это не похоже на «Canva ban».",
        })
    elif tls_ok and http_deny and not http_ok:
        layers.add(Layer.TLS)
        causes.append(CauseCode.HTTP_DENY)
        verdict = "service_http_deny"
        who = "сам сервис / WAF / гео-ограничение (или CDN), сеть до него доходит"
        summary = (
            f"«{host}»: DNS/TCP/TLS до эталонных IP работают, но HTTP отвечает отказом "
            f"(403/401/451…). Похоже на политику самого сервиса/WAF/гео, а не на DPI-обрыв. "
            f"Для подтверждения сравните с чистого выхода (EU VPS): если там тоже 403 — "
            f"это сервис; если там 200, а здесь 403 — тонкая фильтрация HTTP на пути."
        )
        confidence = "medium"
        recs.append({
            "profile": "compare_clean_exit",
            "reason_ru": (
                "Проверьте тот же URL с EU VPS / другого ISP. "
                "Одинаковый отказ → сервис; только у вас → путь/WAF под ваш IP."
            ),
        })
    elif tls_ok and (http_ok or not http):
        verdict = "path_ok"
        who = "блок на сетевом пути не обнаружен"
        summary = (
            f"«{host}»: до эталонных IP путь жив (DNS эталона + TLS"
            f"{' + HTTP OK' if http_ok else ''}). Если в браузере «не открывается» — "
            f"смотрите кэш DNS/прокси/расширения или приложение выше сети."
        )
        confidence = "high" if http_ok else "medium"
        recs.append({
            "profile": "check_client",
            "reason_ru": "Сеть до сервиса проходит; копайте клиент/прокси/DNS кэш.",
        })
    elif not control_ok and not local_ok:
        layers.add(Layer.DNS)
        verdict = "dns_both_fail"
        who = "нет резолва ни у эталона, ни локально (или нет сети)"
        summary = (
            f"«{host}»: не удалось получить A ни с эталонного, ни с локального DNS. "
            f"Проверьте интернет/файрвол до 53/UDP или имя хоста."
        )
        confidence = "medium"

    if not summary:
        summary = (
            f"«{host}»: смешанные признаки (control A={control_ips or '—'}, "
            f"local A={local_ips or '—'}, tcp_ok={tcp_ok}, tls_ok={tls_ok}). "
            f"Сверьте детали матрицы."
        )

    analogues = sorted({CIRCUMVOLVE_LAYER_MAP[l] for l in layers if l in CIRCUMVOLVE_LAYER_MAP})
    # unique recs
    seen: set[str] = set()
    uniq_recs: list[dict[str, str]] = []
    for r in recs:
        if r["profile"] in seen:
            continue
        seen.add(r["profile"])
        uniq_recs.append(r)

    primary = []
    for c in causes:
        if c.value not in primary:
            primary.append(c.value)

    return Classification(
        peer=dest_id,
        primary_causes=primary[:6],
        layers_affected=sorted(l.value for l in layers),
        circumvolve_analogues=analogues,
        summary_ru=summary,
        suggested_profiles=uniq_recs or [{
            "profile": "review_matrix",
            "reason_ru": "Смотрите матрицу проб по слоям DNS/TCP/TLS/HTTP.",
        }],
        confidence=confidence,
        kind="destination",
        verdict=verdict,
        who_blocks_ru=who,
    )


def probe_all_destinations(
    cfg: dict[str, Any],
    on_progress: ProgressCb | None = None,
) -> tuple[list[ProbeResult], list[Classification]]:
    destinations = cfg.get("destinations") or []
    local_resolvers = list(
        (cfg.get("local_dns") or {}).get("resolvers")
        or (cfg.get("dns") or {}).get("local_resolvers")
        or []
    )
    control_resolvers = list(
        (cfg.get("control_dns") or {}).get("resolvers")
        or ["1.1.1.1", "8.8.8.8"]
    )
    timeouts = cfg.get("timeouts") or {}
    timeouts.setdefault("http_sec", 10.0)

    all_results: list[ProbeResult] = []
    classifications: list[Classification] = []
    for dest in destinations:
        if isinstance(dest, str):
            dest = {"host": dest, "id": dest}
        name = str(dest.get("id") or dest.get("host"))
        _emit(on_progress, name, "peer", "start", "destination")
        results, cl = probe_destination(
            dest, local_resolvers, control_resolvers, timeouts, on_progress
        )
        all_results.extend(results)
        classifications.append(cl)
        _emit(on_progress, name, "peer", "done", cl.verdict)
    return all_results, classifications
