from __future__ import annotations

from collections import Counter

from pathprobe.models import (
    CIRCUMVOLVE_LAYER_MAP,
    Availability,
    CauseCode,
    Classification,
    Layer,
    ProbeResult,
)


# Приоритет «серьёзности» причин для выбора primary
_CAUSE_WEIGHT: dict[CauseCode, int] = {
    CauseCode.TLS_CLIENTHELLO_DROP: 100,
    CauseCode.TLS_RST_AFTER_CH: 95,
    CauseCode.DNS_SPOOF_A: 90,
    CauseCode.DNS_SERVFAIL: 85,
    CauseCode.DNS_NXDOMAIN: 80,
    CauseCode.TCP_RST: 75,
    CauseCode.TCP_TIMEOUT: 70,
    CauseCode.UDP_TIMEOUT: 65,
    CauseCode.MTU_BLACKHOLE: 60,
    CauseCode.MTU_LIMITED: 40,
    CauseCode.TLS_HANDSHAKE_FAIL: 55,
    CauseCode.DNS_TIMEOUT: 50,
}


def _profile(name: str, reason: str) -> dict[str, str]:
    return {"profile": name, "reason_ru": reason}


def suggest_profiles(causes: set[CauseCode], layers: set[Layer]) -> list[dict[str, str]]:
    """Подбор профиля (фаза 2 — только рекомендация, без применения)."""
    suggestions: list[dict[str, str]] = []

    tls_dpi = causes & {CauseCode.TLS_CLIENTHELLO_DROP, CauseCode.TLS_RST_AFTER_CH}
    udp_bad = CauseCode.UDP_TIMEOUT in causes
    tcp443_ok = True  # уточняется снаружи; здесь эвристика по отсутствию TCP timeout на 443

    if tls_dpi and udp_bad:
        suggestions.append(
            _profile(
                "openvpn_tcp443",
                "DPI по TLS SNI и блок/фильтр UDP: предпочтителен OpenVPN TCP/443 "
                "(маскировка под HTTPS) — после проверки, что TCP/443 до своего peer жив.",
            )
        )
    elif tls_dpi:
        suggestions.append(
            _profile(
                "openvpn_tcp443",
                "Признаки DPI на ClientHello/SNI: туннель поверх TCP/443 со своим SNI/сервером.",
            )
        )

    if not udp_bad and Layer.UDP in layers:
        if CauseCode.UDP_OK in causes or not tls_dpi:
            suggestions.append(
                _profile(
                    "wireguard",
                    "UDP до peer проходит: WireGuard прост и быстр (порт из конфига, обычно 51820).",
                )
            )
            suggestions.append(
                _profile(
                    "ikev2_ipsec",
                    "UDP 500/4500 доступны или перспективны: IKEv2/IPsec (home Ubuntu strongSwan ↔ MikroTik).",
                )
            )

    if CauseCode.MTU_LIMITED in causes or CauseCode.MTU_BLACKHOLE in causes:
        suggestions.append(
            _profile(
                "gre_ipsec",
                "Ограничение MTU/blackhole: при GRE+IPsec обязателен clamp-mss / учёт overhead; "
                "как альтернатива — WG/OpenVPN с меньшим MTU интерфейса.",
            )
        )

    if CauseCode.DNS_SPOOF_A in causes or CauseCode.DNS_SERVFAIL in causes:
        suggestions.append(
            _profile(
                "ikev2_ipsec",
                "Проблемы DNS на пути: не опираться на публичный DNS для peer; "
                "подключаться по IP, DNS — только внутри туннеля.",
            )
        )

    if not suggestions:
        suggestions.append(
            _profile(
                "wireguard",
                "Явных жёстких блоков туннельных портов не видно — стартовый профиль WireGuard; "
                "резерв: IKEv2/IPsec, затем OpenVPN TCP/443.",
            )
        )
        suggestions.append(
            _profile(
                "ikev2_ipsec",
                "Резерв под ROS 6.49.19: нативный IPsec на MikroTik и strongSwan на Ubuntu.",
            )
        )

    # уникальные по имени, порядок сохраняем
    seen: set[str] = set()
    uniq: list[dict[str, str]] = []
    for s in suggestions:
        if s["profile"] in seen:
            continue
        seen.add(s["profile"])
        uniq.append(s)
    return uniq


def classify_peer(peer: str, results: list[ProbeResult]) -> Classification:
    peer_results = [r for r in results if r.peer == peer]
    bad = [
        r
        for r in peer_results
        if r.availability in (Availability.UNAVAILABLE, Availability.DEGRADED)
        and r.cause not in (CauseCode.OK, CauseCode.TCP_OPEN, CauseCode.TLS_OK, CauseCode.UDP_OK, CauseCode.MTU_OK)
    ]
    # OK causes that are positive
    positive_causes = {r.cause for r in peer_results if r.availability == Availability.AVAILABLE}

    cause_counter = Counter(r.cause for r in bad)
    ranked = sorted(
        cause_counter.keys(),
        key=lambda c: (_CAUSE_WEIGHT.get(c, 10), cause_counter[c]),
        reverse=True,
    )
    primary = [c.value for c in ranked[:5]]
    layers = {r.layer for r in bad}
    layers_affected = sorted(l.value for l in layers)
    analogues = sorted({CIRCUMVOLVE_LAYER_MAP[l] for l in layers if l in CIRCUMVOLVE_LAYER_MAP})

    all_causes = set(cause_counter.keys()) | positive_causes
    # Для suggest: если TCP 443 открыт — отметим косвенно
    tcp443 = [
        r for r in peer_results
        if r.protocol == "tcp" and r.port == 443 and r.availability == Availability.AVAILABLE
    ]
    profiles = suggest_profiles(all_causes, {r.layer for r in peer_results})
    if tcp443 and any(p["profile"] == "openvpn_tcp443" for p in profiles):
        for p in profiles:
            if p["profile"] == "openvpn_tcp443":
                p["reason_ru"] += " TCP/443 до peer подтверждён."

    if not bad:
        summary = (
            f"Peer «{peer}»: критичных блокировок по выполненным пробам не обнаружено. "
            "Можно переходить к фазе 2 (подбор и генерация туннеля)."
        )
        confidence = "high" if peer_results else "low"
    else:
        parts = [r.cause_ru() for r in bad[:4]]
        summary = (
            f"Peer «{peer}»: затронуты слои {', '.join(layers_affected) or '—'}. "
            f"Основные признаки: {'; '.join(parts)}."
        )
        confidence = "high" if len(bad) >= 2 else "medium"

    return Classification(
        peer=peer,
        primary_causes=primary,
        layers_affected=layers_affected,
        circumvolve_analogues=analogues,
        summary_ru=summary,
        suggested_profiles=profiles,
        confidence=confidence,
    )


def classify_all(results: list[ProbeResult]) -> list[Classification]:
    peers = sorted({r.peer for r in results})
    return [classify_peer(p, results) for p in peers]
