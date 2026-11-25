from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Layer(str, Enum):
    DNS = "dns"
    TCP = "tcp"
    TLS = "tls"
    UDP = "udp"
    MTU = "mtu"


class Availability(str, Enum):
    AVAILABLE = "доступен"
    UNAVAILABLE = "недоступен"
    DEGRADED = "деградирован"
    UNKNOWN = "неизвестно"


class CauseCode(str, Enum):
    OK = "ok"
    DNS_NXDOMAIN = "dns_nxdomain"
    DNS_SERVFAIL = "dns_servfail"
    DNS_SPOOF_A = "dns_spoof_a"
    DNS_TIMEOUT = "dns_timeout"
    DNS_REFUSED = "dns_refused"
    DNS_OTHER = "dns_other"
    TCP_OPEN = "tcp_open"
    TCP_RST = "tcp_rst"
    TCP_TIMEOUT = "tcp_timeout"
    TCP_REFUSED = "tcp_refused"
    TLS_OK = "tls_ok"
    TLS_CLIENTHELLO_DROP = "tls_clienthello_drop"
    TLS_RST_AFTER_CH = "tls_rst_after_clienthello"
    TLS_HANDSHAKE_FAIL = "tls_handshake_fail"
    TLS_CERT_MISMATCH = "tls_cert_mismatch"
    UDP_OK = "udp_ok"
    UDP_TIMEOUT = "udp_timeout"
    UDP_ICMP_UNREACH = "udp_icmp_unreach"
    MTU_OK = "mtu_ok"
    MTU_BLACKHOLE = "mtu_blackhole"
    MTU_LIMITED = "mtu_limited"
    HTTP_OK = "http_ok"
    HTTP_DENY = "http_deny"
    HTTP_BLOCK_PAGE = "http_block_page"
    ERROR = "error"


CAUSE_RU: dict[CauseCode, str] = {
    CauseCode.OK: "норма",
    CauseCode.DNS_NXDOMAIN: "DNS: NXDOMAIN (имя не существует с точки зрения резолвера)",
    CauseCode.DNS_SERVFAIL: "DNS: SERVFAIL (отказ/сбой резолвера или фильтра)",
    CauseCode.DNS_SPOOF_A: "DNS: подмена A-записи (ответ не совпал с ожидаемым)",
    CauseCode.DNS_TIMEOUT: "DNS: таймаут запроса",
    CauseCode.DNS_REFUSED: "DNS: REFUSED",
    CauseCode.DNS_OTHER: "DNS: иной аномальный ответ",
    CauseCode.TCP_OPEN: "TCP: порт открыт, соединение установлено",
    CauseCode.TCP_RST: "TCP: получен RST",
    CauseCode.TCP_TIMEOUT: "TCP: таймаут (фильтр/drop или чёрная дыра)",
    CauseCode.TCP_REFUSED: "TCP: соединение отвергнуто (ICMP/отказ локально на peer)",
    CauseCode.TLS_OK: "TLS: рукопожатие успешно",
    CauseCode.TLS_CLIENTHELLO_DROP: "TLS: обрыв/тишина на ClientHello (типично DPI по SNI)",
    CauseCode.TLS_RST_AFTER_CH: "TLS: RST после ClientHello",
    CauseCode.TLS_HANDSHAKE_FAIL: "TLS: ошибка рукопожатия",
    CauseCode.TLS_CERT_MISMATCH: "TLS: сертификат не совпал с ожиданием",
    CauseCode.UDP_OK: "UDP: ответ получен",
    CauseCode.UDP_TIMEOUT: "UDP: таймаут (блок/фильтр UDP или нет echo)",
    CauseCode.UDP_ICMP_UNREACH: "UDP: ICMP unreachable",
    CauseCode.MTU_OK: "MTU: путь пропускает заявленный размер",
    CauseCode.MTU_BLACKHOLE: "MTU: PMTUD blackhole (DF + drop больших кадров)",
    CauseCode.MTU_LIMITED: "MTU: путь ограничен (нужна фрагментация/clamp MSS)",
    CauseCode.HTTP_OK: "HTTP: ответ 2xx/3xx (сервис отвечает)",
    CauseCode.HTTP_DENY: "HTTP: отказ сервиса/WAF (403/401/451 и т.п.)",
    CauseCode.HTTP_BLOCK_PAGE: "HTTP: похоже на страницу блокировки провайдера/фильтра",
    CauseCode.ERROR: "внутренняя ошибка пробы",
}


# Соответствие слоям сценариев CircumVolve (ccs26-circumvolve)
CIRCUMVOLVE_LAYER_MAP: dict[Layer, str] = {
    Layer.DNS: "DNS-Blocking",
    Layer.TCP: "TCP-IP-Header-Manipulation / HTTP-Blocking (порт)",
    Layer.TLS: "TLS-SNI-Blocking",
    Layer.UDP: "QUIC-SNI-Blocking / WireGuard-UDP / IKE",
    Layer.MTU: "фрагментация / path MTU (сопутствующий фактор)",
}


@dataclass
class ProbeResult:
    layer: Layer
    peer: str
    target: str
    protocol: str
    port: int | None
    availability: Availability
    cause: CauseCode
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def cause_ru(self) -> str:
        return CAUSE_RU.get(self.cause, self.cause.value)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["layer"] = self.layer.value
        d["availability"] = self.availability.value
        d["cause"] = self.cause.value
        d["cause_ru"] = self.cause_ru()
        return d


@dataclass
class MatrixCell:
    peer: str
    protocol: str
    port: int | None
    availability: Availability
    cause: CauseCode
    cause_ru: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "peer": self.peer,
            "protocol": self.protocol,
            "port": self.port,
            "availability": self.availability.value,
            "cause": self.cause.value,
            "cause_ru": self.cause_ru,
            "detail": self.detail,
        }


@dataclass
class Classification:
    """Итоговая классификация для peer или destination."""

    peer: str
    primary_causes: list[str]
    layers_affected: list[str]
    circumvolve_analogues: list[str]
    summary_ru: str
    suggested_profiles: list[dict[str, str]]
    confidence: str = "medium"
    kind: str = "peer"  # peer | destination
    verdict: str = ""
    who_blocks_ru: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DiagnosisReport:
    generated_at: str
    config_path: str
    results: list[ProbeResult]
    matrix: list[MatrixCell]
    classifications: list[Classification]
    mode: str = "peers"  # peers | destinations | mixed

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "config_path": self.config_path,
            "mode": self.mode,
            "results": [r.to_dict() for r in self.results],
            "matrix": [c.to_dict() for c in self.matrix],
            "classifications": [c.to_dict() for c in self.classifications],
        }
