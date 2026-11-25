from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Конфиг не найден: {p}")
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError("Корень конфига должен быть mapping")
    peers = data.get("peers") or {}
    destinations = data.get("destinations") or []
    if not peers and not destinations:
        raise ValueError("В конфиге нет peers и destinations — укажите хотя бы одно")
    data.setdefault("timeouts", {})
    for key, default in (
        ("dns_sec", 3.0),
        ("tcp_sec", 5.0),
        ("tls_sec", 8.0),
        ("udp_sec", 3.0),
        ("mtu_sec", 3.0),
        ("http_sec", 10.0),
    ):
        data["timeouts"].setdefault(key, default)
    data.setdefault("control_dns", {})
    data["control_dns"].setdefault("resolvers", ["1.1.1.1", "8.8.8.8"])
    data.setdefault("local_dns", {})
    data["local_dns"].setdefault("resolvers", [])
    return data


def peer_items(cfg: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return list((cfg.get("peers") or {}).items())
