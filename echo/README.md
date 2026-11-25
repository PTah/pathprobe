# Echo-сервисы для pathprobe

Лёгкие слушатели **только на своей инфраструктуре** (домашний Ubuntu, хост за рабочим MikroTik, свой VPS). Нужны, чтобы UDP/TCP/TLS-пробы отличали «порт закрыт у вас» от «фильтр на пути».

| Скрипт | Назначение |
|--------|------------|
| `tcp_echo.py` | TCP connect + echo |
| `udp_echo.py` | UDP echo с маркером `PATHPROBE1` |
| `tls_echo.py` | TLS handshake (+ echo), для проверки SNI |

## Пример на дальнем конце

```bash
python3 echo/udp_echo.py --port 51820
python3 echo/tcp_echo.py --port 8443
```

На MikroTik ROS 6.49.19 — проброс WAN→внутренний хост (см. [`docs/mikrotik-ros649-probe-notes.md`](../docs/mikrotik-ros649-probe-notes.md)). **Pathprobe сам правила на роутер не применяет** (фаза 1).
