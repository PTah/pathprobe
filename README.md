# Pathprobe

Диагностика и классификация блокировок на пути между **домашним Ubuntu-роутером** и **рабочим MikroTik (RouterOS 6.49.19)**.

Фаза 1: только пробы и отчёт. Генерация/применение туннелей (IKEv2, GRE+IPsec, WireGuard, OpenVPN TCP/443) — позже, см. [`docs/architecture-phase2.md`](docs/architecture-phase2.md).

Таксономия слоёв согласована с [CircumVolve / ccs26-circumvolve](../ccs26-circumvolve) (DNS, TCP, TLS-SNI, UDP, MTU) — без OpenEvolve.

Ограничение: цели — **только своя** инфраструктура (`config.yaml` → `peers`).

---

## Установка

```bash
cd pathprobe
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux:
# source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Быстрый старт

1. Скопируйте конфиг и укажите свои адреса:

```bash
copy config.example.yaml config.yaml
# Linux: cp config.example.yaml config.yaml
```

2. На дальнем конце поднимите echo (опционально, для UDP/точного отличия фильтра):

```bash
python echo/udp_echo.py --port 51820
python echo/tcp_echo.py --port 8443
```

3. Запустите диагностику **с домашнего Ubuntu** (или с машины на том же пути):

```bash
pathprobe diagnose -c config.yaml
# или: python -m pathprobe diagnose -c config.yaml
```

Отчёты: `reports/diagnose-*.md` и `.json` (русский язык).

### Отдельные команды

```bash
pathprobe matrix -c config.yaml
pathprobe classify -c config.yaml
```

## Что измеряется

| Слой | Классы причин |
|------|----------------|
| DNS | NXDOMAIN, SERVFAIL, подмена A, timeout, REFUSED |
| TCP | open, RST, timeout, refused |
| TLS | handshake OK, drop ClientHello/SNI, RST after CH, ошибка handshake |
| UDP | echo OK, timeout, ICMP unreachable |
| MTU | OK, limited, PMTUD blackhole |

На выходе: матрица «протокол/порт → доступен/нет» + классификация + **рекомендация профиля** (без apply).

## Документация

- [`docs/circumvolve-mapping.md`](docs/circumvolve-mapping.md) — соответствие CircumVolve
- [`docs/mikrotik-ros649-probe-notes.md`](docs/mikrotik-ros649-probe-notes.md) — ручной NAT на ROS 6.49 (не авто)
- [`echo/README.md`](echo/README.md) — echo-сервисы
- [`profiles/`](profiles/) — реестр профилей фазы 2

## Тесты

```bash
pip install -e ".[dev]"
pytest -q
```

## Версия

`0.1.0` — фаза 1 (диагностика).
