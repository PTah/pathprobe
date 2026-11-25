# Pathprobe

Диагностика и классификация блокировок на пути между **домашним Ubuntu-роутером** и **рабочим MikroTik (RouterOS 6.49.19)**.

Два режима:

| Режим | Где | Как |
|-------|-----|-----|
| **CLI** | Linux (и Windows) | `pathprobe diagnose` |
| **GUI** | Windows | `pathprobe-gui` / `scripts\run-gui.bat` |

Фаза 1: только пробы и отчёт. Генерация/применение туннелей — позже, см. [`docs/architecture-phase2.md`](docs/architecture-phase2.md).

Таксономия слоёв согласована с CircumVolve / ccs26-circumvolve (DNS, TCP, TLS-SNI, UDP, MTU) — без OpenEvolve.

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

Для GUI на Windows дополнительно:

```bash
pip install -e ".[gui]"
```

## Быстрый старт (CLI, Linux)

1. Скопируйте конфиг и укажите свои адреса:

```bash
cp config.example.yaml config.yaml
```

2. На дальнем конце поднимите echo (опционально):

```bash
python echo/udp_echo.py --port 51820
python echo/tcp_echo.py --port 8443
```

3. Диагностика:

```bash
pathprobe diagnose -c config.yaml
pathprobe matrix -c config.yaml
pathprobe classify -c config.yaml
```

Отчёты: `reports/diagnose-*.md` и `.json` (русский язык).

## GUI (Windows)

```bat
pip install -e ".[gui]"
pathprobe-gui
:: или
scripts\run-gui.bat
:: или
pathprobe gui
```

### Готовый exe

```powershell
.\scripts\build-windows-exe.ps1
```

Артефакты: `dist\gui\pathprobe-gui.exe`, `dist\pathprobe-<ver>-windows-amd64.zip` (+ `.sha256` хеш exe).  
Рядом с exe должен лежать `config.yaml` (в архив кладётся пример).

В окне:

1. Укажите `config.yaml` (кнопка «Обзор…»).
2. «Запустить диагностику» — этапы DNS → TCP → TLS → UDP → MTU с прогрессом.
3. Матрица доступности (цвет статуса) + блок классификации и рекомендаций профилей.
4. «Сохранить отчёт» — JSON + Markdown.

Ядро проб общее с CLI; GUI только отображает ход и результат.

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

`0.2.1` — фаза 1 + Windows GUI + сборка `pathprobe-gui.exe`.
