# Pathprobe

Диагностика **почему не открывается сервис** (Canva и др.): DNS подмена/NXDOMAIN, TCP RST/timeout, DPI по SNI, HTTP-заглушка vs отказ самого сервиса.

Два способа запуска:

| Режим | Где | Как |
|-------|-----|-----|
| **CLI** | Linux (и Windows) | `pathprobe diagnose` |
| **GUI** | Windows | `pathprobe-gui` / `scripts\run-gui.bat` |

В конфиге главный блок — `destinations` (+ `local_dns` / `control_dns`). Опционально `peers` — свой роутер/VPS.

Таксономия слоёв согласована с CircumVolve (DNS, TCP, TLS-SNI, HTTP).

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

`0.3.0` — режим `destinations` (кто блокирует сайт: DNS/путь/DPI/сервис).
