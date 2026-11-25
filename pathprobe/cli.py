from __future__ import annotations

import sys
from pathlib import Path

import click

from pathprobe import __version__
from pathprobe.config import load_config
from pathprobe.diagnose.runner import run_diagnosis
from pathprobe.report.json_report import write_json
from pathprobe.report.markdown_ru import render_markdown_ru, write_markdown_ru


def _default_reports_dir() -> Path:
    return Path("reports")


@click.group()
@click.version_option(__version__, prog_name="pathprobe")
def main() -> None:
    """Pathprobe — диагностика блокировок на своём пути (home Ubuntu ↔ work MikroTik)."""


@main.command("diagnose")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default="config.yaml",
    show_default=True,
    help="Путь к YAML-конфигу peers",
)
@click.option(
    "--out-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Каталог отчётов (по умолчанию reports/)",
)
@click.option("--json-only", is_flag=True, help="Только JSON в stdout")
@click.option("--md-only", is_flag=True, help="Только Markdown в stdout")
def diagnose_cmd(
    config_path: Path,
    out_dir: Path | None,
    json_only: bool,
    md_only: bool,
) -> None:
    """Полная диагностика: пробы → матрица → классификация → отчёты."""
    cfg = load_config(config_path)
    report = run_diagnosis(cfg, config_path=str(config_path))

    if json_only:
        import json

        click.echo(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return
    if md_only:
        click.echo(render_markdown_ru(report))
        return

    out = out_dir or _default_reports_dir()
    stamp = report.generated_at.replace(":", "").replace("-", "")
    json_path = write_json(report, out / f"diagnose-{stamp}.json")
    md_path = write_markdown_ru(report, out / f"diagnose-{stamp}.md")

    click.echo(render_markdown_ru(report))
    click.echo(f"\nJSON: {json_path}")
    click.echo(f"Markdown: {md_path}")


@main.command("matrix")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default="config.yaml",
    show_default=True,
)
def matrix_cmd(config_path: Path) -> None:
    """Только матрица протокол/порт → статус."""
    cfg = load_config(config_path)
    report = run_diagnosis(cfg, config_path=str(config_path))
    click.echo("| Peer | Протокол | Порт | Статус | Причина |")
    click.echo("|------|----------|------|--------|---------|")
    for c in report.matrix:
        port = c.port if c.port is not None else "—"
        click.echo(
            f"| {c.peer} | {c.protocol} | {port} | {c.availability.value} | {c.cause_ru} |"
        )


@main.command("classify")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default="config.yaml",
    show_default=True,
)
def classify_cmd(config_path: Path) -> None:
    """Классификация причин + рекомендуемые профили (без применения)."""
    cfg = load_config(config_path)
    report = run_diagnosis(cfg, config_path=str(config_path))
    for cl in report.classifications:
        click.echo(f"=== {cl.peer} ===")
        click.echo(cl.summary_ru)
        click.echo(f"Слои: {', '.join(cl.layers_affected) or 'нет'}")
        click.echo(f"CircumVolve: {', '.join(cl.circumvolve_analogues) or '—'}")
        for p in cl.suggested_profiles:
            click.echo(f"  → {p['profile']}: {p['reason_ru']}")
        click.echo("")


if __name__ == "__main__":
    sys.exit(main())
