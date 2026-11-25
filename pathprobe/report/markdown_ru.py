from __future__ import annotations

from pathlib import Path

from pathprobe.diagnose.matrix import matrix_summary_counts
from pathprobe.models import DiagnosisReport


def render_markdown_ru(report: DiagnosisReport) -> str:
    lines: list[str] = []
    lines.append("# Отчёт pathprobe: диагностика пути")
    lines.append("")
    lines.append(f"- Сформирован: `{report.generated_at}` (UTC)")
    lines.append(f"- Конфиг: `{report.config_path or '—'}`")
    lines.append("")

    counts = matrix_summary_counts(report.matrix)
    lines.append("## Сводка матрицы")
    lines.append("")
    lines.append("| Статус | Количество |")
    lines.append("|--------|------------|")
    for k, v in counts.items():
        lines.append(f"| {k} | {v} |")
    lines.append("")

    lines.append("## Матрица протокол/порт")
    lines.append("")
    lines.append("| Peer | Протокол | Порт | Статус | Причина |")
    lines.append("|------|----------|------|--------|---------|")
    for c in report.matrix:
        port = c.port if c.port is not None else "—"
        detail = (c.detail or "").replace("|", "\\|")
        reason = c.cause_ru
        if detail:
            reason = f"{reason} ({detail})"
        lines.append(
            f"| {c.peer} | {c.protocol} | {port} | {c.availability.value} | {reason} |"
        )
    lines.append("")

    lines.append("## Классификация")
    lines.append("")
    for cl in report.classifications:
        lines.append(f"### Peer: `{cl.peer}`")
        lines.append("")
        lines.append(cl.summary_ru)
        lines.append("")
        lines.append(f"- Уверенность: **{cl.confidence}**")
        lines.append(f"- Затронутые слои: {', '.join(cl.layers_affected) or 'нет'}")
        lines.append(f"- Коды причин: {', '.join(cl.primary_causes) or 'нет'}")
        lines.append(
            f"- Аналоги CircumVolve: {', '.join(cl.circumvolve_analogues) or '—'}"
        )
        lines.append("")
        lines.append("Рекомендуемые профили (фаза 2, без применения):")
        lines.append("")
        for p in cl.suggested_profiles:
            lines.append(f"- **{p['profile']}** — {p['reason_ru']}")
        lines.append("")

    lines.append("## Детали проб")
    lines.append("")
    lines.append("| Слой | Peer | Цель | Причина |")
    lines.append("|------|------|------|---------|")
    for r in report.results:
        lines.append(
            f"| {r.layer.value} | {r.peer} | {r.target} | {r.cause_ru()} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "_Фаза 1 pathprobe: только диагностика. Генерация и применение туннелей — в фазе 2._"
    )
    lines.append("")
    return "\n".join(lines)


def write_markdown_ru(report: DiagnosisReport, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_markdown_ru(report), encoding="utf-8")
    return p
