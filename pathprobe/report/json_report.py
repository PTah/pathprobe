from __future__ import annotations

import json
from pathlib import Path

from pathprobe.models import DiagnosisReport


def write_json(report: DiagnosisReport, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
    return p
