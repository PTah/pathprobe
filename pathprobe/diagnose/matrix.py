from __future__ import annotations

from pathprobe.models import Availability, MatrixCell, ProbeResult


def build_matrix(results: list[ProbeResult]) -> list[MatrixCell]:
    cells: list[MatrixCell] = []
    seen: set[tuple[str, str, int | None]] = set()
    for r in results:
        key = (r.peer, r.protocol, r.port)
        if key in seen and r.layer.value == "dns":
            # DNS: несколько запросов — каждая строка отдельно по target
            pass
        # Для DNS различаем по target
        if r.protocol == "dns":
            cells.append(
                MatrixCell(
                    peer=r.peer,
                    protocol=f"dns:{r.target}",
                    port=53,
                    availability=r.availability,
                    cause=r.cause,
                    cause_ru=r.cause_ru(),
                    detail=r.detail,
                )
            )
            continue
        if key in seen:
            continue
        seen.add(key)
        cells.append(
            MatrixCell(
                peer=r.peer,
                protocol=r.protocol,
                port=r.port,
                availability=r.availability,
                cause=r.cause,
                cause_ru=r.cause_ru(),
                detail=r.detail,
            )
        )
    return cells


def matrix_summary_counts(cells: list[MatrixCell]) -> dict[str, int]:
    counts = {a.value: 0 for a in Availability}
    for c in cells:
        counts[c.availability.value] = counts.get(c.availability.value, 0) + 1
    return counts
