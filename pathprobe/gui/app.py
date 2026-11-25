from __future__ import annotations

import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from pathprobe import __version__
from pathprobe.config import load_config
from pathprobe.diagnose.runner import STAGES, run_diagnosis
from pathprobe.models import Availability, DiagnosisReport
from pathprobe.report.json_report import write_json
from pathprobe.report.markdown_ru import write_markdown_ru

try:
    import customtkinter as ctk
except ImportError:  # pragma: no cover
    ctk = None  # type: ignore[assignment]


STAGE_LABELS = {sid: title for sid, title in STAGES}

AVAIL_COLORS = {
    Availability.AVAILABLE.value: "#1a7f37",
    Availability.UNAVAILABLE.value: "#cf222e",
    Availability.DEGRADED.value: "#9a6700",
    Availability.UNKNOWN.value: "#656d76",
}


class PathprobeApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"Pathprobe {__version__} — диагностика пути")
        self.geometry("1100x720")
        self.minsize(900, 600)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self._report: DiagnosisReport | None = None
        self._busy = False
        self._stage_vars: dict[str, ctk.StringVar] = {}
        self._stage_labels: dict[str, ctk.CTkLabel] = {}

        self._build()

    def _build(self) -> None:
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(top, text="Конфиг:").pack(side="left", padx=(8, 4))
        self.config_var = ctk.StringVar(value=str(Path("config.yaml").resolve()))
        self.config_entry = ctk.CTkEntry(top, textvariable=self.config_var, width=520)
        self.config_entry.pack(side="left", padx=4, fill="x", expand=True)
        ctk.CTkButton(top, text="Обзор…", width=90, command=self._browse).pack(side="left", padx=4)
        self.run_btn = ctk.CTkButton(top, text="Запустить диагностику", width=180, command=self._start)
        self.run_btn.pack(side="left", padx=4)
        self.save_btn = ctk.CTkButton(
            top, text="Сохранить отчёт", width=140, command=self._save, state="disabled"
        )
        self.save_btn.pack(side="left", padx=(4, 8))

        body = ctk.CTkFrame(self)
        body.pack(fill="both", expand=True, padx=12, pady=6)

        left = ctk.CTkFrame(body, width=260)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)

        ctk.CTkLabel(left, text="Этапы проверки", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=12, pady=(12, 8)
        )
        self.peer_status = ctk.CTkLabel(left, text="Peer: —", anchor="w")
        self.peer_status.pack(fill="x", padx=12, pady=(0, 8))

        for sid, title in STAGES:
            row = ctk.CTkFrame(left, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=4)
            var = ctk.StringVar(value="ожидание")
            self._stage_vars[sid] = var
            badge = ctk.CTkLabel(row, text="●", width=20, text_color="#888888")
            badge.pack(side="left")
            self._stage_labels[sid] = badge
            ctk.CTkLabel(row, text=title, width=100, anchor="w").pack(side="left")
            ctk.CTkLabel(row, textvariable=var, anchor="w").pack(side="left", fill="x", expand=True)

        self.log_box = ctk.CTkTextbox(left, height=180)
        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_box.insert("end", "Готов к запуску.\n")

        right = ctk.CTkFrame(body)
        right.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(right, text="Матрица доступности", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=12, pady=(12, 4)
        )

        table_frame = ctk.CTkFrame(right)
        table_frame.pack(fill="both", expand=True, padx=12, pady=4)

        cols = ("peer", "proto", "port", "status", "cause")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=12)
        headings = {
            "peer": "Peer",
            "proto": "Протокол",
            "port": "Порт",
            "status": "Статус",
            "cause": "Причина",
        }
        widths = {"peer": 120, "proto": 140, "port": 60, "status": 110, "cause": 360}
        for c in cols:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor="w")
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        ctk.CTkLabel(
            right, text="Классификация и рекомендации", font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=12, pady=(10, 4))
        self.reco_box = ctk.CTkTextbox(right, height=200)
        self.reco_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.status_bar = ctk.CTkLabel(self, text=f"Pathprobe {__version__} · GUI Windows", anchor="w")
        self.status_bar.pack(fill="x", padx=12, pady=(0, 8))

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Выберите config.yaml",
            filetypes=[("YAML", "*.yaml *.yml"), ("Все файлы", "*.*")],
        )
        if path:
            self.config_var.set(path)

    def _log(self, msg: str) -> None:
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    def _set_stage(self, stage: str, text: str, color: str) -> None:
        if stage in self._stage_vars:
            self._stage_vars[stage].set(text)
        if stage in self._stage_labels:
            self._stage_labels[stage].configure(text_color=color)

    def _reset_stages(self) -> None:
        for sid in self._stage_vars:
            self._set_stage(sid, "ожидание", "#888888")

    def _start(self) -> None:
        if self._busy:
            return
        cfg_path = Path(self.config_var.get().strip())
        if not cfg_path.is_file():
            messagebox.showerror("Конфиг", f"Файл не найден:\n{cfg_path}")
            return
        try:
            cfg = load_config(cfg_path)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Конфиг", str(exc))
            return

        self._busy = True
        self.run_btn.configure(state="disabled")
        self.save_btn.configure(state="disabled")
        self._report = None
        self._reset_stages()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.reco_box.delete("1.0", "end")
        self._log(f"Старт: {cfg_path}")
        self.status_bar.configure(text="Диагностика выполняется…")

        def worker() -> None:
            def on_progress(peer: str, stage: str, event: str, detail: str) -> None:
                self.after(0, lambda: self._on_progress(peer, stage, event, detail))

            try:
                report = run_diagnosis(cfg, config_path=str(cfg_path), on_progress=on_progress)
                self.after(0, lambda: self._on_done(report))
            except Exception as exc:  # noqa: BLE001
                self.after(0, lambda: self._on_fail(str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_progress(self, peer: str, stage: str, event: str, detail: str) -> None:
        if stage == "peer":
            self.peer_status.configure(text=f"Peer: {peer} ({event})")
            self._log(f"[{peer}] {event} {detail}".strip())
            return
        if stage == "classify":
            self._log(f"Классификация: {detail}")
            return
        if event == "start":
            self._set_stage(stage, "идёт…", "#0969da")
            self._log(f"[{peer}] этап {STAGE_LABELS.get(stage, stage)} — старт")
        elif event == "done":
            color = "#1a7f37"
            self._set_stage(stage, detail or "готово", color)
            self._log(f"[{peer}] этап {STAGE_LABELS.get(stage, stage)} — {detail or 'готово'}")
        elif event == "error":
            self._set_stage(stage, "ошибка", "#cf222e")
            self._log(f"[{peer}] этап {STAGE_LABELS.get(stage, stage)} — ошибка: {detail}")

    def _on_done(self, report: DiagnosisReport) -> None:
        self._report = report
        self._busy = False
        self.run_btn.configure(state="normal")
        self.save_btn.configure(state="normal")
        self.status_bar.configure(text=f"Готово · {report.generated_at}")

        for cell in report.matrix:
            port = "" if cell.port is None else str(cell.port)
            iid = self.tree.insert(
                "",
                "end",
                values=(
                    cell.peer,
                    cell.protocol,
                    port,
                    cell.availability.value,
                    cell.cause_ru,
                ),
            )
            color = AVAIL_COLORS.get(cell.availability.value, "#656d76")
            self.tree.tag_configure(cell.availability.value, foreground=color)
            self.tree.item(iid, tags=(cell.availability.value,))

        lines: list[str] = []
        for cl in report.classifications:
            lines.append(f"═══ {cl.peer} ═══")
            lines.append(cl.summary_ru)
            lines.append(f"Уверенность: {cl.confidence}")
            layers = ", ".join(cl.layers_affected) or "нет"
            lines.append(f"Слои: {layers}")
            analogues = ", ".join(cl.circumvolve_analogues) or "—"
            lines.append(f"Аналоги CircumVolve: {analogues}")
            lines.append("")
            lines.append("Рекомендации профилей (фаза 2 — без применения):")
            for p in cl.suggested_profiles:
                lines.append(f"  • {p['profile']}")
                lines.append(f"    {p['reason_ru']}")
            lines.append("")
        self.reco_box.insert("1.0", "\n".join(lines))
        self._log("Диагностика завершена.")

    def _on_fail(self, err: str) -> None:
        self._busy = False
        self.run_btn.configure(state="normal")
        self.status_bar.configure(text="Ошибка")
        self._log(f"ОШИБКА: {err}")
        messagebox.showerror("Диагностика", err)

    def _save(self) -> None:
        if not self._report:
            return
        out_dir = filedialog.askdirectory(title="Каталог для отчётов")
        if not out_dir:
            return
        stamp = self._report.generated_at.replace(":", "").replace("-", "")
        base = Path(out_dir)
        jp = write_json(self._report, base / f"diagnose-{stamp}.json")
        mp = write_markdown_ru(self._report, base / f"diagnose-{stamp}.md")
        messagebox.showinfo("Отчёт", f"Сохранено:\n{jp}\n{mp}")
        self._log(f"Отчёты: {jp.name}, {mp.name}")


def main() -> int:
    if ctk is None:
        print(
            "Для GUI установите: pip install 'pathprobe[gui]' или pip install customtkinter",
            file=sys.stderr,
        )
        return 1

    app = PathprobeApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
