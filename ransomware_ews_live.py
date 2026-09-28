import os
import time
import threading
import queue
from collections import deque
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as tb
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

APP_TITLE = "NEON//RANSOMWARE EWS"
DEFAULT_THRESHOLD = 150
DEFAULT_WINDOW = 10

WEIGHTS = {
    "CREATED": 2,
    "MODIFIED": 3,
    "DELETED": 15,
    "RENAMED": 25,
    "SUSPICIOUS_EXTENSION": 45,
    "RAPID_MODIFICATION": 20,
}

SUSPICIOUS_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".wncry", ".wcry", ".crypt",
    ".locky", ".ryk", ".zepto", ".cerber", ".crypted", ".crypto"
}


class LiveHandler(FileSystemEventHandler):
    def __init__(self, app):
        self.app = app

    def on_created(self, event):
        if not event.is_directory:
            self.app.push_event("CREATED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.app.push_event("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.app.push_event("DELETED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.app.push_event("RENAMED", event.dest_path, extra=event.src_path)


class EWSApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1450x900")
        self.root.minsize(1100, 720)

        self.bg = "#080A12"
        self.panel = "#101321"
        self.panel2 = "#15192A"
        self.cyan = "#00F0FF"
        self.purple = "#A855F7"
        self.pink = "#FF3CAC"
        self.text = "#F4F7FF"
        self.muted = "#8992A8"
        self.green = "#35F0B0"
        self.yellow = "#FFD166"
        self.red = "#FF3864"
        self.border = "#29304A"

        tb.Style("darkly")

        self.folder = None
        self.observer = None
        self.monitoring = False
        self.events = deque(maxlen=1000)
        self.event_queue = queue.Queue()
        self.score_history = deque(maxlen=240)
        self.time_history = deque(maxlen=240)
        self.start_time = time.time()

        self.total = 0
        self.renames = 0
        self.deletes = 0
        self.suspicious = 0

        self._build_ui()
        self.root.after(150, self._process_queue)
        self.root.after(400, self._refresh)
        self.root.after(600, self._plot)

    def _build_ui(self):
        outer = tk.Frame(self.root, bg=self.bg)
        outer.pack(fill="both", expand=True, padx=18, pady=14)

        header = tk.Frame(outer, bg=self.bg)
        header.pack(fill="x", pady=(0, 10))

        tk.Label(
            header, text="NEON//RANSOMWARE EWS",
            bg=self.bg, fg=self.text,
            font=("Segoe UI", 26, "bold")
        ).pack(side="left")

        tk.Label(
            header, text="  LIVE BEHAVIORAL DETECTOR",
            bg=self.bg, fg=self.cyan,
            font=("Consolas", 10, "bold")
        ).pack(side="left", pady=(10, 0))

        self.connection = tk.Label(
            header, text="● OFFLINE",
            bg=self.bg, fg=self.red,
            font=("Consolas", 11, "bold")
        )
        self.connection.pack(side="right", padx=10)

        body = tk.Frame(outer, bg=self.bg)
        body.pack(fill="both", expand=True)

        left = tk.Frame(
            body, bg=self.panel,
            highlightbackground=self.purple,
            highlightthickness=1, width=270
        )
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)

        tk.Label(
            left, text="LIVE MONITOR",
            bg=self.panel, fg=self.pink,
            font=("Consolas", 12, "bold")
        ).pack(anchor="w", padx=16, pady=(18, 10))

        self.folder_label = tk.Label(
            left, text="No folder selected",
            bg=self.panel, fg=self.muted,
            font=("Segoe UI", 9), wraplength=225,
            justify="left"
        )
        self.folder_label.pack(anchor="w", padx=16, pady=(0, 10))

        self.choose_btn = self._button(left, "⌖  SELECT FOLDER", self.purple, self.choose_folder)
        self.choose_btn.pack(fill="x", padx=16, pady=5)

        self.start_btn = self._button(left, "▶  START LIVE MONITOR", self.cyan, self.start_monitor)
        self.start_btn.pack(fill="x", padx=16, pady=5)

        self.stop_btn = self._button(left, "■  STOP MONITOR", self.red, self.stop_monitor)
        self.stop_btn.pack(fill="x", padx=16, pady=5)
        self.stop_btn.configure(state="disabled")

        self.sample_btn = self._button(left, "◇  CREATE TEST DATA", self.pink, self.create_test_data)
        self.sample_btn.pack(fill="x", padx=16, pady=5)

        self.clear_btn = self._button(left, "⌫  CLEAR LOG", "#5B6478", self.clear_log)
        self.clear_btn.pack(fill="x", padx=16, pady=5)

        tk.Frame(left, bg=self.border, height=1).pack(fill="x", padx=16, pady=18)

        tk.Label(
            left, text="DETECTION SETTINGS",
            bg=self.panel, fg=self.cyan,
            font=("Consolas", 10, "bold")
        ).pack(anchor="w", padx=16, pady=(0, 8))

        self.threshold = tk.IntVar(value=DEFAULT_THRESHOLD)
        self.window = tk.IntVar(value=DEFAULT_WINDOW)

        self._slider(left, "Alert Threshold", self.threshold, 50, 400)
        self._slider(left, "Decay Window (s)", self.window, 3, 30)

        tk.Frame(left, bg=self.border, height=1).pack(fill="x", padx=16, pady=18)

        tk.Label(
            left, text="LIVE STATISTICS",
            bg=self.panel, fg=self.purple,
            font=("Consolas", 10, "bold")
        ).pack(anchor="w", padx=16, pady=(0, 8))

        self.stat_score = self._stat(left, "RISK SCORE")
        self.stat_events = self._stat(left, "EVENTS")
        self.stat_rename = self._stat(left, "RENAMES")
        self.stat_delete = self._stat(left, "DELETES")
        self.stat_susp = self._stat(left, "SUSPICIOUS")

        right = tk.Frame(body, bg=self.bg)
        right.pack(side="left", fill="both", expand=True)

        status = tk.Frame(
            right, bg=self.panel,
            highlightbackground=self.cyan,
            highlightthickness=1
        )
        status.pack(fill="x", pady=(0, 10))

        row = tk.Frame(status, bg=self.panel)
        row.pack(fill="x", padx=18, pady=12)

        tk.Label(
            row, text="BEHAVIORAL RISK",
            bg=self.panel, fg=self.muted,
            font=("Consolas", 10, "bold")
        ).pack(side="left")

        self.score = tk.Label(
            row, text="0", bg=self.panel, fg=self.cyan,
            font=("Segoe UI", 30, "bold")
        )
        self.score.pack(side="left", padx=18)

        self.status = tk.Label(
            row, text="● SYSTEM READY",
            bg=self.panel, fg=self.green,
            font=("Consolas", 14, "bold")
        )
        self.status.pack(side="right")

        graph = tk.Frame(
            right, bg=self.panel,
            highlightbackground=self.border,
            highlightthickness=1
        )
        graph.pack(fill="both", expand=True, pady=(0, 10))

        tk.Label(
            graph, text="REAL-TIME RISK TELEMETRY",
            bg=self.panel, fg=self.pink,
            font=("Consolas", 10, "bold")
        ).pack(anchor="w", padx=12, pady=8)

        self.figure = Figure(figsize=(8, 3.6), dpi=100, facecolor=self.panel)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, master=graph)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=5)

        log_panel = tk.Frame(
            right, bg=self.panel,
            highlightbackground=self.purple,
            highlightthickness=1, height=230
        )
        log_panel.pack(fill="x")
        log_panel.pack_propagate(False)

        tk.Label(
            log_panel, text="LIVE FILESYSTEM EVENT STREAM",
            bg=self.panel, fg=self.cyan,
            font=("Consolas", 10, "bold")
        ).pack(anchor="w", padx=12, pady=7)

        frame = tk.Frame(log_panel, bg="#05070C")
        frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self.log = tk.Text(
            frame, bg="#05070C", fg="#B8F9FF",
            insertbackground=self.cyan, relief="flat",
            font=("Consolas", 9), state="disabled"
        )
        self.log.pack(side="left", fill="both", expand=True)

        scroll = tk.Scrollbar(frame, command=self.log.yview)
        scroll.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=scroll.set)

        self.log.tag_configure("normal", foreground="#B8F9FF")
        self.log.tag_configure("suspicious", foreground=self.yellow)
        self.log.tag_configure("critical", foreground=self.red)
        self.log.tag_configure("system", foreground=self.purple)

    def _button(self, parent, text, color, command):
        return tk.Button(
            parent, text=text, command=command,
            bg=color, fg="#05070C",
            activebackground=color, activeforeground="#05070C",
            relief="flat", bd=0, font=("Segoe UI", 9, "bold"),
            pady=9, cursor="hand2"
        )

    def _slider(self, parent, label, variable, low, high):
        tk.Label(
            parent, text=label, bg=self.panel, fg=self.muted,
            font=("Segoe UI", 9)
        ).pack(anchor="w", padx=16)
        tk.Scale(
            parent, from_=low, to=high, variable=variable,
            orient="horizontal", bg=self.panel, fg=self.text,
            troughcolor="#292E40", activebackground=self.cyan,
            highlightthickness=0, showvalue=True
        ).pack(fill="x", padx=12)

    def _stat(self, parent, label):
        row = tk.Frame(parent, bg=self.panel)
        row.pack(fill="x", padx=16, pady=2)
        tk.Label(row, text=label, bg=self.panel, fg=self.muted,
                 font=("Consolas", 8)).pack(side="left")
        value = tk.Label(row, text="0", bg=self.panel, fg=self.cyan,
                         font=("Consolas", 10, "bold"))
        value.pack(side="right")
        return value

    def choose_folder(self):
        folder = filedialog.askdirectory(title="Select folder to monitor")
        if folder:
            self.folder = Path(folder)
            self.folder_label.configure(
                text=str(self.folder),
                fg=self.cyan
            )
            self._system_log(f"[SYSTEM] Selected monitor path: {self.folder}")

    def start_monitor(self):
        if not self.folder:
            messagebox.showwarning("Select Folder", "Choose a folder first.")
            return

        if self.monitoring:
            return

        try:
            self.observer = Observer()
            self.observer.schedule(LiveHandler(self), str(self.folder), recursive=True)
            self.observer.start()
            self.monitoring = True

            self.connection.configure(text="● LIVE", fg=self.green)
            self.status.configure(text="● MONITORING LIVE FILESYSTEM", fg=self.green)
            self.start_btn.configure(state="disabled")
            self.stop_btn.configure(state="normal")
            self._system_log("[SYSTEM] LIVE FILE MONITOR STARTED")
        except Exception as e:
            messagebox.showerror("Monitor Error", str(e))

    def stop_monitor(self):
        self.monitoring = False
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)
            self.observer = None

        self.connection.configure(text="● OFFLINE", fg=self.red)
        self.status.configure(text="● MONITOR STOPPED", fg=self.muted)
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self._system_log("[SYSTEM] LIVE FILE MONITOR STOPPED")

    def push_event(self, kind, path, extra=None):
        self.event_queue.put((kind, path, extra, time.time()))

    def _process_queue(self):
        try:
            while True:
                kind, path, extra, timestamp = self.event_queue.get_nowait()
                self._handle_event(kind, path, extra, timestamp)
        except queue.Empty:
            pass
        self.root.after(100, self._process_queue)

    def _handle_event(self, kind, path, extra, timestamp):
        ext = Path(path).suffix.lower()

        score = WEIGHTS.get(kind, 0)
        label = kind

        if ext in SUSPICIOUS_EXTENSIONS:
            score += WEIGHTS["SUSPICIOUS_EXTENSION"]
            label = f"{kind} + SUSPICIOUS_EXTENSION"

        if kind == "MODIFIED":
            recent = [
                e for e in self.events
                if timestamp - e["time"] <= 2 and e["kind"] == "MODIFIED"
            ]
            if len(recent) >= 8:
                score += WEIGHTS["RAPID_MODIFICATION"]
                label = f"{label} + RAPID_MODIFICATION"

        if kind == "RENAMED":
            self.renames += 1
        if kind == "DELETED":
            self.deletes += 1
        if score >= 25:
            self.suspicious += 1

        self.events.append({
            "time": timestamp,
            "kind": kind,
            "path": path,
            "score": score,
        })
        self.total += 1

        severity = "critical" if score >= 50 else "suspicious" if score >= 20 else "normal"

        t = datetime.now().strftime("%H:%M:%S")
        extra_text = f" | FROM: {extra}" if extra else ""
        self._log(
            f"[{t}] {label:<34} {Path(path).name}{extra_text}  +{score}",
            severity
        )

    def _current_score(self):
        now = time.time()
        window = max(1, int(self.window.get()))
        self.events = deque(
            [e for e in self.events if now - e["time"] <= window],
            maxlen=1000
        )
        return sum(e["score"] for e in self.events)

    def _refresh(self):
        score = self._current_score()
        threshold = int(self.threshold.get())

        self.score.configure(text=str(score), fg=self._score_color(score, threshold))
        self.stat_score.configure(text=str(score))
        self.stat_events.configure(text=str(self.total))
        self.stat_rename.configure(text=str(self.renames))
        self.stat_delete.configure(text=str(self.deletes))
        self.stat_susp.configure(text=str(self.suspicious))

        if score >= threshold:
            self.status.configure(
                text="⚠ RANSOMWARE-LIKE ACTIVITY DETECTED",
                fg=self.red
            )
        elif score >= threshold * 0.55:
            self.status.configure(text="⚠ HIGH RISK BEHAVIOR", fg=self.yellow)
        elif score >= threshold * 0.25:
            self.status.configure(text="◈ ELEVATED ACTIVITY", fg=self.purple)
        else:
            self.status.configure(text="● NO ACTIVE THREAT", fg=self.green)

        self.time_history.append(time.time() - self.start_time)
        self.score_history.append(score)

        self.root.after(300, self._refresh)

    def _score_color(self, score, threshold):
        if score >= threshold:
            return self.red
        if score >= threshold * 0.55:
            return self.yellow
        if score >= threshold * 0.25:
            return self.purple
        return self.cyan

    def _plot(self):
        self.ax.clear()
        self.ax.set_facecolor("#060810")
        self.ax.tick_params(colors="#8992A8", labelsize=8)
        for spine in self.ax.spines.values():
            spine.set_color("#29304A")
        self.ax.grid(True, color="#20263A", alpha=0.7)

        self.ax.plot(
            list(self.time_history), list(self.score_history),
            color=self.cyan, linewidth=2.0
        )
        threshold = int(self.threshold.get())
        self.ax.axhline(threshold, color=self.pink, linestyle="--", linewidth=1.1)

        self.ax.set_xlabel("Time (seconds)", color=self.muted, fontsize=8)
        self.ax.set_ylabel("Risk Score", color=self.muted, fontsize=8)
        self.figure.tight_layout(pad=1.4)
        self.canvas.draw_idle()
        self.root.after(600, self._plot)

    def create_test_data(self):
        if not self.folder:
            folder = filedialog.askdirectory(title="Choose folder for safe EWS test data")
            if not folder:
                return
            self.folder = Path(folder)
            self.folder_label.configure(text=str(self.folder), fg=self.cyan)

        sample = self.folder / "EWS_SAMPLE_DATA"
        sample.mkdir(exist_ok=True)

        files = [
            "normal_document.txt",
            "project_report.txt",
            "photo.jpg",
            "database_backup.txt",
            "employee_records.csv",
            "financial_report.xlsx"
        ]

        for name in files:
            (sample / name).write_text(
                "SAFE EWS TEST FILE\n"
                "This file contains no real credentials or sensitive data.\n",
                encoding="utf-8"
            )

        self._system_log(f"[SYSTEM] Created safe sample dataset: {sample}")
        messagebox.showinfo(
            "Sample Data Created",
            "Safe test files were created.\n\n"
            "Start the LIVE monitor, then edit/rename/delete copies of these "
            "files to generate real filesystem events."
        )

    def clear_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _log(self, text, tag):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _system_log(self, text):
        self._log(text, "system")

    def on_close(self):
        self.stop_monitor()
        self.root.destroy()


if __name__ == "__main__":
    root = tb.Window(themename="darkly")
    app = EWSApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
