"""IPA Lab Desktop — macOS Qt interface inspired by Impactor's restrained aesthetic.

This is an independent application, not Impactor. Long-running work stays in
QThread; every recoverable error offers an in-place retry without losing state.
"""
from __future__ import annotations

import json
import platform
import re
import shlex
import shutil
import subprocess
import tempfile
import traceback
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import Qt, QThread, QTimer, Signal, QSize
from PySide6.QtGui import QCloseEvent, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QSizePolicy,
    QSpinBox, QVBoxLayout, QWidget,
)

from . import core

STEPS: list[tuple[str, str]] = [
    ("source", "Choose source"),
    ("auth", "App Store account"),
    ("search", "Find application"),
    ("results", "Choose bundle"),
    ("download", "Download IPA"),
    ("inspect", "Inspect binaries"),
    ("metadata", "iOS compatibility"),
    ("device", "Select iPhone"),
    ("port", "USB connection"),
    ("ssh", "Root SSH"),
    ("fairplay", "FairPlay setup"),
    ("credential", "Credential retrieval"),
    ("decrypt", "Decrypt IPA"),
    ("export", "Export IPA"),
    ("done", "Complete"),
]

class Job(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, function: Callable[[], Any], parent: QWidget | None = None):
        super().__init__(parent)
        self.function = function

    def run(self) -> None:
        try:
            self.succeeded.emit(self.function())
        except Exception as exc:
            self.failed.emit(str(exc) or type(exc).__name__)


def _vbox(widget: QWidget, margins: tuple[int, int, int, int] = (0, 0, 0, 0), gap: int = 12) -> QVBoxLayout:
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(*margins)
    layout.setSpacing(gap)
    return layout


def _hbox(widget: QWidget, margins: tuple[int, int, int, int] = (0, 0, 0, 0), gap: int = 10) -> QHBoxLayout:
    layout = QHBoxLayout(widget)
    layout.setContentsMargins(*margins)
    layout.setSpacing(gap)
    return layout


def _label(text: str, role: str = "bodyText", wrap: bool = True) -> QLabel:
    label = QLabel(text)
    label.setObjectName(role)
    label.setWordWrap(wrap)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


class LabWindow(QMainWindow):
    incoming_log = Signal(str)

    def __init__(self, *, local_ipa: Path | None = None, fairplay_repo: Path | None = None,
                 port: int = 2222, demo: bool = False):
        super().__init__()
        self.setWindowTitle("IPA Lab — iOS Application Research")
        self.resize(1200, 785)
        self.setMinimumSize(780, 585)
        self.setAcceptDrops(True)
        self.demo = demo
        self.phase = "source"
        self.done_steps: set[str] = set()
        self.fields: dict[str, str] = {"term": "", "limit": "10", "port": str(port)}
        self.local_ipa = local_ipa
        self.repo_override = fairplay_repo
        self.apps: list[dict] = []
        self.selected: dict = {}
        self.devices: list[str] = []
        self.udid = ""
        self.port = port
        self.ipa: Path | None = None
        self.inspection: core.Inspection | None = None
        self.patch = False
        self.repo: Path | None = None
        self.python: Path | None = None
        self.credential: Path | None = None
        self.staged: Path | None = None
        self.final: Path | None = None
        self.tunnel: core.USBTunnel | None = None
        self.workspace_obj = tempfile.TemporaryDirectory(prefix="ipa-lab-private-")
        self.workspace = Path(self.workspace_obj.name)
        self.workspace.chmod(0o700)
        self.busy = False
        self.busy_description = ""
        self.job: Job | None = None
        self.current_retry: Callable[[], None] | None = None
        self.error = ""
        self.error_actions: list[tuple[str, Callable[[], None]]] = []
        self.error_poll: Callable[[], None] | None = None
        self.auto_wait_enabled = False
        self.activity: list[str] = []
        self.runner = core.CommandRunner(self.log)
        self._closed = False
        self.incoming_log.connect(self._append_log)
        self._build_ui()
        self._shortcuts()
        self.refresh_sidebar()
        self.render()
        self.status("Preparing environment…")
        QTimer.singleShot(120, self.preflight)
        self.spin = 0
        self.pulse = QTimer(self)
        self.pulse.setInterval(180)
        self.pulse.timeout.connect(self._heartbeat)
        self.pulse.start()
        self.auto_wait_timer = QTimer(self)
        self.auto_wait_timer.setInterval(3000)
        self.auto_wait_timer.timeout.connect(self._retry_poll)

    def _build_ui(self) -> None:
        css = (Path(__file__).with_name("theme.qss")).read_text(encoding="utf-8")
        self.setStyleSheet(css)
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        all_layout = _vbox(root, gap=0)

        top = QWidget()
        top.setObjectName("topbar")
        tl = _hbox(top, (22, 13, 22, 13), 12)
        brand = _label("◈  IPA LAB", "brand", False)
        tl.addWidget(brand)
        tl.addWidget(_label("DESKTOP  /  3.0", "brandSubtitle", False))
        tl.addStretch(1)
        self.device_badge = _label("No device selected", "pill", False)
        self.device_badge.setMinimumWidth(168)
        tl.addWidget(self.device_badge)
        self.activity_toggle = self.make_button("Activity", self.toggle_activity, flat=True)
        tl.addWidget(self.activity_toggle)
        all_layout.addWidget(top)

        center_row = QWidget()
        center_layout = _hbox(center_row, gap=0)
        all_layout.addWidget(center_row, 1)

        self.sidebar = QWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(230)
        side = _vbox(self.sidebar, (15, 20, 12, 15), 4)
        side.addWidget(_label("WORKFLOW", "sidebarHeader"))
        side.addSpacing(8)
        nav_scroll = QScrollArea()
        nav_scroll.setWidgetResizable(True)
        nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        nav_scroll.setFrameShape(QFrame.Shape.NoFrame)
        nav_contents = QWidget()
        nav_layout = _vbox(nav_contents, gap=4)
        self.sidebar_buttons: dict[str, QPushButton] = {}
        for step, title in STEPS:
            b = self.make_button("○  " + title, lambda name=step: self.navigate(name), flat=False)
            b.setObjectName("sidebarStep")
            b.setProperty("active", False)
            b.setProperty("done", False)
            b.setMinimumHeight(31)
            self.sidebar_buttons[step] = b
            nav_layout.addWidget(b)
        nav_layout.addStretch(1)
        nav_scroll.setWidget(nav_contents)
        side.addWidget(nav_scroll, 1)
        side.addWidget(_label("●  Private workspace", "fineText"))
        side.addWidget(_label("●  Local-only credentials", "fineText"))
        center_layout.addWidget(self.sidebar)

        main = QWidget()
        main_layout = _vbox(main, (26, 24, 26, 14), 15)
        center_layout.addWidget(main, 1)

        self.kicker = _label("STEP 01  /  ACQUIRE", "stepLabel")
        main_layout.addWidget(self.kicker)
        self.hero = _label("Choose your IPA source", "pageTitle")
        main_layout.addWidget(self.hero)
        self.subtitle = _label("Start with an App Store search or open a local IPA.", "pageSubtitle")
        main_layout.addWidget(self.subtitle)

        self.alert_area = QWidget()
        self.alert_layout = _vbox(self.alert_area, gap=0)
        self.alert_area.hide()
        main_layout.addWidget(self.alert_area)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.page = QWidget()
        self.page_layout = _vbox(self.page, (0, 3, 4, 10), 16)
        self.page_layout.addStretch(1)
        scroll.setWidget(self.page)
        main_layout.addWidget(scroll, 1)
        self.main = main

        self.activity_panel = QWidget()
        self.activity_panel.setObjectName("activity")
        self.activity_panel.setFixedWidth(305)
        activity_l = _vbox(self.activity_panel, (14, 20, 15, 18), 10)
        acth = QWidget()
        ahl = _hbox(acth)
        ahl.addWidget(_label("LIVE ACTIVITY", "sidebarHeader"))
        ahl.addStretch()
        ahl.addWidget(self.make_button("Copy", self.copy_activity, flat=True))
        activity_l.addWidget(acth)
        activity_l.addWidget(_label("Operations appear here. Your session stays active after errors.", "fineText"))
        self.activity_edit = QPlainTextEdit()
        self.activity_edit.setReadOnly(True)
        self.activity_edit.setPlaceholderText("No operations yet")
        activity_l.addWidget(self.activity_edit, 1)
        self.activity_visibility_override: bool | None = None
        center_layout.addWidget(self.activity_panel)

        bottom = QWidget()
        bottom.setObjectName("footer")
        bl = _hbox(bottom, (23, 10, 23, 10), 16)
        self.status_label = _label("Ready", "footerStatus", False)
        bl.addWidget(self.status_label, 1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedWidth(145)
        bl.addWidget(self.progress)
        self.retry_btn = self.make_button("↻  Retry", self.retry, flat=True)
        self.retry_btn.hide()
        bl.addWidget(self.retry_btn)
        bl.addWidget(self.make_button("Cancel task", self.cancel_task, flat=True))
        all_layout.addWidget(bottom)
        self._update_responsive()

    def _shortcuts(self) -> None:
        for key, fn in [(QKeySequence("Ctrl+R"), self.retry),
                        (QKeySequence("Ctrl+L"), self.toggle_activity),
                        (QKeySequence("Ctrl+O"), self.open_local_dialog)]:
            shortcut = QShortcut(key, self)
            shortcut.activated.connect(fn)

    def make_button(self, text: str, action: Callable[[], None], *, primary: bool = False,
                    flat: bool = False, danger: bool = False) -> QPushButton:
        btn = QPushButton(text)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        if primary:
            btn.setObjectName("primary")
        elif flat:
            btn.setObjectName("flatButton")
        elif danger:
            btn.setObjectName("dangerButton")
        btn.clicked.connect(lambda _=False: self.safe(action))
        return btn

    def safe(self, fn: Callable[[], None]) -> None:
        if self.busy:
            self.status("Current operation is running. Finish or cancel it before continuing.")
            return
        try:
            fn()
        except Exception as exc:
            self.log("ERROR: " + traceback.format_exc(limit=3))
            self.fail(str(exc), retry=fn)

    def log(self, text: str) -> None:
        if self._closed:
            return
        for line in str(text).splitlines():
            line = line[:1200]
            line = re.sub(r"(?i)(password\s*[:=]\s*)(\S+)", r"\1[REDACTED]", line)
            self.incoming_log.emit(line)

    def _append_log(self, text: str) -> None:
        if self._closed:
            return
        self.activity.append(text)
        self.activity = self.activity[-600:]
        self.activity_edit.appendPlainText(text)
        if self.phase == "decrypt":
            hit = re.match(r"^\s*(\d{1,3})/(\d{1,3})\s+pages=", text)
            if hit:
                completed, total = int(hit.group(1)), int(hit.group(2))
                if total:
                    overall = (len(self.done_steps) + completed / total) / len(STEPS)
                    self.progress.setValue(max(0, min(99, int(100 * overall))))
                    self.status(f"Decrypting Mach-O binaries: {completed}/{total}")
        if self.activity_edit.blockCount() > 650:
            self.activity_edit.setPlainText("\n".join(self.activity))
        scroll = self.activity_edit.verticalScrollBar()
        scroll.setValue(scroll.maximum())

    def copy_activity(self) -> None:
        QApplication.clipboard().setText("\n".join(self.activity))
        self.status("Session activity copied. Review before sharing; file paths may be sensitive.")

    def status(self, message: str) -> None:
        self.status_label.setText(message[:160])

    def _heartbeat(self) -> None:
        if self.busy:
            dots = ["◐", "◓", "◑", "◒"]
            self.spin = (self.spin + 1) % 4
            self.status(f"{dots[self.spin]}  {self.busy_description}")

    def resizeEvent(self, event: Any) -> None:
        super().resizeEvent(event)
        if hasattr(self, "sidebar"):
            self._update_responsive()

    def _update_responsive(self) -> None:
        w = self.width()
        self.sidebar.setVisible(w >= 920)
        should_show = (w >= 1210) if self.activity_visibility_override is None else self.activity_visibility_override
        self.activity_panel.setVisible(should_show)
        if w < 1210 and self.activity_panel.isVisible():
            self.activity_panel.setFixedWidth(260)
        else:
            self.activity_panel.setFixedWidth(305)
        self.activity_toggle.setText("Hide log" if self.activity_panel.isVisible() else "Activity")

    def toggle_activity(self) -> None:
        if self.width() < 1110:
            from PySide6.QtWidgets import QDialog
            dialog = QDialog(self)
            dialog.setWindowTitle("IPA Lab · Activity")
            dialog.resize(max(520, self.width() - 100), 420)
            content = _vbox(dialog, (16, 16, 16, 16), 10)
            content.addWidget(_label("SESSION ACTIVITY", "stepLabel"))
            output = QPlainTextEdit()
            output.setReadOnly(True)
            output.setPlainText("\n".join(self.activity))
            content.addWidget(output, 1)
            dialog.exec()
            return
        self.activity_visibility_override = not self.activity_panel.isVisible()
        self._update_responsive()

    def navigate(self, phase: str) -> None:
        # Do not allow jumping ahead into stages missing their prerequisites.
        if phase == "source":
            self.go("source")
        elif phase in self.done_steps or phase == self.phase:
            self.go(phase)
        elif phase in ("auth", "search") and "source" in self.done_steps:
            self.go(phase)
        elif phase == "results" and self.apps:
            self.go(phase)
        elif phase == "metadata" and self.inspection:
            self.go(phase)
        elif phase == "device" and self.inspection:
            self.go(phase)
        elif phase == "export" and self.staged:
            self.go(phase)
        else:
            self.status("Finish the earlier stages before opening this step.")

    def refresh_sidebar(self) -> None:
        for ix, (step, _) in enumerate(STEPS):
            btn = self.sidebar_buttons[step]
            active = step == self.phase
            done = step in self.done_steps
            btn.setProperty("active", active)
            btn.setProperty("done", done)
            mark = "●" if active else "✓" if done else "○"
            btn.setText(f"{mark}   {STEPS[ix][1]}")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        self.progress.setValue(round(100 * max(0, len(self.done_steps)) / len(STEPS)))
        self.device_badge.setText("[USB] " + self.udid[:10] + "…" if self.udid else "No device selected")

    def go(self, phase: str) -> None:
        self.auto_wait_timer.stop()
        self.auto_wait_enabled = False
        self.phase = phase
        self.clear_error()
        self.render()
        self.refresh_sidebar()

    def mark(self, *phases: str) -> None:
        self.done_steps.update(phases)
        self.refresh_sidebar()

    def _clear_layout(self, layout: QVBoxLayout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
            elif item.layout() is not None:
                while item.layout().count():
                    sub = item.layout().takeAt(0)
                    if sub.widget() is not None:
                        sub.widget().deleteLater()

    def _card(self, *contents: QWidget) -> QWidget:
        surface = QWidget()
        surface.setObjectName("surface")
        layout = _vbox(surface, (22, 21, 22, 22), 14)
        for widget in contents:
            layout.addWidget(widget)
        self.page_layout.addWidget(surface)
        return surface

    def _text_input(self, key: str, title: str, default: str = "") -> QWidget:
        host = QWidget()
        layout = _vbox(host, gap=6)
        layout.addWidget(_label(title, "fineText"))
        entry = QLineEdit(self.fields.setdefault(key, default))
        entry.setClearButtonEnabled(True)
        entry.textChanged.connect(lambda value, field=key: self.fields.__setitem__(field, value))
        layout.addWidget(entry)
        return host

    def _buttons(self, *items: tuple[str, Callable[[], None], bool]) -> QWidget:
        host = QWidget()
        layout = _hbox(host, gap=8)
        for label, action, primary in items:
            layout.addWidget(self.make_button(label, action, primary=primary))
        layout.addStretch(1)
        return host

    def _heading(self, title: str, subtitle: str, *, tag: str | None = None) -> None:
        self.hero.setText(title)
        self.subtitle.setText(subtitle)
        ix = next((i for i, (p, _) in enumerate(STEPS, 1) if p == self.phase), 1)
        self.kicker.setText(tag or f"WORKFLOW  /  {ix:02d} OF {len(STEPS):02d}")

    def render(self) -> None:
        self._clear_layout(self.page_layout)
        fn = getattr(self, f"page_{self.phase}", None)
        if fn is None:
            self._heading("Not available", "Unknown workflow state")
            self._card(_label("This step is unavailable. Return to Choose source."))
        else:
            fn()
        self.page_layout.addStretch(1)

    def clear_error(self) -> None:
        self.error = ""
        self.current_retry = None
        self.error_actions = []
        self.error_poll = None
        self.auto_wait_timer.stop()
        self._clear_layout(self.alert_layout)
        self.alert_area.hide()
        self.retry_btn.hide()

    def fail(self, message: str, *, retry: Callable[[], None] | None = None,
             alternatives: list[tuple[str, Callable[[], None]]] | None = None,
             auto_wait: Callable[[], None] | None = None) -> None:
        self.error = message.strip() or "Unknown error"
        self.current_retry = retry
        self.error_actions = alternatives or []
        self.error_poll = auto_wait
        self.auto_wait_timer.stop()
        self.log("ERROR • " + self.error)
        self._clear_layout(self.alert_layout)
        box = QWidget()
        box.setObjectName("alert")
        l = _vbox(box, (18, 12, 18, 14), 9)
        l.addWidget(_label("Action needed · workflow preserved", "alertTitle"))
        l.addWidget(_label(self.error[:700], "alertText"))
        actions = QWidget()
        al = _hbox(actions, gap=7)
        if retry:
            al.addWidget(self.make_button("↻ Retry", self.retry, primary=True))
        for label, fn in (alternatives or []):
            al.addWidget(self.make_button(label, fn))
        if auto_wait:
            al.addWidget(self.make_button("Auto-wait", self.begin_auto_wait))
        al.addStretch(1)
        l.addWidget(actions)
        self.alert_layout.addWidget(box)
        self.alert_area.show()
        self.retry_btn.setVisible(retry is not None)
        self.status("Recovery available — no progress was reset")
        if auto_wait is not None and self.auto_wait_enabled:
            self.auto_wait_timer.start()

    def retry(self) -> None:
        if self.busy:
            return
        action = self.current_retry
        if action:
            self.clear_error()
            self.safe(action)

    def begin_auto_wait(self) -> None:
        if self.error_poll is not None:
            self.auto_wait_enabled = True
            self.auto_wait_timer.start()
            self.status("Auto-wait active — retrying a safe readiness check every 3 seconds")

    def _retry_poll(self) -> None:
        if self.error_poll and not self.busy:
            if self.phase == "port" and not core.free_port(self.port):
                self.status(f"Waiting for TCP port {self.port} to become available…")
                return
            action = self.error_poll
            self.safe(action)

    def run_job(self, label: str, function: Callable[[], Any], success: Callable[[Any], None],
                *, retry: Callable[[], None] | None = None,
                alternatives: list[tuple[str, Callable[[], None]]] | None = None,
                auto_wait: Callable[[], None] | None = None) -> None:
        if self.busy:
            return
        self.clear_error()
        self.busy = True
        self.busy_description = label
        self.log("▸ " + label)
        self.job = Job(function, self)
        job = self.job

        def finish_success(value: Any) -> None:
            self.busy = False
            if self.runner.cancelled.is_set():
                self._reset_runner()
            if self._closed:
                return
            self.status("✓ " + label)
            try:
                success(value)
            except Exception as exc:
                self.log(traceback.format_exc(limit=5))
                self.fail(str(exc), retry=retry, alternatives=alternatives)

        def finish_error(message: str) -> None:
            self.busy = False
            if self.runner.cancelled.is_set():
                self._reset_runner()
            if not self._closed:
                self.fail(message, retry=retry, alternatives=alternatives, auto_wait=auto_wait)

        job.succeeded.connect(finish_success)
        job.failed.connect(finish_error)
        job.finished.connect(lambda: setattr(self, "job", None) if self.job is job else None)
        job.finished.connect(job.deleteLater)
        job.start()

    def cancel_task(self) -> None:
        if not self.busy:
            self.status("No operation is running.")
            return
        reply = QMessageBox.question(self, "Cancel operation", "Cancel the current external command?\nYou can retry the same step afterwards.")
        if reply == QMessageBox.StandardButton.Yes:
            self.runner.stop_all()
            self.status("Cancellation requested. Returning control to the current step…")
            # Once the worker has finished, a new CommandRunner is required.
            if self.job:
                self.job.finished.connect(lambda: self._reset_runner())

    def _reset_runner(self) -> None:
        if not self._closed:
            self.runner = core.CommandRunner(self.log)

    def _ensure_active(self) -> None:
        if self.demo:
            raise core.WorkflowError("Demo mode cannot modify real IPAs or devices.")
        if platform.system() != "Darwin":
            raise core.WorkflowError("IPA Lab supports macOS only.")

    def preflight(self) -> None:
        if platform.system() != "Darwin" and not self.demo:
            self.fail("IPA Lab requires macOS. This computer is running " + platform.system() + ".",
                      retry=self.preflight)
            return
        missing, other = core.available_tools()
        if self.demo:
            self.status("Preview mode — real macOS commands disabled")
            return
        if other and "brew" in other:
            self.fail("Homebrew is missing. Install it from brew.sh, then choose Retry.", retry=self.preflight)
            return
        if missing:
            self.fail("Required Homebrew packages are missing: " + ", ".join(missing) + ".",
                      retry=self.preflight,
                      alternatives=[("Install packages", lambda: self.install_brew(missing))])
            return
        if other:
            self.fail("Required host tools not detected: " + ", ".join(other) + ".",
                      retry=self.preflight)
            return
        self.status("✓ macOS and required tools are ready")
        if self.local_ipa is not None:
            self.fields["local"] = str(self.local_ipa)
            self.safe(self.use_local)

    def install_brew(self, missing: list[str]) -> None:
        response = QMessageBox.question(
            self, "Install prerequisites",
            "Install these packages with Homebrew?\n\n" + ", ".join(missing) +
            "\n\nThis changes your Mac. IPA Lab will not install anything without approval.")
        if response != QMessageBox.StandardButton.Yes:
            self.status("No packages installed. You can continue when prerequisites are available.")
            return
        self.run_job("Installing Homebrew tools", lambda: self.runner.run(["brew", "install", *missing], timeout=1600),
                     lambda _: self.preflight(), retry=lambda: self.install_brew(missing))

    def open_local_dialog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open an authorized IPA", str(Path.home() / "Downloads"), "IPA archives (*.ipa)")
        if path:
            self.fields["local"] = path
            self.go("source")
            self.use_local()

    def page_source(self) -> None:
        self._heading("Choose your IPA source", "Bring your own IPA, or search and download an application you are authorized to assess.", tag="WELCOME  /  NEW ASSESSMENT")
        self._card(
            _label("Start a new assessment", "cardTitle"),
            _label("One desktop workspace for App Store acquisition, Mach-O inspection, FairPlay processing and verified IPA export."),
            self._buttons(("Search App Store", lambda: self.go("auth"), True),
                          ("Open local IPA…", self.open_local_dialog, False)),
        )
        self._card(
            _label("Local IPA", "cardTitle"),
            self._text_input("local", "Choose an existing .ipa file", str(self.local_ipa or "")),
            self._buttons(("Inspect this IPA", self.use_local, True), ("Browse…", self.open_local_dialog, False)),
            _label("Tip: drag and drop an IPA anywhere into the window.", "fineText"),
        )

    def use_local(self) -> None:
        self._ensure_active()
        path = core.safe_ipa_path(self.fields.get("local", ""))
        core.validate_zip(path)
        self.ipa = path
        self.mark("source")
        self.inspect()

    def page_auth(self) -> None:
        self._heading("Connect App Store account", "Sign in using ipatool in a macOS Terminal window; IPA Lab never reads your Apple password.")
        self._card(
            _label("Apple authentication", "cardTitle"),
            _label("Click Sign in to open ipatool auth login in Terminal. Complete any verification there, then return here."),
            self._buttons(("Sign in with ipatool", self.launch_login, True),
                          ("I'm already signed in", self.auth_next, False)),
            _label("Only ipatool handles Apple credentials. IPA Lab does not store passwords or 2FA codes.", "fineText"),
        )

    def _terminal_command(self, label: str, command: str) -> None:
        self._ensure_active()
        # A restricted local .command file lets Terminal handle native password prompts.
        path = self.workspace / f"terminal-{re.sub(r'[^a-z0-9_-]', '-', label.lower())}.command"
        path.write_text("#!/bin/zsh\n" + command +
                        "\nprintf '\\nReturn to IPA Lab when finished.\\n'\n"
                        "read '?Press Enter to close this session: '\n", encoding="utf-8")
        path.chmod(0o700)
        outcome = subprocess.run(["open", "-a", "Terminal", str(path)], capture_output=True, text=True, timeout=20)
        if outcome.returncode:
            raise core.WorkflowError("Could not open Terminal: " + outcome.stderr.strip())
        self.status("Terminal opened. Complete the prompt, then continue in IPA Lab.")

    def launch_login(self) -> None:
        self._terminal_command("ipatool-login", "ipatool auth login")

    def auth_next(self) -> None:
        self.mark("auth", "source")
        self.go("search")

    def page_search(self) -> None:
        self._heading("Search the App Store", "Search terms can contain spaces. Select the exact bundle identifier before downloading.")
        self._card(
            _label("App discovery", "cardTitle"),
            self._text_input("term", "Application name (e.g. Liv X)", ""),
            self._text_input("limit", "Maximum results (1–50)", "10"),
            self._buttons(("Search apps", self.search_apps, True), ("Account", lambda: self.go("auth"), False)),
        )

    def search_apps(self) -> None:
        self._ensure_active()
        term = self.fields.get("term", "").strip()
        if not term:
            raise core.WorkflowError("Enter an app name before searching.")
        try:
            limit = int(self.fields.get("limit", "10"))
            if limit not in range(1, 51):
                raise ValueError
        except ValueError:
            raise core.WorkflowError("Search limit must be an integer between 1 and 50.") from None
        def task() -> list[dict]:
            _, raw = self.runner.run(["ipatool", "search", term, "--limit", str(limit),
                                      "--platform", "iphone", "--format", "json"], timeout=120,
                                     capture_full=True, log_output=False)
            results = core.parse_search(raw)
            if not results:
                raise core.WorkflowError("No matching applications found. Try a broader search or authenticate again.")
            return results
        self.run_job("Searching the App Store", task, self.search_complete, retry=self.search_apps,
                     alternatives=[("Sign in again", lambda: self.go("auth"))])

    def search_complete(self, apps: list[dict]) -> None:
        self.apps = apps
        self.mark("search")
        self.go("results")

    def page_results(self) -> None:
        self._heading("Choose an application", "Select the bundle identifier matching the application you want to assess.")
        host = QWidget()
        lay = _vbox(host, gap=9)
        lay.addWidget(_label(f"{len(self.apps)} RESULTS", "stepLabel"))
        listview = QListWidget()
        listview.setMinimumHeight(185)
        for app in self.apps:
            title = str(app.get("name", "Unknown app"))
            ident = core.bundle_id(app)
            version = str(app.get("version", "?"))
            item = QListWidgetItem(f"{title}\n{ident}   ·   v{version}")
            item.setSizeHint(QSize(0, 52))
            listview.addItem(item)
        listview.setCurrentRow(0)
        listview.itemDoubleClicked.connect(lambda _: self.choose_app(listview.currentRow()))
        lay.addWidget(listview)
        lay.addWidget(self._buttons(("Choose selected app", lambda: self.choose_app(listview.currentRow()), True),
                                    ("New search", lambda: self.go("search"), False)))
        self._card(host)

    def choose_app(self, index: int) -> None:
        if index < 0 or index >= len(self.apps):
            raise core.WorkflowError("Select an application from the list.")
        self.selected = self.apps[index]
        if not core.bundle_id(self.selected):
            raise core.WorkflowError("Selected application does not include a bundle identifier.")
        self.mark("results")
        self.go("download")

    def page_download(self) -> None:
        name = str(self.selected.get("name", "application"))
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._") or "application"
        self._heading("Download encrypted IPA", f"{name}  ·  {core.bundle_id(self.selected)}")
        self._card(
            _label("Download destination", "cardTitle"),
            self._text_input("download", "Save to a unique .ipa filename", str(Path.home() / "Downloads" / f"{slug}.ipa")),
            self._buttons(("Download IPA", lambda: self.download_app(False), True),
                          ("Acquire free license + download", lambda: self.download_app(True), False)),
            self._buttons(("Choose file…", self.browse_download, False),
                          ("Use existing IPA", self.use_existing_download, False),
                          ("Find unused name", self.unique_download, False)),
            _label("An existing IPA is never overwritten. A free license request is sent only when selected explicitly.", "fineText"),
        )

    def browse_download(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save IPA", self.fields.get("download", str(Path.home() / "Downloads")), "IPA (*.ipa)")
        if path:
            self.fields["download"] = path
            self.go("download")

    def unique_download(self) -> None:
        self.fields["download"] = str(core.unique_ipa_path(core.safe_ipa_path(self.fields.get("download", ""))))
        self.go("download")

    def use_existing_download(self) -> None:
        path = core.safe_ipa_path(self.fields.get("download", ""))
        core.validate_zip(path)
        self.ipa = path
        self.mark("download")
        self.inspect()

    def download_app(self, purchase: bool) -> None:
        self._ensure_active()
        path = core.safe_ipa_path(self.fields.get("download", ""))
        if path.exists() or path.is_symlink():
            self.fail(f"{path.name} already exists. Choose Use existing IPA or Find unused name.",
                      retry=lambda: self.download_app(purchase),
                      alternatives=[("Use existing", self.use_existing_download),
                                    ("Unused name", self.unique_download)])
            return
        bundle = core.bundle_id(self.selected)
        if purchase:
            try:
                if float(self.selected.get("price", "-1")) != 0.0:
                    raise ValueError
            except (ValueError, TypeError):
                raise core.WorkflowError("Acquiring a free license is only available for a confirmed free application.") from None
        def task() -> Path:
            path.parent.mkdir(parents=True, exist_ok=True)
            command = ["ipatool", "download", "--bundle-identifier", bundle, "--output", str(path), "--platform", "iphone"]
            if purchase:
                command.append("--purchase")
            self.runner.run(command, timeout=1600)
            core.validate_zip(path)
            return path
        self.run_job("Downloading " + bundle, task, self.download_complete,
                     retry=lambda: self.download_app(purchase),
                     alternatives=[("New filename", self.unique_download),
                                   ("Reauthenticate", lambda: self.go("auth"))])

    def download_complete(self, path: Path) -> None:
        self.ipa = path
        self.mark("download")
        self.inspect()

    def page_inspect(self) -> None:
        self._heading("Inspecting IPA", "The IPA is unpacked in a private workspace and its Mach-O encryption commands are checked.")
        self._card(_label("Analysis", "cardTitle"),
                   _label(str(self.ipa or "No IPA selected"), "bodyText"),
                   _label("This step can take time for applications containing large frameworks."),
                   self._buttons(("Run inspection", self.inspect, True),
                                 ("Change IPA", lambda: self.go("source"), False)))

    def inspect(self) -> None:
        self._ensure_active()
        if not self.ipa:
            raise core.WorkflowError("Select an IPA to inspect.")
        self.go("inspect")
        def task() -> core.Inspection:
            extracted = self.workspace / "extracted"
            if extracted.exists():
                shutil.rmtree(extracted)
            return core.inspect_ipa(self.ipa, extracted, self.runner, self.log)
        self.run_job("Inspecting Mach-O encryption and Info.plist", task,
                     self.inspect_complete, retry=self.inspect)

    def inspect_complete(self, inspection: core.Inspection) -> None:
        self.inspection = inspection
        self.mark("inspect")
        self.go("metadata")

    def page_metadata(self) -> None:
        i = self.inspection
        if i is None:
            self._heading("Inspection unavailable", "Inspect an IPA first.")
            return
        encrypted = sum(c not in (None, 0) for _, c, _ in i.binaries)
        size = sum(s or 0 for _, c, s in i.binaries if c)
        state = "ENCRYPTED" if i.encrypted else "UNKNOWN" if i.unknown else "NOT ENCRYPTED"
        self._heading("IPA inspection complete", f"{i.bundle}   ·   {state}")
        self._card(
            _label("Application", "cardTitle"),
            _label("Bundle identifier   " + i.bundle, "value"),
            _label("Executable   " + i.executable),
            _label("Minimum iOS   " + i.min_ios, "value"),
            _label(f"Mach-O files   {len(i.binaries)}    ·    {encrypted} encrypted    ·    {size/1048576:.1f} MiB protected"),
            _label("●  " + state, "negativeText" if i.encrypted else "positiveText" if not i.unknown else "bodyText"),
        )
        self._card(
            _label("Minimum supported iOS", "cardTitle"),
            _label("You may change the declared MinimumOSVersion to exactly 15.0. This does not backport iOS 16+ APIs; it invalidates the original code signature."),
            self._buttons(("Keep original", lambda: self.choose_ios(False), True),
                          ("Set exactly 15.0", lambda: self.choose_ios(True), False)),
            _label("Version edits are applied to the final exported IPA, not your original download.", "fineText"),
        )

    def choose_ios(self, patch: bool) -> None:
        self.patch = patch
        self.mark("metadata")
        if self.inspection and (self.inspection.encrypted or self.inspection.unknown):
            self.go("device")
            self.scan_devices()
        else:
            self.staged = self.ipa
            self.mark("device", "port", "ssh", "fairplay", "credential", "decrypt")
            self.go("export")

    def page_device(self) -> None:
        self._heading("Connect jailbroken iPhone", "Connect, unlock, and trust an authorized jailbroken iPhone via USB. Then select the device.")
        holder = QWidget()
        lay = _vbox(holder)
        lay.addWidget(_label("CONNECTED USB DEVICES", "stepLabel"))
        choices = QListWidget()
        choices.setMinimumHeight(125)
        for udid in self.devices:
            choices.addItem("◈   " + udid + "   [USB]")
        if self.devices:
            try:
                choices.setCurrentRow(self.devices.index(self.udid))
            except ValueError:
                choices.setCurrentRow(0)
        lay.addWidget(choices)
        lay.addWidget(self._buttons(("Use selected device", lambda: self.choose_device(choices.currentRow()), True),
                                    ("↻ Rescan USB", self.scan_devices, False)))
        self._card(holder)
        self._card(_label("No device detected?", "cardTitle"),
                   _label("Keep the phone unlocked, approve Trust This Computer and ensure Dopamine/OpenSSH is enabled."),
                   self._buttons(("Retry device scan", self.scan_devices, False),
                                 ("Review inspection", lambda: self.go("metadata"), False)))

    def scan_devices(self) -> None:
        self._ensure_active()
        self.run_job("Looking for USB iPhones", lambda: core.enumerate_usb(self.runner),
                     self.scan_complete, retry=self.scan_devices, auto_wait=self.scan_devices)

    def scan_complete(self, devices: list[str]) -> None:
        self.devices = devices
        self.go("device")
        if not devices:
            self.fail("No USB iPhone found. Connect, unlock and trust your device, then Retry.",
                      retry=self.scan_devices, auto_wait=self.scan_devices)

    def choose_device(self, index: int) -> None:
        if not 0 <= index < len(self.devices):
            raise core.WorkflowError("Choose a connected device first.")
        new_udid = self.devices[index]
        if self.udid != new_udid and self.tunnel:
            self.tunnel.stop()
            self.tunnel = None
        self.udid = new_udid
        self.mark("device")
        self.go("port")

    def page_port(self) -> None:
        self._heading("Establish USB connection", "IPA Lab manages iproxy in the background. Existing processes are never killed to free a port.")
        self._card(
            _label("Secure USB tunnel", "cardTitle"),
            _label("Device   " + self.udid, "value"),
            self._text_input("port", "Mac TCP port  →  iPhone port 22", str(self.port)),
            self._buttons(("Start tunnel", self.start_tunnel, True),
                          ("Find free port", self.use_free_port, False)),
            _label("A busy port is recoverable: use a different port or wait for the existing tunnel to close.", "fineText"),
        )

    def use_free_port(self) -> None:
        port = core.next_free_port(2222, 2600)
        self.port = port
        self.fields["port"] = str(port)
        self.go("port")
        self.status(f"Free port selected: {port}")

    def start_tunnel(self) -> None:
        self._ensure_active()
        try:
            self.port = int(self.fields.get("port", "2222"))
            if not 1024 <= self.port <= 65535:
                raise ValueError
        except ValueError:
            raise core.WorkflowError("Enter a TCP port from 1024 to 65535.") from None
        if not core.free_port(self.port):
            self.fail(f"Port {self.port} is occupied. No existing process was terminated.",
                      retry=self.start_tunnel, alternatives=[("Find free port", self.use_free_port)],
                      auto_wait=self.start_tunnel)
            return
        if not self.udid:
            raise core.WorkflowError("Select a USB device first.")
        def task() -> core.USBTunnel:
            if self.tunnel:
                self.tunnel.stop()
            tunnel = core.USBTunnel(self.udid, self.port, self.log)
            tunnel.start()
            return tunnel
        self.run_job(f"Opening iproxy {self.port}:22", task, self.tunnel_ready,
                     retry=self.start_tunnel,
                     alternatives=[("Find free port", self.use_free_port)])

    def tunnel_ready(self, tunnel: core.USBTunnel) -> None:
        self.tunnel = tunnel
        self.mark("port")
        self.go("ssh")
        self.check_root_ssh()

    def page_ssh(self) -> None:
        self._heading("Verify root SSH", "The FairPlay retriever requires passwordless SSH as root. Passwords are entered only in Terminal.")
        self._card(
            _label("Device access", "cardTitle"),
            _label(f"root@127.0.0.1:{self.port}   →   {self.udid}", "value"),
            self._buttons(("Recheck root SSH", self.check_root_ssh, True),
                          ("Install key as root", lambda: self.setup_key("root"), False)),
            self._buttons(("Mobile + existing sudo", lambda: self.setup_key("mobile"), False),
                          ("Change port", self.change_port, False)),
            _label("Do not change the root password to 'root'. Use the root account's existing password or an already authorized sudo-capable mobile account.", "fineText"),
        )

    def change_port(self) -> None:
        if self.tunnel:
            self.tunnel.stop()
            self.tunnel = None
        self.go("port")

    def check_root_ssh(self) -> None:
        self._ensure_active()
        self.run_job("Checking passwordless root SSH", lambda: core.test_root_ssh(self.port, self.runner),
                     self.ssh_complete, retry=self.check_root_ssh)

    def ssh_complete(self, ready: bool) -> None:
        if ready:
            self.mark("ssh")
            self.go("fairplay")
        else:
            self.fail("Root SSH authentication failed. Add your Mac's public key to root's authorized_keys, then recheck.",
                      retry=self.check_root_ssh,
                      alternatives=[("Configure root key", lambda: self.setup_key("root")),
                                    ("Mobile + sudo", lambda: self.setup_key("mobile"))])

    def setup_key(self, user: str) -> None:
        self._ensure_active()
        public = core.public_key_path()
        if not public.is_file():
            confirm = QMessageBox.question(self, "Create SSH key", "No ed25519 public key found. Open Terminal to create a new SSH key pair?\nDo not share the private key.")
            if confirm != QMessageBox.StandardButton.Yes:
                return
            self._terminal_command("create-ssh-key", "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519")
            self.status("Generate the SSH key in Terminal, then return and click Install key again.")
            return
        key = public.read_text(encoding="utf-8").strip()
        if not key.startswith("ssh-ed25519 ") or "\n" in key:
            raise core.WorkflowError("Expected a valid ed25519 public key at " + str(public))
        if user == "mobile":
            remote = "sudo -H sh -c " + shlex.quote(core.root_key_command(key))
            note = "Use your MOBILE password only if mobile already has working sudo."
        else:
            remote = core.root_key_command(key)
            note = "Enter the device ROOT password, not the mobile password."
        confirm = QMessageBox.question(self, "Install SSH public key", note +
                                       "\n\nAllow adding your Mac's SSH public key to root's authorized_keys on this iPhone?")
        if confirm != QMessageBox.StandardButton.Yes:
            return
        command = shlex.join(core.ssh_cmd(self.port, user=user, batch=False, tty=True) + [remote])
        self._terminal_command("ssh-key-setup", command)
        self.status("Follow the password prompt in Terminal, then click Recheck root SSH.")

    def page_fairplay(self) -> None:
        default = self.repo_override or Path(__file__).resolve().parent.parent / "vendor" / "fairplay-decrypt"
        self._heading("Prepare FairPlay tools", "Reuse your existing fairplay-decrypt checkout or clone the official upstream project.")
        self._card(
            _label("FairPlay repository", "cardTitle"),
            self._text_input("repo", "Checkout directory", str(default)),
            self._buttons(("Prepare checkout", self.prepare_repo, True),
                          ("Browse…", self.choose_repo_folder, False)),
            self._buttons(("Clone upstream here", self.clone_repo, False),
                          ("Recheck SSH", self.check_root_ssh, False)),
            _label("Python requirements, Xcode tools and credential.ios are prepared only if missing and with approval.", "fineText"),
        )

    def repo_path(self) -> Path:
        value = self.fields.get("repo", "").strip()
        if not value:
            raise core.WorkflowError("Choose a FairPlay repository directory.")
        return Path(value).expanduser().absolute()

    def choose_repo_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "FairPlay checkout", self.fields.get("repo", str(Path.home())))
        if path:
            self.fields["repo"] = path
            self.go("fairplay")

    def clone_repo(self) -> None:
        path = self.repo_path()
        if path.exists():
            raise core.WorkflowError("The directory already exists. Choose Prepare checkout or select another folder.")
        answer = QMessageBox.question(self, "Clone repository", "Clone EthanArbuckle/fairplay-decrypt from GitHub into:\n" + str(path) + "?")
        if answer != QMessageBox.StandardButton.Yes:
            return
        def task() -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.runner.run(["git", "clone", "--depth", "1", core.FAIRPLAY_URL, str(path)], timeout=900)
        self.run_job("Cloning fairplay-decrypt", task, lambda _: self.prepare_repo(), retry=self.clone_repo)

    def prepare_repo(self) -> None:
        self._ensure_active()
        repo = self.repo_path()
        if not (repo / "decrypt.py").exists() or not (repo / "credential-retrieval" / "retrieve.py").exists():
            self.fail("This folder is not a FairPlay checkout. Clone upstream or choose the correct directory.",
                      retry=self.prepare_repo,
                      alternatives=[("Clone upstream", self.clone_repo), ("Browse", self.choose_repo_folder)])
            return
        missing_venv = not (repo / "venv" / "bin" / "python3").exists()
        missing_bundle = not (repo / "credential-retrieval" / "build" / "bundle" / "credential.ios").exists()
        if missing_venv or missing_bundle:
            actions = []
            if missing_venv:
                actions.append("create Python venv / install requirements")
            if missing_bundle:
                actions.append("build the iOS credential bundle")
            answer = QMessageBox.question(self, "Prepare FairPlay environment", "Allow IPA Lab to " + " and ".join(actions) + " in:\n" + str(repo) + "?")
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.run_job("Preparing FairPlay build and Python dependencies", lambda: core.prepare_fairplay(repo, self.runner),
                     lambda python: self.fairplay_ready(repo, python), retry=self.prepare_repo,
                     alternatives=[("Choose checkout", self.choose_repo_folder)])

    def fairplay_ready(self, repo: Path, python: Path) -> None:
        self.repo = repo
        self.python = python
        self.mark("fairplay")
        self.go("credential")

    def page_credential(self) -> None:
        self._heading("Retrieve FairPlay credential", "The selected jailbroken iPhone must be authorized with the Apple Account associated with the IPA.")
        self._card(
            _label("Account credential", "cardTitle"),
            _label("FairPlay's 16-byte credential is retrieved via the existing USB tunnel and kept in a private, temporary folder."),
            _label("Device   " + self.udid[:18] + "…"),
            self._buttons(("Retrieve credential", self.retrieve, True),
                          ("Recheck SSH", self.check_root_ssh, False)),
            _label("Do not publish credential.bin. It is deleted when you close the app.", "fineText"),
        )

    def retrieve(self) -> None:
        self._ensure_active()
        if not self.repo or not self.python or not self.ipa:
            raise core.WorkflowError("FairPlay checkout and IPA are required.")
        self.run_job("Retrieving credential.bin", lambda: core.retrieve_credential(
            self.repo, self.python, self.ipa, self.port, self.workspace, self.runner),
            self.retrieve_complete, retry=self.retrieve,
            alternatives=[("SSH check", self.check_root_ssh), ("Change port", self.change_port)])

    def retrieve_complete(self, credential: Path) -> None:
        self.credential = credential
        self.mark("credential")
        self.go("decrypt")
        self.decrypt()

    def page_decrypt(self) -> None:
        self._heading("Decrypt protected Mach-O", "Run the upstream decrypt.py with the credential retrieved during this session.")
        self._card(
            _label("Decryption", "cardTitle"),
            _label("IPA   " + str(self.ipa or "")),
            _label("Each encrypted Mach-O executable and framework is processed. See Activity for per-binary progress."),
            self._buttons(("Start / retry decryption", self.decrypt, True),
                          ("Retrieve again", lambda: self.go("credential"), False)),
        )

    def decrypt(self) -> None:
        self._ensure_active()
        if not all((self.repo, self.python, self.ipa, self.credential)):
            raise core.WorkflowError("Missing FairPlay inputs; retrieve credentials first.")
        self.run_job("Decrypting encrypted IPA", lambda: core.decrypt_ipa(
            self.repo, self.python, self.ipa, self.credential, self.workspace, self.runner),
            self.decrypt_complete, retry=self.decrypt)

    def decrypt_complete(self, path: Path) -> None:
        self.staged = path
        self.mark("decrypt")
        self.go("export")

    def page_export(self) -> None:
        if not self.ipa:
            self._heading("Export", "No source IPA selected")
            return
        default = self.ipa.with_name(self.ipa.stem + ("_ios15" if self.patch else "_decrypted") + ".ipa")
        self._heading("Export and verify IPA", "Copy the final IPA to any Mac volume, including an external exFAT SSD.")
        self._card(
            _label("Destination", "cardTitle"),
            self._text_input("output", "Choose a new, unused .ipa filename", str(default)),
            self._buttons(("Export IPA", self.export, True),
                          ("Choose file…", self.choose_export_path, False)),
            self._buttons(("Find unused name", self.unique_export, False)),
            _label("Output is checked for archive integrity; your original IPA will not be overwritten.", "fineText"),
            _label("iOS minimum: " + ("15.0 (metadata change only)" if self.patch else "preserve original"), "fineText"),
        )

    def choose_export_path(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export IPA", self.fields.get("output", str(Path.home() / "Downloads")), "IPA archive (*.ipa)")
        if path:
            self.fields["output"] = path
            self.go("export")

    def unique_export(self) -> None:
        self.fields["output"] = str(core.unique_ipa_path(core.safe_ipa_path(self.fields.get("output", ""))))
        self.go("export")

    def export(self) -> None:
        self._ensure_active()
        target = core.safe_ipa_path(self.fields.get("output", ""))
        if target.exists() or target.is_symlink():
            self.fail("The output path already exists. Choose an unused name or another destination.",
                      retry=self.export, alternatives=[("Find unused name", self.unique_export)])
            return
        if not self.staged or not self.inspection or not self.ipa:
            raise core.WorkflowError("There is no processed IPA ready to export.")
        if target.resolve() == self.ipa.resolve():
            raise core.WorkflowError("Input and output IPA paths must differ.")
        def task() -> Path:
            source = self.staged
            if self.patch:
                patched = self.workspace / "ios15-final-working.ipa"
                patched.unlink(missing_ok=True)
                core.set_min_ios(source, patched, self.inspection.app_rel)
                source = patched
            core.exclusive_verified_copy(source, target)
            return target
        self.run_job("Writing and verifying final IPA", task, self.export_complete, retry=self.export,
                     alternatives=[("Find unused name", self.unique_export)])

    def export_complete(self, path: Path) -> None:
        self.final = path
        self.mark("export", "done")
        self.go("done")

    def page_done(self) -> None:
        self._heading("IPA is ready", "Export completed with ZIP integrity verification.", tag="ASSESSMENT COMPLETE")
        self._card(
            _label("✓  Completed successfully", "positiveText"),
            _label(str(self.final or ""), "value"),
            _label("Original minimum iOS: " + (self.inspection.min_ios if self.inspection else "unknown")),
            _label("Final minimum iOS: " + ("15.0 (metadata only)" if self.patch else "unchanged")),
            _label("If you changed Info.plist, the original signature is no longer valid. Re-signing and runtime compatibility are separate steps.", "fineText"),
            self._buttons(("Start another", self.reset_session, True),
                          ("Reveal in Finder", self.reveal_final, False)),
        )

    def reveal_final(self) -> None:
        if self.final:
            subprocess.Popen(["open", "-R", str(self.final)])

    def reset_session(self) -> None:
        if self.tunnel:
            self.tunnel.stop()
            self.tunnel = None
        self.workspace_obj.cleanup()
        self.workspace_obj = tempfile.TemporaryDirectory(prefix="ipa-lab-private-")
        self.workspace = Path(self.workspace_obj.name)
        self.workspace.chmod(0o700)
        self.done_steps = {"source"}
        self.ipa = self.inspection = self.credential = self.staged = self.final = None
        self.patch = False
        self.udid = ""
        self.fields.pop("output", None)
        self.go("source")

    def dragEnterEvent(self, event: Any) -> None:
        if event.mimeData().hasUrls() and any(url.toLocalFile().lower().endswith(".ipa") for url in event.mimeData().urls()):
            event.acceptProposedAction()

    def dropEvent(self, event: Any) -> None:
        for url in event.mimeData().urls():
            local = url.toLocalFile()
            if local.lower().endswith(".ipa"):
                self.fields["local"] = local
                if not self.busy:
                    self.safe(self.use_local)
                event.acceptProposedAction()
                return

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.busy:
            reply = QMessageBox.question(self, "Close IPA Lab?",
                                         "A task is running. Cancel it and close the workspace?\nAny temporary credential will be removed.")
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.runner.stop_all()
            if self.job is not None and not self.job.wait(5000):
                self.status("Cancellation in progress; close after the task stops.")
                event.ignore()
                return
        self._closed = True
        self.auto_wait_timer.stop()
        self.pulse.stop()
        if self.tunnel:
            self.tunnel.stop()
            self.tunnel = None
        self.workspace_obj.cleanup()
        event.accept()


def launch(*, local_ipa: Path | None = None, fairplay_repo: Path | None = None,
           port: int = 2222, demo: bool = False) -> int:
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("IPA Lab")
    app.setOrganizationName("IPA Lab")
    window = LabWindow(local_ipa=local_ipa, fairplay_repo=fairplay_repo, port=port, demo=demo)
    window.show()
    return app.exec()
