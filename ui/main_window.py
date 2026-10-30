import os
import platform
import threading
import traceback
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import quote
import psutil

from PySide6.QtCore import Qt, QThread, Signal, QRect, QUrl
from PySide6.QtGui import QColor, QPainter, QPen, QIcon, QDesktopServices
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QStackedWidget, QCheckBox, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QMessageBox, QProgressBar, QSplitter, QListWidget, QListWidgetItem,
    QAbstractItemView, QScrollArea, QSizeGrip, QDialog
)

from core.self_shield import verify_core_integrity, compute_file_sha256, BASELINE_FILE_NAME
from core.ackerman_cleaner import (
    get_available_drives, scan_all_ackerman_categories,
    execute_ackerman_purge, format_bytes
)
from core.inosuke_uninstaller import (
    InstalledApp, scan_installed_applications, scan_orphaned_appdata_ghosts,
    trigger_native_uninstaller, is_app_still_registered, shred_app_leftovers
)
from core.bravo_edr import (
    run_bravo_six_edr_sweep, calculate_shannon_entropy,
    quarantine_suspicious_file, get_quarantined_items,
    restore_quarantined_file, ThreatFinding
)


# =====================================================================
# CREATOR CONTACT & PROFESSIONAL SUPPORT CONFIGURATION
# =====================================================================

CREATOR_NAME = "Jyotipriyo Saha"
CREATOR_EMAIL = "sjyotipriyo@gmail.com"
CREATOR_LINKEDIN = "https://www.linkedin.com/in/jyotipriyo-saha-575652380/"
CREATOR_GITHUB = "https://github.com/sjyotipriyo-droid"


# =====================================================================
# PIXEL-PERFECT WINDOWS 11 VECTOR CAPTION BUTTONS
# =====================================================================

class WindowCaptionButton(QPushButton):
    """
    Custom-painted vector window control button (Minimize, Maximize/Restore, Close)
    with crisp geometric lines and smooth luxury hover states.
    """
    def __init__(self, role: str, parent_window: QMainWindow):
        super().__init__()
        self.role = role  # "min", "max", "close"
        self.parent_window = parent_window
        self.setFixedSize(46, 40)
        self.setCursor(Qt.PointingHandCursor)
        self._hovered = False

        if role == "min":
            self.setToolTip("Minimize Window to Taskbar")
        elif role == "max":
            self.setToolTip("Maximize / Restore Window Size")
        elif role == "close":
            self.setToolTip("Safely Close GhostBlade-141")

    def enterEvent(self, event):
        self._hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing, False)

        if self._hovered:
            if self.role == "close":
                p.fillRect(self.rect(), QColor("#C42B1C"))
            else:
                p.fillRect(self.rect(), QColor("#1F222A"))

        pen_col = QColor("#FFFFFF") if self._hovered else QColor("#9CA3AF")
        pen = QPen(pen_col, 1)
        p.setPen(pen)

        cx = self.width() // 2
        cy = self.height() // 2

        if self.role == "min":
            p.drawLine(cx - 5, cy, cx + 5, cy)

        elif self.role == "max":
            if self.parent_window.isMaximized():
                p.drawRect(cx - 3, cy - 5, 8, 8)
                p.fillRect(cx - 5, cy - 3, 8, 8, QColor("#1F222A") if self._hovered else QColor("#08090B"))
                p.drawRect(cx - 5, cy - 3, 8, 8)
            else:
                p.drawRect(cx - 5, cy - 5, 10, 10)

        elif self.role == "close":
            p.setRenderHint(QPainter.Antialiasing, True)
            p.setPen(QPen(pen_col, 1.5))
            p.drawLine(cx - 5, cy - 5, cx + 5, cy + 5)
            p.drawLine(cx + 5, cy - 5, cx - 5, cy + 5)

        p.end()


# =====================================================================
# CANCELLABLE, EXCEPTION-SAFE BACKGROUND WORKER THREADS
# =====================================================================

class BaseCancelWorker(QThread):
    error_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.cancel_event = threading.Event()

    def request_cancel(self):
        self.cancel_event.set()


class AckermanScanWorker(BaseCancelWorker):
    finished_signal = Signal(int, object)

    def __init__(self, req_id: int, drive_root: str):
        super().__init__()
        self.req_id = req_id
        self.drive_root = drive_root

    def run(self):
        try:
            data = scan_all_ackerman_categories(self.drive_root, cancel_event=self.cancel_event)
            if not self.cancel_event.is_set():
                self.finished_signal.emit(self.req_id, data)
        except Exception:
            self.error_signal.emit(traceback.format_exc(limit=2))


class AckermanPurgeWorker(BaseCancelWorker):
    finished_signal = Signal(object)

    def __init__(self, selected_ids: List[str], drive_root: str, snapshot: Dict[str, dict]):
        super().__init__()
        self.selected_ids = selected_ids
        self.drive_root = drive_root
        self.snapshot = snapshot

    def run(self):
        try:
            res = execute_ackerman_purge(
                self.selected_ids,
                self.drive_root,
                approved_scan_snapshot=self.snapshot,
                cancel_event=self.cancel_event
            )
            self.finished_signal.emit(res)
        except Exception:
            self.error_signal.emit(traceback.format_exc(limit=2))


class InosukeScanWorker(BaseCancelWorker):
    finished_signal = Signal(object, object)

    def run(self):
        try:
            apps = scan_installed_applications(calculate_footprints=True, cancel_event=self.cancel_event)
            ghosts = scan_orphaned_appdata_ghosts(apps, cancel_event=self.cancel_event)
            if not self.cancel_event.is_set():
                self.finished_signal.emit(apps, ghosts)
        except Exception:
            self.error_signal.emit(traceback.format_exc(limit=2))


class LeftoverDeleteWorker(BaseCancelWorker):
    finished_signal = Signal(object)

    def __init__(self, paths: List[Path]):
        super().__init__()
        self.paths = paths

    def run(self):
        try:
            res = shred_app_leftovers(self.paths, cancel_event=self.cancel_event)
            self.finished_signal.emit(res)
        except Exception:
            self.error_signal.emit(traceback.format_exc(limit=2))


class BravoSixScanWorker(BaseCancelWorker):
    finished_signal = Signal(object)

    def run(self):
        try:
            report = run_bravo_six_edr_sweep(cancel_event=self.cancel_event)
            if not self.cancel_event.is_set():
                self.finished_signal.emit(report)
        except Exception:
            self.error_signal.emit(traceback.format_exc(limit=2))


class ForensicFileWorker(BaseCancelWorker):
    finished_signal = Signal(object)

    def __init__(self, filepath: Path):
        super().__init__()
        self.filepath = filepath

    def run(self):
        try:
            if not self.filepath.exists():
                self.finished_signal.emit({"error": "File no longer exists."})
                return
            size_str = format_bytes(self.filepath.stat().st_size)
            entropy, ent_status = calculate_shannon_entropy(self.filepath)
            sha256, hash_status = compute_file_sha256(self.filepath)
            self.finished_signal.emit({
                "name": self.filepath.name,
                "size": size_str,
                "entropy": entropy,
                "ent_status": ent_status,
                "sha256": sha256 if hash_status == "OK" else hash_status,
            })
        except Exception as exc:
            self.error_signal.emit(str(exc))


# =====================================================================
# LUXURY CLICKABLE CHECKBOX ROW
# =====================================================================

class TacticalCheckRow(QFrame):
    selected_signal = Signal(str)

    def __init__(self, cid: str, data: dict, is_checked: bool, accent_color: str):
        super().__init__()
        self.cid = cid
        self.data = data
        self.setObjectName("CheckRow")
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(
            f"Click anywhere on this card to check/uncheck '{data['title']}'.\n"
            f"What it does: {data['description']}"
        )

        hbox = QHBoxLayout(self)
        hbox.setContentsMargins(18, 13, 18, 13)
        hbox.setSpacing(16)

        self.checkbox = QCheckBox()
        self.checkbox.setChecked(is_checked)
        self.checkbox.toggled.connect(lambda _: self.selected_signal.emit(self.cid))
        hbox.addWidget(self.checkbox)

        mid_vbox = QVBoxLayout()
        mid_vbox.setSpacing(3)

        safety_badge = "SAFE DEFAULT" if data["default_checked"] else "OPTIONAL (OPT-IN)"
        tag_lbl = QLabel(f"{data['tag'].upper()}   •   [{safety_badge}]")
        tag_lbl.setTextFormat(Qt.PlainText)
        tag_lbl.setStyleSheet(f"color: {accent_color}; font-size: 10px; font-weight: 700;")

        title_lbl = QLabel(data["title"])
        title_lbl.setTextFormat(Qt.PlainText)
        title_lbl.setStyleSheet("color: #F4F4F6; font-size: 13px; font-weight: 600;")

        desc_lbl = QLabel(f"What this cleans: {data['description']}")
        desc_lbl.setTextFormat(Qt.PlainText)
        desc_lbl.setStyleSheet("color: #D1D5DB; font-size: 11px;")
        desc_lbl.setWordWrap(True)

        quote_lbl = QLabel(data["quote"])
        quote_lbl.setTextFormat(Qt.PlainText)
        quote_lbl.setStyleSheet("color: #8E9299; font-size: 10px; font-style: italic;")
        quote_lbl.setWordWrap(True)

        mid_vbox.addWidget(tag_lbl)
        mid_vbox.addWidget(title_lbl)
        mid_vbox.addWidget(desc_lbl)
        mid_vbox.addWidget(quote_lbl)
        hbox.addLayout(mid_vbox, 1)

        right_vbox = QVBoxLayout()
        right_vbox.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        size_lbl = QLabel(data["formatted_size"])
        size_lbl.setTextFormat(Qt.PlainText)
        size_lbl.setAlignment(Qt.AlignRight)
        size_col = accent_color if data["bytes"] > 0 else "#6B7280"
        size_lbl.setStyleSheet(f"color: {size_col}; font-family: 'Consolas'; font-size: 15px; font-weight: bold;")

        cnt_lbl = QLabel(f"{data['file_count']} FILES")
        cnt_lbl.setTextFormat(Qt.PlainText)
        cnt_lbl.setAlignment(Qt.AlignRight)
        cnt_lbl.setStyleSheet("color: #9CA3AF; font-size: 10px; font-weight: 600;")

        right_vbox.addWidget(size_lbl)
        right_vbox.addWidget(cnt_lbl)
        hbox.addLayout(right_vbox)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.checkbox.setChecked(not self.checkbox.isChecked())
        super().mousePressEvent(event)


# =====================================================================
# SUPPORT & DEVELOPER CONTACT HUB DIALOG
# =====================================================================

class SupportCenterDialog(QDialog):
    """Luxury Developer Profile, Bug Reporting & Diagnostic Support Hub."""
    def __init__(self, parent: QMainWindow, accent: str, shield_status: dict):
        super().__init__(parent)
        self.shield_status = shield_status
        self.setWindowTitle("GHOSTBLADE-141 // SUPPORT & DEVELOPER CONTACT")
        self.setFixedSize(550, 400)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: #0B0C0E;
                border: 1px solid {accent};
            }}
            QLabel {{
                color: #E6E6E9;
                font-family: 'Segoe UI', sans-serif;
                background-color: transparent;
            }}
            QFrame#Card {{
                background-color: #121419;
                border: 1px solid #252830;
                border-left: 3px solid {accent};
                border-radius: 3px;
            }}
        """)

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(22, 20, 22, 20)
        vbox.setSpacing(14)

        card = QFrame()
        card.setObjectName("Card")
        c_vbox = QVBoxLayout(card)
        c_vbox.setContentsMargins(16, 14, 16, 14)
        c_vbox.setSpacing(4)

        title = QLabel("GHOSTBLADE-141  //  OFFICIAL SUPPORT & ARCHITECT PROFILE")
        title.setStyleSheet(f"color: {accent}; font-size: 12px; font-weight: 800;")

        name_lbl = QLabel(f"Lead Architect & Creator:  {CREATOR_NAME}")
        name_lbl.setStyleSheet("color: #FFFFFF; font-size: 15px; font-weight: 700;")

        role_lbl = QLabel("Cybersecurity & Systems Architecture  •  West Bengal, India")
        role_lbl.setStyleSheet("color: #9CA3AF; font-size: 11px;")

        c_vbox.addWidget(title)
        c_vbox.addWidget(name_lbl)
        c_vbox.addWidget(role_lbl)
        vbox.addWidget(card)

        info = QLabel(
            "Facing any issue, found a bug, or want to collaborate on a project?\n"
            "Reach out directly via Email or LinkedIn below. Clicking 'Report Issue via Email' "
            "automatically prepares basic OS & version diagnostics to help resolve your issue faster."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #D1D5DB; font-size: 11px;")
        vbox.addWidget(info)

        btn_email = QPushButton(f"✉   REPORT ISSUE / EMAIL CREATOR ({CREATOR_EMAIL})")
        btn_email.setObjectName("PrimaryExecuteBtn")
        btn_email.setCursor(Qt.PointingHandCursor)
        btn_email.clicked.connect(self._open_email_client)

        btn_linkedin = QPushButton("in   CONNECT WITH JYOTIPRIYO SAHA ON LINKEDIN")
        btn_linkedin.setObjectName("UtilityBtn")
        btn_linkedin.setCursor(Qt.PointingHandCursor)
        btn_linkedin.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(CREATOR_LINKEDIN)))

        row_btns = QHBoxLayout()
        btn_github = QPushButton("🌐  GITHUB / CHECK UPDATES")
        btn_github.setObjectName("UtilityBtn")
        btn_github.setCursor(Qt.PointingHandCursor)
        btn_github.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(CREATOR_GITHUB)))

        btn_diag = QPushButton("📥  SAVE DIAGNOSTIC LOG TO DESKTOP")
        btn_diag.setObjectName("UtilityBtn")
        btn_diag.setCursor(Qt.PointingHandCursor)
        btn_diag.clicked.connect(self._export_diagnostic_log)

        row_btns.addWidget(btn_github)
        row_btns.addWidget(btn_diag)

        vbox.addWidget(btn_email)
        vbox.addWidget(btn_linkedin)
        vbox.addLayout(row_btns)
        vbox.addStretch()

        btn_close = QPushButton("CLOSE SUPPORT WINDOW")
        btn_close.setObjectName("UtilityBtn")
        btn_close.clicked.connect(self.accept)
        vbox.addWidget(btn_close, 0, Qt.AlignRight)

    def _get_system_summary(self) -> str:
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 1)
        return (
            f"--- GhostBlade-141 Diagnostic Telemetry ---\n"
            f"App Version   : v1.0.0 (Signature Edition)\n"
            f"OS Platform   : {platform.system()} {platform.release()} ({platform.version()})\n"
            f"Architecture  : {platform.machine()}\n"
            f"System RAM    : {ram_gb} GB\n"
            f"Elevated Admin: {self.shield_status.get('admin_mode')}\n"
            f"DLL Guard     : {self.shield_status.get('dll_protection')}\n"
            f"Integrity     : {self.shield_status.get('integrity_status')}\n"
            f"-------------------------------------------\n\n"
            f"Describe your issue or feedback below:\n"
        )

    def _open_email_client(self):
        subject = quote("GhostBlade-141 v1.0.0 — Support / Feedback for Jyotipriyo Saha")
        body = quote(self._get_system_summary())
        mailto_url = f"mailto:{CREATOR_EMAIL}?subject={subject}&body={body}"
        QDesktopServices.openUrl(QUrl(mailto_url))

    def _export_diagnostic_log(self):
        desktop = Path(os.environ.get("USERPROFILE", ".")) / "Desktop"
        out_file = (desktop if desktop.exists() else Path(".")) / "GhostBlade141_Diagnostic_Report.txt"
        try:
            out_file.write_text(self._get_system_summary(), encoding="utf-8")
            QMessageBox.information(
                self,
                "Diagnostic Log Saved",
                f"Saved diagnostic report to:\n{out_file}\n\nYou can attach this file when emailing support."
            )
        except OSError as exc:
            QMessageBox.warning(self, "Export Error", f"Could not save log: {exc}")


# =====================================================================
# BESPOKE LUXURY HARDWARE PALETTES
# =====================================================================

THEMES = {
    "PRESTIGE // CHAMPAGNE GOLD": "#C5A059",
    "GHOST // BRUSHED TITANIUM": "#A3B1C6",
    "LEVI // IMPERIAL JADE": "#5E9E82",
    "DEADPOOL // VINTAGE CRIMSON": "#B84A54",
}

def build_stylesheet(accent: str) -> str:
    return f"""
    QMainWindow, QWidget {{
        background-color: #0B0C0E;
        color: #E6E6E9;
        font-family: 'Segoe UI', sans-serif;
        font-size: 12px;
    }}
    QLabel {{
        background-color: transparent;
    }}
    QToolTip {{
        background-color: #16181E;
        color: #F4F4F6;
        border: 1px solid {accent};
        padding: 6px 10px;
        font-size: 11px;
    }}
    QFrame#WindowBorder {{
        background-color: #0B0C0E;
        border: 1px solid #282B33;
    }}
    QFrame#TitleBar {{
        background-color: #08090B;
        border-bottom: 1px solid #1C1E23;
    }}
    QFrame#NavRibbon {{
        background-color: #0F1014;
        border-bottom: 1px solid #1F2228;
    }}
    QFrame#GuideStrip {{
        background-color: #101217;
        border: 1px solid #22252E;
        border-radius: 3px;
    }}
    QFrame#HeroBanner {{
        background-color: #13151A;
        border: 1px solid #23262E;
        border-left: 3px solid {accent};
        border-radius: 3px;
    }}
    QFrame#CheckRow {{
        background-color: #111317;
        border: 1px solid #1E2027;
        border-left: 2px solid #2A2D36;
        border-radius: 3px;
    }}
    QFrame#CheckRow:hover {{
        background-color: #16181E;
        border: 1px solid #2E323D;
        border-left: 2px solid {accent};
    }}
    QFrame#PanelBox {{
        background-color: #111317;
        border: 1px solid #22252C;
        border-radius: 3px;
    }}
    QFrame#StatusBar {{
        background-color: #08090B;
        border-top: 1px solid #1C1E23;
    }}
    QComboBox {{
        background-color: #15171C;
        color: #F4F4F6;
        border: 1px solid #2E323B;
        border-radius: 2px;
        padding: 5px 12px;
        font-weight: 600;
        font-size: 11px;
    }}
    QComboBox:hover {{
        border: 1px solid {accent};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 22px;
    }}
    QComboBox QAbstractItemView {{
        background-color: #121418;
        color: #F4F4F6;
        selection-background-color: {accent};
        selection-color: #0B0C0E;
        border: 1px solid #2E323B;
        font-size: 11px;
    }}
    QPushButton#TabBtn {{
        background-color: transparent;
        color: #9CA3AF;
        border: none;
        border-bottom: 2px solid transparent;
        padding: 13px 16px;
        font-weight: 700;
        font-size: 11px;
    }}
    QPushButton#TabBtn:hover {{
        color: #F4F4F6;
        background-color: #13151A;
    }}
    QPushButton#TabBtn[active="true"] {{
        color: {accent};
        background-color: #14161C;
        border-bottom: 2px solid {accent};
    }}
    QPushButton#PrimaryExecuteBtn {{
        background-color: {accent};
        color: #090A0C;
        border: 1px solid {accent};
        border-radius: 2px;
        padding: 10px 24px;
        font-weight: 700;
        font-size: 11px;
    }}
    QPushButton#PrimaryExecuteBtn:hover {{
        background-color: #F4F4F6;
        border: 1px solid #F4F4F6;
        color: #090A0C;
    }}
    QPushButton#PrimaryExecuteBtn:disabled {{
        background-color: #1C1E24;
        color: #6B7280;
        border: 1px solid #282B33;
    }}
    QPushButton#DangerExecuteBtn {{
        background-color: #2A1417;
        color: #FECDD3;
        border: 1px solid #881337;
        border-radius: 2px;
        padding: 9px 18px;
        font-weight: 600;
        font-size: 11px;
    }}
    QPushButton#DangerExecuteBtn:hover {{
        background-color: #881337;
        color: #FFFFFF;
        border: 1px solid #E11D48;
    }}
    QPushButton#DangerExecuteBtn:disabled {{
        background-color: #18181B;
        color: #52525B;
        border: 1px solid #27272A;
    }}
    QPushButton#UtilityBtn {{
        background-color: #16181E;
        color: #D1D5DB;
        border: 1px solid #2E323D;
        border-radius: 2px;
        padding: 6px 12px;
        font-weight: 600;
        font-size: 11px;
    }}
    QPushButton#UtilityBtn:hover {{
        background-color: #1E2129;
        color: #FFFFFF;
        border: 1px solid {accent};
    }}
    QPushButton#UtilityBtn:disabled {{
        color: #52525B;
        border: 1px solid #1F2229;
    }}
    QTableWidget, QListWidget {{
        background-color: #0E1013;
        border: 1px solid #1F2229;
        gridline-color: #17191E;
        color: #E5E7EB;
        font-size: 12px;
        selection-background-color: #1C1F26;
        selection-color: {accent};
    }}
    QHeaderView::section {{
        background-color: #13151A;
        color: #9CA3AF;
        padding: 9px 12px;
        border: none;
        border-bottom: 1px solid #252830;
        border-right: 1px solid #181A20;
        font-weight: 700;
        font-size: 10px;
    }}
    QProgressBar {{
        background-color: #14161B;
        border: 1px solid #282B33;
        border-radius: 2px;
        height: 16px;
        text-align: center;
        font-family: 'Consolas';
        font-size: 10px;
        font-weight: bold;
        color: #F4F4F6;
    }}
    QProgressBar::chunk {{
        background-color: {accent};
    }}
    QCheckBox::indicator {{
        width: 17px;
        height: 17px;
        border: 1px solid #6B7280;
        border-radius: 2px;
        background-color: #0B0C0E;
    }}
    QCheckBox::indicator:hover {{
        border: 1px solid {accent};
    }}
    QCheckBox::indicator:checked {{
        background-color: {accent};
        border: 1px solid {accent};
    }}
    """


class GhostBladeMainWindow(QMainWindow):
    def __init__(self, base_dir: Path):
        super().__init__()
        self.base_dir = base_dir
        self.shield_status = verify_core_integrity(base_dir)
        self.current_accent = "#C5A059"
        self.selected_drive = get_available_drives()[0]
        self.ackerman_data: Dict[str, dict] = {}
        self.user_check_states: Dict[str, bool] = {}
        self.check_rows: Dict[str, TacticalCheckRow] = {}
        self.installed_apps: List[InstalledApp] = []
        self.app_lookup: Dict[str, InstalledApp] = {}
        self.ghost_folders: List[dict] = []
        self.selected_app: Optional[InstalledApp] = None

        self._active_workers: List[BaseCancelWorker] = []
        self._scan_request_seq = 0
        self._purging_active = False
        self._inosuke_scanning = False
        self._edr_scanning = False

        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowSystemMenuHint | Qt.WindowMinimizeButtonHint)
        self.setWindowTitle("GHOSTBLADE-141 // BY JYOTIPRIYO SAHA")
        icon_file = base_dir / "assets" / "ghostblade.ico"
        if icon_file.exists():
            self.setWindowIcon(QIcon(str(icon_file)))

        self.resize(1280, 820)
        self.setMinimumSize(1020, 680)
        self.setStyleSheet(build_stylesheet(self.current_accent))

        self._build_ui()
        self.trigger_ackerman_scan()

    def _register_worker(self, worker: BaseCancelWorker):
        self._active_workers.append(worker)
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))
        worker.start()

    def _cleanup_worker(self, worker: BaseCancelWorker):
        if worker in self._active_workers:
            self._active_workers.remove(worker)
        worker.wait(500)
        worker.deleteLater()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and event.position().y() < 42:
            win_handle = self.windowHandle()
            if win_handle is not None:
                win_handle.startSystemMove()
            event.accept()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton and event.position().y() < 42:
            self._toggle_max_restore()
            event.accept()

    def _toggle_max_restore(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        self.btn_max.update()

    def _build_ui(self):
        outer = QFrame()
        outer.setObjectName("WindowBorder")
        self.setCentralWidget(outer)
        root_vbox = QVBoxLayout(outer)
        root_vbox.setContentsMargins(1, 1, 1, 1)
        root_vbox.setSpacing(0)

        # 1. LUXURY STEALTH HEADER BAR WITH VECTOR CAPTION BUTTONS & SUPPORT HUB
        title_bar = QFrame()
        title_bar.setObjectName("TitleBar")
        title_bar.setFixedHeight(40)
        tb_hbox = QHBoxLayout(title_bar)
        tb_hbox.setContentsMargins(16, 0, 0, 0)
        tb_hbox.setSpacing(8)

        self.brand_badge = QLabel("GHOSTBLADE // 141")
        self.brand_badge.setStyleSheet(f"color: {self.current_accent}; font-weight: 800; font-size: 13px;")

        sub_lbl = QLabel("SIGNATURE EDITION  •  BY JYOTIPRIYO SAHA")
        sub_lbl.setStyleSheet("color: #9CA3AF; font-weight: 700; font-size: 10px;")

        btn_guide = QPushButton("? HOW TO USE")
        btn_guide.setObjectName("UtilityBtn")
        btn_guide.setToolTip("Click here for a simple, step-by-step explanation of every tool in GhostBlade-141.")
        btn_guide.clicked.connect(self._show_quickstart_guide)

        btn_support = QPushButton("✉ CONTACT & SUPPORT")
        btn_support.setObjectName("UtilityBtn")
        btn_support.setToolTip("Having trouble? Contact Jyotipriyo Saha via Email, LinkedIn, or export a diagnostic log.")
        btn_support.clicked.connect(lambda: SupportCenterDialog(self, self.current_accent, self.shield_status).exec())

        btn_license = QPushButton("LICENSE & EULA")
        btn_license.setObjectName("UtilityBtn")
        btn_license.setToolTip("View Open-Source MIT License and Legal Terms by Jyotipriyo Saha.")
        btn_license.clicked.connect(self._show_license_modal)

        theme_lbl = QLabel("THEME:")
        theme_lbl.setStyleSheet("color: #9CA3AF; font-size: 10px; font-weight: 700;")

        self.theme_combo = QComboBox()
        self.theme_combo.setToolTip("Switch the luxury color finish of the application.")
        for tname in THEMES.keys():
            self.theme_combo.addItem(tname)
        self.theme_combo.currentTextChanged.connect(self._on_theme_changed)

        self.btn_min = WindowCaptionButton("min", self)
        self.btn_min.clicked.connect(self.showMinimized)

        self.btn_max = WindowCaptionButton("max", self)
        self.btn_max.clicked.connect(self._toggle_max_restore)

        self.btn_close = WindowCaptionButton("close", self)
        self.btn_close.clicked.connect(self.close)

        tb_hbox.addWidget(self.brand_badge)
        tb_hbox.addWidget(sub_lbl)
        tb_hbox.addStretch()
        tb_hbox.addWidget(btn_guide)
        tb_hbox.addWidget(btn_support)
        tb_hbox.addWidget(btn_license)
        tb_hbox.addSpacing(4)
        tb_hbox.addWidget(theme_lbl)
        tb_hbox.addWidget(self.theme_combo)
        tb_hbox.addSpacing(6)
        tb_hbox.addWidget(self.btn_min)
        tb_hbox.addWidget(self.btn_max)
        tb_hbox.addWidget(self.btn_close)
        root_vbox.addWidget(title_bar)

        # 2. SELF-EXPLANATORY NAVIGATION RIBBON + DRIVE DROPDOWN
        nav_ribbon = QFrame()
        nav_ribbon.setObjectName("NavRibbon")
        nav_ribbon.setFixedHeight(48)
        nav_hbox = QHBoxLayout(nav_ribbon)
        nav_hbox.setContentsMargins(14, 0, 18, 0)
        nav_hbox.setSpacing(4)

        self.tab_buttons = []
        tabs = [
            ("01  JUNK CLEANER (ACKERMAN)", 0, "Clean temporary files, browser cache, crash dumps, and GPU shader cache."),
            ("02  APP UNINSTALLER (INOSUKE)", 1, "Uninstall programs and remove hidden leftover folders in AppData."),
            ("03  MALWARE & SECURITY SCAN (EDR)", 2, "Scan for suspicious startup entries, imposter processes, and risky files."),
            ("04  FILE VAULT & INTEGRITY", 3, "Verify app security hashes or restore quarantined files with 1 click."),
        ]
        for text, idx, tip in tabs:
            b = QPushButton(text)
            b.setObjectName("TabBtn")
            b.setToolTip(tip)
            b.setProperty("active", "true" if idx == 0 else "false")
            b.clicked.connect(lambda checked=False, i=idx: self._switch_deck(i))
            nav_hbox.addWidget(b)
            self.tab_buttons.append(b)

        nav_hbox.addStretch()

        drv_lbl = QLabel("SELECT DRIVE:")
        drv_lbl.setStyleSheet("color: #9CA3AF; font-size: 10px; font-weight: 700;")

        self.drive_combo = QComboBox()
        self.drive_combo.setMinimumWidth(115)
        self.drive_combo.setToolTip("Choose which hard drive partition (C:\\, D:\\, etc.) you want to scan and clean.")
        for d in get_available_drives():
            self.drive_combo.addItem(f"DRIVE {d}", d)
        self.drive_combo.currentIndexChanged.connect(self._on_drive_changed)

        self.drive_bar = QProgressBar()
        self.drive_bar.setFixedWidth(235)
        self.drive_bar.setToolTip("Shows how much space is currently used and free on the selected drive.")
        self._update_drive_gauge()

        nav_hbox.addWidget(drv_lbl)
        nav_hbox.addWidget(self.drive_combo)
        nav_hbox.addSpacing(8)
        nav_hbox.addWidget(self.drive_bar)
        root_vbox.addWidget(nav_ribbon)

        # 3. MAIN WORKSPACE STACK
        self.deck = QStackedWidget()
        self.deck.addWidget(self._create_ackerman_deck())
        self.deck.addWidget(self._create_inosuke_deck())
        self.deck.addWidget(self._create_bravo_six_deck())
        self.deck.addWidget(self._create_shield_deck())
        root_vbox.addWidget(self.deck, 1)

        # 4. BOTTOM STATUS BAR + NATIVE RESIZE GRIP
        status_bar = QFrame()
        status_bar.setObjectName("StatusBar")
        status_bar.setFixedHeight(36)
        sb_hbox = QHBoxLayout(status_bar)
        sb_hbox.setContentsMargins(18, 0, 6, 0)

        self.dp_tag = QLabel("LIVE ASSISTANT //")
        self.dp_tag.setStyleSheet(f"color: {self.current_accent}; font-weight: 700; font-size: 11px;")

        self.comm_text = QLabel("Welcome! Hover your mouse over any button to see what it does, or click '✉ CONTACT & SUPPORT' above.")
        self.comm_text.setTextFormat(Qt.PlainText)
        self.comm_text.setStyleSheet("color: #D1D5DB; font-size: 11px;")

        priv_mode = "ADMIN MODE (FULL ACCESS)" if self.shield_status["admin_mode"] else "STANDARD USER MODE"
        fps_note = QLabel(f"ARCHITECT: JYOTIPRIYO SAHA  |  {priv_mode}")
        fps_note.setStyleSheet("color: #9CA3AF; font-size: 10px; font-weight: 700;")

        size_grip = QSizeGrip(status_bar)
        size_grip.setFixedSize(16, 16)
        size_grip.setToolTip("Drag corner to resize window")

        sb_hbox.addWidget(self.dp_tag)
        sb_hbox.addSpacing(8)
        sb_hbox.addWidget(self.comm_text, 1)
        sb_hbox.addWidget(fps_note)
        sb_hbox.addSpacing(8)
        sb_hbox.addWidget(size_grip, 0, Qt.AlignBottom | Qt.AlignRight)
        root_vbox.addWidget(status_bar)

    def _make_step_guide_strip(self, step1: str, step2: str, step3: str) -> QFrame:
        strip = QFrame()
        strip.setObjectName("GuideStrip")
        hbox = QHBoxLayout(strip)
        hbox.setContentsMargins(14, 8, 14, 8)
        hbox.setSpacing(16)

        for idx, text in enumerate([step1, step2, step3], start=1):
            lbl = QLabel(f"STEP {idx}:  {text}")
            lbl.setTextFormat(Qt.PlainText)
            lbl.setStyleSheet("color: #D1D5DB; font-size: 11px; font-weight: 600;")
            hbox.addWidget(lbl, 1)
        return strip

    def _show_quickstart_guide(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("GHOSTBLADE-141 // USER GUIDE (HOW EVERYTHING WORKS)")
        msg.setTextFormat(Qt.PlainText)
        msg.setText(
            "WELCOME TO GHOSTBLADE-141 (Created by Jyotipriyo Saha)\n"
            "Here is how each of the 4 tabs works in plain English:\n\n"
            "1. [01 JUNK CLEANER (ACKERMAN)]:\n"
            "   • What it does: Finds temporary junk files, crash reports, and browser caches taking up space.\n"
            "   • How to use: Choose your Drive (C:\\ or D:\\) at the top right -> Check the boxes you want to clean on the left -> Click 'CLEAN SELECTED JUNK NOW' at the bottom right.\n\n"
            "2. [02 APP UNINSTALLER (INOSUKE)]:\n"
            "   • What it does: Normal uninstallers leave hidden folders behind in AppData. This tool finds them.\n"
            "   • How to use: Click an app in the left table -> Click 'STEP 1: LAUNCH OFFICIAL UNINSTALLER' -> Wait for it to finish uninstalling -> Click 'STEP 2: DELETE LEFTOVER APPDATA'.\n\n"
            "3. [03 MALWARE & SECURITY SCAN (EDR)]:\n"
            "   • What it does: Checks if any suspicious program is hiding in your Windows Startup, masquerading as a system file, or using backdoor network ports.\n"
            "   • How to use: Click 'START FULL SECURITY SCAN'. You can also click 'CHECK SINGLE FILE' to test any suspicious downloaded file.\n\n"
            "4. [04 FILE VAULT & INTEGRITY]:\n"
            "   • What it does: Verifies that GhostBlade-141's own code hasn't been tampered with, and lets you restore any quarantined file back to its original folder with 1 click."
        )
        msg.exec()

    def _show_license_modal(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("GHOSTBLADE-141 // OPEN-SOURCE LICENSE & DISCLAIMER")
        msg.setTextFormat(Qt.PlainText)
        msg.setText(
            "GHOSTBLADE-141 (SIGNATURE EDITION)\n"
            "Copyright (c) 2026 Jyotipriyo Saha. All Rights Reserved.\n"
            "Licensed under the Open-Source MIT License.\n\n"
            "LEGAL DISCLAIMER & TERMS OF USE:\n"
            "1. GhostBlade-141 is provided 'AS IS' without warranty of any kind.\n"
            "2. High-impact cleanup modules (GPU Shader Cache, Developer Caches, Secondary Drive Sweeps, "
            "and Recycle Bin) are opt-in (unchecked by default).\n"
            "3. Always verify target paths in the right-hand preview panel before executing a cleanup "
            "or removing application AppData directories.\n"
            "4. Built with Python, PySide6 (Qt6 LGPLv3), and psutil (BSD-3-Clause)."
        )
        msg.exec()

    def _on_theme_changed(self, theme_name: str):
        for cid, rw in self.check_rows.items():
            self.user_check_states[cid] = rw.checkbox.isChecked()

        self.current_accent = THEMES.get(theme_name, "#C5A059")
        self.setStyleSheet(build_stylesheet(self.current_accent))
        self.brand_badge.setStyleSheet(f"color: {self.current_accent}; font-weight: 800; font-size: 13px;")
        self.dp_tag.setStyleSheet(f"color: {self.current_accent}; font-weight: 700; font-size: 11px;")
        self.ack_total_lbl.setStyleSheet(f"color: {self.current_accent}; font-family: 'Consolas'; font-weight: bold; font-size: 14px;")
        self.xray_hdr.setStyleSheet(f"color: {self.current_accent}; font-weight: 700; font-size: 12px;")
        self.edr_badge.setStyleSheet(f"color: {self.current_accent}; font-family: 'Consolas'; font-weight: bold; font-size: 12px;")
        self._rebuild_ackerman_rows_ui()

    def _on_drive_changed(self, index: int):
        if self._purging_active:
            return
        drv = self.drive_combo.itemData(index)
        if drv and drv != self.selected_drive:
            self.selected_drive = drv
            self.user_check_states.clear()
            self._update_drive_gauge()
            self._log_comm(f"Switched active drive to {drv}. Scanning {drv} for reclaimable junk files...")
            self.trigger_ackerman_scan()

    def _update_drive_gauge(self):
        try:
            u = psutil.disk_usage(self.selected_drive)
            free_gb = u.free / (1024 ** 3)
            self.drive_bar.setValue(int(u.percent))
            self.drive_bar.setFormat(f"{self.selected_drive}  {u.percent:.1f}% USED  ({free_gb:.1f} GB FREE)")
        except OSError:
            self.drive_bar.setValue(0)
            self.drive_bar.setFormat(f"{self.selected_drive} N/A")

    def _log_comm(self, text: str):
        self.comm_text.setText(text)

    def _switch_deck(self, idx: int):
        self.deck.setCurrentIndex(idx)
        for i, b in enumerate(self.tab_buttons):
            b.setProperty("active", "true" if i == idx else "false")
            b.style().unpolish(b)
            b.style().polish(b)

        if idx == 0:
            self._log_comm("JUNK CLEANER: Check the categories you want to clean on the left, preview their folders on the right, then click 'CLEAN SELECTED JUNK NOW'.")
        elif idx == 1:
            self._log_comm("APP UNINSTALLER: Select any app on the left -> Click Step 1 to run its uninstaller -> Click Step 2 afterwards to remove leftover AppData.")
            if not self.installed_apps and not self._inosuke_scanning:
                self.trigger_inosuke_scan()
        elif idx == 2:
            self._log_comm("SECURITY SCANNER: Click 'START FULL SECURITY SCAN' below to check your running processes, startup programs, and network connections.")
        elif idx == 3:
            self._refresh_shield_and_vault_ui()
            self._log_comm("FILE VAULT & INTEGRITY: View GhostBlade-141's own file security status or restore any quarantined file back to its original location.")

    # =====================================================================
    # DECK 01: JUNK CLEANER (ACKERMAN PURGE)
    # =====================================================================

    def _create_ackerman_deck(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(18, 14, 18, 14)
        vbox.setSpacing(10)

        hero = QFrame()
        hero.setObjectName("HeroBanner")
        h_hbox = QHBoxLayout(hero)
        h_hbox.setContentsMargins(18, 12, 18, 12)

        h_left = QVBoxLayout()
        h_left.setSpacing(2)
        h_title = QLabel("STORAGE & SHADER JUNK CLEANER (CAPTAIN LEVI PROTOCOL)  •  BY JYOTIPRIYO SAHA")
        h_title.setStyleSheet("color: #F4F4F6; font-weight: 700; font-size: 13px;")
        h_quote = QLabel("Safely removes temporary caches, crash logs, and browser clutter without touching your personal documents or game saves.")
        h_quote.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        h_left.addWidget(h_title)
        h_left.addWidget(h_quote)

        self.ack_total_lbl = QLabel("SCANNING DRIVE...")
        self.ack_total_lbl.setStyleSheet(f"color: {self.current_accent}; font-family: 'Consolas'; font-weight: bold; font-size: 14px;")

        h_hbox.addLayout(h_left)
        h_hbox.addStretch()
        h_hbox.addWidget(self.ack_total_lbl)
        vbox.addWidget(hero)

        vbox.addWidget(self._make_step_guide_strip(
            "Check or uncheck the junk categories on the left list.",
            "Click any category to preview the exact folders on the right.",
            "Click 'CLEAN SELECTED JUNK NOW' at the bottom right to free up space."
        ))

        splitter = QSplitter(Qt.Horizontal)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: 1px solid #1E2027; background-color: #0D0E12; }")
        self.rows_container = QWidget()
        self.rows_layout = QVBoxLayout(self.rows_container)
        self.rows_layout.setContentsMargins(12, 12, 12, 12)
        self.rows_layout.setSpacing(8)
        scroll.setWidget(self.rows_container)
        splitter.addWidget(scroll)

        insp = QFrame()
        insp.setObjectName("PanelBox")
        i_vbox = QVBoxLayout(insp)
        i_vbox.setContentsMargins(16, 14, 16, 14)
        i_vbox.setSpacing(8)

        sel_btns = QHBoxLayout()
        btn_all = QPushButton("CHECK SAFE DEFAULTS")
        btn_all.setObjectName("UtilityBtn")
        btn_all.setToolTip("Checks only the 100% safe everyday junk categories (temp files, crash dumps, browser cache).")
        btn_all.clicked.connect(self._select_safe_defaults)

        btn_none = QPushButton("UNCHECK ALL")
        btn_none.setObjectName("UtilityBtn")
        btn_none.setToolTip("Unchecks every box so you can pick just one specific category.")
        btn_none.clicked.connect(lambda: self._set_all_checks(False))

        sel_btns.addWidget(btn_all)
        sel_btns.addWidget(btn_none)

        i_hdr = QLabel("FOLDER PREVIEW  //  WHAT WILL BE CLEANED")
        i_hdr.setStyleSheet("color: #9CA3AF; font-weight: 700; font-size: 10px;")

        self.ack_detail_title = QLabel("Click any category on the left to see its details.")
        self.ack_detail_title.setTextFormat(Qt.PlainText)
        self.ack_detail_title.setStyleSheet("color: #F4F4F6; font-weight: 700; font-size: 13px;")
        self.ack_detail_title.setWordWrap(True)

        self.ack_detail_desc = QLabel("")
        self.ack_detail_desc.setTextFormat(Qt.PlainText)
        self.ack_detail_desc.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        self.ack_detail_desc.setWordWrap(True)

        self.ack_path_list = QListWidget()
        self.ack_path_list.setToolTip("These are the exact folders or files on your drive that belong to the selected category.")

        i_vbox.addLayout(sel_btns)
        i_vbox.addSpacing(4)
        i_vbox.addWidget(i_hdr)
        i_vbox.addWidget(self.ack_detail_title)
        i_vbox.addWidget(self.ack_detail_desc)
        i_vbox.addWidget(QLabel("EXACT FOLDERS / FILES FOUND ON THIS DRIVE:"))
        i_vbox.addWidget(self.ack_path_list, 1)
        splitter.addWidget(insp)
        splitter.setSizes([770, 450])
        vbox.addWidget(splitter, 1)

        act_hbox = QHBoxLayout()
        self.btn_ack_rescan = QPushButton("RE-SCAN CURRENT DRIVE")
        self.btn_ack_rescan.setObjectName("UtilityBtn")
        self.btn_ack_rescan.setToolTip("Scan the current drive again to refresh file sizes.")
        self.btn_ack_rescan.clicked.connect(self.trigger_ackerman_scan)

        self.btn_ack_purge = QPushButton("CLEAN SELECTED JUNK NOW (EXECUTE PURGE)")
        self.btn_ack_purge.setObjectName("PrimaryExecuteBtn")
        self.btn_ack_purge.setToolTip("Deletes the junk files inside the categories you have checked on the left (asks for confirmation first).")
        self.btn_ack_purge.clicked.connect(self.trigger_ackerman_purge)

        act_hbox.addWidget(self.btn_ack_rescan)
        act_hbox.addStretch()
        act_hbox.addWidget(self.btn_ack_purge)
        vbox.addLayout(act_hbox)
        return w

    def _select_safe_defaults(self):
        for cid, rw in self.check_rows.items():
            default_state = self.ackerman_data.get(cid, {}).get("default_checked", False)
            rw.checkbox.setChecked(default_state)
            self.user_check_states[cid] = default_state

    def _set_all_checks(self, state: bool):
        for cid, rw in self.check_rows.items():
            rw.checkbox.setChecked(state)
            self.user_check_states[cid] = state

    def trigger_ackerman_scan(self):
        if self._purging_active:
            return
        for w in list(self._active_workers):
            if isinstance(w, AckermanScanWorker):
                w.request_cancel()

        self._scan_request_seq += 1
        req_id = self._scan_request_seq
        self.btn_ack_rescan.setEnabled(False)
        self.btn_ack_purge.setEnabled(False)
        self.ack_total_lbl.setText(f"SCANNING {self.selected_drive} ...")

        worker = AckermanScanWorker(req_id, self.selected_drive)
        worker.finished_signal.connect(self._on_ackerman_scan_done)
        worker.error_signal.connect(self._on_ackerman_worker_error)
        self._register_worker(worker)

    def _on_ackerman_worker_error(self, err_msg: str):
        self._purging_active = False
        self.drive_combo.setEnabled(True)
        self.btn_ack_rescan.setEnabled(True)
        self.btn_ack_purge.setEnabled(True)
        self._log_comm(f"Operation encountered an error: {err_msg.splitlines()[-1]}")

    def _on_ackerman_scan_done(self, req_id: int, report: dict):
        if req_id != self._scan_request_seq or self._purging_active:
            return

        self.btn_ack_rescan.setEnabled(True)
        self.btn_ack_purge.setEnabled(True)
        self.ackerman_data = report["categories"]

        inacc = report.get("total_inaccessible", 0)
        inacc_note = f"  [{inacc} locked/skipped]" if inacc > 0 else ""
        self.ack_total_lbl.setText(
            f"JUNK FOUND ON {report['drive']} :  {report['total_formatted']}  ({report['total_files']} FILES){inacc_note}"
        )
        self._update_drive_gauge()
        self._rebuild_ackerman_rows_ui()

        self._log_comm(
            f"Scan complete on {report['drive']}: Found {report['total_formatted']} of cleanable junk ({report['total_files']} files)."
        )

    def _rebuild_ackerman_rows_ui(self):
        while self.rows_layout.count():
            item = self.rows_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.check_rows.clear()

        first_cid = None
        for cid, data in self.ackerman_data.items():
            if first_cid is None:
                first_cid = cid
            is_checked = self.user_check_states.get(cid, data["default_checked"])
            row_widget = TacticalCheckRow(cid, data, is_checked, self.current_accent)
            row_widget.selected_signal.connect(self._on_ack_row_clicked)
            self.rows_layout.addWidget(row_widget)
            self.check_rows[cid] = row_widget

        self.rows_layout.addStretch()
        if first_cid:
            self._on_ack_row_clicked(first_cid)

    def _on_ack_row_clicked(self, cid: str):
        if cid in self.check_rows:
            self.user_check_states[cid] = self.check_rows[cid].checkbox.isChecked()
        data = self.ackerman_data.get(cid)
        if not data:
            return
        self.ack_detail_title.setText(f"{data['title']}   —   {data['formatted_size']}")
        self.ack_detail_desc.setText(data["description"])
        self.ack_path_list.clear()
        if data["active_paths"]:
            for p in data["active_paths"]:
                self.ack_path_list.addItem(p)
        else:
            self.ack_path_list.addItem("[ Clean! No junk files currently in this category ]")

    def trigger_ackerman_purge(self):
        if self._purging_active:
            return
        selected_ids = [cid for cid, rw in self.check_rows.items() if rw.checkbox.isChecked()]
        if not selected_ids:
            QMessageBox.information(self, "No Categories Checked", "Please check at least one junk category on the left before clicking Clean.")
            return

        target_titles = [self.ackerman_data[cid]["title"] for cid in selected_ids if cid in self.ackerman_data]
        summary_lines = "\n".join(f"• {t}" for t in target_titles)

        box = QMessageBox(self)
        box.setWindowTitle("CONFIRM JUNK CLEANUP")
        box.setTextFormat(Qt.PlainText)
        box.setIcon(QMessageBox.Warning)
        box.setText(
            f"Are you ready to clean the following {len(selected_ids)} selected category(s) on drive {self.selected_drive}?\n\n"
            f"{summary_lines}\n\n"
            f"Note: Any file currently in use by Windows or a running program will be safely skipped."
        )
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        if box.exec() != QMessageBox.Yes:
            return

        self._purging_active = True
        self.drive_combo.setEnabled(False)
        self.btn_ack_rescan.setEnabled(False)
        self.btn_ack_purge.setEnabled(False)

        captured_drive = self.selected_drive
        snapshot_copy = dict(self.ackerman_data)
        self._log_comm(f"Cleaning selected junk categories on drive {captured_drive}...")

        worker = AckermanPurgeWorker(selected_ids, captured_drive, snapshot_copy)
        worker.finished_signal.connect(self._on_ackerman_purge_done)
        worker.error_signal.connect(self._on_ackerman_worker_error)
        self._register_worker(worker)

    def _on_ackerman_purge_done(self, res: dict):
        self._purging_active = False
        self.drive_combo.setEnabled(True)
        purged_drive = res.get("drive", self.selected_drive)

        self._log_comm(
            f"Cleanup finished on {purged_drive}: Freed {res['reclaimed_formatted']} ({res['deleted_items']} junk items removed)."
        )
        msg = QMessageBox(self)
        msg.setWindowTitle("CLEANUP COMPLETE")
        msg.setTextFormat(Qt.PlainText)
        msg.setText(
            f"GHOSTBLADE-141  •  BY JYOTIPRIYO SAHA\n\n"
            f"• Drive Cleaned          : {purged_drive}\n"
            f"• Space Freed (Estimated): {res['reclaimed_formatted']}\n"
            f"• Junk Items Deleted     : {res['deleted_items']}\n"
            f"• In-Use Files Skipped   : {res['skipped_or_failed']}"
        )
        msg.exec()
        self.trigger_ackerman_scan()

    # =====================================================================
    # DECK 02: APP UNINSTALLER & LEFTOVER CLEANER (INOSUKE)
    # =====================================================================

    def _create_inosuke_deck(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(18, 14, 18, 14)
        vbox.setSpacing(10)

        hero = QFrame()
        hero.setObjectName("HeroBanner")
        h_hbox = QHBoxLayout(hero)
        h_hbox.setContentsMargins(18, 12, 18, 12)

        h_left = QVBoxLayout()
        h_left.setSpacing(2)
        h_title = QLabel("DEEP APPLICATION UNINSTALLER & LEFTOVER CLEANER (INOSUKE RADAR)  •  BY JYOTIPRIYO SAHA")
        h_title.setStyleSheet("color: #F4F4F6; font-weight: 700; font-size: 13px;")
        h_quote = QLabel("Finds all installed programs on your PC and reveals the hidden AppData folders they leave behind.")
        h_quote.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        h_left.addWidget(h_title)
        h_left.addWidget(h_quote)

        self.btn_ino_rescan = QPushButton("REFRESH APP LIST")
        self.btn_ino_rescan.setObjectName("UtilityBtn")
        self.btn_ino_rescan.setToolTip("Re-scan Windows Registry and AppData folders to update the installed apps list.")
        self.btn_ino_rescan.clicked.connect(self.trigger_inosuke_scan)

        h_hbox.addLayout(h_left)
        h_hbox.addStretch()
        h_hbox.addWidget(self.btn_ino_rescan)
        vbox.addWidget(hero)

        vbox.addWidget(self._make_step_guide_strip(
            "Click any installed app in the left table to see its hidden AppData folders.",
            "Click 'STEP 1: LAUNCH OFFICIAL UNINSTALLER' and complete the normal uninstall.",
            "After uninstall finishes, click 'STEP 2: DELETE LEFTOVER APPDATA' to wipe remaining junk."
        ))

        splitter = QSplitter(Qt.Horizontal)

        self.app_table = QTableWidget(0, 4)
        self.app_table.setHorizontalHeaderLabels(["INSTALLED APPLICATION", "PUBLISHER", "INSTALL SIZE", "APPDATA FOOTPRINT"])
        self.app_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.app_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.app_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.app_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.app_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.app_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.app_table.verticalHeader().setVisible(False)
        self.app_table.itemSelectionChanged.connect(self._on_app_selected)
        splitter.addWidget(self.app_table)

        right_box = QFrame()
        right_box.setObjectName("PanelBox")
        r_vbox = QVBoxLayout(right_box)
        r_vbox.setContentsMargins(16, 14, 16, 14)
        r_vbox.setSpacing(8)

        self.xray_hdr = QLabel("SELECTED APP DETAILS  //  CLICK AN APP ON THE LEFT")
        self.xray_hdr.setTextFormat(Qt.PlainText)
        self.xray_hdr.setStyleSheet(f"color: {self.current_accent}; font-weight: 700; font-size: 12px;")

        self.xray_info = QLabel("Click any program in the left table to see its publisher, version, and hidden AppData folders here.")
        self.xray_info.setTextFormat(Qt.PlainText)
        self.xray_info.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        self.xray_info.setWordWrap(True)

        self.leftover_list = QListWidget()
        self.leftover_list.setFixedHeight(110)
        self.leftover_list.setToolTip("Folders in AppData/ProgramData associated with the selected application.")

        act_row = QHBoxLayout()
        self.btn_run_uninst = QPushButton("STEP 1: LAUNCH OFFICIAL UNINSTALLER")
        self.btn_run_uninst.setObjectName("PrimaryExecuteBtn")
        self.btn_run_uninst.setToolTip("Runs the program's official uninstaller first. Wait for it to finish before clicking Step 2.")
        self.btn_run_uninst.clicked.connect(self._run_official_uninstall)

        self.btn_slice_leftovers = QPushButton("STEP 2: DELETE LEFTOVER APPDATA")
        self.btn_slice_leftovers.setObjectName("DangerExecuteBtn")
        self.btn_slice_leftovers.setToolTip("ONLY click this AFTER you have uninstalled the app in Step 1! Deletes its leftover AppData folders.")
        self.btn_slice_leftovers.clicked.connect(self._remove_selected_app_leftovers)

        act_row.addWidget(self.btn_run_uninst)
        act_row.addWidget(self.btn_slice_leftovers)

        orphan_lbl = QLabel("UNMATCHED APPDATA FOLDERS (FROM OLD UNINSTALLED APPS — VERIFY BEFORE DELETING):")
        orphan_lbl.setStyleSheet("color: #9CA3AF; font-weight: 700; font-size: 10px; margin-top: 6px;")

        self.ghost_list = QListWidget()
        self.ghost_list.setToolTip("These AppData folders do not match any currently installed program in the Registry.")

        self.btn_shred_orphan = QPushButton("DELETE SELECTED UNMATCHED FOLDER")
        self.btn_shred_orphan.setObjectName("UtilityBtn")
        self.btn_shred_orphan.setToolTip("Deletes the unmatched folder you selected in the list above (asks for confirmation first).")
        self.btn_shred_orphan.clicked.connect(self._remove_selected_orphan_ghost)

        r_vbox.addWidget(self.xray_hdr)
        r_vbox.addWidget(self.xray_info)
        r_vbox.addWidget(QLabel("HIDDEN APPDATA / PROGRAMDATA FOLDERS FOR THIS APP:"))
        r_vbox.addWidget(self.leftover_list)
        r_vbox.addLayout(act_row)
        r_vbox.addWidget(orphan_lbl)
        r_vbox.addWidget(self.ghost_list, 1)
        r_vbox.addWidget(self.btn_shred_orphan)

        splitter.addWidget(right_box)
        splitter.setSizes([680, 500])
        vbox.addWidget(splitter, 1)
        return w

    def trigger_inosuke_scan(self):
        if self._inosuke_scanning:
            return
        self._inosuke_scanning = True
        self.selected_app = None
        self.btn_ino_rescan.setEnabled(False)
        self._log_comm("Scanning Windows Registry and mapping AppData folders...")
        worker = InosukeScanWorker()
        worker.finished_signal.connect(self._on_inosuke_scan_done)
        worker.error_signal.connect(self._on_inosuke_error)
        self._register_worker(worker)

    def _on_inosuke_error(self, err_msg: str):
        self._inosuke_scanning = False
        self.btn_ino_rescan.setEnabled(True)
        self.btn_slice_leftovers.setEnabled(True)
        self.btn_shred_orphan.setEnabled(True)
        self._log_comm(f"Uninstaller radar error: {err_msg.splitlines()[-1]}")

    def _on_inosuke_scan_done(self, apps: List[InstalledApp], ghosts: List[dict]):
        self._inosuke_scanning = False
        self.btn_ino_rescan.setEnabled(True)
        self.installed_apps = apps
        self.app_lookup = {a.key_id: a for a in apps}
        self.ghost_folders = ghosts
        self.selected_app = None

        self.xray_hdr.setText("SELECTED APP DETAILS  //  CLICK AN APP ON THE LEFT")
        self.xray_info.setText("Click any program in the left table to see its publisher, version, and hidden AppData folders here.")
        self.leftover_list.clear()

        self.app_table.setRowCount(len(apps))
        for r, app in enumerate(apps):
            name_item = QTableWidgetItem(app.name)
            name_item.setData(Qt.UserRole, app.key_id)
            self.app_table.setItem(r, 0, name_item)
            self.app_table.setItem(r, 1, QTableWidgetItem(app.publisher))

            s_item = QTableWidgetItem(app.formatted_install_size)
            s_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.app_table.setItem(r, 2, s_item)

            l_item = QTableWidgetItem(app.formatted_leftover_size if app.leftover_bytes > 0 else "0.00 MB")
            l_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            if app.leftover_bytes > 0:
                l_item.setForeground(QColor(self.current_accent))
            self.app_table.setItem(r, 3, l_item)

        self.ghost_list.clear()
        for g in ghosts:
            it = QListWidgetItem(f"{g['formatted_size'].rjust(10)}   |   {g['location']}   |   {g['folder_name']}")
            it.setData(Qt.UserRole, g["full_path"])
            self.ghost_list.addItem(it)

        self._log_comm(f"Found {len(apps)} installed programs and {len(ghosts)} unmatched AppData folders.")

    def _on_app_selected(self):
        rows = self.app_table.selectionModel().selectedRows()
        if not rows:
            self.selected_app = None
            return
        r = rows[0].row()
        name_item = self.app_table.item(r, 0)
        if not name_item:
            return
        key_id = name_item.data(Qt.UserRole)
        app = self.app_lookup.get(key_id)
        if not app:
            return
        self.selected_app = app

        self.xray_hdr.setText(f"SELECTED APP  //  {app.name.upper()}")
        self.xray_info.setText(
            f"PUBLISHER: {app.publisher}   |   VERSION: {app.version}\n"
            f"REGISTRY LOCATION: {app.registry_path}\n"
            f"INSTALL SIZE: {app.formatted_install_size}   |   APPDATA FOOTPRINT: {app.formatted_leftover_size}"
        )
        self.leftover_list.clear()
        if app.leftover_paths:
            for p in app.leftover_paths:
                self.leftover_list.addItem(str(p))
        else:
            self.leftover_list.addItem("[ No separate AppData folders detected for this app ]")

    def _run_official_uninstall(self):
        if not self.selected_app:
            QMessageBox.information(self, "Select an Application", "Please click an application in the left table first.")
            return

        box = QMessageBox(self)
        box.setWindowTitle("STEP 1: LAUNCH OFFICIAL UNINSTALLER")
        box.setTextFormat(Qt.PlainText)
        box.setIcon(QMessageBox.Question)
        box.setText(
            f"Application : {self.selected_app.name}\n"
            f"Publisher   : {self.selected_app.publisher}\n"
            f"Command     : {self.selected_app.uninstall_string}\n\n"
            f"Do you want to launch this program's official uninstaller now?\n"
            f"(After it finishes uninstalling, you can use Step 2 to delete its leftover AppData folders)."
        )
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        if box.exec() != QMessageBox.Yes:
            return

        ok, msg = trigger_native_uninstaller(self.selected_app)
        if ok:
            self._log_comm(f"{msg}. Wait for the uninstaller window to finish before clicking Step 2.")
        else:
            QMessageBox.warning(self, "Uninstaller Launch Blocked / Failed", msg)

    def _remove_selected_app_leftovers(self):
        if not self.selected_app or not self.selected_app.leftover_paths:
            QMessageBox.information(self, "No Leftover Folders", "There are no mapped AppData folders to delete for this app.")
            return

        still_reg = is_app_still_registered(self.selected_app)
        reg_warn = (
            f"⚠️ IMPORTANT WARNING: '{self.selected_app.name}' is STILL installed on your PC!\n"
            f"Only delete these AppData folders AFTER you have uninstalled the app using Step 1, "
            f"otherwise you will reset the app's settings or login data.\n\n"
            if still_reg else ""
        )
        paths_str = "\n".join(f"• {p}" for p in self.selected_app.leftover_paths)

        box = QMessageBox(self)
        box.setWindowTitle("STEP 2: CONFIRM LEFTOVER APPDATA DELETION")
        box.setTextFormat(Qt.PlainText)
        box.setIcon(QMessageBox.Warning)
        box.setText(
            f"{reg_warn}"
            f"Permanently delete the following {len(self.selected_app.leftover_paths)} folder(s) "
            f"(Estimated {self.selected_app.formatted_leftover_size})?\n\n{paths_str}"
        )
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        if box.exec() != QMessageBox.Yes:
            return

        self.btn_slice_leftovers.setEnabled(False)
        worker = LeftoverDeleteWorker(list(self.selected_app.leftover_paths))
        worker.finished_signal.connect(self._on_leftover_delete_done)
        worker.error_signal.connect(self._on_inosuke_error)
        self._register_worker(worker)

    def _remove_selected_orphan_ghost(self):
        item = self.ghost_list.currentItem()
        if not item:
            QMessageBox.information(self, "Select a Folder", "Please click an unmatched folder in the bottom-right list first.")
            return
        target_path: Path = item.data(Qt.UserRole)

        box = QMessageBox(self)
        box.setWindowTitle("CONFIRM UNMATCHED FOLDER DELETION")
        box.setTextFormat(Qt.PlainText)
        box.setIcon(QMessageBox.Warning)
        box.setText(
            f"Make sure this folder does not belong to a portable app you still use:\n\n"
            f"Folder Path: {target_path}\n\n"
            f"Permanently delete this folder?"
        )
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        if box.exec() != QMessageBox.Yes:
            return

        self.btn_shred_orphan.setEnabled(False)
        worker = LeftoverDeleteWorker([target_path])
        worker.finished_signal.connect(self._on_leftover_delete_done)
        worker.error_signal.connect(self._on_inosuke_error)
        self._register_worker(worker)

    def _on_leftover_delete_done(self, res: dict):
        self.btn_slice_leftovers.setEnabled(True)
        self.btn_shred_orphan.setEnabled(True)
        self._log_comm(
            f"Deleted {res['shredded_folders']} leftover folder(s) (Freed {res['reclaimed_formatted']}, "
            f"{res['locked_skipped']} locked/skipped)."
        )
        self.trigger_inosuke_scan()

    # =====================================================================
    # DECK 03: MALWARE & SECURITY SCANNER (BRAVO-SIX EDR)
    # =====================================================================

    def _create_bravo_six_deck(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(18, 14, 18, 14)
        vbox.setSpacing(10)

        hero = QFrame()
        hero.setObjectName("HeroBanner")
        h_hbox = QHBoxLayout(hero)
        h_hbox.setContentsMargins(18, 12, 18, 12)

        h_left = QVBoxLayout()
        h_left.setSpacing(2)
        h_title = QLabel("STEALTH MALWARE, STARTUP & PROCESS SECURITY SCANNER (BRAVO-SIX EDR)  •  BY JYOTIPRIYO SAHA")
        h_title.setStyleSheet("color: #F4F4F6; font-weight: 700; font-size: 13px;")
        h_quote = QLabel("Checks for fake Windows system processes, suspicious auto-startup programs, backdoor network ports, and deceptive files.")
        h_quote.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        h_left.addWidget(h_title)
        h_left.addWidget(h_quote)

        self.edr_badge = QLabel("STATUS: READY TO SCAN")
        self.edr_badge.setStyleSheet(f"color: {self.current_accent}; font-family: 'Consolas'; font-weight: bold; font-size: 12px;")

        h_hbox.addLayout(h_left)
        h_hbox.addStretch()
        h_hbox.addWidget(self.edr_badge)
        vbox.addWidget(hero)

        vbox.addWidget(self._make_step_guide_strip(
            "Click 'START FULL SECURITY SCAN' below to audit your PC.",
            "Click any finding in the table to read the full technical explanation below.",
            "Use 'CHECK SINGLE FILE' to test any suspicious download, or 'LOCK FILE IN QUARANTINE' to isolate a threat."
        ))

        self.edr_table = QTableWidget(0, 5)
        self.edr_table.setHorizontalHeaderLabels(["RISK LEVEL", "CONFIDENCE", "MITRE ID", "WHAT WAS FOUND", "LOCATION / PROCESS"])
        self.edr_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.edr_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.edr_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.edr_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.edr_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.edr_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.edr_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.edr_table.verticalHeader().setVisible(False)
        self.edr_table.itemSelectionChanged.connect(self._on_edr_finding_selected)
        vbox.addWidget(self.edr_table, 1)

        ev_box = QFrame()
        ev_box.setObjectName("PanelBox")
        ev_layout = QVBoxLayout(ev_box)
        ev_layout.setContentsMargins(14, 10, 14, 10)
        self.edr_detail_lbl = QLabel("DETAILED EXPLANATION PANE: Click any row in the table above to see why it was flagged and what you should do.")
        self.edr_detail_lbl.setTextFormat(Qt.PlainText)
        self.edr_detail_lbl.setWordWrap(True)
        self.edr_detail_lbl.setStyleSheet("color: #D1D5DB; font-family: 'Consolas'; font-size: 11px;")
        ev_layout.addWidget(self.edr_detail_lbl)
        vbox.addWidget(ev_box)

        ctrl_hbox = QHBoxLayout()
        self.btn_edr_sweep = QPushButton("START FULL SECURITY SCAN")
        self.btn_edr_sweep.setObjectName("PrimaryExecuteBtn")
        self.btn_edr_sweep.setToolTip("Scans all running processes, Windows Startup registry entries, network ports, and Downloads/Temp folders.")
        self.btn_edr_sweep.clicked.connect(self.trigger_bravo_six_sweep)

        self.btn_entropy_xray = QPushButton("CHECK SINGLE FILE (ENTROPY & SHA-256)")
        self.btn_entropy_xray.setObjectName("UtilityBtn")
        self.btn_entropy_xray.setToolTip("Pick any file on your computer to check its SHA-256 fingerprint and see if it contains packed/encrypted code.")
        self.btn_entropy_xray.clicked.connect(self._scan_custom_file)

        self.btn_quarantine = QPushButton("LOCK SELECTED FILE IN QUARANTINE VAULT")
        self.btn_quarantine.setObjectName("DangerExecuteBtn")
        self.btn_quarantine.setToolTip("Moves a suspicious file selected in the table into the safe Quarantine Vault so it cannot run (Restorable anytime in Tab 04).")
        self.btn_quarantine.clicked.connect(self._quarantine_selected_threat)

        ctrl_hbox.addWidget(self.btn_edr_sweep)
        ctrl_hbox.addWidget(self.btn_entropy_xray)
        ctrl_hbox.addStretch()
        ctrl_hbox.addWidget(self.btn_quarantine)
        vbox.addLayout(ctrl_hbox)
        return w

    def trigger_bravo_six_sweep(self):
        if self._edr_scanning:
            return
        self._edr_scanning = True
        self.btn_edr_sweep.setEnabled(False)
        self.edr_badge.setText("SCANNING PROCESSES, STARTUP & NETWORK...")
        self._log_comm("Running security scan across active processes, startup registry keys, and network connections...")
        worker = BravoSixScanWorker()
        worker.finished_signal.connect(self._on_bravo_six_done)
        worker.error_signal.connect(self._on_edr_error)
        self._register_worker(worker)

    def _on_edr_error(self, err_msg: str):
        self._edr_scanning = False
        self.btn_edr_sweep.setEnabled(True)
        self.btn_entropy_xray.setEnabled(True)
        self._log_comm(f"Security scan error: {err_msg.splitlines()[-1]}")

    def _on_bravo_six_done(self, report: dict):
        self._edr_scanning = False
        self.btn_edr_sweep.setEnabled(True)
        findings: List[ThreatFinding] = report["findings"]
        self.edr_table.setRowCount(0)

        ver_p = report["processes_verified"]
        unv_p = report["processes_unverifiable"]
        drop_f = report["dropzone_files_audited"]
        self.edr_badge.setText(
            f"{report['status']}  |  {ver_p} PROCESSES CHECKED  |  {drop_f} FILES CHECKED"
        )

        if not findings:
            self.edr_table.setRowCount(1)
            self.edr_table.setItem(0, 0, QTableWidgetItem("ALL CLEAR"))
            self.edr_table.setItem(0, 1, QTableWidgetItem("HIGH"))
            self.edr_table.setItem(0, 2, QTableWidgetItem("NONE"))
            self.edr_table.setItem(0, 3, QTableWidgetItem("No suspicious startup hooks, fake system processes, or backdoor ports found"))
            self.edr_table.setItem(0, 4, QTableWidgetItem(f"{ver_p} Processes Verified ({unv_p} Protected OS Processes)"))
            self.edr_detail_lbl.setText(
                f"SCAN SUMMARY: Checked {ver_p} active processes ({unv_p} protected Windows kernel processes skipped), "
                f"{report['reg_keys_checked']} Startup registry locations, and {drop_f} files in Downloads/Temp. Everything looks clean!"
            )
            self._log_comm(f"Security scan complete: No suspicious activity found across {ver_p} accessible processes.")
        else:
            self.edr_table.setRowCount(len(findings))
            for r, f in enumerate(findings):
                sev = QTableWidgetItem(f.severity)
                sev.setForeground(QColor("#EF4444" if f.severity in {"CRITICAL", "HIGH"} else "#F59E0B"))
                sev.setData(Qt.UserRole, f)
                self.edr_table.setItem(r, 0, sev)
                self.edr_table.setItem(r, 1, QTableWidgetItem(f.confidence))
                self.edr_table.setItem(r, 2, QTableWidgetItem(f.mitre_id))
                self.edr_table.setItem(r, 3, QTableWidgetItem(f.title))
                p_item = QTableWidgetItem(f.target_path)
                p_item.setData(Qt.UserRole, f.target_path)
                self.edr_table.setItem(r, 4, p_item)
            self.edr_table.selectRow(0)

    def _on_edr_finding_selected(self):
        rows = self.edr_table.selectionModel().selectedRows()
        if not rows:
            return
        r = rows[0].row()
        sev_item = self.edr_table.item(r, 0)
        if not sev_item:
            return
        f: Optional[ThreatFinding] = sev_item.data(Qt.UserRole)
        if not f:
            return
        self.edr_detail_lbl.setText(
            f"CATEGORY      : {f.category}  ({f.title})\n"
            f"WHY FLAGGED   : {f.details}\n"
            f"TACTICAL NOTE : {f.character_comm}"
        )

    def _scan_custom_file(self):
        fp_str, _ = QFileDialog.getOpenFileName(self, "Select Any File to Check Its SHA-256 Hash & Encryption Entropy")
        if not fp_str:
            return
        self.btn_entropy_xray.setEnabled(False)
        self._log_comm(f"Analyzing file '{Path(fp_str).name}' in background...")
        worker = ForensicFileWorker(Path(fp_str))
        worker.finished_signal.connect(self._on_forensic_file_done)
        worker.error_signal.connect(self._on_edr_error)
        self._register_worker(worker)

    def _on_forensic_file_done(self, res: dict):
        self.btn_entropy_xray.setEnabled(True)
        if "error" in res:
            QMessageBox.warning(self, "File Check Error", res["error"])
            return

        ent = res["entropy"]
        ent_status = res["ent_status"]
        if ent_status != "OK":
            verdict = f"Could not read file ({ent_status})"
            ent_display = ent_status
        elif ent >= 7.25:
            verdict = "HIGH ENTROPY (>= 7.25) — File is compressed (like a ZIP/Installer) or packed/encrypted."
            ent_display = f"{ent} / 8.00"
        else:
            verdict = "NORMAL ENTROPY (< 7.25) — Standard uncompressed file structure."
            ent_display = f"{ent} / 8.00"

        msg = QMessageBox(self)
        msg.setWindowTitle("FILE INSPECTION REPORT")
        msg.setTextFormat(Qt.PlainText)
        msg.setText(
            f"GHOSTBLADE-141  •  BY JYOTIPRIYO SAHA\n\n"
            f"File Name       : {res['name']}\n"
            f"File Size       : {res['size']}\n"
            f"SHA-256 Hash    : {res['sha256']}\n"
            f"Shannon Entropy : {ent_display}\n\n"
            f"Result          : {verdict}"
        )
        msg.exec()

    def _quarantine_selected_threat(self):
        rows = self.edr_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Select a Finding", "Click a row in the table first.")
            return
        r = rows[0].row()
        p_item = self.edr_table.item(r, 4)
        if not p_item:
            return
        target = Path(p_item.data(Qt.UserRole) or p_item.text())
        if not target.exists() or not target.is_file():
            QMessageBox.warning(
                self,
                "Not a Direct Disk File",
                "The selected item is a registry entry or network connection, not a movable file on disk."
            )
            return

        box = QMessageBox(self)
        box.setWindowTitle("CONFIRM QUARANTINE")
        box.setTextFormat(Qt.PlainText)
        box.setIcon(QMessageBox.Warning)
        box.setText(
            f"Move this file into the isolated Quarantine Vault so it cannot run?\n\n"
            f"{target}\n\n"
            f"(You can easily restore it back to its original place anytime from Tab 04: FILE VAULT & INTEGRITY)."
        )
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        box.setDefaultButton(QMessageBox.No)
        if box.exec() != QMessageBox.Yes:
            return

        ok, msg = quarantine_suspicious_file(target, self.base_dir)
        if ok:
            self._log_comm(f"Quarantined {target.name}: {msg}")
            self.trigger_bravo_six_sweep()
        else:
            QMessageBox.warning(self, "Quarantine Failed", msg)

    # =====================================================================
    # DECK 04: FILE VAULT & INTEGRITY (SELF-SHIELD + QUARANTINE RESTORE)
    # =====================================================================

    def _create_shield_deck(self) -> QWidget:
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.setContentsMargins(18, 14, 18, 14)
        vbox.setSpacing(10)

        hero = QFrame()
        hero.setObjectName("HeroBanner")
        h_hbox = QHBoxLayout(hero)
        h_hbox.setContentsMargins(18, 12, 18, 12)
        h_left = QVBoxLayout()
        h_left.setSpacing(2)
        h_title = QLabel("SELF-SHIELD INTEGRITY & QUARANTINE RECOVERY VAULT  •  BY JYOTIPRIYO SAHA")
        h_title.setStyleSheet("color: #F4F4F6; font-weight: 700; font-size: 13px;")
        h_quote = QLabel(
            f"Top Table: Verifies GhostBlade-141's own code files haven't been altered.   |   "
            f"Bottom Table: Restore quarantined files with 1 click."
        )
        h_quote.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        h_left.addWidget(h_title)
        h_left.addWidget(h_quote)

        btn_repin = QPushButton("SAVE CURRENT HASHES AS BASELINE")
        btn_repin.setObjectName("UtilityBtn")
        btn_repin.setToolTip("Saves the current SHA-256 fingerprints of GhostBlade-141's files as your trusted baseline.")
        btn_repin.clicked.connect(self._repin_baseline)

        h_hbox.addLayout(h_left)
        h_hbox.addStretch()
        h_hbox.addWidget(btn_repin)
        vbox.addWidget(hero)

        self.shield_table = QTableWidget(0, 3)
        self.shield_table.setHorizontalHeaderLabels(["GHOSTBLADE-141 FILE", "SHA-256 SECURITY FINGERPRINT", "VERIFICATION STATUS"])
        self.shield_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.shield_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.shield_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.shield_table.verticalHeader().setVisible(False)
        self.shield_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        vbox.addWidget(self.shield_table, 1)

        v_hdr = QLabel("QUARANTINE VAULT  //  SELECT ANY ISOLATED FILE BELOW TO RESTORE IT TO ITS ORIGINAL FOLDER")
        v_hdr.setStyleSheet("color: #9CA3AF; font-weight: 700; font-size: 11px; margin-top: 6px;")
        vbox.addWidget(v_hdr)

        self.vault_table = QTableWidget(0, 4)
        self.vault_table.setHorizontalHeaderLabels(["VAULT FILE NAME", "ORIGINAL LOCATION BEFORE QUARANTINE", "SHA-256", "DATE QUARANTINED"])
        self.vault_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.vault_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.vault_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.vault_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.vault_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.vault_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.vault_table.verticalHeader().setVisible(False)
        vbox.addWidget(self.vault_table, 1)

        v_btns = QHBoxLayout()
        btn_refresh_vault = QPushButton("REFRESH VAULT LIST")
        btn_refresh_vault.setObjectName("UtilityBtn")
        btn_refresh_vault.clicked.connect(self._refresh_shield_and_vault_ui)

        btn_restore = QPushButton("RESTORE SELECTED FILE TO ORIGINAL LOCATION")
        btn_restore.setObjectName("PrimaryExecuteBtn")
        btn_restore.setToolTip("Moves the selected file out of the Quarantine Vault and puts it right back where it came from.")
        btn_restore.clicked.connect(self._restore_selected_vault_item)

        v_btns.addWidget(btn_refresh_vault)
        v_btns.addStretch()
        v_btns.addWidget(btn_restore)
        vbox.addLayout(v_btns)

        self._refresh_shield_and_vault_ui()
        return w

    def _repin_baseline(self):
        bp = self.base_dir / BASELINE_FILE_NAME
        try:
            if bp.exists():
                bp.unlink()
        except OSError:
            pass
        self.shield_status = verify_core_integrity(self.base_dir)
        self._refresh_shield_and_vault_ui()
        self._log_comm("Saved fresh SHA-256 baseline fingerprints for all GhostBlade-141 modules.")

    def _refresh_shield_and_vault_ui(self):
        self.shield_status = verify_core_integrity(self.base_dir)
        hashes = self.shield_status["module_hashes"]
        states = self.shield_status["module_states"]

        self.shield_table.setRowCount(len(hashes))
        for r, (mname, hval) in enumerate(hashes.items()):
            st_text = states.get(mname, "UNKNOWN")
            self.shield_table.setItem(r, 0, QTableWidgetItem(mname))
            self.shield_table.setItem(r, 1, QTableWidgetItem(hval))
            st_item = QTableWidgetItem(f"{st_text}  •  JYOTIPRIYO SAHA")
            if "MATCHED" in st_text or "RECORDED" in st_text:
                st_item.setForeground(QColor(self.current_accent))
            else:
                st_item.setForeground(QColor("#EF4444"))
            self.shield_table.setItem(r, 2, st_item)

        q_items = get_quarantined_items(self.base_dir)
        self.vault_table.setRowCount(len(q_items))
        for r, item in enumerate(q_items):
            v_item = QTableWidgetItem(item["vault_name"])
            v_item.setData(Qt.UserRole, item["vault_name"])
            self.vault_table.setItem(r, 0, v_item)
            self.vault_table.setItem(r, 1, QTableWidgetItem(item["original_path"]))
            self.vault_table.setItem(r, 2, QTableWidgetItem(item["sha256"][:24] + "..."))
            self.vault_table.setItem(r, 3, QTableWidgetItem(item["quarantined_at"]))

    def _restore_selected_vault_item(self):
        rows = self.vault_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Select a File", "Please click a quarantined file in the bottom table first.")
            return
        r = rows[0].row()
        v_item = self.vault_table.item(r, 0)
        if not v_item:
            return
        vname = v_item.data(Qt.UserRole)
        ok, msg = restore_quarantined_file(vname, self.base_dir)
        if ok:
            self._log_comm(msg)
            self._refresh_shield_and_vault_ui()
        else:
            QMessageBox.warning(self, "Restore Failed", msg)

    def closeEvent(self, event):
        running = [w for w in self._active_workers if w.isRunning()]
        if running and self._purging_active:
            reply = QMessageBox.question(
                self,
                "CLEANUP IN PROGRESS",
                "A cleanup operation is currently running. Cancel it and exit safely?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                event.ignore()
                return

        for w in running:
            w.request_cancel()
        for w in running:
            w.wait(3000)

        event.accept()