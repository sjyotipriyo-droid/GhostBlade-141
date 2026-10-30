import sys
import ctypes
from pathlib import Path

# 1. Execute DLL Search Order Hardening BEFORE importing Qt6 or third-party extensions
from core.self_shield import harden_process_security
harden_process_security()

from PySide6.QtWidgets import QApplication, QMessageBox
from PySide6.QtGui import QIcon
from ui.main_window import GhostBladeMainWindow


def acquire_single_instance_mutex() -> int | None:
    """Prevents multiple instances of GhostBlade-141 from running concurrent purges."""
    if sys.platform != "win32":
        return 1
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    mutex_name = "Local\\GhostBlade141_Singleton_Mutex_JyotipriyoSaha"
    handle = kernel32.CreateMutexW(None, False, mutex_name)
    ERROR_ALREADY_EXISTS = 183
    if not handle or ctypes.get_last_error() == ERROR_ALREADY_EXISTS:
        return None
    return handle


def set_windows_taskbar_app_id():
    """Ensures Windows 11 Taskbar displays GhostBlade-141's custom icon instead of Python's icon."""
    if sys.platform == "win32":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("JyotipriyoSaha.GhostBlade141.Suite.1.0")
        except OSError:
            pass


def main():
    set_windows_taskbar_app_id()
    app = QApplication(sys.argv)
    app.setApplicationName("GhostBlade-141")

    base_dir = Path(__file__).parent.resolve()
    icon_path = base_dir / "assets" / "ghostblade.ico"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    mutex_handle = acquire_single_instance_mutex()
    if mutex_handle is None:
        QMessageBox.warning(
            None,
            "GHOSTBLADE-141 // INSTANCE ACTIVE",
            "An instance of GhostBlade-141 is already running on this workstation."
        )
        sys.exit(0)

    window = GhostBladeMainWindow(base_dir)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()