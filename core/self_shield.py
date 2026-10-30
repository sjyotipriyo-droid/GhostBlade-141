import os
import sys
import json
import ctypes
import hashlib
from pathlib import Path

BASELINE_FILE_NAME = ".ghostblade_baseline.json"

def is_admin() -> bool:
    """Checks if current process holds elevated Windows Administrator token."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False

def harden_process_security() -> tuple[bool, str]:
    """
    Removes current working directory from Windows DLL search order and restricts
    default search paths to prevent local directory DLL hijacking.
    Checks return values explicitly instead of silently passing.
    """
    if sys.platform != "win32":
        return False, "NON_WINDOWS_OS"

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ok_dir = kernel32.SetDllDirectoryW("")
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000
    ok_def = kernel32.SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)

    if ok_dir and ok_def:
        return True, "LOCKED (Default Trusted Dirs)"
    err_code = ctypes.get_last_error()
    return False, f"PARTIAL (WinError {err_code})"

def compute_file_sha256(filepath: Path) -> tuple[str, str]:
    """
    Returns (hex_digest, status_str). Never conflates read errors with valid hashes.
    """
    if not filepath.exists():
        return "", "MISSING"
    if not filepath.is_file():
        return "", "NOT_A_FILE"

    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest(), "OK"
    except OSError as exc:
        return "", f"READ_ERROR ({exc.errno or 'OS'})"

def verify_core_integrity(base_dir: Path) -> dict:
    """
    Verifies all GhostBlade-141 modules (and the main executable when frozen)
    against a cryptographic baseline manifest. Detects missing, unreadable,
    or modified files accurately.
    """
    dll_ok, dll_msg = harden_process_security()

    if getattr(sys, "frozen", False):
        target_files = [Path(sys.executable)]
    else:
        target_files = [
            base_dir / "app.py",
            base_dir / "core" / "self_shield.py",
            base_dir / "core" / "ackerman_cleaner.py",
            base_dir / "core" / "inosuke_uninstaller.py",
            base_dir / "core" / "bravo_edr.py",
            base_dir / "ui" / "main_window.py",
        ]

    baseline_path = base_dir / BASELINE_FILE_NAME
    baseline_hashes = {}
    baseline_loaded = False

    if baseline_path.exists():
        try:
            raw = json.loads(baseline_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                baseline_hashes = raw
                baseline_loaded = True
        except (OSError, ValueError):
            baseline_loaded = False

    manifest = {}
    file_states = {}
    missing_or_error = False
    modified_detected = False

    for fp in target_files:
        digest, status = compute_file_sha256(fp)
        name = fp.name
        if status != "OK":
            manifest[name] = status
            file_states[name] = status
            missing_or_error = True
            continue

        manifest[name] = digest
        if baseline_loaded:
            expected = baseline_hashes.get(name)
            if expected is None:
                file_states[name] = "UNTRACKED_IN_BASELINE"
                modified_detected = True
            elif expected != digest:
                file_states[name] = "MODIFIED_MISMATCH"
                modified_detected = True
            else:
                file_states[name] = "BASELINE_MATCHED"
        else:
            file_states[name] = "HASH_RECORDED (INITIAL)"

    # If no baseline exists yet and all files are healthy, pin initial baseline
    if not baseline_loaded and not missing_or_error:
        try:
            baseline_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        except OSError:
            pass

    if missing_or_error:
        overall_status = "MISSING_OR_UNREADABLE_MODULE"
    elif modified_detected:
        overall_status = "MODIFIED_SINCE_BASELINE"
    elif baseline_loaded:
        overall_status = "BASELINE_VERIFIED"
    else:
        overall_status = "BASELINE_INITIALIZED"

    return {
        "admin_mode": is_admin(),
        "dll_ok": dll_ok,
        "dll_protection": dll_msg,
        "integrity_status": overall_status,
        "module_hashes": manifest,
        "module_states": file_states,
    }