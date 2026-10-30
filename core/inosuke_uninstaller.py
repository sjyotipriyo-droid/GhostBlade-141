import os
import re
import sys
import stat
import ctypes
import winreg
import threading
from ctypes import wintypes
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from core.ackerman_cleaner import (
    format_bytes, is_reparse_point, is_strictly_contained, _env_path, get_system_drive
)


@dataclass
class InstalledApp:
    key_id: str
    name: str
    publisher: str
    version: str
    install_location: str
    uninstall_string: str
    quiet_uninstall_string: str
    estimated_size_kb: int
    registry_path: str
    leftover_paths: List[Path] = field(default_factory=list)
    leftover_bytes: int = 0

    @property
    def formatted_install_size(self) -> str:
        if self.estimated_size_kb > 0:
            return format_bytes(self.estimated_size_kb * 1024)
        return "Unknown"

    @property
    def formatted_leftover_size(self) -> str:
        return format_bytes(self.leftover_bytes)


# Fixed typos and expanded protected developer/system/gamer directories
PROTECTED_VENDORS = {
    "microsoft", "windows", "google", "mozilla", "nvidia", "nvidia corporation",
    "amd", "intel", "realtek", "asus", "acer", "lenovo", "hp", "dell",
    "packages", "temp", "commondialog", "connecteddevicesplatform", "d3dscache",
    "diagnostics", "elevateddiagnostics", "fontcache", "identitycrl", "pip",
    "npm", "npm-cache", "pnpm", "yarn", "uv", "ms-playwright", "go-build", "node-gyp",
    "programs", "publishers", "squirreltemp", "virtualstore", "crashdumps",
    "vs", "vscode", "code", "git", "python", "nodejs", "docker", "steam",
    "battleye", "cef", "comms", "package cache", "ghostblade141", "adobe", "jetbrains"
}

MSI_GUID_REGEX = re.compile(r"(?i)msiexec(?:\.exe)?[\"']?\s+/[ix]\s*(\{[0-9a-fA-F\-]{36}\})")


def _normalize_token(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9\s]", " ", text.lower())
    for stop in ["inc", "corp", "corporation", "ltd", "llc", "gmbh", "x64", "x86", "64", "32", "bit", "runtime", "app"]:
        cleaned = re.sub(rf"\b{stop}\b", "", cleaned)
    return cleaned.strip()


def _get_allowed_appdata_roots() -> List[Path]:
    """Returns canonical, validated AppData and ProgramData root paths."""
    local_app = _env_path("LOCALAPPDATA")
    roaming_app = _env_path("APPDATA")
    locallow_app = local_app.parent / "LocalLow" if (local_app and local_app.exists()) else None
    prog_data = _env_path("PROGRAMDATA") or Path(f"{get_system_drive()}ProgramData")

    roots = []
    for p in [local_app, roaming_app, locallow_app, prog_data]:
        if p and p.exists() and not is_reparse_point(p):
            roots.append(Path(os.path.realpath(p)))
    return roots


def _compute_dir_size_cached(folder: Path, cache: Dict[str, int], max_depth: int = 3) -> int:
    key = os.path.normcase(str(folder))
    if key in cache:
        return cache[key]

    total = 0
    try:
        for root, dirs, files in os.walk(folder, topdown=True):
            root_p = Path(root)
            rel_depth = len(root_p.relative_to(folder).parts)
            if rel_depth > max_depth:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if not is_reparse_point(root_p / d)]
            for f in files:
                fp = root_p / f
                try:
                    if not is_reparse_point(fp):
                        total += fp.stat().st_size
                except OSError:
                    continue
    except OSError:
        pass

    cache[key] = total
    return total


def scan_installed_applications(
    calculate_footprints: bool = True,
    cancel_event: Optional[threading.Event] = None
) -> List[InstalledApp]:
    registry_targets = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM_64"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM_32"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKCU_USER"),
    ]

    seen_keys = set()
    apps: List[InstalledApp] = []
    size_cache: Dict[str, int] = {}

    appdata_roots = _get_allowed_appdata_roots()
    indexed_dirs: List[tuple[str, Path]] = []
    for root in appdata_roots:
        try:
            for item in root.iterdir():
                if item.is_dir() and not is_reparse_point(item):
                    indexed_dirs.append((item.name.lower(), item))
        except OSError:
            continue

    for hive, subkey_path, tag in registry_targets:
        if cancel_event and cancel_event.is_set():
            break
        try:
            with winreg.OpenKey(hive, subkey_path) as key:
                num_subkeys = winreg.QueryInfoKey(key)[0]
                for i in range(num_subkeys):
                    if cancel_event and cancel_event.is_set():
                        break
                    try:
                        sub_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, sub_name) as subkey:
                            def get_val(val_name: str, default=""):
                                try:
                                    return winreg.QueryValueEx(subkey, val_name)[0]
                                except OSError:
                                    return default

                            display_name = str(get_val("DisplayName", "")).strip()
                            uninstall_str = str(get_val("UninstallString", "")).strip()
                            system_comp = get_val("SystemComponent", 0)
                            release_type = str(get_val("ReleaseType", "")).strip().lower()
                            parent_key = str(get_val("ParentKeyName", "")).strip()

                            if not display_name or not uninstall_str or system_comp == 1:
                                continue
                            if release_type in {"update", "security update", "hotfix"} or parent_key:
                                continue
                            if display_name.startswith(("Security Update for", "Update for Microsoft", "Hotfix for")):
                                continue

                            publisher = str(get_val("Publisher", "Unknown Vendor")).strip()
                            version = str(get_val("DisplayVersion", "N/A")).strip()
                            install_loc = str(get_val("InstallLocation", "")).strip()
                            quiet_uninst = str(get_val("QuietUninstallString", "")).strip()

                            # Safe integer parsing (prevents ValueError crashes on malformed registry data)
                            raw_size = get_val("EstimatedSize", 0)
                            try:
                                est_size = int(raw_size) if raw_size else 0
                            except (ValueError, TypeError):
                                est_size = 0

                            dedup_id = f"{display_name.lower()}|{publisher.lower()}|{version.lower()}"
                            if dedup_id in seen_keys:
                                continue
                            seen_keys.add(dedup_id)

                            reg_id = f"{tag}\\{sub_name}"
                            app = InstalledApp(
                                key_id=reg_id,
                                name=display_name,
                                publisher=publisher,
                                version=version,
                                install_location=install_loc,
                                uninstall_string=uninstall_str,
                                quiet_uninstall_string=quiet_uninst,
                                estimated_size_kb=est_size,
                                registry_path=reg_id,
                            )

                            # Strict boundary matching (no broad substring collisions)
                            if calculate_footprints:
                                norm_name = _normalize_token(display_name)
                                tokens = [t for t in norm_name.split() if len(t) >= 4 and t not in PROTECTED_VENDORS]
                                primary_token = tokens[0] if tokens else ""

                                if primary_token:
                                    matched_paths = []
                                    total_leftover = 0
                                    for folder_name, folder_path in indexed_dirs:
                                        if folder_name in PROTECTED_VENDORS:
                                            continue
                                        folder_words = _normalize_token(folder_name).split()
                                        if folder_name == primary_token or primary_token in folder_words:
                                            matched_paths.append(folder_path)
                                            total_leftover += _compute_dir_size_cached(folder_path, size_cache, max_depth=3)
                                    app.leftover_paths = matched_paths
                                    app.leftover_bytes = total_leftover

                            apps.append(app)
                    except OSError:
                        continue
        except OSError:
            continue

    apps.sort(key=lambda a: (a.estimated_size_kb * 1024) + a.leftover_bytes, reverse=True)
    return apps


def scan_orphaned_appdata_ghosts(
    installed_apps: Optional[List[InstalledApp]] = None,
    cancel_event: Optional[threading.Event] = None
) -> List[Dict]:
    """
    Identifies unmatched AppData folders conservatively while protecting developer
    toolchains (npm, uv, pnpm, steam, vscode, etc.) and reparse points.
    """
    if installed_apps is None:
        installed_apps = scan_installed_applications(calculate_footprints=False, cancel_event=cancel_event)

    active_tokens = set()
    for app in installed_apps:
        for word in _normalize_token(app.name).split():
            if len(word) >= 3:
                active_tokens.add(word)
        for word in _normalize_token(app.publisher).split():
            if len(word) >= 3:
                active_tokens.add(word)

    local_app = _env_path("LOCALAPPDATA")
    roaming_app = _env_path("APPDATA")
    size_cache: Dict[str, int] = {}
    ghosts = []

    scan_pairs = []
    if local_app and local_app.exists():
        scan_pairs.append(("AppData\\Local", local_app))
    if roaming_app and roaming_app.exists():
        scan_pairs.append(("AppData\\Roaming", roaming_app))

    for root_label, root_dir in scan_pairs:
        if cancel_event and cancel_event.is_set():
            break
        try:
            for folder in root_dir.iterdir():
                if cancel_event and cancel_event.is_set():
                    break
                if not folder.is_dir() or is_reparse_point(folder):
                    continue
                fname = folder.name.lower()
                if fname in PROTECTED_VENDORS or fname.startswith("."):
                    continue

                folder_words = [w for w in _normalize_token(fname).split() if len(w) >= 3]
                if not folder_words:
                    continue

                is_matched = any(w in active_tokens for w in folder_words)
                if not is_matched:
                    size = _compute_dir_size_cached(folder, size_cache, max_depth=3)
                    if size > 0:
                        ghosts.append({
                            "folder_name": folder.name,
                            "location": root_label,
                            "full_path": folder,
                            "bytes": size,
                            "formatted_size": format_bytes(size),
                        })
        except OSError:
            continue

    ghosts.sort(key=lambda g: g["bytes"], reverse=True)
    return ghosts


def parse_windows_command(cmd_string: str) -> tuple[str, str]:
    """
    Uses official Windows Shell32 CommandLineToArgvW API to split an UninstallString
    into (executable_path, arguments_string) without any shell interpretation.
    """
    expanded = os.path.expandvars(cmd_string.strip())
    if not expanded:
        return "", ""

    # Check if MSI installation command (convert /I to /X for uninstall)
    msi_match = MSI_GUID_REGEX.search(expanded)
    if msi_match:
        sys_root = os.environ.get("SystemRoot", "C:\\Windows")
        msi_exe = str(Path(sys_root) / "System32" / "msiexec.exe")
        return msi_exe, f"/X {msi_match.group(1)}"

    if sys.platform != "win32":
        return "", ""

    argc = ctypes.c_int(0)
    CommandLineToArgvW = ctypes.windll.shell32.CommandLineToArgvW
    CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)

    argv_ptr = CommandLineToArgvW(expanded, ctypes.byref(argc))
    if not argv_ptr:
        return "", ""

    try:
        tokens = [argv_ptr[i] for i in range(argc.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(argv_ptr)

    if not tokens:
        return "", ""

    exe_candidate = tokens[0].strip('"')
    if os.path.isfile(exe_candidate):
        rest = expanded[len(tokens[0]):].strip()
        return str(Path(os.path.realpath(exe_candidate))), rest

    # Handle unquoted paths with spaces safely by matching existing .exe prefix
    lower_exp = expanded.lower()
    exe_idx = lower_exp.find(".exe")
    if exe_idx != -1:
        exe_part = expanded[:exe_idx + 4].strip('" ')
        arg_part = expanded[exe_idx + 4:].strip()
        if os.path.isfile(exe_part):
            return str(Path(os.path.realpath(exe_part))), arg_part

    return "", ""


def trigger_native_uninstaller(app: InstalledApp) -> tuple[bool, str]:
    """
    Safely launches the application's uninstaller using Windows ShellExecuteW
    (honors UAC elevation prompts cleanly and eliminates subprocess shell=True completely).
    """
    if sys.platform != "win32":
        return False, "Unsupported OS platform."

    exe_path, args = parse_windows_command(app.uninstall_string)
    if not exe_path or not os.path.isfile(exe_path):
        return False, f"Uninstaller binary not found or invalid path: {app.uninstall_string}"

    # Refuse batch/script stagers disguised as uninstallers
    ext = Path(exe_path).suffix.lower()
    if ext not in {".exe", ".msi"}:
        return False, f"Blocked non-binary uninstaller extension ({ext}) for security."

    rc = ctypes.windll.shell32.ShellExecuteW(None, "open", exe_path, args or None, None, 1)
    if rc > 32:
        return True, f"Launched {Path(exe_path).name} {args}".strip()
    return False, f"ShellExecuteW failed with Win32 status code {rc}."


def is_app_still_registered(app: InstalledApp) -> bool:
    """Checks if the app's Uninstall registry key still exists."""
    parts = app.registry_path.split("\\", 1)
    if len(parts) != 2:
        return False
    tag, sub_name = parts
    hive = winreg.HKEY_CURRENT_USER if tag == "HKCU_USER" else winreg.HKEY_LOCAL_MACHINE
    base = (
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        if tag == "HKLM_32"
        else r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    try:
        with winreg.OpenKey(hive, f"{base}\\{sub_name}"):
            return True
    except OSError:
        return False


def shred_app_leftovers(
    paths_to_shred: List[Path],
    cancel_event: Optional[threading.Event] = None
) -> dict:
    """
    Strictly guarded AppData/ProgramData leftover removal:
    1. Enforces canonical containment inside _get_allowed_appdata_roots().
    2. Rejects any reparse point (junction/symlink) or protected vendor folder.
    """
    allowed_roots = _get_allowed_appdata_roots()
    reclaimed = 0
    removed_folders = 0
    skipped_errors = 0

    for p in paths_to_shred:
        if cancel_event and cancel_event.is_set():
            break
        if not p or not p.exists() or is_reparse_point(p):
            skipped_errors += 1
            continue

        if p.name.lower() in PROTECTED_VENDORS:
            skipped_errors += 1
            continue

        # Strict containment verification (eliminates substring bypass S2 / A-02)
        if not any(is_strictly_contained(p, root) for root in allowed_roots):
            skipped_errors += 1
            continue

        folder_reclaimed = 0
        folder_failed = False

        for root, dirs, files in os.walk(p, topdown=False):
            if cancel_event and cancel_event.is_set():
                break
            root_p = Path(root)
            if is_reparse_point(root_p):
                continue
            for f in files:
                fp = root_p / f
                if is_reparse_point(fp):
                    continue
                try:
                    sz = fp.stat().st_size
                    try:
                        fp.unlink()
                    except PermissionError:
                        os.chmod(fp, stat.S_IWRITE)
                        fp.unlink()
                    folder_reclaimed += sz
                except OSError:
                    folder_failed = True
                    skipped_errors += 1
            for d in dirs:
                dp = root_p / d
                if not is_reparse_point(dp):
                    try:
                        dp.rmdir()
                    except OSError:
                        pass
        try:
            p.rmdir()
            removed_folders += 1
        except OSError:
            if not folder_failed:
                skipped_errors += 1

        reclaimed += folder_reclaimed

    return {
        "reclaimed_bytes": reclaimed,
        "reclaimed_formatted": format_bytes(reclaimed),
        "shredded_folders": removed_folders,
        "locked_skipped": skipped_errors,
    }