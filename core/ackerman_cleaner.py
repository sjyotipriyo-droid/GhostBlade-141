import os
import sys
import stat
import time
import shutil
import ctypes
import threading
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import psutil


@dataclass
class CleanTarget:
    id: str
    title: str
    character_tag: str
    character_quote: str
    description: str
    default_checked: bool
    requires_admin: bool = False
    paths: List[Path] = field(default_factory=list)
    is_deep_drive_scan: bool = False
    is_recycle_bin: bool = False
    min_age_seconds: int = 0


def get_system_drive() -> str:
    """Returns canonical OS system drive (e.g., 'C:\\') instead of hardcoding C:."""
    win_dir = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or "C:\\Windows"
    drive = Path(win_dir).drive or "C:"
    return f"{drive.upper()}\\"


def get_available_drives() -> List[str]:
    """Returns only mounted FIXED local disks (excludes USB/CD-ROM/network shares)."""
    drives = []
    for part in psutil.disk_partitions(all=False):
        opts = part.opts.lower()
        if "cdrom" in opts or "removable" in opts or not part.fstype:
            continue
        if "fixed" in opts or part.mountpoint.upper() == get_system_drive():
            drives.append(part.mountpoint)
    return drives if drives else [get_system_drive()]


def format_bytes(size_bytes: int) -> str:
    if size_bytes <= 0:
        return "0.00 MB"
    val = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if val < 1024.0:
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} PB"


def is_reparse_point(p: Path) -> bool:
    """
    Detects Windows Symlinks, Directory Junctions, and Mount Points
    using FILE_ATTRIBUTE_REPARSE_POINT (0x400). Fails closed on error.
    """
    try:
        st = os.lstat(p)
        if bool(st.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            return True
        if hasattr(os.path, "isjunction") and os.path.isjunction(p):
            return True
        return p.is_symlink()
    except OSError:
        return True


def is_strictly_contained(candidate: Path, allowed_root: Path) -> bool:
    """
    Verifies that the resolved canonical path of candidate is strictly inside
    allowed_root (prevents '..' traversal, sibling prefix bugs, and root deletion).
    """
    try:
        real_cand = Path(os.path.realpath(candidate))
        real_root = Path(os.path.realpath(allowed_root))
        return real_cand != real_root and real_cand.is_relative_to(real_root)
    except (OSError, ValueError):
        return False


def _env_path(var_name: str) -> Optional[Path]:
    """Safely resolves environment path; never falls back to Path('') current directory."""
    raw = os.environ.get(var_name, "").strip()
    if not raw:
        return None
    p = Path(raw)
    return p if p.is_absolute() else None


def get_ackerman_targets(drive_root: str = "C:\\") -> Dict[str, CleanTarget]:
    drive_path = Path(drive_root)
    sys_drive = get_system_drive()
    is_system_drive = drive_path.drive.upper() == Path(sys_drive).drive.upper()

    local_app = _env_path("LOCALAPPDATA")
    roaming_app = _env_path("APPDATA")
    win_dir = _env_path("SystemRoot") or _env_path("WINDIR") or Path(f"{sys_drive}Windows")
    prog_data = _env_path("PROGRAMDATA") or Path(f"{sys_drive}ProgramData")
    user_temp = _env_path("TEMP") or (local_app / "Temp" if local_app else None)

    targets: Dict[str, CleanTarget] = {}

    if is_system_drive and local_app and roaming_app:
        temp_paths = [p for p in [user_temp, win_dir / "Temp"] if p is not None]
        targets["user_system_temp"] = CleanTarget(
            id="user_system_temp",
            title="System & App Temporary Files (%TEMP% — >24h Old)",
            character_tag="CAPTAIN LEVI // CLEAN-FREAK PROTOCOL",
            character_quote="\"Tch. Filthy temporary scraps older than 24 hours cluttering the floor. Sweep them.\"",
            description="Clears transient files in %TEMP% and Windows\\Temp untouched for at least 24 hours (protects active installers).",
            default_checked=True,
            requires_admin=False,
            paths=temp_paths,
            min_age_seconds=86400,  # 24-hour safety cushion for live installers
        )
        targets["crash_dumps_wer"] = CleanTarget(
            id="crash_dumps_wer",
            title="Application Crash Dumps & Windows Error Reports (WER)",
            character_tag="DEADPOOL // FOURTH-WALL CLEANUP",
            character_quote="\"App crashed? Tragic. Let's remove the old memory dump logs and free up storage.\"",
            description="Removes crash dumps and Windows Error Reporting archives.",
            default_checked=True,
            requires_admin=False,
            paths=[
                local_app / "CrashDumps",
                local_app / "Microsoft" / "Windows" / "WER" / "ReportArchive",
                local_app / "Microsoft" / "Windows" / "WER" / "ReportQueue",
                prog_data / "Microsoft" / "Windows" / "WER" / "ReportArchive",
                win_dir / "Minidump",
            ],
        )
        targets["windows_update_cache"] = CleanTarget(
            id="windows_update_cache",
            title="Windows 11 Update Delivery Cache (Admin Required)",
            character_tag="CAPTAIN LEVI // SURVEY CORPS HQ",
            character_quote="\"Old update installers sitting inside SoftwareDistribution\\Download. Unchecked by default.\"",
            description="Purges downloaded Windows Update cache older than 48 hours inside SoftwareDistribution\\Download.",
            default_checked=False,
            requires_admin=True,
            paths=[win_dir / "SoftwareDistribution" / "Download"],
            min_age_seconds=172800,
        )
        targets["gpu_shader_cache"] = CleanTarget(
            id="gpu_shader_cache",
            title="Gamer GPU Shader Cache (NVIDIA / AMD / DirectX)",
            character_tag="GHOST // TF-141 VISUAL RECON",
            character_quote="\"Corrupted shader caches cause FPS micro-stutters. Enable only when troubleshooting game stutters.\"",
            description="Clears DirectX, NVIDIA DXCache/GLCache, and AMD DxcCache.",
            default_checked=False,
            requires_admin=False,
            paths=[
                local_app / "D3DSCache",
                local_app / "NVIDIA" / "DXCache",
                local_app / "NVIDIA" / "GLCache",
                local_app / "AMD" / "DxCache",
                local_app / "AMD" / "DxcCache",
            ],
        )
        targets["browser_web_cache"] = CleanTarget(
            id="browser_web_cache",
            title="Browser Media & Code Caches (Chrome / Edge / Brave)",
            character_tag="DEADPOOL // MERCENARY SWEEP",
            character_quote="\"Clears temporary web cache & Code Cache without touching logins, cookies, or history.\"",
            description="Removes disposable browser media cache (Close browsers before purging for full effect).",
            default_checked=True,
            requires_admin=False,
            paths=[
                local_app / "Google" / "Chrome" / "User Data" / "Default" / "Cache" / "Cache_Data",
                local_app / "Google" / "Chrome" / "User Data" / "Default" / "Code Cache",
                local_app / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache" / "Cache_Data",
                local_app / "Microsoft" / "Edge" / "User Data" / "Default" / "Code Cache",
                local_app / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cache" / "Cache_Data",
            ],
        )
        targets["dev_package_cache"] = CleanTarget(
            id="dev_package_cache",
            title="Developer Pip, NPM & VS Code Cache Archives",
            character_tag="INOSUKE // BEAST BREATHING",
            character_quote="\"Found gigabytes of cached wheel and package archives inside AppData!\"",
            description="Cleans pip cache, npm-cache/_cacache, and VS Code cached data (Opt-in).",
            default_checked=False,
            requires_admin=False,
            paths=[
                local_app / "pip" / "Cache",
                local_app / "npm-cache" / "_cacache",
                roaming_app / "Code" / "Cache",
                roaming_app / "Code" / "CachedData",
            ],
        )

    # Recycle Bin via Official Windows Shell API (Never deletes C:\Temp or D:\tmp user folders!)
    targets["drive_recycle_bin"] = CleanTarget(
        id="drive_recycle_bin",
        title=f"Volume {drive_path.drive} Windows Recycle Bin",
        character_tag="CAPTAIN PRICE // BRAVO-SIX",
        character_quote=f"\"Emptying the official Recycle Bin on {drive_path.drive} via Windows Shell API.\"",
        description=f"Safely empties the Windows Recycle Bin on {drive_root} using SHEmptyRecycleBinW.",
        default_checked=False,
        requires_admin=False,
        paths=[drive_path / "$RECYCLE.BIN"],
        is_recycle_bin=True,
    )

    if not is_system_drive:
        targets["drive_dev_shader_junk"] = CleanTarget(
            id="drive_dev_shader_junk",
            title=f"Volume {drive_path.drive} Compiled Build Caches (__pycache__, .pytest_cache, .next/cache)",
            character_tag="INOSUKE // DUAL-BLADE SLICE",
            character_quote=f"\"Sniffed out disposable Python & Next.js build cache directories on {drive_path.drive}!\"",
            description=f"Locates strictly disposable __pycache__, .pytest_cache, and .next/cache folders across {drive_root} (Opt-in).",
            default_checked=False,  # Opt-in safety per audit
            paths=[drive_path],
            is_deep_drive_scan=True,
        )
        targets["drive_loose_junk"] = CleanTarget(
            id="drive_loose_junk",
            title=f"Volume {drive_path.drive} Crash Dumps & Incomplete Downloads (.dmp, .mdmp, .crdownload)",
            character_tag="CAPTAIN LEVI // EXPEDITION SWEEP",
            character_quote=f"\"Optional scan for crash .dmp files and abandoned .crdownload files on {drive_path.drive}.\"",
            description=f"Finds .dmp, .mdmp, and .crdownload files older than 24h on {drive_root} (Never touches .bak/.old user backups).",
            default_checked=False,  # Opt-in safety per audit
            paths=[drive_path],
            is_deep_drive_scan=True,
            min_age_seconds=86400,
        )

    return targets


def _scan_secondary_drive_safe(
    drive_path: Path,
    mode: str,
    min_age_seconds: int = 0,
    max_depth: int = 4,
    cancel_event: Optional[threading.Event] = None
) -> tuple[int, int, List[Path], int]:
    """
    Reparse-safe scanner for secondary volumes. Never follows junctions/symlinks
    and never flags .bak/.old/.tmp user files.
    """
    total_bytes = 0
    file_count = 0
    inaccessible_count = 0
    matched_items: List[Path] = []
    skip_sys = {"$recycle.bin", "system volume information", "windows", "node_modules", ".git", ".venv", "venv"}
    safe_crash_exts = (".dmp", ".mdmp", ".crdownload")
    now = time.time()

    try:
        for root, dirs, files in os.walk(drive_path, topdown=True):
            if cancel_event and cancel_event.is_set():
                break
            root_p = Path(root)
            rel_parts = root_p.relative_to(drive_path).parts
            if len(rel_parts) > max_depth:
                dirs[:] = []
                continue

            # Filter out system dirs and any reparse point / junction directories
            filtered_dirs = []
            for d in dirs:
                if d.lower() in skip_sys:
                    continue
                dp = root_p / d
                if is_reparse_point(dp):
                    continue
                filtered_dirs.append(d)
            dirs[:] = filtered_dirs

            if mode == "cache_dirs":
                for d in list(dirs):
                    dl = d.lower()
                    if dl in {"__pycache__", ".pytest_cache"} or (
                        dl == "cache" and len(rel_parts) > 0 and rel_parts[-1].lower() == ".next"
                    ):
                        full_d = root_p / d
                        if not is_reparse_point(full_d) and is_strictly_contained(full_d, drive_path):
                            matched_items.append(full_d)
                            try:
                                for f in full_d.rglob("*"):
                                    if f.is_file() and not is_reparse_point(f):
                                        total_bytes += f.stat().st_size
                                        file_count += 1
                            except OSError:
                                inaccessible_count += 1
                        dirs.remove(d)

            elif mode == "loose_files":
                for f in files:
                    fl = f.lower()
                    if fl.endswith(safe_crash_exts):
                        fp = root_p / f
                        try:
                            if is_reparse_point(fp):
                                continue
                            st = fp.stat()
                            if min_age_seconds > 0 and (now - st.st_mtime) < min_age_seconds:
                                continue
                            total_bytes += st.st_size
                            file_count += 1
                            matched_items.append(fp)
                        except OSError:
                            inaccessible_count += 1
    except OSError:
        inaccessible_count += 1

    return total_bytes, file_count, matched_items, inaccessible_count


def scan_category_size(target: CleanTarget, cancel_event: Optional[threading.Event] = None) -> dict:
    total_bytes = 0
    file_count = 0
    inaccessible_count = 0
    accessible_paths = []
    discovered_items: List[Path] = []
    now = time.time()

    if target.is_deep_drive_scan and target.paths:
        mode = "loose_files" if target.id == "drive_loose_junk" else "cache_dirs"
        total_bytes, file_count, discovered_items, inaccessible_count = _scan_secondary_drive_safe(
            target.paths[0], mode, target.min_age_seconds, cancel_event=cancel_event
        )
        accessible_paths = [str(p) for p in discovered_items[:30]]
    else:
        for folder in target.paths:
            if cancel_event and cancel_event.is_set():
                break
            if not folder or not folder.exists() or is_reparse_point(folder):
                continue
            accessible_paths.append(str(folder))
            try:
                for root, dirs, files in os.walk(folder, topdown=True):
                    if cancel_event and cancel_event.is_set():
                        break
                    root_p = Path(root)
                    # Do not descend into junctions or symlinks
                    dirs[:] = [d for d in dirs if not is_reparse_point(root_p / d)]
                    for f in files:
                        fp = root_p / f
                        try:
                            if is_reparse_point(fp):
                                continue
                            st = fp.stat()
                            if target.min_age_seconds > 0 and (now - st.st_mtime) < target.min_age_seconds:
                                continue
                            total_bytes += st.st_size
                            file_count += 1
                            discovered_items.append(fp)
                        except OSError:
                            inaccessible_count += 1
            except OSError:
                inaccessible_count += 1

    return {
        "id": target.id,
        "title": target.title,
        "tag": target.character_tag,
        "quote": target.character_quote,
        "description": target.description,
        "bytes": total_bytes,
        "formatted_size": format_bytes(total_bytes),
        "file_count": file_count,
        "inaccessible_count": inaccessible_count,
        "default_checked": target.default_checked,
        "requires_admin": target.requires_admin,
        "active_paths": accessible_paths,
        "discovered_items": discovered_items,
    }


def scan_all_ackerman_categories(
    drive_root: str = "C:\\",
    cancel_event: Optional[threading.Event] = None
) -> dict:
    targets = get_ackerman_targets(drive_root)
    results = {}
    seen_files = set()
    grand_total_bytes = 0
    grand_total_files = 0
    total_inaccessible = 0

    for key, target in targets.items():
        if cancel_event and cancel_event.is_set():
            break
        stat_res = scan_category_size(target, cancel_event=cancel_event)
        results[key] = stat_res
        total_inaccessible += stat_res["inaccessible_count"]

        # Deduplicate across categories by canonical path
        if stat_res["discovered_items"]:
            for fp in stat_res["discovered_items"]:
                norm_p = os.path.normcase(str(fp))
                if norm_p not in seen_files:
                    seen_files.add(norm_p)
            grand_total_bytes += stat_res["bytes"]
            grand_total_files += stat_res["file_count"]

    return {
        "drive": drive_root,
        "categories": results,
        "total_bytes": grand_total_bytes,
        "total_formatted": format_bytes(grand_total_bytes),
        "total_files": grand_total_files,
        "total_inaccessible": total_inaccessible,
    }


def _safe_delete_item(item: Path, allowed_roots: List[Path], min_age_seconds: int = 0) -> tuple[int, int, int]:
    """
    Guarded deletion helper:
    1. Rejects any reparse point (junction/symlink).
    2. Verifies strict path containment inside allowed_roots.
    3. Clears read-only attribute on WinError 5 if needed.
    Returns (reclaimed_bytes, deleted_count, failed_or_skipped_count).
    """
    if not item.exists() or is_reparse_point(item):
        return 0, 0, 1
    if not any(is_strictly_contained(item, r) for r in allowed_roots if r and r.exists()):
        return 0, 0, 1

    now = time.time()
    reclaimed = 0
    deleted = 0
    failed = 0

    if item.is_file():
        try:
            st = item.stat()
            if min_age_seconds > 0 and (now - st.st_mtime) < min_age_seconds:
                return 0, 0, 0
            try:
                item.unlink()
            except PermissionError:
                os.chmod(item, stat.S_IWRITE)
                item.unlink()
            return st.st_size, 1, 0
        except OSError:
            return 0, 0, 1

    elif item.is_dir():
        for root, dirs, files in os.walk(item, topdown=False):
            root_p = Path(root)
            if is_reparse_point(root_p):
                continue
            for f in files:
                fp = root_p / f
                if is_reparse_point(fp):
                    continue
                try:
                    st = fp.stat()
                    if min_age_seconds > 0 and (now - st.st_mtime) < min_age_seconds:
                        continue
                    try:
                        fp.unlink()
                    except PermissionError:
                        os.chmod(fp, stat.S_IWRITE)
                        fp.unlink()
                    reclaimed += st.st_size
                    deleted += 1
                except OSError:
                    failed += 1
            for d in dirs:
                dp = root_p / d
                if is_reparse_point(dp):
                    continue
                try:
                    dp.rmdir()
                except OSError:
                    pass
        try:
            item.rmdir()
        except OSError:
            pass

    return reclaimed, deleted, failed


def execute_ackerman_purge(
    selected_ids: List[str],
    drive_root: str = "C:\\",
    approved_scan_snapshot: Optional[Dict[str, dict]] = None,
    cancel_event: Optional[threading.Event] = None
) -> dict:
    """
    Executes guarded cleanup on selected categories, bound to the exact drive_root
    and approved scan snapshot so no unreviewed files or reparse targets are touched.
    """
    targets = get_ackerman_targets(drive_root)
    reclaimed_bytes = 0
    deleted_files = 0
    failed_or_locked = 0

    for cid in selected_ids:
        if cancel_event and cancel_event.is_set():
            break
        target = targets.get(cid)
        if not target:
            continue

        # Official Windows Shell API for Recycle Bin
        if target.is_recycle_bin and sys.platform == "win32":
            try:
                SHERB_NOCONFIRMATION = 0x00000001
                SHERB_NOPROGRESSUI = 0x00000002
                SHERB_NOSOUND = 0x00000004
                flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
                ctypes.windll.shell32.SHEmptyRecycleBinW(None, drive_root, flags)
                if approved_scan_snapshot and cid in approved_scan_snapshot:
                    reclaimed_bytes += approved_scan_snapshot[cid].get("bytes", 0)
                    deleted_files += approved_scan_snapshot[cid].get("file_count", 0)
            except OSError:
                failed_or_locked += 1
            continue

        # Use approved snapshot items when available to prevent TOCTOU surprises
        if target.is_deep_drive_scan:
            snap_items = []
            if approved_scan_snapshot and cid in approved_scan_snapshot:
                snap_items = approved_scan_snapshot[cid].get("discovered_items", [])
            for item in snap_items:
                if cancel_event and cancel_event.is_set():
                    break
                r_b, d_c, f_c = _safe_delete_item(Path(item), target.paths, target.min_age_seconds)
                reclaimed_bytes += r_b
                deleted_files += d_c
                failed_or_locked += f_c
            continue

        for folder in target.paths:
            if cancel_event and cancel_event.is_set():
                break
            if not folder or not folder.exists() or is_reparse_point(folder):
                continue
            try:
                for child in folder.iterdir():
                    if cancel_event and cancel_event.is_set():
                        break
                    r_b, d_c, f_c = _safe_delete_item(child, [folder], target.min_age_seconds)
                    reclaimed_bytes += r_b
                    deleted_files += d_c
                    failed_or_locked += f_c
            except OSError:
                failed_or_locked += 1

    return {
        "drive": drive_root,
        "reclaimed_bytes": reclaimed_bytes,
        "reclaimed_formatted": format_bytes(reclaimed_bytes),
        "deleted_items": deleted_files,
        "skipped_or_failed": failed_or_locked,
    }