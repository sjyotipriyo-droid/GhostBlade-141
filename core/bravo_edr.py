import os
import json
import math
import time
import shutil
import winreg
import ipaddress
import threading
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional
import psutil
from core.self_shield import compute_file_sha256
from core.ackerman_cleaner import _env_path, get_system_drive, is_reparse_point


@dataclass
class ThreatFinding:
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    confidence: str        # HIGH, MEDIUM, HEURISTIC
    category: str
    title: str
    target_path: str
    details: str
    mitre_id: str
    character_comm: str


CORE_WINDOWS_BINARIES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "smss.exe", "taskhostw.exe"
}

EXPECTED_PARENTS = {
    "svchost.exe": {"services.exe"},
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
}

SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6667, 6697, 9001, 9050, 5555}

HIGH_RISK_SCRIPT_TOKENS = [
    "-encodedcommand", "frombase64string", "downloadstring",
    "invoke-expression", "mshta", "certutil -urlcache", "bitsadmin /transfer"
]


def _get_windows_dirs() -> tuple[Path, Path, Path]:
    win_raw = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or f"{get_system_drive()}Windows"
    win_dir = Path(os.path.realpath(win_raw))
    return win_dir, win_dir / "System32", win_dir / "SysWOW64"


def calculate_shannon_entropy(filepath: Path, max_read_bytes: int = 1048576) -> tuple[float, str]:
    """
    Returns (entropy_value, status_string).
    Never returns 0.0 on read failure so unreadable files are never mislabeled 'CLEAN'.
    """
    if not filepath.exists() or not filepath.is_file():
        return -1.0, "FILE_MISSING"
    try:
        with open(filepath, "rb") as f:
            data = f.read(max_read_bytes)
        if not data:
            return 0.0, "EMPTY_FILE"
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 2), "OK"
    except OSError as exc:
        return -1.0, f"UNREADABLE ({exc.errno or 'ACCESS_DENIED'})"


def is_public_routable_ip(ip_str: str) -> bool:
    """
    Uses Python's standard ipaddress module to accurately exclude loopback,
    RFC1918 (10/8, 172.16/12, 192.168/16), link-local, multicast, and IPv6 ULA.
    """
    try:
        clean_ip = ip_str.split("%")[0]
        addr = ipaddress.ip_address(clean_ip)
        mapped = getattr(addr, "ipv4_mapped", None)
        if mapped is not None:
            addr = mapped
        return addr.is_global
    except ValueError:
        return False


def scan_startup_persistence() -> tuple[List[ThreatFinding], int, int]:
    """Returns (findings, keys_checked, keys_inaccessible)."""
    findings: List[ThreatFinding] = []
    checked = 0
    inaccessible = 0

    run_keys = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM_WOW64_Run"),
    ]

    for hive, subkey, label in run_keys:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                checked += 1
                num_vals = winreg.QueryInfoKey(key)[1]
                for i in range(num_vals):
                    try:
                        name, cmd_val, _ = winreg.EnumValue(key, i)
                        cmd_str = os.path.expandvars(str(cmd_val).strip())
                        cmd_lower = cmd_str.lower()

                        for indicator in HIGH_RISK_SCRIPT_TOKENS:
                            if indicator in cmd_lower:
                                findings.append(ThreatFinding(
                                    severity="HIGH",
                                    confidence="MEDIUM",
                                    category="PERSISTENCE_LOTL",
                                    title=f"Script Stager Indicator in Startup: {name}",
                                    target_path=f"{label}\\{name}",
                                    details=f"Expanded command contains '{indicator}': {cmd_str}",
                                    mitre_id="T1547.001 / T1059",
                                    character_comm="PRICE: \"Startup entry uses script/encoded stager syntax. Verify legitimacy.\""
                                ))
                                break

                        if any(p in cmd_lower for p in ["\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\"]):
                            findings.append(ThreatFinding(
                                severity="MEDIUM",
                                confidence="HEURISTIC",
                                category="PERSISTENCE_PATH",
                                title=f"Volatile Path Binary in Startup: {name}",
                                target_path=f"{label}\\{name}",
                                details=f"Startup command executes from Temp/Downloads/Public directory: {cmd_str}",
                                mitre_id="T1547.001",
                                character_comm="GHOST: \"Startup binary points to a temporary or public staging directory.\""
                            ))
                    except OSError:
                        inaccessible += 1
        except OSError:
            inaccessible += 1

    roaming = _env_path("APPDATA")
    prog_data = _env_path("PROGRAMDATA")
    startup_dirs = []
    if roaming:
        startup_dirs.append(roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
    if prog_data:
        startup_dirs.append(prog_data / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")

    for sdir in startup_dirs:
        if not sdir.exists():
            continue
        try:
            for item in sdir.iterdir():
                if item.suffix.lower() in {".vbs", ".bat", ".cmd", ".ps1", ".js", ".hta", ".scr"}:
                    findings.append(ThreatFinding(
                        severity="MEDIUM",
                        confidence="HEURISTIC",
                        category="STARTUP_SCRIPT",
                        title=f"Startup Script Present: {item.name}",
                        target_path=str(item),
                        details=f"Script file ({item.suffix}) located in Windows Startup folder.",
                        mitre_id="T1547.001",
                        character_comm="GHOST: \"Script found in auto-launch Startup folder. Confirm you placed it there.\""
                    ))
        except OSError:
            inaccessible += 1

    return findings, checked, inaccessible


def scan_active_processes_and_c2(cancel_event: Optional[threading.Event] = None) -> dict:
    """
    Audits live processes with exact System32/SysWOW64 path validation, parent process
    verification, and accurate coverage accounting (verified vs unverifiable/access-denied).
    """
    findings: List[ThreatFinding] = []
    verified_procs = 0
    unverifiable_procs = 0
    _, sys32_dir, syswow64_dir = _get_windows_dirs()
    allowed_sys_dirs = {os.path.normcase(str(sys32_dir)), os.path.normcase(str(syswow64_dir))}

    pid_to_name: Dict[int, str] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
        if cancel_event and cancel_event.is_set():
            break
        try:
            info = proc.info
            pid = info.get("pid")
            pname = (info.get("name") or "").strip()
            pname_lower = pname.lower()
            pexe = info.get("exe")
            ppid = info.get("ppid")

            if pid and pname:
                pid_to_name[pid] = pname

            if not pexe:
                unverifiable_procs += 1
                continue

            verified_procs += 1
            exe_path = Path(os.path.realpath(pexe))
            exe_parent_norm = os.path.normcase(str(exe_path.parent))

            # 1. Exact System32 / SysWOW64 Masquerade & Parent Check
            if pname_lower in CORE_WINDOWS_BINARIES:
                if exe_parent_norm not in allowed_sys_dirs:
                    findings.append(ThreatFinding(
                        severity="CRITICAL",
                        confidence="HIGH",
                        category="PROCESS_MASQUERADE",
                        title=f"System Binary Outside System32: {pname} (PID {pid})",
                        target_path=str(exe_path),
                        details=f"Core Windows binary '{pname}' is running from non-System32 directory: {exe_path}",
                        mitre_id="T1036.005",
                        character_comm="PRICE: \"Imposter path! Core Windows binary running outside System32!\""
                    ))
                elif pname_lower in EXPECTED_PARENTS and ppid:
                    try:
                        parent_name = psutil.Process(ppid).name().lower()
                        if parent_name not in EXPECTED_PARENTS[pname_lower]:
                            findings.append(ThreatFinding(
                                severity="HIGH",
                                confidence="MEDIUM",
                                category="PARENT_ANOMALY",
                                title=f"Unusual Parent for {pname} (PID {pid})",
                                target_path=str(exe_path),
                                details=f"{pname} spawned by '{parent_name}' (PID {ppid}) instead of {EXPECTED_PARENTS[pname_lower]}.",
                                mitre_id="T1036",
                                character_comm="GHOST: \"System process has an unexpected parent lineage.\""
                            ))
                    except (psutil.Error, OSError):
                        pass

            # 2. High-Entropy Process in Temp/Public
            pexe_lower = str(exe_path).lower()
            if "\\appdata\\local\\temp\\" in pexe_lower or "\\users\\public\\" in pexe_lower:
                ent, status = calculate_shannon_entropy(exe_path)
                if status == "OK" and ent >= 7.25:
                    findings.append(ThreatFinding(
                        severity="MEDIUM",
                        confidence="HEURISTIC",
                        category="PACKED_TEMP_PROCESS",
                        title=f"High-Entropy Binary Running in Temp: {pname} (PID {pid})",
                        target_path=str(exe_path),
                        details=f"Executing from volatile folder with entropy {ent}/8.00 (May be packed installer or payload).",
                        mitre_id="T1027.002",
                        character_comm="GHOST: \"Packed binary executing in Temp. Verify if an installer is currently running.\""
                    ))

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            unverifiable_procs += 1
            continue

    # 3. Network Socket Audit with ipaddress.is_global & PID-to-Process Resolution
    socket_audit_ok = True
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED" and conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                if remote_port in SUSPICIOUS_PORTS and is_public_routable_ip(remote_ip):
                    proc_label = pid_to_name.get(conn.pid, f"PID {conn.pid}")
                    findings.append(ThreatFinding(
                        severity="HIGH",
                        confidence="HEURISTIC",
                        category="NETWORK_ANOMALY",
                        title=f"Non-Standard Outbound Port {remote_port} ({proc_label})",
                        target_path=f"{proc_label} (PID {conn.pid}) -> {remote_ip}:{remote_port}",
                        details=f"Process '{proc_label}' connected to public IP {remote_ip} on monitored port {remote_port}.",
                        mitre_id="T1571",
                        character_comm="PRICE: \"Outbound connection on a non-standard port to a public IP.\""
                    ))
    except (psutil.AccessDenied, OSError):
        socket_audit_ok = False

    return {
        "findings": findings,
        "verified_procs": verified_procs,
        "unverifiable_procs": unverifiable_procs,
        "socket_audit_ok": socket_audit_ok,
    }


def scan_high_risk_drop_zones(cancel_event: Optional[threading.Event] = None) -> tuple[List[ThreatFinding], int, int]:
    """
    Scans Downloads and Temp root for deceptive double extensions (verifying PE 'MZ' magic bytes)
    and high-entropy executables.
    """
    findings: List[ThreatFinding] = []
    files_inspected = 0
    files_skipped = 0

    user_profile = _env_path("USERPROFILE")
    temp_dir = _env_path("TEMP")
    drop_zones = []
    if user_profile and (user_profile / "Downloads").exists():
        drop_zones.append(user_profile / "Downloads")
    if temp_dir and temp_dir.exists():
        drop_zones.append(temp_dir)

    double_ext_patterns = (
        ".pdf.exe", ".docx.exe", ".xlsx.exe", ".jpg.exe", ".png.exe",
        ".txt.exe", ".mp4.exe", ".pdf.scr", ".jpg.scr", ".pdf.bat", ".pdf.cmd"
    )

    for zone in drop_zones:
        if cancel_event and cancel_event.is_set():
            break
        try:
            for item in zone.iterdir():
                if cancel_event and cancel_event.is_set():
                    break
                if not item.is_file() or is_reparse_point(item):
                    continue
                files_inspected += 1
                name_lower = item.name.lower()

                if name_lower.endswith(double_ext_patterns):
                    is_pe = False
                    try:
                        with open(item, "rb") as f:
                            is_pe = (f.read(2) == b"MZ")
                    except OSError:
                        pass

                    findings.append(ThreatFinding(
                        severity="HIGH" if is_pe else "MEDIUM",
                        confidence="HIGH" if is_pe else "HEURISTIC",
                        category="DECEPTIVE_DOUBLE_EXT",
                        title=f"Deceptive Double-Extension File: {item.name}",
                        target_path=str(item),
                        details=f"Disguised executable extension in drop-zone (PE 'MZ' header verified: {is_pe}).",
                        mitre_id="T1036.007",
                        character_comm="DEADPOOL: \"Double file extension detected in drop zone!\""
                    ))
        except OSError:
            files_skipped += 1

    return findings, files_inspected, files_skipped


def run_bravo_six_edr_sweep(cancel_event: Optional[threading.Event] = None) -> Dict:
    p_findings, reg_checked, reg_skipped = scan_startup_persistence()
    proc_res = scan_active_processes_and_c2(cancel_event=cancel_event)
    d_findings, drop_checked, drop_skipped = scan_high_risk_drop_zones(cancel_event=cancel_event)

    all_threats = p_findings + proc_res["findings"] + d_findings
    incomplete = (reg_skipped > 0) or (not proc_res["socket_audit_ok"]) or (proc_res["unverifiable_procs"] > 0)

    if len(all_threats) > 0:
        status_label = f"ANOMALIES_FLAGGED ({len(all_threats)})"
    elif incomplete:
        status_label = "NO_MATCHES (PARTIAL COVERAGE — RUN AS ADMIN FOR FULL ACCESS)"
    else:
        status_label = "NO_MATCHES (COMPLETE COVERAGE)"

    return {
        "processes_verified": proc_res["verified_procs"],
        "processes_unverifiable": proc_res["unverifiable_procs"],
        "dropzone_files_audited": drop_checked,
        "reg_keys_checked": reg_checked,
        "threat_count": len(all_threats),
        "status": status_label,
        "findings": all_threats,
    }


def quarantine_suspicious_file(target_file: Path, base_dir: Path) -> tuple[bool, str]:
    """
    Safely isolates a suspicious file into Quarantine_Vault with a unique timestamped
    name and records its original path & SHA-256 in vault_manifest.json for 1-click restore.
    Refuses to quarantine core Windows system files.
    """
    if not target_file.exists() or not target_file.is_file() or is_reparse_point(target_file):
        return False, "Target is not a valid regular disk file."

    real_target = Path(os.path.realpath(target_file))
    win_dir, _, _ = _get_windows_dirs()
    if real_target.is_relative_to(win_dir):
        return False, "Refused: Target resides inside Windows system directory."

    sha256, status = compute_file_sha256(real_target)
    if status != "OK":
        return False, f"Cannot read file for quarantine ({status})."

    vault_dir = base_dir / "Quarantine_Vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    manifest_file = vault_dir / "vault_manifest.json"

    vault_name = f"{int(time.time())}_{sha256[:8]}_{real_target.name}.quarantine"
    dest = vault_dir / vault_name

    try:
        shutil.move(str(real_target), str(dest))
    except OSError as exc:
        return False, f"Move failed (File may be in use by a running process): {exc}"

    manifest = {}
    if manifest_file.exists():
        try:
            manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            manifest = {}

    manifest[vault_name] = {
        "original_path": str(real_target),
        "sha256": sha256,
        "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    except OSError:
        pass

    return True, f"Isolated as {vault_name}"


def get_quarantined_items(base_dir: Path) -> List[Dict]:
    vault_dir = base_dir / "Quarantine_Vault"
    manifest_file = vault_dir / "vault_manifest.json"
    if not manifest_file.exists():
        return []
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        items = []
        for vname, meta in manifest.items():
            vpath = vault_dir / vname
            if vpath.exists():
                items.append({
                    "vault_name": vname,
                    "vault_path": vpath,
                    "original_path": meta.get("original_path", ""),
                    "sha256": meta.get("sha256", ""),
                    "quarantined_at": meta.get("quarantined_at", ""),
                })
        return items
    except (OSError, ValueError):
        return []


def restore_quarantined_file(vault_name: str, base_dir: Path) -> tuple[bool, str]:
    vault_dir = base_dir / "Quarantine_Vault"
    manifest_file = vault_dir / "vault_manifest.json"
    if not manifest_file.exists():
        return False, "Quarantine manifest not found."

    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        meta = manifest.get(vault_name)
        if not meta:
            return False, "Item not found in manifest."

        vpath = vault_dir / vault_name
        orig_path = Path(meta["original_path"])
        if not vpath.exists():
            return False, "Quarantined file missing from vault."

        orig_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(vpath), str(orig_path))
        del manifest[vault_name]
        manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return True, f"Restored to {orig_path}"
    except OSError as exc:
        return False, f"Restore failed: {exc}"