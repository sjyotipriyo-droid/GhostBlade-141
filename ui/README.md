<div align="center">

# 🗡️ GhostBlade-141 (Signature Edition)

**A zero-bloat Windows toolkit that cleans, uninstalls, audits, and protects, all in one app.**

### By Jyotipriyo Saha

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![PySide6 / Qt6](https://img.shields.io/badge/PySide6-Qt6-41CD52?style=for-the-badge&logo=qt&logoColor=white)](https://doc.qt.io/qtforpython-6/)
[![Windows 11 | 10](https://img.shields.io/badge/Windows-11%20%7C%2010-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Bandit Verified](https://img.shields.io/badge/Bandit%20Verified-0%20Vulnerabilities-2EA44F?style=for-the-badge)](https://bandit.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-D4AF37?style=for-the-badge)](LICENSE)

[⬇️ Download Latest Release](https://github.com/sjyotipriyo-droid/GhostBlade-141/releases) · [🐞 Report an Issue](https://github.com/sjyotipriyo-droid/GhostBlade-141/issues)

</div>

---

## 🌟 Overview: Why GhostBlade-141?

A Windows PC slowly fills up with leftovers and hidden risks. Temp files pile up. Uninstalled programs leave folders behind. And most security tools either run in the background all day or flag things without ever explaining why.

**GhostBlade-141 (Signature Edition)** combines four jobs into one desktop app:

| | Module | Plain-English job |
|---|---|---|
| 🧹 | **Junk Cleaner** | Safely clears temporary files, crash dumps, and caches |
| 🧭 | **Deep App Uninstaller** | Removes a program and then finds the hidden folders it left behind |
| 🛡️ | **Malware & Security Scanner (EDR)** | Checks your PC for suspicious processes, startup entries, and files, and shows you what it found |
| 🔐 | **Self-Shield & Quarantine Vault** | Protects GhostBlade itself from tampering and lets you isolate and restore suspicious files |

It is built to stay out of your way: **0 MB background RAM when closed**. Nothing keeps running after you exit. The interface uses a custom **Obsidian & Champagne Gold** dark theme.

<!-- Add a screenshot here, for example: ![GhostBlade-141 main window](docs/screenshot.png) -->

> **Created and architected by Jyotipriyo Saha** · Cybersecurity & Systems Architecture · West Bengal, India

---

## ⚡ Quick Installation Guide

### Method 1: One-Click Installer (Recommended for All Users)

1. Go to the **[GitHub Releases](https://github.com/sjyotipriyo-droid/GhostBlade-141/releases)** section on the right side of this repository.
2. Download **`GhostBlade141_Setup_v1.0.0.exe`**.
3. Double-click the installer, accept the MIT License, and click **Install**.

The installer automatically creates **Desktop and Start Menu shortcuts** and registers an **official uninstaller**, so you can remove GhostBlade-141 cleanly from Windows Settings at any time.

<details>
<summary><b>Windows shows a "Windows protected your PC" (SmartScreen) message?</b></summary>

<br>

New or independent installers can trigger this warning. If you downloaded the file from this repository's Releases page, click **More info**, then **Run anyway**.

To double-check your download, compare its SHA-256 hash with the one listed in the release notes:

```powershell
Get-FileHash .\GhostBlade141_Setup_v1.0.0.exe -Algorithm SHA256
```

</details>

### Method 2: Run from Source Code (For Developers & Students)

You need [Git](https://git-scm.com/) and [Python 3.12](https://www.python.org/downloads/).

```powershell
git clone https://github.com/sjyotipriyo-droid/GhostBlade-141.git
cd GhostBlade-141
pip install PySide6 psutil
python app.py
```

---

## 🧩 Core Modules: The 4 Decks Explained Simply

### 01 // Junk Cleaner (Ackerman Purge Protocol) 🧹

**What it does:** Frees up disk space by clearing:

- **Temporary files** older than 24 hours (so installers that are running right now are never broken)
- **Crash dumps** and **Windows Error Reports** (files Windows saves when a program crashes)
- **Browser media caches**, without touching your passwords or history
- **GPU shader caches** (optional)
- **The Recycle Bin**, emptied through the official Windows Shell APIs

> 💡 **What is a shader cache?** Games and apps save pre-built graphics data so they load faster. It is safe to delete, but a game may take a little longer on its next launch while it rebuilds. That is why this one is optional.

**Safety built in:** GhostBlade refuses to follow **symlinks and junctions** (special folder shortcuts that can trick a cleaner into deleting files somewhere it should not).

### 02 // Deep App Uninstaller (Inosuke Spatial Radar) 🧭

**What it does:** Lists your installed programs and maps the hidden folders they leave behind in **`AppData`** and **`ProgramData`**.

> 💡 **What are AppData leftovers?** When you uninstall a program, Windows removes the program itself but often leaves its settings and cache folders behind. Over time these add up and take space for software you no longer have.

It uses a safe two-step workflow:

| Step | Action |
|---|---|
| **Step 1** | Launch the program's **official uninstaller** using native Win32 APIs |
| **Step 2** | Review and **clean the leftover folders** |

**Safety built in:** Essential developer tools (`npm`, `pip`, `vscode`, `steam`, `git`) are protected from removal. Uninstallers are launched through native Win32 APIs with **zero `shell=True` risk**. (`shell=True` passes text through the Windows command interpreter, which is a classic way for attackers to sneak in extra commands. GhostBlade avoids it entirely.)

### 03 // Malware & Security Scanner (Bravo-Six EDR) 🛡️

**What it does:** A **point-in-time security scanner**: it takes a snapshot of your PC right now and checks for:

| Check | In plain English | Why it matters |
|---|---|---|
| **Fake Windows system processes** | Programs pretending to be Windows but running from outside `System32` | Malware often disguises itself with a real system name |
| **Suspicious startup programs** | Things set to launch every time you boot | A common way for unwanted software to survive a restart |
| **Unusual outbound network ports** | Programs talking to the internet on uncommon ports | Can reveal hidden communication |
| **Deceptive double-extension files** | Files like `invoice.pdf.exe` that look like documents but are programs | A classic phishing trick |

**Single File Inspector:** Check any file's **SHA-256 hash** (its unique fingerprint, useful for looking it up on threat-intelligence sites) and its **Shannon Entropy**.

> 💡 **What is file entropy?** Entropy measures how random a file's contents are. Normal documents and programs have patterns, so their randomness is lower. Encrypted or packed (compressed and obfuscated) files look almost completely random. High entropy is a **clue, not proof**: legitimate archives and media files can score high too.

> ⚠️ **Good to know:** GhostBlade's scanner is heuristic, which means it flags things that *look* suspicious. Treat results as leads to review, not final verdicts. It complements, and does not replace, Windows Security or a full antivirus.

### 04 // Self-Shield & Quarantine Recovery Vault 🔐

**What it does:**

- **DLL hijacking protection at startup.** *(DLL hijacking is when an attacker places a malicious library file where an app looks first, so the app loads it by mistake.)* GhostBlade-141 guards against this when it launches.
- **Tamper detection.** It verifies **SHA-256 baseline hashes** of its own code modules, so it can tell if its files have been changed.
- **1-click Quarantine Restore Vault.** Safely isolate suspicious files and restore them anytime if you change your mind.

---

## 🔒 Security & Code Quality Highlights

*For recruiters, reviewers, and engineers.*

| Highlight | Detail | What it means in plain English |
|---|---|---|
| **Static analysis** | Audited with **Bandit (PyCQA)**: **0 High, 0 Medium, 0 Low** findings across **2,840+ lines** of code | An automated scan found none of the common Python security mistakes |
| **No shell execution** | Zero `subprocess(..., shell=True)`. Uses native Win32 `CommandLineToArgvW` and `ShellExecuteW` | Closes off the command-injection route |
| **Safe deletion guards** | Strict canonical path containment (`is_relative_to`) and Windows Reparse-Point (`FILE_ATTRIBUTE_REPARSE_POINT`) checks before any file is deleted | The app can only delete inside folders it is meant to touch, and cannot be redirected by shortcuts |
| **Responsive architecture** | Non-blocking multi-threaded Qt6 workers with cooperative cancellation and single-instance mutex locking | The UI never freezes, you can cancel safely mid-task, and only one copy of the app runs at a time |

> Bandit is a static analyzer. It catches common security mistakes but does not replace manual review or penetration testing.

<details>
<summary><b>Reproduce the Bandit scan yourself</b></summary>

<br>

```powershell
pip install bandit
bandit -r .
```

</details>

<details>
<summary><b>Project layout</b></summary>

<br>

```text
GhostBlade-141/
├── app.py                        # Application entry point
├── main_window.py                # Main Qt6 window and UI
└── core/
    ├── ackerman_cleaner.py       # 01 // Junk Cleaner
    ├── inosuke_uninstaller.py    # 02 // Deep App Uninstaller
    ├── bravo_edr.py              # 03 // Malware & Security Scanner
    └── self_shield.py            # 04 // Self-Shield & Quarantine Vault
```

</details>

---

## 📘 Built-in User Guide & Support Hub

GhostBlade-141 is designed so a first-time user is never lost:

- **Interactive visual workflow:** each deck walks you through a clear **Step 1 → Step 2 → Step 3** flow right inside the app.
- **Hover tooltips:** hover over any control to see what it does before you click it.
- **Contact & Support Hub:**
  - **1-click diagnostic log export**, so you can attach logs to a bug report without digging through folders
  - **Email reporting** to reach the developer directly
  - **LinkedIn connection** to get in touch or follow the project

---

## 📄 License & Author Credit

**MIT License**. Copyright (c) 2026 **Jyotipriyo Saha**. See the [LICENSE](LICENSE) file for the full text.

**Created & Lead Architect:** Jyotipriyo Saha · Cybersecurity & Systems Architecture · West Bengal, India

[![GitHub](https://img.shields.io/badge/GitHub-@sjyotipriyo--droid-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/sjyotipriyo-droid)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/<YOUR_LINKEDIN_ID>)

<div align="center">

**If GhostBlade-141 saved you time or space, consider giving the repo a ⭐**

</div>