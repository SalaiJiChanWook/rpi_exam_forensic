# 🛡️ RPi Exam Forensic & SOC Integrity Analyzer (v1.0)

[![Version: 1.0](https://img.shields.io/badge/Version-1.0-blue.svg)](#)
[![Platform: Raspberry Pi OS 64-bit](https://img.shields.io/badge/Platform-Raspberry%20Pi%20OS%2064--bit-C51A4A?logo=raspberry-pi&logoColor=white)](https://www.raspberrypi.com/)
[![Stack: LAMP / MoodleBox](https://img.shields.io/badge/Stack-LAMP%20%2F%20MoodleBox-F98012?logo=apache&logoColor=white)](https://moodlebox.net/)
[![Language: Python 3 & Bash](https://img.shields.io/badge/Language-Python%203%20%7C%20Bash-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Forensics: Integrity & Chain of Custody](https://img.shields.io/badge/Security-SHA256%20Chain%20of%20Custody-10B981)](#-chain-of-custody--tamper-evidence)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An automated host-based forensic artifact collector, deep threat hunter, and security integrity auditor tailored for **offline, air-gapped examination servers** (MoodleBox on LAMP stack / Raspberry Pi OS 64-bit).

---

## 📌 Problem & Context

In remote, rural, or conflict-affected regions where internet connectivity is unavailable, offline exam servers (running on single-board computers like the Raspberry Pi 4/5 with Moodle) provide critical educational infrastructure.

However, air-gapped deployments without a Real-Time Clock (RTC) battery face severe physical and logical security threats:
- **Physical Exfiltration:** Unauthorized connection of USB flash drives or card readers to copy exam databases, questions, or grading schemas.
- **Network & SSH/SFTP Theft:** Rogue local connections pulling `.sql` dumps or Moodle course backups (`.mbz`) over SCP/SFTP.
- **Web Exploits & Reverse Shells:** SQL Injection (SQLi) against the Moodle web interface, unauthorized Question Bank exports, or reverse shell backdoors.
- **RTC-Less Clock Drift & Anti-Forensics:** Because Raspberry Pi 4 lacks an onboard RTC battery, system clocks freeze upon power-off—allowing attackers to hide activities outside standard time-window filters or wipe `.bash_history` logs.

**RPi Exam Forensic Tool** solves these challenges by performing **RTC-independent boot sequence auditing**, eliminating false-positive hardware alerts, and generating an **All-in-One Interactive SOC & Executive Dashboard** with bilingual (English & Burmese) incident summaries.

---

## 🚀 Key Features

* **Zero External Dependencies:** Built entirely with native Python 3 standard libraries and Linux core utilities—runs out-of-the-box in strictly air-gapped environments without `pip install`.
* **Precision USB Mass-Storage Hunter:** Filters out internal Raspberry Pi root hubs (`1d6b`, `2109`, `0424`) to eliminate false positives while capturing true external USB drive insertions, serial numbers, and `udisksd` mount paths across all historical boots.
* **RTC-Less Timeline Reconstruction:** Bypasses unreliable wall-clock filters (`--since`) and tracks every power-on session via systemd boot IDs (`journalctl --list-boots`).
* **Deep Threat Hunting (SQLi, Reverse Shells & SFTP):**
  * Scans Apache access/error logs for **SQL Injection (SQLi)** payloads (`UNION SELECT`, `OR 1=1`, `SLEEP()`) and unauthorized Moodle Question Bank exports (`/question/export.php`).
  * Hunts for **Reverse Shells** (`nc -e`, `/dev/tcp/`, `pty.spawn`, PHP webshells) and **SCP/SFTP** file exfiltration sessions.
  * Locates rogue `.sql`, `.sql.gz`, `.dump`, and Moodle `.mbz` backup archives across the filesystem.
* **Executive Burmese + Technical SOC Reporting:** Translates complex forensic artifacts into plain, actionable Burmese summaries for non-IT executives/educators alongside raw technical logs for SOC analysts.
* **Self-Contained Split-Pane Workbench:** Embeds all collected raw logs directly into `forensic_report.html` for instant browser-based inspection without requiring secondary scripts.
* **Cryptographic Chain of Custody:** Generates an end-to-end `SHA256SUMS.txt` manifest and archive checksum to guarantee tamper-evident preservation.

---

## 🏗️ Architecture & Workflow

    [ Offline Raspberry Pi 4/5 (MoodleBox / LAMP) ]
                         │
                         ▼  sudo ./venv/bin/python rpi_exam_forensic_V1.py
      ┌──────────────────────────────────────────────────────────────────┐
      │ 0. RTC-Less Boot Sequence & Power-On Session Enumeration         │
      │ 1. Precision USB Mass-Storage & Mount Point Tracking             │
      │ 2. SSH / SFTP / SCP File Transfer & Sudo Abuse Auditing          │
      │ 3. Reverse Shell, Webshell & Anti-Forensic History Hunting       │
      │ 4. Apache SQL Injection (SQLi) & Moodle Question Export Audit    │
      │ 5. Unmanaged SQL Dump (.sql) & Moodle Backup (.mbz) Discovery    │
      └──────────────────────────────────────────────────────────────────┘
                         │
                         ▼
      RPi_Forensic_<Host>_<Timestamp>/
      ├── forensic_report.html       <-- Self-Contained Executive & SOC Workbench
      ├── quick_summary.csv          <-- UTF-8-SIG Spreadsheet Report (Excel Ready)
      ├── security_findings.json     <-- Structured SIEM / Incident Data
      ├── hashes/SHA256SUMS.txt      <-- SHA-256 Cryptographic Integrity Seal
      └── raw_evidence/              <-- Full Raw Command & Kernel Logs

---

## 🛠️ Quick Start

### 1. Run on Raspberry Pi (Air-Gapped Exam Server)

Clone or copy the repository to your Raspberry Pi exam server and run with root privileges:

    git clone https://github.com/SalaiJiChanWook/rpi_exam_forensic.git
    cd rpi_exam_forensic
    python3 -m venv venv
    source venv/bin/activate
    sudo ./venv/bin/python rpi_exam_forensic_V1.py

The tool automatically compiles all evidence, embeds raw logs into the HTML dashboard, and outputs:
* `RPi_Forensic_<Hostname>_<Timestamp>.tar.gz`
* `RPi_Forensic_<Hostname>_<Timestamp>.tar.gz.sha256`

---

### 2. Transfer & Inspect on Workstation (Windows 11 / Linux / macOS)

Pull the forensic bundle from the Raspberry Pi to your workstation via `scp`:

    scp salai@Moe-Moodlebox.local:/home/salai/Desktop/RPi_Forensic_*.tar.gz* .

#### Verify & Open Dashboard:
1. Run `inspect_report.bat` on Windows 11 to verify the archive's SHA-256 hash against the `.sha256` signature.
2. Extract the archive in PowerShell or 7-Zip:

    tar -xvf RPi_Forensic_<Hostname>_<Timestamp>.tar.gz

3. Open `forensic_report.html` directly in any modern web browser to review the Executive Burmese Summary, Risk Breakdown, and Embedded Raw Log Viewer.

---

## 📊 Threat Detection Matrix (MITRE ATT&CK Aligned)

| Category | Threat Vector | MITRE ATT&CK | Forensic Method | Key Indicators |
| :--- | :--- | :---: | :--- | :--- |
| **USB Data Theft** | Flash drives / External disks | `T1052.001` | Filters `journalctl -k` & `udisksd` across all boots | `Direct-Access`, `sd[a-z]`, USB Serial Numbers, `/media/` mounts |
| **SSH / SFTP Exfil** | Network file pulling | `T1048` | Audits `sshd` & `sftp-server` journal/auth records | `subsystem request for sftp`, `scp -f`, rogue client IPs |
| **Reverse Shells** | Remote interactive control | `T1059.004` | Scans shell histories & webroots for shell payloads | `/dev/tcp/`, `nc -e`, `pty.spawn`, `eval(base64_decode)` |
| **SQL Injection (SQLi)** | Web database extraction | `T1190` | Parses Apache access logs for injection strings | `UNION SELECT`, `INFORMATION_SCHEMA`, `SLEEP()`, `/question/export.php` |
| **SQL / Backup Theft** | Local database dumping | `T1005` | Hunts non-system partitions for dump/backup files | `.sql`, `.sql.gz`, `.dump`, `.mbz`, `mysqldump` in history |
| **Anti-Forensics** | Log & history wiping | `T1070.003` | Inspects history file byte sizes and wipe commands | 0-byte `.bash_history`, `history -c`, `rm -rf /var/log` |

---

## 🔒 Chain of Custody & Tamper Evidence

To ensure digital evidence meets forensic preservation standards:
1. Every raw command output is saved into discrete evidence categories under `raw_evidence/`.
2. A complete cryptographic manifest (`hashes/SHA256SUMS.txt`) is computed prior to archiving.
3. The `.tar.gz` bundle is paired with an external `.sha256` signature, ensuring any post-collection modification is immediately detected during verification.

---

## 📂 Repository Structure

    ├── rpi_exam_forensic_V1.py    # Core Python Forensic Collector & SOC Analyzer (Run on RPi)
    ├── inspect_report.bat         # Windows 11 SHA-256 Integrity Verifier & Helper
    ├── update_dashboard.py        # Standalone Dashboard Re-builder Utility (Optional)
    ├── rpi_exam_forensic.sh       # Legacy Bash Collector (Fallback)
    ├── requirements.txt           # Environment Manifest (Standard Library Zero-Dependency)
    ├── LICENSE                    # MIT License
    └── README.md                  # Project Documentation

---

## 👤 Author

**Salai**  
* GitHub: [@SalaiJiChanWook](https://github.com/SalaiJiChanWook)  
* Focus: Backend Development, Linux System Administration, Offline Educational Infrastructure, and Defensive Security

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the [LICENSE](LICENSE) file for details.
