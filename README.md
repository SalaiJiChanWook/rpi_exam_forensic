# 🛡️ RPi Exam Forensic & Integrity Analyzer (v1.0)

[![Platform: Raspberry Pi OS 64-bit](https://img.shields.io/badge/Platform-Raspberry%20Pi%20OS%2064--bit-C51A4A?logo=raspberry-pi&logoColor=white)](https://www.raspberrypi.com/)
[![Stack: LAMP / MoodleBox](https://img.shields.io/badge/Stack-LAMP%20%2F%20MoodleBox-F98012?logo=apache&logoColor=white)](https://moodlebox.net/)
[![Language: Python 3 & Bash](https://img.shields.io/badge/Language-Python%203%20%7C%20Bash-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Forensics: Integrity & Chain of Custody](https://img.shields.io/badge/Security-SHA256%20Chain%20of%20Custody-10B981)](#-chain-of-custody--tamper-evidence)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An automated host-based forensic artifact collector and security integrity auditor tailored for **offline, air-gapped examination servers** (MoodleBox on LAMP stack / Raspberry Pi OS 64-bit).

---

## 📌 Problem & Context

In remote, rural, or conflict-affected regions where internet connectivity is unavailable, offline exam servers (running on single-board computers like the Raspberry Pi with Moodle) provide critical educational infrastructure. 

However, air-gapped deployments face specific physical security threats:
- **Physical Exfiltration:** Unauthorized connection of USB drives to copy exam databases, questions, or grading schemas.
- **Privilege Escalation:** Sudo abuse, unauthorized root logins, or tampering with Apache webroots and `config.php`.
- **Anti-Forensics:** Intentional wiping of shell histories (`.bash_history`), clearing `/var/log` artifacts, or unlinking database dumps.

**RPi Exam Forensic Tool** was developed to bridge this gap by automatically gathering volatile and non-volatile evidence, computing tamper-proof cryptographic digests, and rendering an interactive **All-in-One Forensic Dashboard** for post-examination audit.

---

## 🚀 Key Features

* **Zero External Dependencies:** Built entirely with native Python standard libraries and Linux core utilities—runs natively in air-gapped environments without `pip install` access.
* **Hardware & Storage Audit:** Analyzes kernel ring-buffers (`journalctl -k`) to detect USB mass-storage insertions, SCSI subsystem registrations, and removable disk IDs.
* **Authentication & Persistence Verification:** Audits `/var/log/auth.log`, non-standard UID 0 accounts, modified sudoers configurations, custom systemd timers, and cron persistence.
* **Integrity & Exfiltration Hunting:** Scans for rogue `.sql`, `.sql.gz`, or compressed archives across non-system locations, verifies Moodle `config.php` permissions/metadata (with credentials safely redacted).
* **Anti-Forensic Detection:** Detects zero-byte truncated bash history files and wipes.
* **Executive HTML Dashboard:** Exports an interactive, split-panel dark-mode web console that combines threat classification metrics with an embedded raw evidence log inspector.
* **Cryptographic Verification:** Generates an end-to-end SHA-256 manifest to guarantee evidence chain of custody.

---

## 🏗️ Architecture & Workflow

```text
[ Offline Raspberry Pi (MoodleBox / LAMP) ]
                     │
                     ▼  sudo ./venv/bin/python rpi_exam_forensic_V1.py
  ┌──────────────────────────────────────────────────────────────────┐
  │ 1. Kernel USB & Mass Storage Vector Scanning                     │
  │ 2. Authentication, Sudo & Non-Standard UID 0 Discovery           │
  │ 3. Database Dump & Backup Archive Identification                 │
  │ 4. Moodle / Webroot Metadata Integrity Check                     │
  │ 5. Bash History & Anti-Forensic Anomaly Detection                │
  └──────────────────────────────────────────────────────────────────┘
                     │
                     ▼
  RPi_Forensic_<Host>_<Timestamp>/
  ├── forensic_report.html       <-- Interactive Forensic Dashboard
  ├── quick_summary.csv          <-- Structured Findings (Spreadsheet Ready)
  ├── security_findings.json     <-- Structured Incident Data
  ├── hashes/SHA256SUMS.txt      <-- SHA-256 Cryptographic Integrity Seal
  └── raw_evidence/              <-- Categorized Raw Command & System Logs
```

---

## 🛠️ Quick Start

### 1. Run on Raspberry Pi (Air-Gapped Server)

Clone or copy the tool repository to your Raspberry Pi exam server:

```bash
# Clone the repository
git clone [https://github.com/SalaiJiChanWook/rpi_exam_forensic.git](https://github.com/SalaiJiChanWook/rpi_exam_forensic.git)
cd rpi_exam_forensic

# Initialize Python Virtual Environment (using Python standard library)
python3 -m venv venv
source venv/bin/activate

# Execute collection with elevated root privileges
sudo ./venv/bin/python rpi_exam_forensic_V1.py
```

The tool will compile all artifacts, generate the manifest, and create a timestamped compressed package:
`RPi_Forensic_<Hostname>_<Timestamp>.tar.gz` and its corresponding `.sha256` checksum.

---

### 2. Inspect on Workstation (Windows 11 / Linux / macOS)

Transfer both the `.tar.gz` and `.sha256` files to your analysis workstation.

#### Windows Verification & Extraction:
1. Run `inspect_report.bat` to verify the archive's SHA-256 hash.
2. Extract the archive using 7-Zip or PowerShell:
   ```powershell
   tar -xvf RPi_Forensic_<Hostname>_<Timestamp>.tar.gz
   ```
3. Run the dashboard integrator to embed all raw logs into the single-page view:
   ```powershell
   python update_dashboard.py
   ```
4. Open `forensic_report.html` in your web browser (or via VS Code Live Server) to access the interactive investigation console.

---

## 📊 Threat Detection Matrix

| Category | Vector | Forensic Method | Suspicious Indicators |
| :--- | :--- | :--- | :--- |
| **Physical Storage** | Flash drives / External disks | Parses `journalctl -k` for mass-storage device nodes | USB vendor/product IDs (`idVendor`, `idProduct`), `Direct-Access` storage events |
| **Data Exfiltration** | Database extraction | Searches root partitions for unmanaged dumps | Newly created `.sql`, `.dump`, or `.tar.gz` files outside `/var/lib/mysql` |
| **Privileged Abuse** | Root-level alterations | Audits `auth.log` and user accounts | Unauthorized `sudo` executions, non-root users assigned UID 0 |
| **Anti-Forensics** | Log clearing / wiping | Checks size and command patterns of history files | Truncated 0-byte `.bash_history` files, execution of `history -c` |
| **System Integrity** | Web backdoor / tampering | Analyzes modified timestamps and configuration roots | Changes to Moodle `config.php` or unexpected `.php` scripts in webroots |

---

## 🔒 Chain of Custody & Tamper Evidence

To ensure digital evidence meets forensic preservation standards:
1. Every individual raw command output is saved into discrete evidence buckets under `raw_evidence/`.
2. A cryptographic manifest (`hashes/SHA256SUMS.txt`) is generated before packaging.
3. The resulting `.tar.gz` archive is paired with an external `.sha256` file, ensuring any post-collection tampering or accidental corruption is immediately identifiable during review.

---

## 📂 Repository Structure

```text
├── rpi_exam_forensic_V1.py     # Core Python Forensic Collector & Analyzer (Run on Raspberry Pi)
├── update_dashboard.py        # All-in-One Interactive Dashboard Embedder (Run on Workstation)
├── inspect_report.bat         # Windows 11 SHA-256 Integrity Verifier & Helper
├── rpi_exam_forensic.sh       # Legacy Bash Collector (v2.0 Fallback)
├── requirements.txt           # Environment Manifest (Standard Library Zero-Dependency)
└── README.md                  # Project Documentation
```

---

## 👤 Author

**Salai**  
* GitHub: [@SalaiJiChanWook](https://github.com/SalaiJiChanWook)  
* Focus: Backend Development, Linux System Administration, Offline Educational Infrastructure, and Defensive Security

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.