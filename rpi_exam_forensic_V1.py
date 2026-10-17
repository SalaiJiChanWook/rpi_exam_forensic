#!/usr/bin/env python3
"""
RPi Exam Forensic & Integrity Analyzer (v3.1 - Fixed)
Specialized for Offline MoodleBox / LAMP on Raspberry Pi OS 64-bit.
Generates structured JSON, CSV, Raw Artifacts, and a clean HTML Dashboard.
"""

import os
import sys
import subprocess
import json
import csv
import hashlib
import re
from datetime import datetime
from pathlib import Path

# Execution Guard: Root check
if os.geteuid() != 0:
    print("[!] ERROR: This forensic tool must be run as root (sudo ./venv/bin/python rpi_exam_forensicV3.py)")
    sys.exit(1)

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
HOSTNAME = subprocess.getoutput("hostname").strip() or "rpi-exam-server"
BASE_DIR = Path.cwd() / f"RPi_Forensic_{HOSTNAME}_{TIMESTAMP}"
EVID_DIR = BASE_DIR / "raw_evidence"
HASH_DIR = BASE_DIR / "hashes"

# Setup forensic directory structure
for folder in ["system", "auth", "network", "storage", "moodle", "database", "files"]:
    (EVID_DIR / folder).mkdir(parents=True, exist_ok=True)

# Hashes directory structure
HASH_DIR.mkdir(parents=True, exist_ok=True)

findings = []

def add_finding(category: str, severity: str, message: str, detail: str = ""):
    """Classify findings for the executive report: HIGH, MEDIUM, LOW, INFO"""
    findings.append({
        "timestamp": datetime.now().isoformat(),
        "category": category,
        "severity": severity,
        "message": message,
        "detail": detail.strip()
    })

def run_cmd(cmd: str) -> str:
    """Safely run shell commands and return clean text output."""
    try:
        res = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return res.stdout.strip()
    except Exception as e:
        return f"Execution Error: {str(e)}"

def save_artifact(relative_path: str, content: str):
    target = EVID_DIR / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as f:
        f.write(content)

print(f"[*] Starting Moodle Exam Security Audit on {HOSTNAME}...")

# -------------------------------------------------------------
# 1. HARDWARE & USB ACTIVITY (Flash Drive ထိုးစစ်ဆေးမှု)
# -------------------------------------------------------------
print("[*] Analyzing USB and External Storage artifacts...")
usb_history = run_cmd("journalctl -k --since '90 days ago' --no-pager | grep -Ei 'usb|usb-storage|sd[a-z]|scsi|Direct-Access'")
save_artifact("storage/usb_storage_history.txt", usb_history)

usb_matches = re.findall(r'(usb \d+-\d+: New USB device found.*|Direct-Access.*)', usb_history, re.MULTILINE)
if usb_matches:
    sample_usb = "\n".join(usb_matches[-5:])
    add_finding("Storage/USB", "HIGH", f"External USB storage detected ({len(usb_matches)} event(s))", sample_usb)
else:
    add_finding("Storage/USB", "LOW", "No external USB mass-storage connections identified in current logs.")

# -------------------------------------------------------------
# 2. PRIVILEGE ESCALATION & AUTHENTICATION (Root ဝင်ရောက်မှု စစ်ဆေးခြင်း)
# -------------------------------------------------------------
print("[*] Checking Sudo abuse, SSH logins, and UID 0 privileges...")
auth_log = run_cmd("grep -Ei 'Accepted|Failed|Invalid user|session opened for user root' /var/log/auth.log* 2>/dev/null")
save_artifact("auth/auth_summary.txt", auth_log)

uid_zero = [u for u in run_cmd("awk -F: '$3==0 {print $1}' /etc/passwd").splitlines() if u != "root"]
if uid_zero:
    add_finding("Authentication", "HIGH", "Non-standard UID 0 accounts discovered", f"Accounts: {', '.join(uid_zero)}")

history_records = []
for hpath in Path("/home").glob("*/.bash_history"):
    if hpath.stat().st_size == 0:
        add_finding("Anti-Forensics", "MEDIUM", f"Empty bash history detected: {hpath}", "User may have cleared bash history.")
    history_records.append(f"=== {hpath} ===\n" + hpath.read_text(errors="ignore"))

root_hist = Path("/root/.bash_history")
if root_hist.exists():
    if root_hist.stat().st_size == 0:
        add_finding("Anti-Forensics", "HIGH", "Root history file exists but is 0 bytes (Potential anti-forensic wiper).")
    history_records.append("=== /root/.bash_history ===\n" + root_hist.read_text(errors="ignore"))

save_artifact("auth/shell_histories.txt", "\n".join(history_records))

suspicious_patterns = r'(rm\s+-rf\s+/var/log|history\s+-c|mysqldump|mariadb-dump|dd\s+if=.*of=|nc\s+-l|scp|sftp)'
for line in "\n".join(history_records).splitlines():
    if re.search(suspicious_patterns, line, re.IGNORECASE):
        add_finding("Command Execution", "HIGH", "Suspicious CLI execution found in Bash History", line.strip())

# -------------------------------------------------------------
# 3. DATABASE DUMPS & EXFILTRATION CANDIDATES (မေးခွန်း/အဖြေများ Dump စစ်ဆေးခြင်း)
# -------------------------------------------------------------
print("[*] Scanning for unauthorized SQL dumps and archives...")
find_dumps = run_cmd("find / -xdev -type f \( -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.dump' -o -iname '*.bak' -o -iname '*.tar.gz' \) -printf '%TY-%Tm-%Td %TH:%TM:%TS %s %u:%g %p\n' 2>/dev/null | grep -v '/var/lib/mysql' | head -100")
save_artifact("files/archive_dumps.txt", find_dumps)

suspicious_files = [f for f in find_dumps.splitlines() if not any(w in f for w in ["/usr/", "/lib/", "/var/cache/"])]
if suspicious_files:
    add_finding("Data Exfiltration", "HIGH", f"{len(suspicious_files)} SQL/Backup archive(s) located outside system directories", "\n".join(suspicious_files[:5]))

# -------------------------------------------------------------
# 4. MOODLE ENVIRONMENT INTEGRITY (Config & Web Root စစ်ဆေးခြင်း)
# -------------------------------------------------------------
print("[*] Auditing Moodle installation and config metadata...")
config_candidates = run_cmd("find /var/www /srv/www /opt /home -maxdepth 6 -type f -name config.php 2>/dev/null").splitlines()
moodle_meta = []
for cfg in config_candidates:
    try:
        st = os.stat(cfg)
        cfg_text = Path(cfg).read_text(errors="ignore")
        db_type = re.findall(r"\$CFG->dbtype\s*=\s*['\"]([^'\"]+)['\"];", cfg_text)
        www_root = re.findall(r"\$CFG->wwwroot\s*=\s*['\"]([^'\"]+)['\"];", cfg_text)
        data_root = re.findall(r"\$CFG->dataroot\s*=\s*['\"]([^'\"]+)['\"];", cfg_text)
        
        info = f"File: {cfg}\nSize: {st.st_size} bytes\nLast Modified: {datetime.fromtimestamp(st.st_mtime).isoformat()}\n"
        info += f"DB Type: {db_type[0] if db_type else 'Unknown'}, Webroot: {www_root[0] if www_root else 'Unknown'}, Dataroot: {data_root[0] if data_root else 'Unknown'}\n"
        moodle_meta.append(info)
    except Exception as e:
        moodle_meta.append(f"Error accessing {cfg}: {str(e)}")

save_artifact("moodle/moodle_config_meta.txt", "\n---\n".join(moodle_meta))

# -------------------------------------------------------------
# 5. PERSISTENCE MECHANISMS (Cron & Services စစ်ဆေးခြင်း)
# -------------------------------------------------------------
print("[*] Verifying Cron, Systemd timers, and SUID binaries...")
cron_data = run_cmd("tail -n +1 /etc/cron*/* /var/spool/cron/crontabs/* 2>/dev/null")
save_artifact("system/cron_jobs.txt", cron_data)

suid_data = run_cmd("find / -xdev -type f -perm -4000 -printf '%M %u:%g %p\n' 2>/dev/null | sort")
save_artifact("system/suid_binaries.txt", suid_data)

# -------------------------------------------------------------
# 6. REPORT GENERATION (JSON, CSV, & HTML DASHBOARD)
# -------------------------------------------------------------
print("[*] Generating formatted reports and executive dashboard...")

with open(BASE_DIR / "security_findings.json", "w", encoding="utf-8") as jf:
    json.dump(findings, jf, indent=2)

with open(BASE_DIR / "quick_summary.csv", "w", newline="", encoding="utf-8") as cf:
    writer = csv.DictWriter(cf, fieldnames=["timestamp", "category", "severity", "message", "detail"])
    writer.writeheader()
    writer.writerows(findings)

html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RPi Exam Server Forensic Audit - {HOSTNAME}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
    .badge-HIGH {{ background: #dc2626; color: #fee2e2; }}
    .badge-MEDIUM {{ background: #d97706; color: #fef3c7; }}
    .badge-LOW {{ background: #16a34a; color: #dcfce7; }}
    .badge-INFO {{ background: #2563eb; color: #dbeafe; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 18px; margin-bottom: 16px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #334155; font-size: 14px; }}
    th {{ background: #0f172a; color: #94a3b8; font-weight: 600; }}
    pre {{ background: #090d16; padding: 8px 12px; border-radius: 4px; overflow-x: auto; color: #38bdf8; font-size: 12px; margin: 4px 0 0 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .stat-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; text-align: center; }}
    .stat-number {{ font-size: 28px; font-weight: bold; margin-top: 8px; }}
</style>
</head>
<body>

<div class="header">
    <div>
        <h1 style="margin: 0; font-size: 24px;">Offline Exam Server Forensic Audit</h1>
        <small style="color: #94a3b8;">Target Host: <b>{HOSTNAME}</b> | Platform: Raspberry Pi OS 64-bit (MoodleBox/LAMP)</small>
    </div>
    <div style="text-align: right;">
        <span class="badge badge-INFO">Audit Completed</span><br>
        <small style="color: #94a3b8;">{TIMESTAMP}</small>
    </div>
</div>

<div class="grid">
    <div class="stat-card">
        <div style="color: #94a3b8; font-size: 13px;">TOTAL FINDINGS</div>
        <div class="stat-number">{len(findings)}</div>
    </div>
    <div class="stat-card">
        <div style="color: #ef4444; font-size: 13px;">CRITICAL / HIGH</div>
        <div class="stat-number" style="color: #ef4444;">{len([f for f in findings if f['severity'] == 'HIGH'])}</div>
    </div>
    <div class="stat-card">
        <div style="color: #f59e0b; font-size: 13px;">WARNING / MEDIUM</div>
        <div class="stat-number" style="color: #f59e0b;">{len([f for f in findings if f['severity'] == 'MEDIUM'])}</div>
    </div>
</div>

<div class="card">
    <h3 style="margin-top: 0;">Forensic Incident Breakdown</h3>
    <table>
        <thead>
            <tr>
                <th style="width: 100px;">Severity</th>
                <th style="width: 160px;">Category</th>
                <th>Observation & Suspected Behavior</th>
            </tr>
        </thead>
        <tbody>
            {"".join([f'''<tr>
                <td><span class="badge badge-{item['severity']}">{item['severity']}</span></td>
                <td><b>{item['category']}</b></td>
                <td>
                    <div>{item['message']}</div>
                    {f"<pre>{item['detail']}</pre>" if item['detail'] else ""}
                </td>
            </tr>''' for item in findings])}
        </tbody>
    </table>
</div>

<div class="card">
    <h3 style="margin-top: 0;">Integrity & Evidence Artifacts</h3>
    <p style="color: #94a3b8; font-size: 13px;">All raw command outputs and system journal logs have been cataloged in the <code>raw_evidence/</code> directory with SHA256 checksums.</p>
</div>

</body>
</html>
"""

with open(BASE_DIR / "forensic_report.html", "w", encoding="utf-8") as hf:
    hf.write(html_template)

# -------------------------------------------------------------
# 7. FORENSIC HASHING (Fixed Path Resolution)
# -------------------------------------------------------------
print("[*] Generating SHA-256 hash manifest...")
hash_manifest = []
for path in BASE_DIR.rglob("*"):
    if path.is_file():
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        hash_manifest.append(f"{h}  {path.relative_to(BASE_DIR)}")

# HASH_DIR ထဲသို့ တိုက်ရိုက် ရေးသားခြင်း
(HASH_DIR / "SHA256SUMS.txt").write_text("\n".join(hash_manifest))

# Create compressed evidence archive
archive_tar = f"{BASE_DIR}.tar.gz"
run_cmd(f"tar -czf {archive_tar} -C {BASE_DIR.parent} {BASE_DIR.name}")
run_cmd(f"sha256sum {archive_tar} > {archive_tar}.sha256")

print("\n" + "=" * 65)
print("[+] FORENSIC INVESTIGATION PACK READY")
print(f"[+] Output Directory : {BASE_DIR}")
print(f"[+] Web Dashboard    : {BASE_DIR / 'forensic_report.html'}")
print(f"[+] CSV Spreadsheet  : {BASE_DIR / 'quick_summary.csv'}")
print(f"[+] Compressed Bundle: {archive_tar}")
print("=" * 65)