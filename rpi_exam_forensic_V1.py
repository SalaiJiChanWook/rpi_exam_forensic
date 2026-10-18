#!/usr/bin/env python3
"""
RPi Exam Forensic & SOC Integrity Analyzer (v3.0 - Deep Threat Hunter & RTC-Less Edition)
Detects:
  1. USB Mass-Storage Exfiltration (with Serial Numbers & Mount Paths)
  2. SSH / SFTP / SCP File Theft
  3. Reverse Shells (Bash, Netcat, Python, PHP Webshells)
  4. SQL Injection (SQLi) & Moodle Question Bank Export Theft
  5. SQL Dumps & Moodle Backup (.mbz) Stealing
  6. RTC-Less Boot Sequence & Offline Timeline Reconstruction
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

if os.geteuid() != 0:
    print("[!] ERROR: Run as root -> sudo ./venv/bin/python rpi_exam_forensic_V1.py")
    sys.exit(1)

TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
HOSTNAME = subprocess.getoutput("hostname").strip() or "Moe-Moodlebox"
BASE_DIR = Path.cwd() / f"RPi_Forensic_{HOSTNAME}_{TIMESTAMP}"
EVID_DIR = BASE_DIR / "raw_evidence"
HASH_DIR = BASE_DIR / "hashes"

for folder in ["system", "auth", "network", "storage", "moodle", "database", "files", "web"]:
    (EVID_DIR / folder).mkdir(parents=True, exist_ok=True)
HASH_DIR.mkdir(parents=True, exist_ok=True)

findings = []

def add_finding(category: str, severity: str, title_en: str, exec_mm: str, technical_detail: str = "", log_ref: str = ""):
    findings.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": category,
        "severity": severity,
        "title": title_en,
        "exec_mm": exec_mm,
        "detail": technical_detail.strip(),
        "log_ref": log_ref
    })

def run_cmd(cmd: str) -> str:
    try:
        res = subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return res.stdout.strip()
    except Exception as e:
        return f"Error: {str(e)}"

def save_artifact(rel_path: str, content: str):
    target = EVID_DIR / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content if content else "No records found.", encoding="utf-8")

print(f"[*] Starting Deep Threat Hunter & RTC-Aware Audit on {HOSTNAME}...")

# =========================================================================
# 0. RTC-LESS BOOT SEQUENCE & POWER-ON HISTORY (စက်ဘယ်နှစ်ခါ ပွင့်ခဲ့သလဲ စစ်ဆေးခြင်း)
# =========================================================================
print("[*] [0/6] Analyzing Boot Sequence History (RTC-Independent Timeline)...")
boot_list = run_cmd("journalctl --list-boots --no-pager 2>/dev/null; echo '\n=== LAST REBOOTS ==='; last -x -F reboot shutdown 2>/dev/null | head -n 50")
save_artifact("system/boot_sequence.txt", boot_list)

boot_lines = [l for l in boot_list.splitlines() if re.match(r'^\s*-?\d+\s+[0-9a-f]{32}', l)]
add_finding(
    category="Boot Timeline (RTC-Less)",
    severity="LOW",
    title_en=f"Recorded Power-On / Boot Sessions: {len(boot_lines)} sessions",
    exec_mm=f"Raspberry Pi တွင် RTC နာရီဓာတ်ခဲ မပါဝင်သော်လည်း စက်ကို ပါဝါဖွင့်ခဲ့သည့် အကြိမ်ရေ ({len(boot_lines)}) ကြိမ်လုံးကို မှတ်တမ်းတင်ထားပါသည်။ သတ်မှတ်ထားသော စာမေးပွဲရက်များထက် စက်ဖွင့်ထားသည့် အကြိမ်ရေ ပိုများနေခြင်း ရှိ/မရှိ စစ်ဆေးနိုင်ပါသည်။",
    technical_detail="\n".join(boot_lines[-10:]) if boot_lines else "Single boot or non-persistent journal.",
    log_ref="system/boot_sequence.txt"
)

# =========================================================================
# 1. USB EXFILTRATION & MOUNT TRACKING (ALL BOOTS - NO TIME LIMIT)
# =========================================================================
print("[*] [1/6] Hunting USB Stick Connections & Mount Events across ALL Boots...")
usb_raw = run_cmd("journalctl -k --no-pager 2>/dev/null | grep -Ei 'usb|scsi|sd[a-z]|Mass Storage|Direct-Access'")
mount_raw = run_cmd("journalctl --no-pager 2>/dev/null | grep -Ei 'udisksd|Mounted /dev/sd|media|usb-storage'")
save_artifact("storage/usb_storage_history.txt", f"=== KERNEL USB LOGS ===\n{usb_raw}\n\n=== USB MOUNT EVENTS ===\n{mount_raw}")

real_usb_events = []
for line in usb_raw.splitlines():
    if any(ignore in line for ignore in ["idVendor=1d6b", "idVendor=2109", "idVendor=0424", "USB hub found", "Product: USB2.0 Hub", "xHCI Host Controller"]):
        continue
    if re.search(r'(Direct-Access|Mass Storage|sd[a-z]:|Attached SCSI removable disk|SerialNumber:)', line, re.IGNORECASE):
        real_usb_events.append(line)

if mount_raw:
    real_usb_events.extend(mount_raw.splitlines()[-5:])

if real_usb_events:
    add_finding(
        category="USB Data Theft",
        severity="HIGH",
        title_en=f"External USB Drive Activity Detected ({len(real_usb_events)} traces)",
        exec_mm="စာဖြေစက်တွင် ပြင်ပမှ USB Stick (သို့မဟုတ်) Hard Drive ထိုးသွင်းချိတ်ဆက်ခဲ့သည့် မှတ်တမ်းနှင့် Serial နံပါတ်များကို တွေ့ရှိရပါသည်။ ခွင့်ပြုချက်မရှိဘဲ ဖိုင်ကူးယူခြင်း ဟုတ်/မဟုတ် စစ်ဆေးရန် လိုအပ်ပါသည်။",
        technical_detail="\n".join(real_usb_events[-10:]),
        log_ref="storage/usb_storage_history.txt"
    )
else:
    add_finding(
        category="USB Data Theft",
        severity="LOW",
        title_en="Zero External USB Stick Connections",
        exec_mm="စက်၏ သက်တမ်းတစ်လျှောက် ပြင်ပမှ USB Flash Drive လာရောက်ထိုးသွင်းထားခြင်း လုံးဝမရှိပါ။",
        technical_detail="Checked all historical kernel boots. No external mass-storage devices attached.",
        log_ref="storage/usb_storage_history.txt"
    )

# =========================================================================
# 2. SSH / SFTP / SCP FILE THEFT & UNAUTHORIZED LOGINS
# =========================================================================
print("[*] [2/6] Auditing SSH Logins, SFTP File Transfers & SCP Theft...")
auth_all = run_cmd(
    "{ zgrep -hEi 'sshd|sudo:|su:|sftp|scp' /var/log/auth.log* 2>/dev/null; "
    "journalctl --no-pager 2>/dev/null | grep -Ei 'sshd|sudo:|su:|sftp-server|scp'; } | tail -n 2500"
)
save_artifact("auth/auth_summary.txt", auth_all)

sftp_transfers = [l for l in auth_all.splitlines() if re.search(r'(subsystem request for sftp|sftp-server|scp\s+-f)', l, re.IGNORECASE)]
ssh_accepted = [l for l in auth_all.splitlines() if "Accepted " in l]

if sftp_transfers:
    add_finding(
        category="SSH / SFTP File Transfer",
        severity="HIGH",
        title_en=f"SFTP / SCP File Transfer Sessions Detected ({len(sftp_transfers)} events)",
        exec_mm="Network မှတစ်ဆင့် SSH/SFTP အသုံးပြုပြီး စာဖြေစက်ထဲသို့ ဝင်ရောက်ကာ ဖိုင်အပို့/အယူ ပြုလုပ်ထားသည့် မှတ်တမ်း တွေ့ရှိရပါသည်။ (Admin ကိုယ်တိုင် လုပ်ဆောင်ခဲ့ခြင်း ဟုတ်/မဟုတ် စစ်ဆေးပါ)။",
        technical_detail="\n".join(sftp_transfers[-8:] + ssh_accepted[-5:]),
        log_ref="auth/auth_summary.txt"
    )

# =========================================================================
# 3. REVERSE SHELLS & SUSPICIOUS CLI COMMANDS
# =========================================================================
print("[*] [3/6] Scanning for Reverse Shells, Netcat, & Dump Commands...")
history_blocks = []
rev_shell_hits = []
dump_cmd_hits = []

rev_shell_regex = re.compile(r'(/dev/tcp/|nc\s+-e|ncat\s+|bash\s+-i|socat\s+|mkfifo\s+|python.*pty\.spawn|php\s+-r.*fsockopen|base64\s+-d|curl\s+.*\|\s*sh|wget\s+.*\|\s*sh)', re.IGNORECASE)
exfil_cmd_regex = re.compile(r'(mysqldump|mariadb-dump|scp\s+|sftp\s+|rsync\s+|tar\s+.*var/www|zip\s+.*var/www|history\s+-c|rm\s+-rf\s+/var/log)', re.IGNORECASE)

for hfile in list(Path("/home").glob("*/.bash_history")) + [Path("/root/.bash_history")]:
    if not hfile.exists():
        continue
    user = hfile.parent.name
    content = hfile.read_text(errors="ignore")
    history_blocks.append(f"=== User: {user} ({hfile}) ===\n{content}")
    
    for idx, line in enumerate(content.splitlines(), 1):
        if "rpi_exam_forensic" in line or "RPi_Forensic_" in line:
            continue
        if rev_shell_regex.search(line):
            rev_shell_hits.append(f"[{user} L{idx}]: {line.strip()}")
        elif exfil_cmd_regex.search(line):
            dump_cmd_hits.append(f"[{user} L{idx}]: {line.strip()}")

save_artifact("auth/shell_histories.txt", "\n\n".join(history_blocks))

if rev_shell_hits:
    add_finding(
        category="Reverse Shell / Backdoor",
        severity="HIGH",
        title_en=f"Reverse Shell / Remote Control Payload Detected ({len(rev_shell_hits)} hits)",
        exec_mm="စာဖြေစက်အား အဝေးမှ ခိုးဝင်ထိန်းချုပ်ရန် ကြိုးပမ်းသည့် အန္တရာယ်ရှိသော ကွန်ပျူတာကုတ် (Reverse Shell) ရိုက်နှိပ်ထားသည်ကို တွေ့ရှိရပါသည်။",
        technical_detail="\n".join(rev_shell_hits),
        log_ref="auth/shell_histories.txt"
    )

if dump_cmd_hits:
    add_finding(
        category="Command Audit",
        severity="HIGH",
        title_en=f"Data Dump / Copy / Wipe Commands in History ({len(dump_cmd_hits)} commands)",
        exec_mm="စာမေးပွဲ ဒေတာဘေ့စ် ထုတ်ယူခြင်း (mysqldump)၊ ဖိုင်ပို့ခြင်း သို့မဟုတ် မှတ်တမ်းဖျက်ခြင်းနှင့် သက်ဆိုင်သော command များ ရိုက်နှိပ်ထားသည်ကို တွေ့ရှိရပါသည်။",
        technical_detail="\n".join(dump_cmd_hits[-10:]),
        log_ref="auth/shell_histories.txt"
    )

# =========================================================================
# 4. SQL INJECTION (SQLi), WEBSHELLS & MOODLE QUESTION EXPORT THEFT
# =========================================================================
print("[*] [4/6] Hunting SQL Injection, Moodle Question Exports & Webshells in Apache Logs...")
apache_access = run_cmd("zgrep -h '' /var/log/apache2/*access* 2>/dev/null | tail -n 5000")
apache_error = run_cmd("zgrep -h '' /var/log/apache2/*error* 2>/dev/null | tail -n 2000")
save_artifact("web/apache_logs.txt", f"=== ACCESS LOGS (LAST 5000) ===\n{apache_access}\n\n=== ERROR LOGS ===\n{apache_error}")

sqli_regex = re.compile(r'(UNION.*SELECT|SELECT.*FROM|INFORMATION_SCHEMA|SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|\bOR\b\s+1=1|%27.*%20OR%20|/etc/passwd|\.\./\.\./)', re.IGNORECASE)
moodle_export_regex = re.compile(r'(/question/export\.php|/backup/backup\.php|/admin/tool/xmldb/|/admin/cli/)', re.IGNORECASE)

sqli_hits = []
export_hits = []

for line in apache_access.splitlines():
    if sqli_regex.search(line):
        sqli_hits.append(line)
    if moodle_export_regex.search(line):
        export_hits.append(line)

if sqli_hits:
    add_finding(
        category="SQL Injection (SQLi) Attack",
        severity="HIGH",
        title_en=f"SQL Injection / Web Exploit Attempts Detected ({len(sqli_hits)} requests)",
        exec_mm="ဝက်ဘ်ဆိုက် စာမျက်နှာမှတစ်ဆင့် စာမေးပွဲ Database ကို ဖောက်ထွင်းရန် ကြိုးပမ်းသည့် (SQL Injection) တိုက်ခိုက်မှု မှတ်တမ်းများ တွေ့ရှိရပါသည်။",
        technical_detail="\n".join(sqli_hits[-8:]),
        log_ref="web/apache_logs.txt"
    )
else:
    add_finding(
        category="SQL Injection (SQLi) Attack",
        severity="LOW",
        title_en="No SQL Injection Attacks in Web Logs",
        exec_mm="Moodle ဝက်ဘ်ဆိုက်သို့ SQL Injection နည်းလမ်းဖြင့် ဖောက်ထွင်းတိုက်ခိုက်ထားသည့် မှတ်တမ်း လုံးဝမရှိပါ။",
        technical_detail="Scanned Apache access logs for UNION SELECT, OR 1=1, SLEEP(), and path traversal payloads.",
        log_ref="web/apache_logs.txt"
    )

if export_hits:
    add_finding(
        category="Moodle Question Export",
        severity="MEDIUM",
        title_en=f"Moodle Question Bank / Course Backup Export Accessed ({len(export_hits)} times)",
        exec_mm="Moodle စနစ်အတွင်းမှ စာမေးပွဲမေးခွန်းများ (Question Bank) သို့မဟုတ် Course Backup ကို Download ဆွဲထုတ်သည့် စာမျက်နှာသို့ ဝင်ရောက်ထားကြောင်း တွေ့ရှိရပါသည်။",
        technical_detail="\n".join(export_hits[-8:]),
        log_ref="web/apache_logs.txt"
    )

# Scan Moodle Webroot for PHP Webshells / Reverse Shells
webshell_scan = run_cmd("grep -RniE '(eval\\s*\\(\\s*base64_decode|shell_exec\\s*\\(|passthru\\s*\\(|system\\s*\\(\\s*\\$_|fsockopen\\s*\\()' /var/www /srv/www 2>/dev/null | grep -v '/vendor/' | grep -v '/lib/' | head -n 50")
save_artifact("moodle/webshell_scan.txt", webshell_scan)

# =========================================================================
# 5. SQL DUMP STEALING & MOODLE BACKUP (.MBZ) FILES (NO TIME LIMIT)
# =========================================================================
print("[*] [5/6] Hunting All SQL Dumps, Moodle (.mbz) Backups & Archives...")
all_dumps = run_cmd(
    "find /home /tmp /var/tmp /dev/shm /var/www /opt /root -xdev -type f "
    "\\( -iname '*.sql' -o -iname '*.sql.gz' -o -iname '*.dump' -o -iname '*.mbz' -o -iname '*.bak' -o -iname '*.tar.gz' -o -iname '*.zip' \\) "
    "-printf '%TY-%Tm-%Td %TH:%TM:%TS | %s bytes | %u:%g | %p\n' 2>/dev/null | sort -r"
)

suspicious_archives = [l for l in all_dumps.splitlines() if not any(x in l for x in ["RPi_Forensic_", "/venv/", "/node_modules/"])]
save_artifact("files/archive_dumps.txt", "\n".join(suspicious_archives))

if suspicious_archives:
    add_finding(
        category="SQL Dump / Backup Files",
        severity="HIGH",
        title_en=f"SQL Dumps / Moodle Backups (.mbz) Found ({len(suspicious_archives)} file(s))",
        exec_mm=f"စာဖြေစက်အတွင်း၌ စာမေးပွဲဒေတာဘေ့စ် (.sql)၊ Moodle မေးခွန်း Backup (.mbz) သို့မဟုတ် Archive ဖိုင် ({len(suspicious_archives)}) ခု တွေ့ရှိရပါသည်။ ခိုးယူရန် စုဆောင်းထားသော ဖိုင်များ ဟုတ်/မဟုတ် စစ်ဆေးပါ။",
        technical_detail="\n".join(suspicious_archives[:10]),
        log_ref="files/archive_dumps.txt"
    )
else:
    add_finding(
        category="SQL Dump / Backup Files",
        severity="LOW",
        title_en="Zero Unmanaged SQL Dumps or .mbz Backups",
        exec_mm="စက်အတွင်း၌ မေးခွန်းနှင့် အဖြေများကို ခိုးယူရန် ထုတ်ထားသော SQL Dump သို့မဟုတ် Backup ဖိုင်အပိုများ လုံးဝမရှိပါ။",
        technical_detail="Full filesystem scan across user/temp/web directories returned 0 unauthorized archives.",
        log_ref="files/archive_dumps.txt"
    )

# Additional Context Logs
save_artifact("network/network_state.txt", run_cmd("ip -br addr; echo ''; ss -lntup; echo ''; ip neigh"))
save_artifact("database/db_status.txt", run_cmd("systemctl status mariadb mysql --no-pager 2>/dev/null | head -n 35"))

# =========================================================================
# 6. GENERATE EXECUTIVE BURMESE REPORT & ALL-IN-ONE WORKBENCH
# =========================================================================
print("[*] [6/6] Generating Executive Report & Single-File Dashboard...")

with open(BASE_DIR / "security_findings.json", "w", encoding="utf-8") as jf:
    json.dump(findings, jf, indent=2, ensure_ascii=False)

with open(BASE_DIR / "quick_summary.csv", "w", newline="", encoding="utf-8-sig") as cf:
    writer = csv.DictWriter(cf, fieldnames=["timestamp", "category", "severity", "title", "exec_mm", "detail", "log_ref"])
    writer.writeheader()
    writer.writerows(findings)

evidence_tree = {}
for root, _, files in os.walk(EVID_DIR):
    rel_dir = Path(root).relative_to(EVID_DIR)
    cat = str(rel_dir).replace("\\", "/")
    for f in sorted(files):
        fpath = Path(root) / f
        key = f"{cat}/{f}" if cat != "." else f
        evidence_tree[key] = fpath.read_text(encoding="utf-8", errors="ignore")

high_count = sum(1 for f in findings if f["severity"] == "HIGH")
med_count = sum(1 for f in findings if f["severity"] == "MEDIUM")

if high_count == 0 and med_count == 0:
    verdict_badge = "<span class='badge badge-LOW'>✅ စာဖြေစက် လုံခြုံရေး အပြည့်အဝ ကောင်းမွန်သည် (SECURE)</span>"
    verdict_box_color = "#10b981"
    verdict_text_mm = (
        "<b>အုပ်ချုပ်ရေးအဖွဲ့နှင့် အထက်လူကြီးများအတွက် အနှစ်ချုပ် အစီရင်ခံစာ -</b><br>"
        f"ဤစာဖြေစက် (<b>{HOSTNAME}</b>) အား ကဏ္ဍစုံမှ အသေးစိတ် စစ်ဆေးချက်အရ ပြင်ပမှ USB Stick ထိုး၍ ဖိုင်ခိုးကူးခြင်း၊ "
        "SSH/Network မှ ဖိုင်ဆွဲယူခြင်း၊ Reverse Shell ဖွင့်ခြင်း၊ SQL Injection တိုက်ခိုက်ခြင်း သို့မဟုတ် Database Dump ထုတ်ယူထားခြင်း "
        "<b>လုံးဝမတွေ့ရှိရပါ</b>။ စာမေးပွဲမေးခွန်းနှင့် အဖြေများ လုံခြုံစိတ်ချရပါသည်။"
    )
elif high_count > 0:
    verdict_badge = f"<span class='badge badge-HIGH'>🚨 အရေးကြီး စစ်ဆေးရန် အချက် ({high_count}) ခု တွေ့ရှိသည်</span>"
    verdict_box_color = "#ef4444"
    verdict_text_mm = (
        "<b>အုပ်ချုပ်ရေးအဖွဲ့နှင့် အထက်လူကြီးများအတွက် အနှစ်ချုပ် အစီရင်ခံစာ -</b><br>"
        f"ဤစာဖြေစက် (<b>{HOSTNAME}</b>) တွင် လုံခြုံရေးဆိုင်ရာ အထူးစစ်ဆေးရမည့် အချက် (<b>{high_count}</b>) ချက် တွေ့ရှိထားပါသည်။ "
        "အောက်ပါ ဇယားရှိ <b>အနီရောင် (HIGH)</b> ပြထားသော လုပ်ဆောင်ချက်များသည် တာဝန်ခံ ဆရာ/Admin ကိုယ်တိုင် လုပ်ဆောင်ခဲ့ခြင်း ဟုတ်/မဟုတ် တိုက်ဆိုင်စစ်ဆေးပေးပါရန်။"
    )
else:
    verdict_badge = f"<span class='badge badge-MEDIUM'>⚠️ သတိပြုစစ်ဆေးရန် ({med_count}) ခု တွေ့ရှိသည်</span>"
    verdict_box_color = "#f59e0b"
    verdict_text_mm = (
        "<b>အုပ်ချုပ်ရေးအဖွဲ့နှင့် အထက်လူကြီးများအတွက် အနှစ်ချုပ် အစီရင်ခံစာ -</b><br>"
        "ပြင်းထန်သော တိုက်ခိုက်မှု မတွေ့ရသော်လည်း သတိပြုစစ်ဆေးသင့်သည့် အချက်အနည်းငယ် တွေ့ရှိရပါသည်။"
    )

rows_html = ""
for item in findings:
    sev = item["severity"]
    detail_block = f"<pre>{item['detail']}</pre>" if item["detail"] else ""
    rows_html += f"""
    <tr>
        <td><span class="badge badge-{sev}">{sev}</span></td>
        <td><b>{item['category']}</b></td>
        <td>
            <div style="font-weight: 600; color: #f8fafc; margin-bottom: 4px;">{item['title']}</div>
            <div style="color: #cbd5e1; font-size: 13px; line-height: 1.6; background: #0f172a; padding: 8px 12px; border-left: 3px solid #38bdf8; border-radius: 4px;">
                {item['exec_mm']}
            </div>
            {detail_block}
            <div style="margin-top: 6px;">
                <span class="quick-link" onclick="openArtifact('{item['log_ref']}')">📂 မူရင်းမှတ်တမ်းဖိုင်ကြည့်ရန် ({item['log_ref']})</span>
            </div>
        </td>
    </tr>
    """

html_doc = f"""<!DOCTYPE html>
<html lang="my">
<head>
<meta charset="UTF-8">
<title>SOC & Executive Forensic Report - {HOSTNAME}</title>
<style>
    :root {{ --bg: #0b0f19; --card: #131c2e; --border: #23324d; --text: #f1f5f9; --sub: #94a3b8; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: "Padauk", "Pyidaungsu", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--text); display: flex; flex-direction: column; height: 100vh; overflow: hidden; }}
    header {{ padding: 14px 24px; background: var(--card); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }}
    .badge {{ padding: 5px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; display: inline-block; }}
    .badge-HIGH {{ background: #dc2626; color: #fff; }}
    .badge-MEDIUM {{ background: #d97706; color: #fff; }}
    .badge-LOW {{ background: #059669; color: #fff; }}
    .main {{ display: flex; flex: 1; overflow: hidden; }}
    .left {{ width: 55%; padding: 20px; overflow-y: auto; border-right: 1px solid var(--border); }}
    .right {{ width: 45%; display: flex; flex-direction: column; background: #070a12; }}
    .verdict-box {{ background: #162033; border: 2px solid {verdict_box_color}; border-radius: 8px; padding: 16px; margin-bottom: 18px; line-height: 1.7; font-size: 14px; }}
    .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 18px; }}
    .stat {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px; text-align: center; }}
    .stat-num {{ font-size: 26px; font-weight: 800; margin-top: 4px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px 10px; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; font-size: 13px; }}
    th {{ color: var(--sub); font-size: 12px; text-transform: uppercase; }}
    pre {{ background: #070a12; color: #38bdf8; padding: 10px; border-radius: 6px; font-size: 11.5px; overflow-x: auto; margin: 8px 0 0 0; border: 1px solid #1e293b; white-space: pre-wrap; }}
    .quick-link {{ color: #38bdf8; cursor: pointer; font-size: 12px; font-weight: 600; text-decoration: none; }}
    .quick-link:hover {{ text-decoration: underline; }}
    .toolbar {{ padding: 10px 14px; background: var(--card); border-bottom: 1px solid var(--border); display: flex; gap: 10px; align-items: center; }}
    select {{ background: #0f172a; color: #38bdf8; border: 1px solid var(--border); padding: 8px 12px; border-radius: 6px; font-weight: 600; width: 100%; outline: none; }}
    .viewer {{ flex: 1; padding: 16px; overflow: auto; font-family: Consolas, monospace; font-size: 12px; line-height: 1.5; color: #a5f3fc; white-space: pre; }}
</style>
</head>
<body>
<header>
    <div>
        <h2 style="margin:0; font-size: 19px;">🛡️ RPi Offline Exam Security & Forensic Report (v3.0)</h2>
        <small style="color: var(--sub);">စက်အမည် (Host): <b>{HOSTNAME}</b> | စစ်ဆေးသည့်အချိန်: {TIMESTAMP}</small>
    </div>
    <div>{verdict_badge}</div>
</header>

<div class="main">
    <div class="left">
        <div class="verdict-box">{verdict_text_mm}</div>
        <div class="grid">
            <div class="stat">
                <div style="font-size:11px; color:var(--sub);">စစ်ဆေးသည့် ကဏ္ဍပေါင်း</div>
                <div class="stat-num">{len(findings)}</div>
            </div>
            <div class="stat">
                <div style="font-size:11px; color:#ef4444;">အရေးကြီး (HIGH RISK)</div>
                <div class="stat-num" style="color:#ef4444;">{high_count}</div>
            </div>
            <div class="stat">
                <div style="font-size:11px; color:#f59e0b;">သတိပြုရန် (WARNING)</div>
                <div class="stat-num" style="color:#f59e0b;">{med_count}</div>
            </div>
        </div>
        <div class="card">
            <h3 style="margin-top:0; font-size:15px;">ကဏ္ဍအလိုက် စစ်ဆေးတွေ့ရှိချက် အသေးစိတ် (Executive & SOC Breakdown)</h3>
            <table>
                <thead>
                    <tr>
                        <th style="width:75px;">အဆင့်</th>
                        <th style="width:130px;">ကဏ္ဍ</th>
                        <th>တွေ့ရှိချက် ရှင်းလင်းချက်နှင့် သက်သေအထောက်အထား</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
        </div>
    </div>
    <div class="right">
        <div class="toolbar">
            <select id="fileSelect" onchange="showFile(this.value)"></select>
        </div>
        <div id="logBox" class="viewer"></div>
    </div>
</div>

<script>
const logs = {json.dumps(evidence_tree)};
const sel = document.getElementById('fileSelect');
const box = document.getElementById('logBox');

for (const k in logs) {{
    const o = document.createElement('option');
    o.value = k;
    o.textContent = "📄 Raw Artifact: " + k;
    sel.appendChild(o);
}}

function showFile(k) {{
    box.textContent = logs[k] || "No content.";
}}

function openArtifact(name) {{
    for (let i = 0; i < sel.options.length; i++) {{
        if (sel.options[i].value === name) {{
            sel.selectedIndex = i;
            showFile(name);
            break;
        }}
    }}
}}

if (sel.options.length > 0) showFile(sel.options[0].value);
</script>
</body>
</html>
"""

(BASE_DIR / "forensic_report.html").write_text(html_doc, encoding="utf-8")

hashes = []
for p in sorted(BASE_DIR.rglob("*")):
    if p.is_file() and "SHA256SUMS.txt" not in p.name:
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        hashes.append(f"{h}  {p.relative_to(BASE_DIR)}")
(HASH_DIR / "SHA256SUMS.txt").write_text("\n".join(hashes), encoding="utf-8")

archive = f"{BASE_DIR}.tar.gz"
run_cmd(f"tar -czf {archive} -C {BASE_DIR.parent} {BASE_DIR.name}")
run_cmd(f"sha256sum {archive} > {archive}.sha256")

print("\n" + "="*65)
print(f"[+] DEEP AUDIT COMPLETE: {BASE_DIR.name}")
print(f"[+] HIGH RISK: {high_count} | WARNING: {med_count}")
print(f"[+] Ready Archive : {archive}")
print("="*65)
