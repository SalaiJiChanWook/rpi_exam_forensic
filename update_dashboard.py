import os
import json
from pathlib import Path

# လက်ရှိ folder လမ်းကြောင်းကို ယူခြင်း
current_dir = Path(__file__).resolve().parent

# forensic_report.html ရှိတဲ့ path ကို အလိုအလျောက်ရှာဖွေခြင်း
target_dir = None
if (current_dir / "raw_evidence").exists():
    target_dir = current_dir
else:
    for sub in current_dir.iterdir():
        if sub.is_dir() and (sub / "raw_evidence").exists():
            target_dir = sub
            break

if not target_dir:
    print("[!] Error: 'raw_evidence' folder ရှာမတွေ့ပါ။")
    exit(1)

raw_evidence_dir = target_dir / "raw_evidence"
findings_file = target_dir / "security_findings.json"

# Findings Data ဖတ်ယူခြင်း
findings = []
if findings_file.exists():
    try:
        findings = json.loads(findings_file.read_text(encoding="utf-8"))
    except:
        findings = []

# raw_evidence အောက်က log ဖိုင်အားလုံးကို လိုက်လံဖတ်ယူခြင်း
evidence_tree = {}
for root, _, files in os.walk(raw_evidence_dir):
    rel_root = Path(root).relative_to(raw_evidence_dir)
    category = str(rel_root)
    if category == ".":
        category = "general"
    
    for f in sorted(files):
        if f.endswith(".txt") or f.endswith(".log"):
            fpath = Path(root) / f
            file_key = f"{category}/{f}" if category != "general" else f
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                evidence_tree[file_key] = content
            except Exception as e:
                evidence_tree[file_key] = f"Error reading file: {e}"

evidence_json = json.dumps(evidence_tree)
hostname = target_dir.name.split("_")[2] if "_" in target_dir.name else "Moe-Moodlebox"

# Standalone All-in-One Dashboard တည်ဆောက်ခြင်း
html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Forensic Incident Dashboard - {hostname}</title>
<style>
    :root {{
        --bg-main: #0b0f19;
        --bg-card: #131c2e;
        --border: #23324d;
        --text-main: #f1f5f9;
        --text-sub: #94a3b8;
        --accent: #38bdf8;
        --red: #ef4444;
        --yellow: #f59e0b;
        --green: #10b981;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background: var(--bg-main);
        color: var(--text-main);
        display: flex;
        flex-direction: column;
        height: 100vh;
        overflow: hidden;
    }}
    header {{
        padding: 16px 24px;
        background: var(--bg-card);
        border-bottom: 1px solid var(--border);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }}
    .badge {{
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
    }}
    .badge-HIGH {{ background: #dc2626; color: #fee2e2; }}
    .badge-MEDIUM {{ background: #d97706; color: #fef3c7; }}
    .badge-LOW {{ background: #16a34a; color: #dcfce7; }}
    .container {{
        display: flex;
        flex: 1;
        overflow: hidden;
    }}
    /* ဘယ်ဘက်ခြမ်း Summary & Findings */
    .left-panel {{
        width: 48%;
        padding: 20px;
        overflow-y: auto;
        border-right: 1px solid var(--border);
    }}
    /* ညာဘက်ခြမ်း File Explorer & Log Viewer */
    .right-panel {{
        width: 52%;
        display: flex;
        flex-direction: column;
        background: #090d16;
    }}
    .file-tabs {{
        display: flex;
        background: var(--bg-card);
        border-bottom: 1px solid var(--border);
        padding: 8px 12px;
        gap: 8px;
        overflow-x: auto;
    }}
    select.file-select {{
        background: #0f172a;
        color: var(--accent);
        border: 1px solid var(--border);
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        outline: none;
        width: 100%;
    }}
    .log-viewer {{
        flex: 1;
        padding: 16px;
        overflow: auto;
        font-family: "Cascadia Code", Consolas, "Courier New", monospace;
        font-size: 12px;
        line-height: 1.5;
        color: #38bdf8;
        white-space: pre;
    }}
    .card {{
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }}
    .grid {{
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 12px;
        margin-bottom: 16px;
    }}
    .stat-card {{
        background: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 12px;
        text-align: center;
    }}
    .stat-num {{ font-size: 24px; font-weight: bold; margin-top: 4px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px; border-bottom: 1px solid var(--border); text-align: left; font-size: 13px; }}
    th {{ color: var(--text-sub); }}
    .quick-link {{
        color: var(--accent);
        cursor: pointer;
        text-decoration: underline;
        font-size: 12px;
    }}
</style>
</head>
<body>

<header>
    <div>
        <h2 style="margin: 0; font-size: 20px;">RPi Offline Forensic Workbench</h2>
        <small style="color: var(--text-sub);">Host: <b>{hostname}</b> | LAMP Moodle Examination Audit</small>
    </div>
    <div>
        <span class="badge" style="background:#2563eb; color:#fff;">Live Inspector Mode</span>
    </div>
</header>

<div class="container">
    <!-- ဘယ်ဘက်ခြမ်း Findings & Breakdown -->
    <div class="left-panel">
        <div class="grid">
            <div class="stat-card">
                <div style="font-size: 12px; color: var(--text-sub);">TOTAL FINDINGS</div>
                <div class="stat-num">{len(findings)}</div>
            </div>
            <div class="stat-card">
                <div style="font-size: 12px; color: var(--red);">HIGH RISK</div>
                <div class="stat-num" style="color: var(--red);">{len([f for f in findings if f.get('severity') == 'HIGH'])}</div>
            </div>
            <div class="stat-card">
                <div style="font-size: 12px; color: var(--yellow);">MEDIUM RISK</div>
                <div class="stat-num" style="color: var(--yellow);">{len([f for f in findings if f.get('severity') == 'MEDIUM'])}</div>
            </div>
        </div>

        <div class="card">
            <h3 style="margin-top: 0; font-size: 15px;">Incident Investigation Breakdown</h3>
            <table>
                <thead>
                    <tr>
                        <th style="width: 80px;">Risk</th>
                        <th>Category</th>
                        <th>Description & Action</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join([f'''<tr>
                        <td><span class="badge badge-{f.get('severity')}">{f.get('severity')}</span></td>
                        <td><b>{f.get('category')}</b></td>
                        <td>
                            <div>{f.get('message')}</div>
                            <div style="margin-top: 6px;">
                                <span class="quick-link" onclick="openArtifact('storage/usb_storage_history.txt')">View USB Log</span> | 
                                <span class="quick-link" onclick="openArtifact('auth/shell_histories.txt')">View Bash Commands</span>
                            </div>
                        </td>
                    </tr>''' for f in findings])}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h4 style="margin-top: 0; font-size: 14px;">Summary Assessment</h4>
            <p style="font-size: 13px; color: var(--text-sub); margin: 0; line-height: 1.6;">
                အထက်ပါ စစ်ဆေးတွေ့ရှိချက်များအရ ပြင်ပ USB Flash Drive ထိုးသွင်းထားသည့် မှတ်တမ်းကို တွေ့ရှိထားပါသည်။ 
                ညာဘက်ခြမ်းရှိ Dropdown မှတစ်ဆင့် မည်သည့် command များ ရိုက်နှိပ်ခဲ့သနည်း (Shell History) နှင့် မည်သည့်အချိန်တွင် USB ချိတ်ဆက်ခဲ့သည်ကို တိုက်ရိုက် ကြည့်ရှုစစ်ဆေးနိုင်ပါသည်။
            </p>
        </div>
    </div>

    <!-- ညာဘက်ခြမ်း Raw Evidence Integrated Viewer -->
    <div class="right-panel">
        <div class="file-tabs">
            <select id="fileDropdown" class="file-select" onchange="renderFile(this.value)">
                <!-- JavaScript မှတစ်ဆင့် အလိုအလျောက် populate လုပ်မည် -->
            </select>
        </div>
        <div id="logViewer" class="log-viewer">Select a log file from above to inspect raw contents...</div>
    </div>
</div>

<script>
    const evidenceData = {evidence_json};

    const dropdown = document.getElementById('fileDropdown');
    const viewer = document.getElementById('logViewer');

    // Populate dropdown with all collected logs
    for (const fileName in evidenceData) {{
        const opt = document.createElement('option');
        opt.value = fileName;
        opt.textContent = "📄 " + fileName;
        dropdown.appendChild(opt);
    }}

    function renderFile(fileName) {{
        if (evidenceData[fileName]) {{
            viewer.textContent = evidenceData[fileName];
        }} else {{
            viewer.textContent = "Log file content is empty or not found.";
        }}
    }}

    function openArtifact(name) {{
        for (let i = 0; i < dropdown.options.length; i++) {{
            if (dropdown.options[i].value.includes(name)) {{
                dropdown.selectedIndex = i;
                renderFile(dropdown.options[i].value);
                break;
            }}
        }}
    }}

    // Default အနေဖြင့် ပထမဆုံး log ဖိုင် (သို့မဟုတ်) USB log ကို ဖွင့်ထားပေးခြင်း
    window.onload = function() {{
        openArtifact('storage/usb_storage_history.txt');
    }};
</script>

</body>
</html>
"""

# HTML အား အစားထိုး သိမ်းဆည်းခြင်း
report_path = target_dir / "forensic_report.html"
report_path.write_text(html_content, encoding="utf-8")
print(f"[+] All-in-One Dashboard updated successfully: {report_path}")