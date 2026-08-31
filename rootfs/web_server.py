#!/usr/bin/env python3
"""
Lightweight Ingress Web UI for Home Assistant: Omada & Cloudflare SSL Manager
Provides live certificate status, 'Check & Sync Now', 'Force Renew Certificate Now',
and 'Clear Log File' actions.
"""

import os
import sys
import json
import time
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

CONFIG_PATH = "/data/options.json"
ADDON_LOG_PATH = "/data/addon.log"
LETSENCRYPT_LOG_PATH = "/data/letsencrypt-log/letsencrypt.log"
RUN_LOCK = threading.Lock()
LAST_ACTION_OUTPUT = ""
LAST_ACTION_TIME = ""


def run_command_action(cmd):
    global LAST_ACTION_OUTPUT, LAST_ACTION_TIME
    with RUN_LOCK:
        LAST_ACTION_TIME = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=180
            )
            LAST_ACTION_OUTPUT = proc.stdout
            return proc.returncode == 0, proc.stdout
        except Exception as exc:
            LAST_ACTION_OUTPUT = f"Error executing action: {exc}"
            return False, LAST_ACTION_OUTPUT


def get_status_data():
    options = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                options = json.load(f)
        except Exception:
            pass

    domains = options.get("domains", [])
    primary_domain = domains[0] if domains else "Not configured"
    cert_path = f"/data/letsencrypt/live/{primary_domain}/fullchain.pem"

    cert_info = {}
    if os.path.exists(cert_path):
        try:
            proc = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-enddate", "-fingerprint", "-sha256"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            for line in proc.stdout.strip().split("\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    cert_info[k.strip().lower()] = v.strip()
        except Exception:
            pass

    # Read recent logs from addon log file
    recent_logs = ""
    if os.path.exists(ADDON_LOG_PATH):
        try:
            with open(ADDON_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                recent_logs = "".join(lines[-150:])
        except Exception:
            pass

    return {
        "primary_domain": primary_domain,
        "domains": domains,
        "cert_exists": os.path.exists(cert_path),
        "cert_subject": cert_info.get("subject", "N/A"),
        "cert_expires": cert_info.get("notafter", "N/A"),
        "cert_fingerprint": cert_info.get("sha256 fingerprint", "N/A"),
        "omada_enabled": options.get("omada", {}).get("enabled", False),
        "omada_url": options.get("omada", {}).get("url", "N/A"),
        "schedule_frequency": options.get("schedule_frequency", "daily"),
        "schedule_time": options.get("schedule_time", "03:00"),
        "last_action_time": LAST_ACTION_TIME,
        "last_action_output": LAST_ACTION_OUTPUT,
        "recent_logs": recent_logs
    }


class IngressHandler(BaseHTTPRequestHandler):
    def _send_html(self, content, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.endswith("/api/status"):
            self._send_json(get_status_data())
            return

        if path.endswith("/api/logs"):
            data = get_status_data()
            self._send_json({"logs": data.get("recent_logs", "")})
            return

        ingress_path = self.headers.get("X-Ingress-Path", "").rstrip("/")
        status = get_status_data()

        cert_badge = '<span class="badge success">Active</span>' if status["cert_exists"] else '<span class="badge warning">Not Issued Yet</span>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Omada & Cloudflare SSL Certificate Manager</title>
    <style>
        :root {{
            --bg-color: #111827;
            --card-bg: #1f2937;
            --card-border: #374151;
            --text-color: #f9fafb;
            --text-muted: #9ca3af;
            --primary: #2563eb;
            --primary-hover: #1d4ed8;
            --accent: #10b981;
            --accent-hover: #059669;
            --danger: #ef4444;
            --danger-hover: #dc2626;
            --warning: #f59e0b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 960px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--card-border);
        }}
        .header h1 {{
            font-size: 20px;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 18px;
        }}
        .card h2 {{
            font-size: 14px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0;
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .item {{
            margin-bottom: 10px;
        }}
        .item-label {{
            font-size: 12px;
            color: var(--text-muted);
        }}
        .item-value {{
            font-size: 14px;
            font-weight: 500;
            word-break: break-all;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 9999px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge.success {{ background-color: rgba(16, 185, 129, 0.2); color: #34d399; }}
        .badge.warning {{ background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
        .badge.danger {{ background-color: rgba(239, 68, 68, 0.2); color: #f87171; }}
        .actions {{
            display: flex;
            gap: 12px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }}
        .btn {{
            background-color: var(--primary);
            color: white;
            border: none;
            padding: 10px 18px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            transition: background-color 0.15s ease;
        }}
        .btn:hover {{ background-color: var(--primary-hover); }}
        .btn.btn-accent {{ background-color: var(--accent); }}
        .btn.btn-accent:hover {{ background-color: var(--accent-hover); }}
        .btn.btn-danger {{ background-color: var(--danger); }}
        .btn.btn-danger:hover {{ background-color: var(--danger-hover); }}
        .btn.btn-muted {{ background-color: #4b5563; }}
        .btn.btn-muted:hover {{ background-color: #374151; }}
        .btn:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
        }}
        .console-card {{
            background-color: #0d1117;
            border: 1px solid var(--card-border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 20px;
        }}
        .console-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            font-size: 13px;
            color: var(--text-muted);
        }}
        pre {{
            margin: 0;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 13px;
            color: #58a6ff;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 320px;
            overflow-y: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Omada & Cloudflare SSL Certificate Manager</h1>
            <div>{cert_badge}</div>
        </div>

        <div class="grid">
            <div class="card">
                <h2>Let's Encrypt Certificate (2048-bit RSA)</h2>
                <div class="item">
                    <div class="item-label">Primary Domain</div>
                    <div class="item-value">{status["primary_domain"]}</div>
                </div>
                <div class="item">
                    <div class="item-label">Subject</div>
                    <div class="item-value">{status["cert_subject"]}</div>
                </div>
                <div class="item">
                    <div class="item-label">Expiration Date</div>
                    <div class="item-value">{status["cert_expires"]}</div>
                </div>
                <div class="item">
                    <div class="item-label">SHA256 Fingerprint</div>
                    <div class="item-value" style="font-size:12px;">{status["cert_fingerprint"]}</div>
                </div>
            </div>

            <div class="card">
                <h2>Omada Controller</h2>
                <div class="item">
                    <div class="item-label">Controller URL</div>
                    <div class="item-value">{status["omada_url"]}</div>
                </div>
                <div class="item">
                    <div class="item-label">Authentication</div>
                    <div class="item-value">OpenAPI Application Client</div>
                </div>
                <div class="item">
                    <div class="item-label">Scheduled Maintenance</div>
                    <div class="item-value">{str(status["schedule_frequency"]).capitalize()} at {status["schedule_time"]}</div>
                </div>
                <div class="item">
                    <div class="item-label">Key & Format</div>
                    <div class="item-value">RSA PEM (/certificate & /ssl-key)</div>
                </div>
            </div>
        </div>

        <div class="actions">
            <button id="btnCheck" class="btn btn-accent" onclick="triggerAction('check')">
                🔄 Check & Sync Certificate Now
            </button>
            <button id="btnForce" class="btn btn-danger" onclick="triggerAction('force_renew')">
                ⚡ Force Renew Certificate Now
            </button>
            <button id="btnClear" class="btn btn-muted" onclick="triggerAction('clear_logs')">
                🧹 Clear Log File
            </button>
            <button class="btn" onclick="location.reload()">
                🔃 Refresh Dashboard
            </button>
        </div>
        <div style="margin-bottom: 20px; font-size: 13px; color: var(--text-muted); display: flex; align-items: center; gap: 8px;">
            <input type="checkbox" id="chkForceUpload" style="cursor: pointer; width: 16px; height: 16px;">
            <label for="chkForceUpload" style="cursor: pointer; user-select: none;">
                Force full Let's Encrypt renewal on next check (bypasses expiration check)
            </label>
        </div>

        <div class="console-card">
            <div class="console-header">
                <span>Action Output Console</span>
                <span id="actionTime">{status["last_action_time"] or "Idle"}</span>
            </div>
            <pre id="output">{status["last_action_output"] or "Ready for actions..."}</pre>
        </div>

        <div class="console-card">
            <div class="console-header">
                <span>Add-on Daemon Activity Log</span>
                <span>Auto-refreshed</span>
            </div>
            <pre id="daemonLogs" style="color: #7ee787;">{status["recent_logs"] or "No log output recorded yet."}</pre>
        </div>
    </div>

    <script>
        const baseUrl = "{ingress_path}";
        
        async function triggerAction(action) {{
            const btnCheck = document.getElementById("btnCheck");
            const btnForce = document.getElementById("btnForce");
            const btnClear = document.getElementById("btnClear");
            const chkForce = document.getElementById("chkForceUpload");
            const output = document.getElementById("output");
            const actionTime = document.getElementById("actionTime");

            let targetAction = action;
            if (action === "check" && chkForce && chkForce.checked) {{
                targetAction = "force_renew";
            }}

            if (btnCheck) btnCheck.disabled = true;
            if (btnForce) btnForce.disabled = true;
            if (btnClear) btnClear.disabled = true;
            output.innerText = "Executing " + targetAction + "... please wait...";

            try {{
                const res = await fetch(baseUrl + "/api/" + targetAction, {{ method: "POST" }});
                const data = await res.json();
                output.innerText = data.output || data.message || "Action finished.";
                actionTime.innerText = new Date().toLocaleTimeString();
                if (action === "clear_logs") {{
                    document.getElementById("daemonLogs").innerText = "Logs cleared.";
                }}
            }} catch (err) {{
                output.innerText = "Error executing action: " + err;
            }} finally {{
                if (btnCheck) btnCheck.disabled = false;
                if (btnForce) btnForce.disabled = false;
                if (btnClear) btnClear.disabled = false;
            }}
        }}
    </script>
</body>
</html>"""
        self._send_html(html)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.endswith("/api/check"):
            options = {}
            if os.path.exists(CONFIG_PATH):
                try:
                    with open(CONFIG_PATH, "r") as f:
                        options = json.load(f)
                except Exception:
                    pass
            domains = options.get("domains", [])
            primary_domain = domains[0] if domains else ""
            cert_path = f"/data/letsencrypt/live/{primary_domain}/fullchain.pem"
            key_path = f"/data/letsencrypt/live/{primary_domain}/privkey.pem"

            cmd = f"python3 /deploy_omada.py deploy '{cert_path}' '{key_path}' '{CONFIG_PATH}'"
            success, out = run_command_action(cmd)
            self._send_json({"success": success, "output": out})
            return

        if path.endswith("/api/force_renew"):
            options = {}
            if os.path.exists(CONFIG_PATH):
                try:
                    with open(CONFIG_PATH, "r") as f:
                        options = json.load(f)
                except Exception:
                    pass

            domains = options.get("domains", [])
            primary_domain = domains[0] if domains else ""
            email = options.get("letsencrypt_email", "")
            cf_token = options.get("cloudflare_api_token", "")

            cf_ini = "/data/letsencrypt/cloudflare.ini"
            domain_args = " ".join([f"-d {d}" for d in domains])

            # Run certbot with official Let's Encrypt Production server & --force-renewal
            certbot_cmd = (
                f"certbot certonly --config-dir /data/letsencrypt --work-dir /data/letsencrypt-work "
                f"--logs-dir /data/letsencrypt-log --server https://acme-v02.api.letsencrypt.org/directory "
                f"--dns-cloudflare --dns-cloudflare-credentials '{cf_ini}' "
                f"--dns-cloudflare-propagation-seconds 30 --non-interactive --agree-tos --email '{email}' "
                f"--cert-name '{primary_domain}' --key-type rsa --rsa-key-size 2048 --force-renewal {domain_args}"
            )
            success, cert_out = run_command_action(certbot_cmd)

            cert_path = f"/data/letsencrypt/live/{primary_domain}/fullchain.pem"
            key_path = f"/data/letsencrypt/live/{primary_domain}/privkey.pem"

            if success:
                deploy_cmd = f"python3 /deploy_omada.py deploy '{cert_path}' '{key_path}' '{CONFIG_PATH}'"
                d_success, d_out = run_command_action(deploy_cmd)
                full_out = f"Certbot Output:\n{cert_out}\n\nOmada Deploy Output:\n{d_out}"
                self._send_json({"success": d_success, "output": full_out})
            elif os.path.exists(cert_path) and os.path.exists(key_path):
                # Fallback to deploying existing certificate on disk
                deploy_cmd = f"python3 /deploy_omada.py deploy '{cert_path}' '{key_path}' '{CONFIG_PATH}'"
                d_success, d_out = run_command_action(deploy_cmd)
                full_out = f"Certbot Notice (rate-limited or skipped):\n{cert_out}\n\nExisting certificate on disk deployed to Omada:\n{d_out}"
                self._send_json({"success": d_success, "output": full_out})
            else:
                self._send_json({"success": False, "output": f"Certbot Force Renewal Failed:\n{cert_out}"})
            return

        if path.endswith("/api/clear_logs"):
            global LAST_ACTION_OUTPUT, LAST_ACTION_TIME
            LAST_ACTION_OUTPUT = "Logs cleared successfully."
            LAST_ACTION_TIME = time.strftime("%Y-%m-%d %H:%M:%S")
            try:
                if os.path.exists(ADDON_LOG_PATH):
                    with open(ADDON_LOG_PATH, "w") as f:
                        f.write(f"{LAST_ACTION_TIME} [INFO] Addon log file cleared.\n")
                if os.path.exists(LETSENCRYPT_LOG_PATH):
                    with open(LETSENCRYPT_LOG_PATH, "w") as f:
                        f.write("")
            except Exception as exc:
                self._send_json({"success": False, "output": f"Could not clear logs: {exc}"})
                return
            self._send_json({"success": True, "output": "All add-on log files cleared successfully."})
            return

        self._send_json({"error": "Unknown endpoint"}, 404)


def main():
    port = int(os.environ.get("INGRESS_PORT", 8099))
    server = HTTPServer(("0.0.0.0", port), IngressHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
