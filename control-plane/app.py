import json
import os
import tarfile
import time
from typing import List, Dict
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
import redis
from pydantic import BaseModel

app = FastAPI(title="Security Control Plane")

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REDIS_HOST = os.getenv("REDISHOST", os.getenv("REDIS_HOST", "localhost"))
REDIS_PORT = int(os.getenv("REDISPORT", os.getenv("REDIS_PORT", 6379)))
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

BUNDLE_DIR = "/tmp/bundle" if os.name != 'nt' else "C:\\Users\\user\\OneDrive\\바탕 화면\\sidecar-security-gateway\\control-plane\\bundle"
BUNDLE_PATH = os.path.join(BUNDLE_DIR, "security.tar.gz")

# Ensure bundle directory exists
os.makedirs(BUNDLE_DIR, exist_ok=True)

# In-memory blacklist, alerts, and HTTP logs fallback
blacklist_ips = {}  # Map IP -> Reason
alerts_list = []
http_logs_list = []

# Initial Rego Policy and Data
REGO_POLICY = """package env_security

import rego.v1

# Default response is to deny
default allow = {
    "allowed": false,
    "http_status": 403,
    "body": "Access Denied by Sidecar Gateway"
}

# Allow if path is public and IP is not blacklisted
allow = {
    "allowed": true
} if {
    not is_blacklisted
    is_public_path
}

# Allow checkout only if JWT is valid and IP is not blacklisted, injecting user info header
allow = {
    "allowed": true,
    "headers": {
        "x-user-info": user_name
    }
} if {
    not is_blacklisted
    is_checkout_path
    user_name := get_user_from_jwt
}

# Check blacklist
is_blacklisted if {
    # Lookup in dynamic data file data.json (loaded via bundle)
    data.blacklist[_] == input.attributes.request.http.headers["x-forwarded-for"]
}
is_blacklisted if {
    data.blacklist[_] == input.attributes.source.address.address
}

# Path definitions
is_public_path if {
    input.attributes.request.http.path == "/"
}
is_public_path if {
    input.attributes.request.http.path == "/products"
}
is_public_path if {
    input.attributes.request.http.path == "/cart"
}

is_checkout_path if {
    input.attributes.request.http.path == "/checkout"
}

# Extract username from JWT (Mock format: Bearer mock-jwt-username)
get_user_from_jwt = user_name if {
    auth_header := input.attributes.request.http.headers.authorization
    startswith(auth_header, "Bearer mock-jwt-")
    user_name := trim_prefix(auth_header, "Bearer mock-jwt-")
}
"""

class LogEntry(BaseModel):
    client_ip: str
    path: str
    method: str
    status: int
    user_agent: str
    timestamp: str

def rebuild_bundle():
    """Generates the OPA policy bundle tarball containing policy.rego and data.json"""
    # Fetch blacklist from Redis or fallback
    try:
        current_blacklist = list(r.smembers("blacklist"))
    except Exception as e:
        print(f"Redis error, using memory blacklist: {e}")
        current_blacklist = list(blacklist_ips.keys())

    data_content = {"blacklist": current_blacklist}

    rego_file = os.path.join(BUNDLE_DIR, "policy.rego")
    data_file = os.path.join(BUNDLE_DIR, "data.json")

    with open(rego_file, "w") as f:
        f.write(REGO_POLICY)

    with open(data_file, "w") as f:
        json.dump(data_content, f)

    # Create tar.gz bundle
    with tarfile.open(BUNDLE_PATH, "w:gz") as tar:
        tar.add(rego_file, arcname="policy.rego")
        tar.add(data_file, arcname="data.json")
    
    print(f"Bundle rebuilt successfully. Current Blacklist: {current_blacklist}")

@app.on_event("startup")
def startup_event():
    # Setup initial bundle
    rebuild_bundle()

@app.get("/bundles/security.tar.gz")
def get_bundle():
    if not os.path.exists(BUNDLE_PATH):
        rebuild_bundle()
    return FileResponse(BUNDLE_PATH, media_type="application/gzip", filename="security.tar.gz")

@app.post("/logs")
def receive_logs(entry: LogEntry, background_tasks: BackgroundTasks):
    client_ip = entry.client_ip
    path = entry.path
    
    print(f"Received Log: IP={client_ip}, Path={path}, Status={entry.status}")

    # Store general HTTP log for live monitor
    log_time = time.strftime("%H:%M:%S")
    http_logs_list.append({
        "timestamp": log_time,
        "ip": client_ip,
        "method": entry.method,
        "path": path,
        "status": entry.status
    })
    if len(http_logs_list) > 100:
        http_logs_list.pop(0)

    try:
        # 1. Rate Limiting Check (Simple sliding/fixed window of 1 minute)
        rate_key = f"rate:{client_ip}"
        requests_count = r.incr(rate_key)
        if requests_count == 1:
            r.expire(rate_key, 60) # 1 minute window

        if requests_count > 20:
            is_new = r.sadd("blacklist", client_ip)
            # Store reason in hash
            r.hset("blacklist_reasons", client_ip, "Rate Limit Exceeded")
            blacklist_ips[client_ip] = "Rate Limit Exceeded"
            
            if is_new:
                print(f"[ALERT] Rate limit exceeded for IP {client_ip} ({requests_count} req/min). Blacklisting.")
                alerts_list.append({
                    "type": "Rate Limit Exceeded",
                    "ip": client_ip,
                    "timestamp": log_time,
                    "details": f"Hit threshold: {requests_count} req/min. Dynamic block applied."
                })
                if len(alerts_list) > 50:
                    alerts_list.pop(0)
                background_tasks.add_task(rebuild_bundle)
            return {"status": "blacklisted", "reason": "Rate limit exceeded"}

        # 2. Workflow Validation Check
        session_key = f"session:{client_ip}"
        
        if path in ["/", "/products", "/cart"]:
            # Record visitation
            r.sadd(session_key, path)
            r.expire(session_key, 600) # 10 minute session TTL
        elif path == "/checkout":
            # Check if user visited products and cart
            visited = r.smembers(session_key)
            has_products = "/products" in visited
            has_cart = "/cart" in visited

            if not (has_products and has_cart):
                # Workflow violation! Direct API abuse.
                violations_key = f"violations:{client_ip}"
                violations = r.incr(violations_key)
                r.expire(violations_key, 600)
                print(f"[ALERT] Workflow violation detected for IP {client_ip}! Step skipped. Total violations: {violations}")

                if violations >= 2:
                    is_new = r.sadd("blacklist", client_ip)
                    r.hset("blacklist_reasons", client_ip, "Workflow Sequence Abuse")
                    blacklist_ips[client_ip] = "Workflow Sequence Abuse"
                    
                    if is_new:
                        print(f"[ALERT] Multiple workflow violations for IP {client_ip}. Blacklisting IP.")
                        alerts_list.append({
                            "type": "Workflow Sequence Abuse",
                            "ip": client_ip,
                            "timestamp": log_time,
                            "details": f"Skipped preceding flow steps. Triggered {violations} violations."
                        })
                        if len(alerts_list) > 50:
                            alerts_list.pop(0)
                        background_tasks.add_task(rebuild_bundle)
                    return {"status": "blacklisted", "reason": "Workflow violation"}
            
    except Exception as e:
        print(f"Error handling log entry: {e}")

    return {"status": "processed"}

@app.get("/blacklist")
def get_current_blacklist():
    try:
        blacklist = list(r.smembers("blacklist"))
        reasons = r.hgetall("blacklist_reasons")
        formatted = [{"ip": ip, "reason": reasons.get(ip, "Unknown Anomaly")} for ip in blacklist]
        return {"blacklist": formatted}
    except Exception:
        return {"blacklist": [{"ip": ip, "reason": reason} for ip, reason in blacklist_ips.items()]}

@app.post("/blacklist/clear")
def clear_blacklist(background_tasks: BackgroundTasks):
    try:
        r.delete("blacklist")
        r.delete("blacklist_reasons")
    except Exception:
        pass
    blacklist_ips.clear()
    
    # Add system audit log
    alerts_list.append({
        "type": "System Status Audit",
        "ip": "127.0.0.1",
        "timestamp": time.strftime("%H:%M:%S"),
        "details": "Administrator cleared the active blacklist database. All blocks lifted."
    })
    if len(alerts_list) > 50:
        alerts_list.pop(0)
        
    background_tasks.add_task(rebuild_bundle)
    return {"status": "cleared"}

@app.post("/blacklist/release")
def release_ip(ip: str, background_tasks: BackgroundTasks):
    try:
        r.srem("blacklist", ip)
        r.hdel("blacklist_reasons", ip)
    except Exception:
        pass
    if ip in blacklist_ips:
        del blacklist_ips[ip]

    alerts_list.append({
        "type": "System Status Audit",
        "ip": ip,
        "timestamp": time.strftime("%H:%M:%S"),
        "details": f"Administrator manually released IP {ip} from blacklist."
    })
    if len(alerts_list) > 50:
        alerts_list.pop(0)

    background_tasks.add_task(rebuild_bundle)
    return {"status": "released", "ip": ip}

@app.get("/alerts")
def get_alerts():
    return {"alerts": alerts_list}

@app.get("/http-logs")
def get_http_logs():
    return {"logs": http_logs_list}

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sidecar API Gateway Console</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #07070a;
            --card-bg: rgba(18, 18, 28, 0.75);
            --card-border: rgba(138, 43, 226, 0.25);
            --primary: #9d4edd;
            --primary-glow: rgba(157, 78, 221, 0.4);
            --accent: #00f5ff;
            --accent-glow: rgba(0, 245, 255, 0.3);
            --danger: #ff0055;
            --danger-glow: rgba(255, 0, 85, 0.3);
            --text-main: #f3f3f6;
            --text-muted: #8e90a6;
            --success: #00ff87;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            min-height: 100vh;
            background-image: radial-gradient(circle at 15% 15%, rgba(90, 15, 120, 0.2) 0%, transparent 45%),
                              radial-gradient(circle at 85% 85%, rgba(0, 245, 255, 0.08) 0%, transparent 45%);
            padding: 2rem;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--card-border);
            padding-bottom: 1.2rem;
        }
        h1 { font-size: 2.2rem; font-weight: 700; background: linear-gradient(45deg, var(--primary), var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        
        .status-badge { display: flex; align-items: center; gap: 0.5rem; background: rgba(0, 255, 135, 0.08); border: 1px solid var(--success); padding: 0.5rem 1.2rem; border-radius: 50px; color: var(--success); font-weight: 600; font-size: 0.9rem; }
        .status-dot { width: 8px; height: 8px; background-color: var(--success); border-radius: 50%; box-shadow: 0 0 10px var(--success); animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }
        
        /* Stats Dashboard Counters Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        @media(max-width: 1024px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
        @media(max-width: 600px) { .stats-grid { grid-template-columns: 1fr; } }
        
        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(16px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        .stat-card:hover { transform: translateY(-3px); border-color: rgba(0, 245, 255, 0.4); }
        .stat-card::after {
            content: '';
            position: absolute;
            top: -50%; left: -50%; width: 200%; height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.03) 0%, transparent 70%);
            pointer-events: none;
        }
        .stat-label { font-size: 0.95rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .stat-value { font-size: 2.8rem; font-weight: 700; margin-top: 0.5rem; line-height: 1; }
        .stat-card.blocked-active .stat-value { color: var(--danger); text-shadow: 0 0 15px var(--danger-glow); }
        .stat-card.incidents-total .stat-value { color: var(--primary); text-shadow: 0 0 15px var(--primary-glow); }
        .stat-card.rate-limit .stat-value { color: #ffaa00; text-shadow: 0 0 15px rgba(255, 170, 0, 0.3); }
        .stat-card.workflow-abuse .stat-value { color: var(--accent); text-shadow: 0 0 15px var(--accent-glow); }
        
        /* Middle Grid Layout */
        .middle-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        @media(max-width: 900px) { .middle-grid { grid-template-columns: 1fr; } }
        
        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            height: 380px;
        }
        .card-title { font-size: 1.25rem; font-weight: 600; margin-bottom: 1.2rem; color: var(--accent); display: flex; justify-content: space-between; align-items: center; }
        
        .btn {
            background: linear-gradient(135deg, var(--primary), #5a189a);
            color: white; border: none; padding: 0.5rem 1rem; border-radius: 8px; font-weight: 600; cursor: pointer; transition: all 0.3s;
            box-shadow: 0 4px 15px var(--primary-glow); font-size: 0.85rem;
        }
        .btn:hover { transform: translateY(-1px); box-shadow: 0 6px 20px var(--primary); }
        .btn-danger { background: linear-gradient(135deg, var(--danger), #b3003b); box-shadow: 0 4px 15px rgba(255, 0, 85, 0.3); }
        .btn-danger:hover { box-shadow: 0 6px 20px var(--danger); }
        .btn-sm { padding: 0.3rem 0.6rem; font-size: 0.8rem; border-radius: 4px; }
        
        .list-container { overflow-y: auto; flex-grow: 1; padding-right: 0.5rem; }
        
        /* Table Styles */
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { font-weight: 600; color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--card-border); }
        td { padding: 0.7rem 0.8rem; border-bottom: 1px solid rgba(255,255,255,0.03); font-size: 0.9rem; vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        
        .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; border: 1px solid transparent; text-transform: uppercase; letter-spacing: 0.5px; }
        .badge-danger { background: rgba(255, 0, 85, 0.1); border-color: var(--danger); color: var(--danger); }
        .badge-warning { background: rgba(255, 170, 0, 0.1); border-color: #ffaa00; color: #ffaa00; }
        .badge-info { background: rgba(0, 245, 255, 0.1); border-color: var(--accent); color: var(--accent); }
        .badge-success { background: rgba(0, 255, 135, 0.1); border-color: var(--success); color: var(--success); }
        
        /* Alert Items */
        .alert-item { border-left: 4px solid var(--primary); background: rgba(157, 78, 221, 0.04); margin-bottom: 0.5rem; border-radius: 4px; padding: 0.65rem; display: flex; flex-direction: column; gap: 0.2rem; }
        .alert-item.rate-limit { border-left-color: var(--danger); background: rgba(255, 0, 85, 0.04); }
        .alert-item.system-status { border-left-color: var(--success); background: rgba(0, 255, 135, 0.04); }
        .alert-header { display: flex; justify-content: space-between; font-weight: 600; font-size: 0.85rem; }
        .alert-type { font-weight: 700; }
        .alert-item.rate-limit .alert-type { color: var(--danger); }
        .alert-item.workflow-sequence .alert-type { color: var(--primary); }
        .alert-item.system-status .alert-type { color: var(--success); }
        .alert-time { color: var(--text-muted); font-size: 0.75rem; }
        .alert-details { font-size: 0.82rem; color: var(--text-muted); }
        
        /* Bottom Full Width Logs Console */
        .bottom-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            height: 400px;
        }
        
        /* Custom scrollbar */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: rgba(255,255,255,0.01); }
        ::-webkit-scrollbar-thumb { background: rgba(138, 43, 226, 0.3); border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(138, 43, 226, 0.5); }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Sidecar Security Console</h1>
            <p style="color: var(--text-muted); font-size: 0.95rem; margin-top: 0.2rem;">Real-time API Microservice Policy Enforcement & Anomaly Control</p>
        </div>
        <div class="status-badge">
            <div class="status-dot"></div>
            <span>GATEWAY ONLINE</span>
        </div>
    </header>

    <!-- Stats Dashboard Counter Cards -->
    <div class="stats-grid">
        <div class="stat-card blocked-active">
            <span class="stat-label">Active Blocks</span>
            <span class="stat-value" id="count-active-blocks">0</span>
        </div>
        <div class="stat-card incidents-total">
            <span class="stat-label">Total Security Events</span>
            <span class="stat-value" id="count-total-incidents">0</span>
        </div>
        <div class="stat-card rate-limit">
            <span class="stat-label">Rate Limit Attacks</span>
            <span class="stat-value" id="count-rate-limit">0</span>
        </div>
        <div class="stat-card workflow-abuse">
            <span class="stat-label">Workflow Violations</span>
            <span class="stat-value" id="count-workflow">0</span>
        </div>
    </div>

    <!-- Middle: Blacklist & Alerts -->
    <div class="middle-grid">
        <!-- Card 1: Blacklist Control Panel -->
        <div class="card">
            <div class="card-title">
                <span>Active Blacklist Control</span>
                <button class="btn btn-danger" onclick="clearBlacklist()">Clear All Blocks</button>
            </div>
            <div class="list-container" style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Blocked IP</th>
                            <th>Detection Type</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="blacklist-table-body">
                        <!-- Dynamic Content -->
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Card 2: Security Incidents -->
        <div class="card">
            <div class="card-title">
                <span>Security Incident Stream</span>
            </div>
            <div class="list-container" id="alerts-list">
                <!-- Dynamic Content -->
            </div>
        </div>
    </div>

    <!-- Bottom: Live Traffic Monitor -->
    <div class="bottom-card">
        <div class="card-title" style="margin-bottom: 0.8rem;">
            <span>Live HTTP Gateway Traffic Monitor (Real-time logs)</span>
        </div>
        <div class="list-container" style="overflow-x: auto;">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Client IP</th>
                        <th>Method</th>
                        <th>API Path</th>
                        <th>Envoy Status</th>
                    </tr>
                </thead>
                <tbody id="traffic-table-body">
                    <!-- Dynamic Content -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // Track stats counters
        let totalIncidentsCount = 0;
        let rateLimitCount = 0;
        let workflowCount = 0;

        async function fetchBlacklist() {
            try {
                const res = await fetch('/blacklist');
                const data = await res.json();
                const tbody = document.getElementById('blacklist-table-body');
                
                // Update stats counter
                document.getElementById('count-active-blocks').innerText = data.blacklist.length;
                
                if (data.blacklist.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" style="color: var(--text-muted); text-align: center; padding: 4rem 0;">No active blocks. Security policy is fully open.</td></tr>';
                    return;
                }
                
                tbody.innerHTML = data.blacklist.map(item => {
                    const isRateLimit = item.reason.includes("Rate");
                    const badgeClass = isRateLimit ? "badge-danger" : "badge-info";
                    return `
                        <tr>
                            <td style="font-weight: 600; color: #fff;">${item.ip}</td>
                            <td><span class="badge ${badgeClass}">${item.reason}</span></td>
                            <td>
                                <button class="btn btn-sm" onclick="releaseIP('${item.ip}')">Release</button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (err) {
                console.error("Error fetching blacklist:", err);
            }
        }

        async function fetchAlerts() {
            try {
                const res = await fetch('/alerts');
                const data = await res.json();
                const container = document.getElementById('alerts-list');
                
                // Update counters
                totalIncidentsCount = data.alerts.length;
                rateLimitCount = data.alerts.filter(a => a.type.includes("Rate")).length;
                workflowCount = data.alerts.filter(a => a.type.includes("Workflow") || a.type.includes("Sequence")).length;
                
                document.getElementById('count-total-incidents').innerText = totalIncidentsCount;
                document.getElementById('count-rate-limit').innerText = rateLimitCount;
                document.getElementById('count-workflow').innerText = workflowCount;
                
                if (data.alerts.length === 0) {
                    container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 5rem 0;">No security events recorded. Monitoring live traffic...</div>';
                    return;
                }
                
                // Show alerts in reverse order (newest first)
                const sortedAlerts = [...data.alerts].reverse();
                
                container.innerHTML = sortedAlerts.map(alert => {
                    let itemClass = "system-status";
                    if (alert.type.includes("Rate")) {
                        itemClass = "rate-limit";
                    } else if (alert.type.includes("Workflow") || alert.type.includes("Sequence")) {
                        itemClass = "workflow-sequence";
                    }
                    return `
                        <div class="alert-item ${itemClass}">
                            <div class="alert-header">
                                <span class="alert-type">${alert.type}</span>
                                <span class="alert-time">${alert.timestamp}</span>
                            </div>
                            <div style="font-size: 0.9rem; font-weight: 600; margin-top: 0.15rem;">Source: ${alert.ip}</div>
                            <div class="alert-details">${alert.details}</div>
                        </div>
                    `;
                }).join('');
            } catch (err) {
                console.error("Error fetching alerts:", err);
            }
        }

        async function fetchHttpLogs() {
            try {
                const res = await fetch('/http-logs');
                const data = await res.json();
                const tbody = document.getElementById('traffic-table-body');
                
                if (data.logs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="color: var(--text-muted); text-align: center; padding: 4rem 0;">No HTTP traffic logs received yet. Run verify.py to generate logs.</td></tr>';
                    return;
                }
                
                // Show logs in reverse order (newest first)
                const sortedLogs = [...data.logs].reverse();
                
                tbody.innerHTML = sortedLogs.map(log => {
                    const statusClass = log.status === 200 ? "badge-success" : (log.status === 403 ? "badge-danger" : "badge-warning");
                    const methodClass = log.method === "GET" ? "color: var(--success);" : "color: var(--accent);";
                    return `
                        <tr>
                            <td style="color: var(--text-muted); font-size: 0.85rem;">${log.timestamp}</td>
                            <td style="font-weight: 600;">${log.ip}</td>
                            <td style="${methodClass} font-weight: bold;">${log.method}</td>
                            <td style="font-family: monospace; color: #dedede;">${log.path}</td>
                            <td><span class="badge ${statusClass}">${log.status}</span></td>
                        </tr>
                    `;
                }).join('');
            } catch (err) {
                console.error("Error fetching HTTP logs:", err);
            }
        }

        async function clearBlacklist() {
            if (!confirm("Are you sure you want to clear all blacklisted clients?")) return;
            try {
                const res = await fetch('/blacklist/clear', { method: 'POST' });
                if (res.ok) {
                    fetchBlacklist();
                    fetchAlerts();
                }
            } catch (err) {
                console.error("Error clearing blacklist:", err);
            }
        }

        async function releaseIP(ip) {
            try {
                const res = await fetch(`/blacklist/release?ip=${encodeURIComponent(ip)}`, { method: 'POST' });
                if (res.ok) {
                    fetchBlacklist();
                    fetchAlerts();
                }
            } catch (err) {
                console.error("Error releasing IP:", err);
            }
        }

        // Poll every 1.5 seconds for extremely real-time feel
        setInterval(() => {
            fetchBlacklist();
            fetchAlerts();
            fetchHttpLogs();
        }, 1500);

        // Initial fetch
        fetchBlacklist();
        fetchAlerts();
        fetchHttpLogs();
    </script>
</body>
</html>"""
    return HTMLResponse(content=html_content, status_code=200)
