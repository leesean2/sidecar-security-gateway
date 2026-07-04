import time
import requests
import json
import os

LOG_FILE = "/var/log/envoy/access.log"
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://control-plane-service:8090/logs")

print(f"Log forwarder started. Monitoring {LOG_FILE}, sending to {CONTROL_PLANE_URL}")

# Wait until log file is created by Envoy
while not os.path.exists(LOG_FILE):
    print("Waiting for log file to be created...")
    time.sleep(1)

with open(LOG_FILE, "r") as f:
    f.seek(0, 2)  # Seek to end of file to ignore past logs at startup
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        
        line_str = line.strip()
        if not line_str:
            continue
            
        try:
            log_data = json.loads(line_str)
            
            x_ff = log_data.get("x_forwarded_for")
            if x_ff and x_ff != "-":
                client_ip = x_ff.split(",")[0].strip()
            else:
                client_ip = log_data.get("client_ip", "0.0.0.0")

            payload = {
                "client_ip": client_ip,
                "path": log_data.get("path", "/"),
                "method": log_data.get("method", "GET"),
                "status": int(log_data.get("status", 200)),
                "user_agent": log_data.get("user_agent", "unknown"),
                "timestamp": log_data.get("timestamp", "")
            }
            res = requests.post(CONTROL_PLANE_URL, json=payload, timeout=2)
            print(f"Forwarded log: {payload['client_ip']} -> {payload['path']} ({res.status_code})")
        except Exception as e:
            print(f"Error forwarding log line: {e}. Line: {line_str}")
