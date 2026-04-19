from flask import Flask, jsonify, render_template
from flask_cors import CORS
import threading
import time
import subprocess
import platform
from sniffer import start_sniffing, get_stats, get_recent_packets

app = Flask(__name__)
CORS(app)

latest_latency = 0
latency_history = []
active_alerts = []

def ping_loop():
    global latest_latency, latency_history, active_alerts
    is_windows = platform.system().lower() == "windows"
    
    while True:
        try:
            if is_windows:
                res = subprocess.run(["ping", "-n", "1", "-w", "1000", "8.8.8.8"], capture_output=True, text=True)
                latency = 0
                if "time=" in res.stdout:
                    part = res.stdout.split("time=")[1]
                    latency_str = part.split("ms")[0].strip()
                    latency = float(latency_str)
                else:
                    latency = 1000
            else:
                res = subprocess.run(["ping", "-c", "1", "-W", "1", "8.8.8.8"], capture_output=True, text=True)
                latency = 0
                if "time=" in res.stdout:
                    part = res.stdout.split("time=")[1]
                    latency_str = part.split(" ")[0].strip()
                    latency = float(latency_str)
                else:
                    latency = 1000
            
            latest_latency = latency
            current_time = time.strftime("%H:%M:%S")
            latency_history.append({"time": current_time, "latency": latency})
            if len(latency_history) > 60:
                latency_history.pop(0)
                
            if latency > 100:
                active_alerts.insert(0, {"time": current_time, "msg": f"Spike: {latency}ms"})
                if len(active_alerts) > 10:
                    active_alerts.pop()
                    
            time.sleep(1)
        except Exception as e:
            print("Ping error:", e)
            time.sleep(1)

@app.route("/")
def index():
    with open("templates/index.html", "r") as f:
        return f.read()

@app.route("/api/stats")
def stats():
    return jsonify({
        "traffic": get_stats(),
        "latency": {"current": latest_latency, "history": latency_history},
        "alerts": active_alerts
    })

@app.route("/api/packets")
def packets():
    return jsonify({"packets": get_recent_packets()})

if __name__ == "__main__":
    t_sniff = threading.Thread(target=start_sniffing, daemon=True)
    t_sniff.start()
    
    t_ping = threading.Thread(target=ping_loop, daemon=True)
    t_ping.start()
    
    app.run(host="0.0.0.0", port=5000)
