from flask import Flask, render_template, jsonify, request  # type: ignore
from flask_cors import CORS  # type: ignore
from typing import Any
import os
import sys

# Import the manager
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from xdp_manager import XDPFilter  # pyre-ignore[21]

app = Flask(__name__)
CORS(app)

# Single instance of the XDP Filter
# Ensure the device matches your network interface (e.g. eth0, wlan0)
DEFAULT_DEVICE = "ens33"
xdp_filter = XDPFilter(DEFAULT_DEVICE)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status", methods=["GET"])
def get_status():
    """Returns the current status of the filter and dropped packet stats."""
    return jsonify({
        "status": "running" if xdp_filter.is_running else "stopped",
        "interface": xdp_filter.device,
        "stats": xdp_filter.get_stats(),
        "rules": xdp_filter.get_blocked_rules() if xdp_filter.is_running else {"ips": [], "ports": []}
    })

@app.route("/api/rules/block_ip", methods=["POST"])
def block_ip():
    """Blocks a specific IP address."""
    if not xdp_filter.is_running:
        return jsonify({"success": False, "message": "Filter must be running to add rules."}), 400
    
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "message": "IP address is required."}), 400
    
    if xdp_filter.block_ip(ip):
        return jsonify({"success": True, "message": f"Blocked IP: {ip}"})
    else:
        return jsonify({"success": False, "message": f"Failed to block IP: {ip}"}), 500

@app.route("/api/rules/unblock_ip", methods=["POST"])
def unblock_ip():
    """Unblocks a specific IP address."""
    if not xdp_filter.is_running:
        return jsonify({"success": False, "message": "Filter must be running to remove rules."}), 400
    
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "message": "IP address is required."}), 400
    
    if xdp_filter.unblock_ip(ip):
        return jsonify({"success": True, "message": f"Unblocked IP: {ip}"})
    else:
        return jsonify({"success": False, "message": f"Failed to unblock IP: {ip}"}), 500

@app.route("/api/rules/block_port", methods=["POST"])
def block_port():
    """Blocks a specific port."""
    if not xdp_filter.is_running:
        return jsonify({"success": False, "message": "Filter must be running to add rules."}), 400
    
    data = request.get_json(silent=True) or {}
    port = data.get("port")
    if port is None:
        return jsonify({"success": False, "message": "Port number is required."}), 400
    
    if xdp_filter.block_port(port):
        return jsonify({"success": True, "message": f"Blocked Port: {port}"})
    else:
        return jsonify({"success": False, "message": f"Failed to block port: {port}"}), 500

@app.route("/api/rules/unblock_port", methods=["POST"])
def unblock_port():
    """Unblocks a specific port."""
    if not xdp_filter.is_running:
        return jsonify({"success": False, "message": "Filter must be running to remove rules."}), 400
    
    data = request.get_json(silent=True) or {}
    port = data.get("port")
    if port is None:
        return jsonify({"success": False, "message": "Port number is required."}), 400
    
    if xdp_filter.unblock_port(port):
        return jsonify({"success": True, "message": f"Unblocked Port: {port}"})
    else:
        return jsonify({"success": False, "message": f"Failed to unblock port: {port}"}), 500

@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Returns currently active dynamic rules."""
    return jsonify(xdp_filter.get_blocked_rules() if xdp_filter.is_running else {"ips": [], "ports": []})

@app.route("/api/start", methods=["POST"])
def start_filter():
    """Starts the XDP filter."""
    if xdp_filter.is_running:
        return jsonify({"status": "running", "message": "Filter is already running"}), 400
        
    data = request.get_json(silent=True) or {}
    if "interface" in data and data["interface"].strip() and data["interface"] != "auto":
        xdp_filter.device = data["interface"]
        
    success = xdp_filter.start()
    if success:
        return jsonify({"status": "running", "message": f"Attached XDP to {xdp_filter.device}"})
    else:
        return jsonify({"status": "stopped", "message": "Failed to attach program. Ensure you are running as root and python3-bpfcc is installed."}), 500

@app.route("/api/stop", methods=["POST"])
def stop_filter():
    """Stops the XDP filter."""
    if not xdp_filter.is_running:
        return jsonify({"status": "stopped", "message": "Filter is not running"}), 400
        
    success = xdp_filter.stop()
    if success:
        return jsonify({"status": "stopped", "message": "Detached XDP program"})
    else:
        return jsonify({"status": "running", "message": "Failed to detach program."}), 500

if __name__ == "__main__":
    # Ensure cleanup on unexpected exit
    import atexit
    def cleanup(*args: Any, **kwargs: Any) -> None:
        if xdp_filter.is_running:
            xdp_filter.stop()
    atexit.register(cleanup)
    
    # Run the Flask app on all interfaces at port 5000
    print(f"[*] Starting XDP Web GUI on http://0.0.0.0:5000/ ...")
    app.run(host="0.0.0.0", port=5000, debug=False)
