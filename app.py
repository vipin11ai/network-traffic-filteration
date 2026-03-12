from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import os
import sys

# Import the manager
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from xdp_manager import XDPFilter

app = Flask(__name__)
CORS(app)

# Single instance of the XDP Filter
# Ensure the device matches your network interface (e.g. eth0, wlan0)
DEFAULT_DEVICE = "eth0"
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
        "stats": xdp_filter.get_stats()
    })

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
    atexit.register(lambda: xdp_filter.stop() if xdp_filter.is_running else None)
    
    # Run the Flask app on all interfaces at port 5000
    print(f"[*] Starting XDP Web GUI on http://0.0.0.0:5000/ ...")
    app.run(host="0.0.0.0", port=5000, debug=False)
