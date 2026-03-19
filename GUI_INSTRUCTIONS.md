# How to Make It Look Awesome and Run It

1. **Move these files to your Linux server/VM:**
   You will need all these files on your Kali/Ubuntu machine:
   - `xdp_filter.c`
   - `xdp_manager.py`
   - `app.py`
   - `templates/index.html`
   - `static/style.css`
   - `static/app.js`

2. **Install Flask on Linux:**
   ```bash
   sudo apt update
   sudo apt install python3-flask python3-bpfcc
   ```

3. **Run the Dashboard:**
   Because XDP requires root permissions to attach to the network interface, you must run the web server as root!
   ```bash
   sudo python3 app.py
   ```

4. **Access the Beautiful UI:**
   Open a web browser on your **Windows machine** and go to:
   ```
   http://<YOUR_LINUX_IP_ADDRESS>:5000
   ```
   *Note: If port 5000 is blocked, you might need to run `sudo ufw allow 5000` on the Linux machine.*

5. **Test the Filter:**
   1. Click **"Activate Shield"** on the dashboard.
   2. Open a terminal on Kali and run a test flood against the server:
      `sudo hping3 --flood --udp <YOUR_LINUX_IP_ADDRESS>`
   3. Watch the Live Dashboard counters spin up instantly in real-time as the kernel drops the packets!
