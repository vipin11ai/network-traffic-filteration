#!/usr/bin/env python3
"""
monitor.py - Live curses-based monitoring CLI for the XDP DDoS filter.

Usage:
    sudo python3 monitor.py [interface]

Example:
    sudo python3 monitor.py eth0

Interactive commands (type at the bottom prompt):
    block ip <addr>       Block an IP address
    unblock ip <addr>     Unblock an IP address
    block port <num>      Block a port
    unblock port <num>    Unblock a port
    quit / q              Clean exit
"""
import sys
import os
import curses
import time
import signal
import pyfiglet  # pyre-ignore[21]
from typing import Any, Optional, List, Tuple

# Ensure sibling imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xdp_manager import XDPFilter  # pyre-ignore[21]

# ─── Traffic History ─────────────────────────────────────────────────────────

class TrafficHistory:
    """Tracks historical PPS data for charting."""
    def __init__(self, max_samples: int = 100):
        self.max_samples = max_samples
        self.ingress: List[int] = []
        self.drops: List[int] = []
        self.egress: List[int] = []
        self.top_talker: List[int] = []

    def add_sample(self, ingress: int, drops: int, egress: int, top_talker: int = 0):
        self.ingress.append(ingress)
        self.drops.append(drops)
        self.egress.append(egress)
        self.top_talker.append(top_talker)
        if len(self.ingress) > self.max_samples:
            self.ingress.pop(0)
            self.drops.pop(0)
            self.egress.pop(0)
            self.top_talker.pop(0)

# ─── Constants ────────────────────────────────────────────────────────────────

REFRESH_INTERVAL = 1.0  # seconds between stat refreshes
FEEDBACK_DURATION = 5.0  # seconds to show command feedback

# ─── Color pairs ──────────────────────────────────────────────────────────────

C_DEFAULT  = 0
C_TITLE    = 1
C_BORDER   = 2
C_DROP     = 3
C_INGRESS  = 4
C_EGRESS   = 5
C_BLACKLST = 6
C_RULES    = 7
C_PROMPT   = 8
C_FEEDBACK = 9
C_HEADER   = 10
C_DIM      = 11
C_WARN     = 12

# Rainbow colors for lolcat effect
C_RAINBOW_START = 20  # Starting index for rainbow pairs
RAINBOW_COLORS = [
    curses.COLOR_RED,
    curses.COLOR_YELLOW,
    curses.COLOR_GREEN,
    curses.COLOR_CYAN,
    curses.COLOR_BLUE,
    curses.COLOR_MAGENTA,
]


def init_colors():
    """Set up color pairs for the TUI."""
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_TITLE,    curses.COLOR_CYAN,    -1)
    curses.init_pair(C_BORDER,   curses.COLOR_BLUE,    -1)
    curses.init_pair(C_DROP,     curses.COLOR_RED,     -1)
    curses.init_pair(C_INGRESS,  curses.COLOR_GREEN,   -1)
    curses.init_pair(C_EGRESS,   curses.COLOR_MAGENTA, -1)
    curses.init_pair(C_BLACKLST, curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_RULES,    curses.COLOR_WHITE,   -1)
    curses.init_pair(C_PROMPT,   curses.COLOR_CYAN,    -1)
    curses.init_pair(C_FEEDBACK, curses.COLOR_GREEN,   -1)
    curses.init_pair(C_HEADER,   curses.COLOR_WHITE,   -1)
    curses.init_pair(C_DIM,      curses.COLOR_WHITE,   -1)
    curses.init_pair(C_WARN,     curses.COLOR_YELLOW,  -1)

    # Initialize rainbow pairs
    for i, color in enumerate(RAINBOW_COLORS):
        curses.init_pair(C_RAINBOW_START + i, color, -1)


# ─── Formatting helpers ──────────────────────────────────────────────────────

def fmt_num(n: int) -> str:
    """Format a number with comma separators."""
    return f"{n:,}"


def safe_addstr(win: Any, y: int, x: int, text: str, attr: int = 0) -> None:
    """addstr that silently ignores out-of-bounds writes."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0:
        return
    # Truncate text to available width
    avail = w - x - 1
    if avail <= 0:
        return
    try:
        win.addnstr(y, x, text, avail, attr)
    except curses.error:
        pass


def draw_hline(win: Any, y: int, x: int, length: int, ch: str = '─', attr: int = 0) -> None:
    """Draw a horizontal line."""
    safe_addstr(win, y, x, ch * length, attr)


def draw_chart(win: Any, y: int, x: int, width: int, height: int, history: List[int], color_pair: int, label: str) -> int:
    """Draw a simple ASCII bar chart."""
    if not history or width < 5 or height < 2:
        return y

    safe_addstr(win, y, x, label, curses.color_pair(color_pair) | curses.A_BOLD)
    y += 1
    
    max_val = max(history) if history else 1
    if max_val == 0: max_val = 1
    
    # Use block characters for bars
    chars = [" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
    
    start_idx = max(0, len(history) - (width - 2))
    chart_data: List[int] = history[start_idx:]  # type: ignore
    for i, val in enumerate(chart_data):
        bar_h = int((val / max_val) * (height * 8))
        for r in range(height):
            char_idx = min(8, bar_h - (r * 8))
            if char_idx > 0:
                safe_addstr(win, y + height - 1 - r, x + i, chars[char_idx], curses.color_pair(color_pair))  # type: ignore
    
    safe_addstr(win, y + height, x, f"Max: {fmt_num(max_val)} PPS", curses.color_pair(C_DIM))
    return y + height + 1


def draw_rainbow_text(win: Any, y: int, x: int, text: str) -> int:
    """Draw text with a vibrant rainbow (lolcat) effect. Returns next y."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        for j, char in enumerate(line):
            if char.isspace():
                continue
            # Smoother color rotation
            color_idx = (i + j // 2) % len(RAINBOW_COLORS)
            safe_addstr(win, y + i, x + j, char, curses.color_pair(C_RAINBOW_START + color_idx) | curses.A_BOLD)
    return y + len(lines)


# ─── Panel drawing ───────────────────────────────────────────────────────────

def draw_section_header(win: Any, y: int, x: int, icon: str, title: str, color_pair: int) -> int:
    """Draw a section header like '🛡  DROPPED PACKETS'."""
    safe_addstr(win, y, x, f" {icon}  ", curses.color_pair(C_DIM))
    safe_addstr(win, y, x + len(f" {icon}  "), title, curses.color_pair(color_pair) | curses.A_BOLD)
    return y + 1


def draw_proto_table(win: Any, y: int, x: int, data: dict, color_pair: int, col_width: int = 24, pps_data: Optional[dict] = None) -> int:
    """Draw a protocol:count table. Returns the next y position."""
    if not data:
        safe_addstr(win, y, x + 2, "(none)", curses.color_pair(C_DIM) | curses.A_DIM)
        return y + 1

    # Sort by PPS descending, then by protocol name
    sorted_data = []
    for proto, count in data.items():
        pps_val = 0
        if pps_data is not None and proto in pps_data:  # type: ignore
            pps_val = pps_data[proto]  # type: ignore
        sorted_data.append((proto, count, pps_val))
    
    sorted_data.sort(key=lambda x: (x[2], x[0]), reverse=True)

    for proto, count, pps_val in sorted_data:
        if y >= 195: # Safety limit for pad
            break
        
        label = f"  {proto}:"
        pps_str = f"{fmt_num(pps_val)} pps"
        
        safe_addstr(win, y, x, label, curses.color_pair(color_pair))
        safe_addstr(win, y, x + 16, pps_str.rjust(14), curses.color_pair(color_pair) | curses.A_BOLD)
        y += 1
    return y


def draw_dashboard(win: Any, xdp: Any, history: TrafficHistory, last_feedback: str, feedback_ts: float, term_w: int, term_h: int) -> int:
    """Render the full dashboard layout. Returns the total used height."""
    w = term_w
    win.erase()
    if term_h < 10 or term_w < 40:
        safe_addstr(win, 0, 0, "Terminal too small.", curses.color_pair(C_DROP))
        return 1

    # Title Banner
    banner_text = "Dos Karega ?"
    fig = pyfiglet.Figlet(font='slant', width=w-4)
    banner_ascii = fig.renderText(banner_text)
    banner_lines = banner_ascii.splitlines()
    banner_height = len(banner_lines)
    banner_width = max(len(l) for l in banner_lines) if banner_lines else 0
    center_x = max(2, (w - banner_width) // 2)
    draw_rainbow_text(win, 1, center_x, banner_ascii)

    # Traffic Charts
    row = 1 + banner_height + 1
    safe_addstr(win, row, 2, "📈 LIVE TRAFFIC (PPS)", curses.color_pair(C_HEADER) | curses.A_BOLD)
    draw_hline(win, row + 1, 2, w - 4, '─', curses.color_pair(C_DIM))
    row += 2
    row = draw_chart(win, row, 2, w - 4, 6, history.ingress, C_INGRESS, "INGRESS (INCOMING)")
    row = draw_chart(win, row, 2, w - 4, 3, history.top_talker, C_WARN, "TOP TALKER (ACTIVE IP)")
    row = draw_chart(win, row, 2, w - 4, 2, history.drops, C_DROP, "DROPS (BLOCKED)")
    row += 1

    # System Status Info
    now_str = time.strftime("%H:%M:%S")
    dev_label = f" {xdp.device} "
    status_icon = "●" if xdp.is_running else "○"
    status_color = C_INGRESS if xdp.is_running else C_DROP
    status_label = " ACTIVE " if xdp.is_running else " STOPPED "
    
    border_attr = curses.color_pair(C_BORDER) | curses.A_DIM
    safe_addstr(win, 0, 0, "┌" + "─" * (w - 2) + "┐", border_attr)
    
    attack_status = xdp.get_attack_status()
    attack_color = C_DROP if "UNDER ATTACK" in attack_status else C_DIM
    
    info_row = row
    safe_addstr(win, info_row, 2, dev_label, curses.color_pair(C_HEADER) | curses.A_DIM)
    if attack_status != "NORMAL":
        safe_addstr(win, info_row, 2 + len(dev_label) + 2, f" {attack_status} ", curses.color_pair(attack_color) | curses.A_BOLD)
    
    safe_addstr(win, info_row, w - len(now_str) - len(status_label) - 5, status_icon, curses.color_pair(status_color) | curses.A_BOLD)
    safe_addstr(win, info_row, w - len(now_str) - len(status_label) - 3, status_label, curses.color_pair(status_color))
    safe_addstr(win, info_row, w - len(now_str) - 2, now_str, curses.color_pair(C_DIM))
    row += 1
    safe_addstr(win, row, 0, "├" + "─" * (w - 2) + "┤", border_attr)
    row += 1

    # Fetch Data
    stats = xdp.get_stats()
    blacklist = xdp.get_blacklist()
    rules = xdp.get_blocked_rules()
    
    drops   = stats.get("drops", {})
    ingress = stats.get("ingress", {})
    egress  = stats.get("egress", {})
    pps     = stats.get("pps", {})

    # Two-column content
    content_start_row = row
    left_x = 2
    mid_x = max(w // 2, 28)

    # Left: DROPS
    row_left = draw_section_header(win, content_start_row, left_x, "🛡", "DROPPED PACKETS", C_DROP)
    draw_hline(win, row_left, left_x + 1, min(22, mid_x - left_x - 2), '─', curses.color_pair(C_DROP) | curses.A_DIM)
    row_left = draw_proto_table(win, row_left + 1, left_x, drops, C_DROP, pps_data=pps.get("drops", {}))

    # Right: INGRESS
    row_right = draw_section_header(win, content_start_row, mid_x, "📥", "Incoming Packets", C_INGRESS)
    draw_hline(win, row_right, mid_x + 1, min(22, w - mid_x - 3), '─', curses.color_pair(C_INGRESS) | curses.A_DIM)
    row_right = draw_proto_table(win, row_right + 1, mid_x, ingress, C_INGRESS, pps_data=pps.get("ingress", {}))

    row = max(row_left, row_right) + 1
    
    # Left: EGRESS
    row_left = draw_section_header(win, row, left_x, "📤", "Outgoing Packets", C_EGRESS)
    draw_hline(win, row_left, left_x + 1, min(22, mid_x - left_x - 2), '─', curses.color_pair(C_EGRESS) | curses.A_DIM)
    row_left = draw_proto_table(win, row_left + 1, left_x, egress, C_EGRESS, pps_data=pps.get("egress", {}))

    # Right: BLOCKED RULES
    row_right = draw_section_header(win, row, mid_x, "🚫", "BLOCKED RULES", C_RULES)
    draw_hline(win, row_right, mid_x + 1, min(22, w - mid_x - 3), '─', curses.color_pair(C_RULES) | curses.A_DIM)
    row_right += 1
    
    blocked_ips = rules.get("ips", [])
    blocked_ports = rules.get("ports", [])
    if blocked_ips:
        safe_addstr(win, row_right, mid_x + 1, "IPs:", curses.color_pair(C_RULES) | curses.A_DIM)
        ip_text = ", ".join(blocked_ips)
        safe_addstr(win, row_right, mid_x + 7, ip_text, curses.color_pair(C_RULES))
        row_right += 1
    else:
        safe_addstr(win, row_right, mid_x + 2, "IPs:   (none)", curses.color_pair(C_DIM) | curses.A_DIM)
        row_right += 1

    if blocked_ports:
        port_str = ", ".join(str(p) for p in blocked_ports)
        safe_addstr(win, row_right, mid_x + 1, "Ports:", curses.color_pair(C_RULES) | curses.A_DIM)
        safe_addstr(win, row_right, mid_x + 8, port_str, curses.color_pair(C_RULES))
    else:
        safe_addstr(win, row_right, mid_x + 2, "Ports: (none)", curses.color_pair(C_DIM) | curses.A_DIM)
    row_right += 2

    # Attack Analysis
    row_right = draw_section_header(win, row_right, mid_x, "⚔", "ATTACK ANALYSIS", C_DROP)
    draw_hline(win, row_right, mid_x + 1, min(22, w - mid_x - 3), '─', curses.color_pair(C_DROP) | curses.A_DIM)
    row_right += 1
    if attack_status == "NORMAL":
        safe_addstr(win, row_right, mid_x + 2, "STATUS: NORMAL", curses.color_pair(C_INGRESS))
    else:
        safe_addstr(win, row_right, mid_x + 2, f"STATUS: {attack_status}", curses.color_pair(C_DROP) | curses.A_BOLD)
    row_right += 2

    # Top Talkers
    row_left += 1
    row_left = draw_section_header(win, row_left, left_x, "🎯", "TOP TALKERS", C_WARN)
    draw_hline(win, row_left, left_x + 1, min(30, mid_x - left_x - 2), '─', curses.color_pair(C_WARN) | curses.A_DIM)
    row_left += 1
    top_ips = xdp.get_top_ips(5)
    if top_ips:
        for ip, count, _ in top_ips:
            safe_addstr(win, row_left, left_x + 1, f"  {ip}", curses.color_pair(C_WARN) | curses.A_BOLD)
            safe_addstr(win, row_left, left_x + 18, fmt_num(count).rjust(12), curses.color_pair(C_WARN))
            row_left += 1
    else:
        safe_addstr(win, row_left, left_x + 2, "(none)", curses.color_pair(C_DIM) | curses.A_DIM)
        row_left += 1

    # Auto-Blacklist
    row = max(row_left, row_right) + 1
    row = draw_section_header(win, row, left_x, "⚠ ", "AUTO-BLACKLISTED", C_BLACKLST)
    draw_hline(win, row, left_x + 1, min(30, w - 4), '─', curses.color_pair(C_BLACKLST) | curses.A_DIM)
    row += 1
    active_bl = {ip: info for ip, info in blacklist.items() if info.get("active", False)}
    if active_bl:
        for ip, info in active_bl.items():
            ttl = info.get("remaining_seconds", 0)
            safe_addstr(win, row, left_x + 1, f"  {ip}", curses.color_pair(C_BLACKLST) | curses.A_BOLD)
            safe_addstr(win, row, left_x + 20, f"(expires in {ttl}s)", curses.color_pair(C_BLACKLST) | curses.A_DIM)
            row += 1
    else:
        safe_addstr(win, row, left_x + 2, "(none)", curses.color_pair(C_DIM) | curses.A_DIM)
        row += 1

    # Final side borders and bottom border
    for r in range(1, row):
        safe_addstr(win, r, 0, "│", border_attr)
        safe_addstr(win, r, w - 1, "│", border_attr)
    safe_addstr(win, row, 0, "└" + "─" * (w - 2) + "┘", border_attr)
    row += 1

    # Feedback and Footer
    if last_feedback and (time.time() - feedback_ts) < FEEDBACK_DURATION:
        fb_color = C_INGRESS if last_feedback.startswith("[+]") else C_DROP
        safe_addstr(win, row, 2, str(last_feedback), curses.color_pair(fb_color) | curses.A_BOLD)
        row += 1

    # Footer
    creator_text = "created by vipin singh rana"
    team_text = "by team knights"
    try:
        row += 1
        if term_h > 40:
            f_footer = pyfiglet.Figlet(font='ansi_shadow', width=w)
            f_lines = f_footer.renderText(creator_text).splitlines()
            t_lines = f_footer.renderText(team_text).splitlines()
            for line in f_lines:
                safe_addstr(win, row, (w - len(str(line))) // 2, str(line), curses.color_pair(C_DIM))
                row += 1
            row += 1
            for line in t_lines:
                safe_addstr(win, row, (w - len(str(line))) // 2, str(line), curses.color_pair(C_TITLE) | curses.A_BOLD)
                row += 1
        else:
            safe_addstr(win, row, 2, team_text, curses.color_pair(C_TITLE) | curses.A_BOLD)
            safe_addstr(win, row, w - len(creator_text) - 4, creator_text, curses.color_pair(C_DIM) | curses.A_BOLD)
            row += 1
    except: pass

    return row + 2

# ─── Command processing ──────────────────────────────────────────────────────

def process_command(xdp: Any, cmd_str: str) -> str:
    """Process a user command. Returns a feedback message string."""
    parts = str(cmd_str).strip().lower().split()
    if not parts: return ""
    if parts[0] in ("quit", "q", "exit"): return "__QUIT__"
    if parts[0] == "help": return "[+] Commands: block ip <addr>, unblock ip <addr>, block port <num>, unblock port <num>, quit"

    if len(parts) == 3 and parts[0] == "block" and parts[1] == "ip":
        ok = xdp.block_ip(parts[2])
        return f"[+] Blocked IP: {parts[2]}" if ok else f"[-] Failed to block IP: {parts[2]}"

    if len(parts) == 3 and parts[0] == "unblock" and parts[1] == "ip":
        ok = xdp.unblock_ip(parts[2])
        return f"[+] Unblocked IP: {parts[2]}" if ok else f"[-] Failed to unblock IP: {parts[2]}"

    if len(parts) == 3 and parts[0] == "block" and parts[1] == "port":
        try:
            port = int(parts[2])
            ok = xdp.block_port(port)
            return f"[+] Blocked Port: {port}" if ok else f"[-] Failed to block port: {port}"
        except ValueError:
            return "[-] Invalid port number"

    if len(parts) == 3 and parts[0] == "unblock" and parts[1] == "port":
        try:
            port = int(parts[2])
            ok = xdp.unblock_port(port)
            return f"[+] Unblocked Port: {port}" if ok else f"[-] Failed to unblock port: {port}"
        except ValueError:
            return "[-] Invalid port number"

    if parts[0] == "help":
        return "Commands: block/unblock ip <addr> | block/unblock port <num> | quit"

    return f"[-] Unknown command: {cmd_str.strip()}. Type 'help' for commands."


# ─── Input bar ────────────────────────────────────────────────────────────────

def draw_input_bar(win: Any, input_buf: str) -> None:
    """Draw the command input bar at the bottom."""
    h, w = win.getmaxyx()
    prompt_row = h - 2
    border_attr = curses.color_pair(C_BORDER) | curses.A_DIM

    # Clear the prompt portion of that row
    safe_addstr(win, prompt_row, 1, " " * (w - 2), 0)
    safe_addstr(win, prompt_row, 0, "│", border_attr)
    safe_addstr(win, prompt_row, w - 1, "│", border_attr)

    prompt = "❯ "
    safe_addstr(win, prompt_row, 2, prompt, curses.color_pair(C_PROMPT) | curses.A_BOLD)
    safe_addstr(win, prompt_row, 2 + len(prompt), input_buf, curses.color_pair(C_PROMPT))

    # Position cursor after input text
    cursor_x = min(2 + len(prompt) + len(input_buf), w - 2)
    try:
        win.move(prompt_row, cursor_x)
    except curses.error:
        pass

    win.noutrefresh()


# ─── Main loop ────────────────────────────────────────────────────────────────

def main(stdscr: "curses.window") -> None:  # type: ignore[name-defined]
    """Main curses application loop."""
    # Curses setup
    curses.curs_set(1)  # show cursor in input bar
    curses.halfdelay(1) # block for 0.1s max on getch() - perfectly smooth typing but updates UI when idle
    stdscr.keypad(True)
    init_colors()

    device = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    xdp = XDPFilter(device, src_file="xdp_filter.c")
    
    history: Any = TrafficHistory(200)

    if not xdp.start():
        curses.curs_set(0)
        stdscr.nodelay(False)
        stdscr.clear()
        stdscr.addstr(0, 0, f"[!] Failed to start XDP filter on '{device}'.")
        stdscr.addstr(1, 0, "    Make sure you're running as root and bcc is installed.")
        stdscr.addstr(2, 0, "    Press any key to exit.")
        stdscr.refresh()
        stdscr.getch()
        return

    input_buf: str = ""
    last_feedback: str = ""
    feedback_ts: float = 0.0
    last_draw: float = 0.0
    scroll_pos: int = 0
    total_content_height: int = 100

    # Create a large pad for the dashboard content
    # We'll re-create or resize it if terminal width changes
    h, w = stdscr.getmaxyx()
    dashboard_pad: Any = curses.newpad(200, w)

    try:
        while True:
            now = time.time()
            h, w = stdscr.getmaxyx()

            # Redraw dashboard at REFRESH_INTERVAL
            if float(now) - float(last_draw) >= REFRESH_INTERVAL:
                # Update history
                stats = xdp.get_stats()
                pps = stats.get("pps", {})
                top_ips = xdp.get_top_ips(1)
                top_pps = top_ips[0][2] if top_ips else 0
                
                # Get total PPS across all protocols
                in_pps = sum(pps.get("ingress", {}).values())
                out_pps = sum(pps.get("egress", {}).values())
                drop_pps = sum(pps.get("drops", {}).values())
                history.add_sample(in_pps, drop_pps, out_pps, top_pps)

                total_content_height = draw_dashboard(dashboard_pad, xdp, history, last_feedback, feedback_ts, w, h)
                
                # Refresh pad area to screen
                # Pad coordinates: y, x (in pad) | screen y, x | screen height, width
                # We leave space at the bottom for the input bar (h-2)
                try:
                    dashboard_pad.refresh(scroll_pos, 0, 0, 0, h - 3, w - 1)
                except curses.error:
                    pass

                draw_input_bar(stdscr, input_buf)
                curses.doupdate()
                last_draw = now

            # Non-blocking key read
            try:
                ch = stdscr.getch()
            except curses.error:
                ch = -1

            if ch == -1:
                continue

            # Handle resize
            if ch == curses.KEY_RESIZE:
                stdscr.clear()
                h, w = stdscr.getmaxyx()
                dashboard_pad = curses.newpad(200, w)
                last_draw = 0 
                continue

            # Scrolling
            if ch == curses.KEY_DOWN:
                scroll_pos = min(scroll_pos + 1, max(0, total_content_height - (h - 3)))  # pyre-ignore
                last_draw = 0
                continue
            if ch == curses.KEY_UP:
                scroll_pos = max(0, scroll_pos - 1)  # pyre-ignore
                last_draw = 0
                continue
            if ch in (curses.KEY_NPAGE, 338): # Page Down
                scroll_pos = min(scroll_pos + 10, max(0, total_content_height - (h - 3)))  # type: ignore
                last_draw = 0
                continue
            if ch in (curses.KEY_PPAGE, 339): # Page Up
                scroll_pos = max(0, scroll_pos - 10)  # type: ignore
                last_draw = 0
                continue

            # Enter key — execute command
            if ch in (curses.KEY_ENTER, 10, 13):
                if input_buf.strip():  # type: ignore
                    fb: str = process_command(xdp, input_buf)  # type: ignore
                    if fb == "__QUIT__":
                        break
                    last_feedback = fb
                    feedback_ts = time.time()
                input_buf = ""
                last_draw = 0
                continue

            # Backspace
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                input_buf = input_buf[:-1]  # type: ignore
                draw_input_bar(stdscr, input_buf)
                curses.doupdate()
                continue

            # Escape — clear input
            if ch == 27:
                input_buf = ""
                draw_input_bar(stdscr, input_buf)
                curses.doupdate()
                continue

            # Printable character
            if 32 <= ch <= 126:
                input_buf += chr(ch)
                draw_input_bar(stdscr, input_buf)
                curses.doupdate()

    except KeyboardInterrupt:
        pass
    finally:
        xdp.stop()


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This tool requires root privileges. Run with: sudo python3 monitor.py [interface]")
        sys.exit(1)
    curses.wrapper(main)  # pyre-ignore[6]
