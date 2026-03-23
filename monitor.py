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
from typing import Any, Optional

# Ensure sibling imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from xdp_manager import XDPFilter  # pyre-ignore[21]

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


# ─── Panel drawing ───────────────────────────────────────────────────────────

def draw_section_header(win: Any, y: int, x: int, icon: str, title: str, color_pair: int) -> int:
    """Draw a section header like '🛡  DROPPED PACKETS'."""
    safe_addstr(win, y, x, f" {icon}  ", curses.color_pair(C_DIM))
    safe_addstr(win, y, x + len(f" {icon}  "), title, curses.color_pair(color_pair) | curses.A_BOLD)
    return y + 1


def draw_proto_table(win: Any, y: int, x: int, data: dict, color_pair: int, col_width: int = 24, pps_data: Optional[dict] = None) -> int:
    """Draw a protocol:count table. Returns the next y position."""
    h, w = win.getmaxyx()
    if not data:
        safe_addstr(win, y, x + 2, "(none)", curses.color_pair(C_DIM) | curses.A_DIM)
        return y + 1

    # Sort by PPS descending, then by protocol name
    sorted_data = []
    for proto, count in data.items():
        pps_val = 0
        if pps_data is not None and proto in pps_data:  # pyre-ignore[16]
            pps_val = pps_data[proto]  # pyre-ignore[16, 29]
        sorted_data.append((proto, count, pps_val))
    
    sorted_data.sort(key=lambda x: (x[2], x[0]), reverse=True)

    for proto, count, pps_val in sorted_data:
        if y >= h - 3:
            break
        
        label = f"  {proto}:"
        pps_str = f"{fmt_num(pps_val)} pps"
        
        safe_addstr(win, y, x, label, curses.color_pair(color_pair))
        safe_addstr(win, y, x + 16, pps_str.rjust(14), curses.color_pair(color_pair) | curses.A_BOLD)
            
        y += 1
    return y


def draw_dashboard(win: Any, xdp: Any, last_feedback: str, feedback_ts: float) -> None:
    """Render the full dashboard layout."""
    h, w = win.getmaxyx()
    if h < 10 or w < 40:
        safe_addstr(win, 0, 0, "Terminal too small. Resize to at least 40x10.", curses.color_pair(C_DROP))
        return

    win.erase()

    # Title bar
    now_str = time.strftime("%H:%M:%S")
    title = f" XDP Network Monitor "
    dev_label = f" {xdp.device} "
    status_icon = "●" if xdp.is_running else "○"
    status_color = C_INGRESS if xdp.is_running else C_DROP
    status_label = " ACTIVE " if xdp.is_running else " STOPPED "

    # Top border
    border_attr = curses.color_pair(C_BORDER) | curses.A_DIM
    safe_addstr(win, 0, 0, "┌" + "─" * (w - 2) + "┐", border_attr)

    attack_status = xdp.get_attack_status()
    attack_color = C_DROP if "UNDER ATTACK" in attack_status else C_DIM

    # Title line
    safe_addstr(win, 1, 0, "│", border_attr)
    safe_addstr(win, 1, w - 1, "│", border_attr)
    center_x = max(1, (w - len(title)) // 2)
    safe_addstr(win, 1, center_x, title, curses.color_pair(C_TITLE) | curses.A_BOLD)
    safe_addstr(win, 1, 2, dev_label, curses.color_pair(C_HEADER) | curses.A_DIM)
    
    # Attack status banner
    if attack_status != "NORMAL":
        safe_addstr(win, 1, center_x + len(title) + 2, f" {attack_status} ", curses.color_pair(attack_color) | curses.A_BOLD)
    
    safe_addstr(win, 1, w - len(now_str) - len(status_label) - 5, status_icon, curses.color_pair(status_color) | curses.A_BOLD)
    safe_addstr(win, 1, w - len(now_str) - len(status_label) - 3, status_label, curses.color_pair(status_color))
    safe_addstr(win, 1, w - len(now_str) - 2, now_str, curses.color_pair(C_DIM))

    safe_addstr(win, 2, 0, "├" + "─" * (w - 2) + "┤", border_attr)

    # ── Fetch data ────────────────────────────────────────────────────────
    stats = xdp.get_stats()
    blacklist = xdp.get_blacklist()
    rules = xdp.get_blocked_rules()

    drops   = stats.get("drops", {})
    ingress = stats.get("ingress", {})
    egress  = stats.get("egress", {})
    pps     = stats.get("pps", {})

    # ── Two-column layout ─────────────────────────────────────────────────
    left_x = 2
    mid_x = max(w // 2, 28)
    row = 3

    # Side borders for content area
    for r in range(3, h - 3):
        safe_addstr(win, r, 0, "│", border_attr)
        safe_addstr(win, r, w - 1, "│", border_attr)

    # ── Left column: DROPS ────────────────────────────────────────────────
    row_left = draw_section_header(win, row, left_x, "🛡", "DROPPED PACKETS", C_DROP)
    draw_hline(win, row_left, left_x + 1, min(22, mid_x - left_x - 2), '─', curses.color_pair(C_DROP) | curses.A_DIM)
    row_left = draw_proto_table(win, row_left + 1, left_x, drops, C_DROP, pps_data=pps.get("drops", {}))

    # ── Right column: INGRESS ─────────────────────────────────────────────
    row_right = draw_section_header(win, row, mid_x, "📥", "Incoming Packets", C_INGRESS)
    draw_hline(win, row_right, mid_x + 1, min(22, w - mid_x - 3), '─', curses.color_pair(C_INGRESS) | curses.A_DIM)
    row_right = draw_proto_table(win, row_right + 1, mid_x, ingress, C_INGRESS, pps_data=pps.get("ingress", {}))

    # ── Next row pair ─────────────────────────────────────────────────────
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
        # Wrap IPs across lines
        ip_text: str = ", ".join(blocked_ips)
        avail: int = w - mid_x - 8
        while ip_text and row_right < h - 4:
            chunk: str = ip_text[:avail]  # pyre-ignore[16]
            safe_addstr(win, row_right, mid_x + 7, chunk, curses.color_pair(C_RULES))
            ip_text = ip_text[avail:]  # pyre-ignore[16]
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

    # ── ATTACK ANALYSIS ───────────────────────────────────────────────────
    if row_right < h - 6:
        row_right = draw_section_header(win, row_right, mid_x, "⚔", "ATTACK ANALYSIS", C_DROP)
        draw_hline(win, row_right, mid_x + 1, min(22, w - mid_x - 3), '─', curses.color_pair(C_DROP) | curses.A_DIM)
        row_right += 1
        
        status = xdp.get_attack_status()
        if status == "NORMAL":
            safe_addstr(win, row_right, mid_x + 2, "STATUS: ", curses.color_pair(C_INGRESS))
            safe_addstr(win, row_right, mid_x + 10, "NORMAL", curses.color_pair(C_INGRESS) | curses.A_BOLD)
        else:
            # Highlight the attack type
            parts = status.split("(", 1)
            main_status = parts[0].strip()
            type_info = parts[1].replace(")", "").strip() if len(parts) > 1 else ""
            
            safe_addstr(win, row_right, mid_x + 2, "STATUS: ", curses.color_pair(C_DROP))
            safe_addstr(win, row_right, mid_x + 10, main_status, curses.color_pair(C_DROP) | curses.A_BOLD)
            row_right += 1
            if type_info:
                safe_addstr(win, row_right, mid_x + 2, "TYPE:   ", curses.color_pair(C_WARN))
                safe_addstr(win, row_right, mid_x + 10, type_info, curses.color_pair(C_WARN) | curses.A_BOLD)
    row_right += 1

    # ── TOP TALKERS ───────────────────────────────────────────────────────
    row_left += 1
    if row_left < h - 7:
        row_left = draw_section_header(win, row_left, left_x, "🎯", "TOP TALKERS", C_WARN)
        draw_hline(win, row_left, left_x + 1, min(30, mid_x - left_x - 2), '─', curses.color_pair(C_WARN) | curses.A_DIM)
        row_left += 1
        
        top_ips = xdp.get_top_ips(5)
        if top_ips:
            for i, (ip, count, _) in enumerate(top_ips):
                if row_left >= h - 6:
                    break
                safe_addstr(win, row_left, left_x + 1, f"  {ip}", curses.color_pair(C_WARN) | curses.A_BOLD)
                safe_addstr(win, row_left, left_x + 18, fmt_num(count).rjust(12), curses.color_pair(C_WARN))
                row_left += 1
        else:
            safe_addstr(win, row_left, left_x + 2, "(none)", curses.color_pair(C_DIM) | curses.A_DIM)
            row_left += 1

    # ── AUTO-BLACKLIST ────────────────────────────────────────────────────
    row = max(row_left, row_right) + 1
    if row < h - 6:
        row = draw_section_header(win, row, left_x, "⚠ ", "AUTO-BLACKLISTED", C_BLACKLST)
        draw_hline(win, row, left_x + 1, min(30, w - 4), '─', curses.color_pair(C_BLACKLST) | curses.A_DIM)
        row += 1

        active_bl = {ip: info for ip, info in blacklist.items() if info.get("active", False)}
        if active_bl:
            for ip, info in active_bl.items():
                if row >= h - 5:
                    break
                ttl = info.get("remaining_seconds", 0)
                safe_addstr(win, row, left_x + 1, f"  {ip}", curses.color_pair(C_BLACKLST) | curses.A_BOLD)
                safe_addstr(win, row, left_x + 20, f"(expires in {ttl}s)", curses.color_pair(C_BLACKLST) | curses.A_DIM)
                row += 1
        else:
            safe_addstr(win, row, left_x + 2, "(none)", curses.color_pair(C_DIM) | curses.A_DIM)

    # ── Command bar separator ─────────────────────────────────────────────
    cmd_row = h - 5
    safe_addstr(win, cmd_row, 0, "├" + "─" * (w - 2) + "┤", border_attr)

    # ── Help Steps ────────────────────────────────────────────────────────
    help_row = h - 4
    safe_addstr(win, help_row, 0, "│", border_attr)
    safe_addstr(win, help_row, w - 1, "│", border_attr)
    help_str = " Actions: type 'block ip <addr>', 'unblock port <num>', or 'quit' below"
    safe_addstr(win, help_row, 2, help_str, curses.color_pair(C_DIM))

    # ── Feedback line ─────────────────────────────────────────────────────
    fb_row = h - 3
    safe_addstr(win, fb_row, 0, "│", border_attr)
    safe_addstr(win, fb_row, w - 1, "│", border_attr)

    if last_feedback and (time.time() - feedback_ts) < FEEDBACK_DURATION:
        fb_color = C_INGRESS if last_feedback.startswith("[+]") else C_DROP
        safe_addstr(win, fb_row, 2, last_feedback, curses.color_pair(fb_color))

    # ── Empty prompt line for input bar (so it doesn't flicker) ───────────
    safe_addstr(win, h - 2, 0, "│", border_attr)
    safe_addstr(win, h - 2, w - 1, "│", border_attr)

    # ── Bottom border ─────────────────────────────────────────────────────
    safe_addstr(win, h - 1, 0, "└" + "─" * (w - 2) + "┘", border_attr)
    creator_str = " Created by Vipin Singh Rana "
    safe_addstr(win, h - 1, w - len(creator_str) - 2, creator_str, curses.color_pair(C_DIM))

    win.noutrefresh()


# ─── Command processing ──────────────────────────────────────────────────────

def process_command(xdp: Any, cmd_str: str) -> str:
    """Process a user command. Returns a feedback message string."""
    parts = cmd_str.strip().lower().split()
    if not parts:
        return ""

    if parts[0] in ("quit", "q", "exit"):
        return "__QUIT__"

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
    if not xdp.start():
        curses.curs_set(0)
        stdscr.nodelay(False)
        stdscr.clear()
        stdscr.addstr(0, 0, f"[!] Failed to start XDP filter on '{device}'.")
        stdscr.addstr(1, 0, "    Make sure you're running as root and bcc is installed.")
        stdscr.addstr(2, 0, "    Press any key to exit.")
        stdscr.refresh()
        stdscr.nodelay(False)
        stdscr.getch()
        return

    input_buf: str = ""
    last_feedback: str = ""
    feedback_ts: float = 0.0
    last_draw: float = 0.0

    try:
        while True:
            now = time.time()

            # Redraw dashboard at REFRESH_INTERVAL
            if float(now) - float(last_draw) >= REFRESH_INTERVAL:
                draw_dashboard(stdscr, xdp, last_feedback, feedback_ts)
                draw_input_bar(stdscr, input_buf)
                curses.doupdate()
                last_draw = now

            # Non-blocking key read
            try:
                ch = stdscr.getch()
            except curses.error:
                ch = -1

            if ch == -1:
                # No input, continue to next frame. `halfdelay` already throttles the loop context
                continue

            # Handle resize
            if ch == curses.KEY_RESIZE:
                stdscr.clear()
                last_draw = 0  # force redraw
                continue

            # Enter key — execute command
            if ch in (curses.KEY_ENTER, 10, 13):
                if input_buf.strip():  # pyre-ignore[16]
                    fb: str = process_command(xdp, input_buf)
                    if fb == "__QUIT__":
                        break
                    last_feedback = fb
                    feedback_ts = time.time()
                input_buf = ""
                last_draw = 0  # force redraw
                continue

            # Backspace
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                input_buf = input_buf[:-1]  # pyre-ignore[29]
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
