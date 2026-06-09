#!/usr/bin/env python3
"""DRIFT WATCH — HDT Live Detection Monitor with socket/promiscuous modes."""

import socket
import threading
import time
import os
import sys
import ctypes
import string
from collections import deque, defaultdict
from datetime import datetime

# Import our real algorithm engine
try:
    from hdt_engine import (
        ConnectionRecord, EntityRegistry,
        threat_bar, sparkline, alert_badge,
        THRESH_LOW, THRESH_MEDIUM, THRESH_HIGH,
        RESET, BOLD,
    )
except ImportError:
    print("\n  ERROR: hdt_engine.py not found in the same directory.")
    print("  Make sure hdt_engine.py is in the same folder as this script.\n")
    sys.exit(1)

HOST = "0.0.0.0"
PORTS = list(range(5001, 5011))
BANNER_DONE = threading.Event()
ACTIVE_MODE = "SOCKET LISTENERS"
SCAPY_INTERFACE = r"\Device\NPF_Loopback" if os.name == "nt" else "lo"
CAPTURE_FILTER = "tcp and portrange 5001-5010"

RED = "\033[91m"; YELLOW = "\033[93m"; GREEN = "\033[92m"; CYAN = "\033[96m"
MAGENTA = "\033[95m"; WHITE = "\033[97m"; DIM = "\033[2m"; RESET = "\033[0m"
BOLD = "\033[1m"; BLINK = "\033[5m"

HDT_TYPES = {"SLOW-EXFIL", "BASELINE-POISON", "RECON-SWEEP"}
TOOL_TYPES = {"NMAP-SWEEP", "CURL-HTTP", "NETCAT-MANUAL", "BROWSER-HTTP", "PYTHON-SOCKET", "PORT-HAMMER"}
ALERT_ORDER = {"MONITORING": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

registry = EntityRegistry()
state_lock = threading.RLock()
ip_byte_totals = defaultdict(int)
ip_conn_counts = defaultdict(int)
ip_port_sets = defaultdict(set)
ip_vol_history = defaultdict(lambda: deque(maxlen=15))
ip_alert_level = defaultdict(lambda: "MONITORING")
ip_last_seen = defaultdict(float)
ip_attack_types = defaultdict(set)
ip_hdt_types = defaultdict(set)
ip_tool_types = defaultdict(set)
ip_recent_ports = defaultdict(lambda: deque(maxlen=100))
ip_port_hits = defaultdict(lambda: deque(maxlen=100))
seen_scapy_packets = set()
total_connections = 0
total_bytes = 0
start_time = time.time()
alert_counts = {"MONITORING": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}


def enable_ansi():
    """Enable ANSI escape sequences in Windows CMD so colours do not print raw."""
    if os.name == "nt":
        os.system("color")
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


def ts(): return datetime.now().strftime("%H:%M:%S.%f")[:-3]
def fmt_bytes(n):
    if n >= 1_048_576: return f"{n/1_048_576:.2f} MB"
    if n >= 1024: return f"{n/1014:.1f} KB"
    return f"{n} B"
def uptime():
    s = int(time.time() - start_time)
    return f"{s//60:02d}:{s%60:02d}"
def term_width(default=100):
    try: return max(80, os.get_terminal_size().columns)
    except OSError: return default

def alert_colour(level):
    return {"HIGH": RED, "MEDIUM": YELLOW, "LOW": YELLOW, "MONITORING": GREEN}.get(level, GREEN)

def type_style(t):
    if t in HDT_TYPES: return RED, "⚑"
    if t in TOOL_TYPES: return CYAN, "◈"
    return WHITE, " "

def is_printable_ascii(data: bytes) -> bool:
    return bool(data) and all(b in set(bytes(string.printable, "ascii")) for b in data)


def classify_payload(data: bytes, src_ip=None, dst_port=None, src_port=None, now=None) -> str:
    """Classify HDT simulator traffic plus independent tools such as nmap/curl/netcat/browser."""
    now = now or time.time(); raw = data or b""; size = len(raw)
    try:
        text = raw[:4096].decode(errors="replace"); upper = text.upper(); lower = text.lower()
    except Exception:
        upper = ""; lower = ""

    # Preserve existing HDT attacker-script classification first.
    if "EXFIL" in upper: return "SLOW-EXFIL"
    if "POISON" in upper: return "BASELINE-POISON"
    if "RECON" in upper or "SWEEP" in upper or "PROBE" in upper: return "RECON-SWEEP"

    # Behavioural external-tool classification.
    if src_ip is not None and dst_port is not None:
        hits = ip_port_hits[src_ip]; recent = ip_recent_ports[src_ip]
        while hits and now - hits[0][0] > 20: hits.popleft()
        while recent and now - recent[0][0] > 30: recent.popleft()
        if sum(1 for _, p in hits if p == dst_port) > 5: return "PORT-HAMMER"
        if size < 100 and len({p for _, p, b in recent if b < 100} | {dst_port}) >= 3: return "NMAP-SWEEP"

    # Payload-based external-tool classification.
    if "USER-AGENT:" in upper: return "BROWSER-HTTP"
    if "python" in lower or "urllib" in lower: return "PYTHON-SOCKET"
    if upper.startswith(("GET ", "POST ", "PUT ", "HEAD ", "HTTP/")): return "CURL-HTTP"
    if 0 < size < 10 * 1024 and is_printable_ascii(raw): return "NETCAT-MANUAL"
    return "UNKNOWN"


def bar(score, width=24):
    score = max(0.0, min(1.0, float(score)))
    filled = int(round(score * width))
    return "█" * filled + "░" * (width - filled)

def highest_alert_level():
    level = "MONITORING"
    for val in ip_alert_level.values():
        if ALERT_ORDER[val] > ALERT_ORDER[level]: level = val
    return level

def layer_line(label, score):
    c = RED + BOLD + BLINK if score >= 0.75 else (YELLOW if score >= 0.35 else GREEN)
    return f"║   {label:<11} {score:>6.3f}  {c}{bar(score)}{RESET}   ║"


def ask_capture_mode():
    global ACTIVE_MODE
    print(f"""
{GREEN}{BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                         🌀 DRIFT WATCH STARTUP                             ║
╚══════════════════════════════════════════════════════════════════════════════╝{RESET}

{BOLD}Run in promiscuous mode?{RESET} {DIM}(captures ALL traffic like Wireshark){RESET}

  {CYAN}[Y]{RESET} Yes — full interface capture
  {GREEN}[N]{RESET} No  — port listeners only {DIM}(default){RESET}
""")
    choice = input(f"  Select [{CYAN}Y{RESET}/{GREEN}N{RESET}] : ").strip().lower()
    ACTIVE_MODE = "PROMISCUOUS CAPTURE" if choice == "y" else "SOCKET LISTENERS"
    return "promiscuous" if choice == "y" else "socket"


def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    mode_colour = CYAN if ACTIVE_MODE == "PROMISCUOUS CAPTURE" else GREEN
    print(f"""
{GREEN}{BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  BBBBB    OOO   III  L      III  N   N   GGG      FFFFF RRRR   OOO   GGG    ║
║  B    B  O   O   I   L       I   NN  N  G         F     R   R O   O G       ║
║  BBBBB   O   O   I   L       I   N N N  G  GG     FFFF  RRRR  O   O G  GG   ║
║  B    B  O   O   I   L       I   N  NN  G   G     F     R  R  O   O G   G   ║
║  BBBBB    OOO   III  LLLLL  III  N   N   GGG      F     R   R  OOO   GGG    ║
║                                                                              ║
║                 HYBRID DETECTION TAPESTRY — LIVE MONITOR                    ║
║                                                                              ║
║  MODE: {mode_colour}{ACTIVE_MODE:<25}{GREEN}{BOLD} PORTS: 5001–5010                    ║
║                                                                              ║
║  ┌─ ALGORITHM STACK ─────────────────────────────────────────────────────┐   ║
║  │ {GREEN}●{RESET}{GREEN}{BOLD} L1 Adaptive GMM      byte-volume baseline                  {GREEN}{BOLD}│   ║
║  │ {GREEN}●{RESET}{GREEN}{BOLD} L2 Global KDE        low-density feature-space detection   {GREEN}{BOLD}│   ║
║  │ {GREEN}●{RESET}{GREEN}{BOLD} L3 LOWESS Trend      slow rising-gradient analysis         {GREEN}{BOLD}│   ║
║  │ {GREEN}●{RESET}{GREEN}{BOLD} ADS Drift Sentinel   anchor divergence / poisoning guard   {GREEN}{BOLD}│   ║
║  └───────────────────────────────────────────────────────────────────────┘   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{RESET}
""")


def print_startup_status():
    print(f"  {GREEN}●{RESET}  Active mode                 {BOLD}{ACTIVE_MODE}{RESET}")
    print(f"  {GREEN}●{RESET}  HDT Engine loaded           {BOLD}GMM + KDE + LOWESS + ADS{RESET}")
    print(f"  {GREEN}●{RESET}  Capture filter              {BOLD}{CAPTURE_FILTER}{RESET}")
    print(f"  {GREEN}●{RESET}  Baseline building           {BOLD}anchor sets after 10 observations{RESET}")
    print(f"\n  {DIM}Waiting for traffic …{RESET}\n")
    print("  " + "─" * 74)


def report_to_web_dashboard(src_ip, src_port, dst_port, byte_count, payload_label):
    """Pipes python network packet captures to our React live telemetry dashboard!"""
    import urllib.request
    import json
    try:
        url = "http://localhost:3000/api/observations"
        data = json.dumps({
            "srcIp": str(src_ip),
            "srcPort": int(src_port or 0),
            "dstPort": int(dst_port or 0),
            "byteCount": int(byte_count),
            "payloadLabel": str(payload_label)
        }).encode("utf-8")
        
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        # Fast 0.5s timeout to ensure CLI never blocks
        with urllib.request.urlopen(req, timeout=0.5):
            pass
    except Exception:
        pass


def display_connection(conn, scores, engine, attack_type):
    ac = alert_colour(scores.alert); type_colour, symbol = type_style(attack_type); width = 94
    if scores.alert == "HIGH":
        print(f"\n{RED}{BOLD}" + "█" * term_width(width) + RESET)
        print(f"{RED}{BOLD}█  HIGH ALERT — DRIFT WATCH DETECTION THRESHOLD REACHED".ljust(term_width(width)-5) + f"█{RESET}")
        print(f"{RED}{BOLD}" + "█" * term_width(width) + RESET)

    print(f"\n{ac}{BOLD}╔" + "═" * width + f"╗{RESET}")
    print(f"{ac}{BOLD}║{RESET} {BOLD}{ts()}  INBOUND DETECTION EVENT{RESET}".ljust(width + 10) + f"{ac}{BOLD}║{RESET}")
    print(f"{ac}{BOLD}║{RESET} Source: {CYAN}{conn.src_ip}:{conn.src_port}{RESET}  →  Port: {BOLD}{conn.dst_port}{RESET}  Bytes: {BOLD}{fmt_bytes(conn.byte_count)}{RESET}".ljust(width + 18) + f"{ac}{BOLD}║{RESET}")
    print(f"{ac}{BOLD}║{RESET} Traffic: {type_colour}{BOLD}{symbol} {attack_type}{RESET}  Mode: {BOLD}{ACTIVE_MODE}{RESET}".ljust(width + 22) + f"{ac}{BOLD}║{RESET}")
    print(f"{ac}{BOLD}╠" + "═" * width + f"╣{RESET}")
    print(layer_line("L1 GMM", scores.l1_gmm)); print(layer_line("L2 KDE", scores.l2_kde))
    print(layer_line("L3 LOWESS", scores.l3_lowess)); print(layer_line("ADS", scores.ads))
    print(f"{ac}{BOLD}╠" + "═" * width + f"╣{RESET}")
    print(f"{ac}{BOLD}║{RESET} {BOLD}FUSION{RESET}      {scores.fusion:>6.3f}  {alert_colour(scores.alert)}{bar(scores.fusion)}{RESET}   ALERT: {ac}{BOLD}[ {scores.alert:^12} ]{RESET}".ljust(width + 22) + f"{ac}{BOLD}║{RESET}")
    print(f"{ac}{BOLD}║{RESET} Observations: #{scores.obs_count:<4}  Baseline: {GREEN + 'anchor ✔' + RESET if engine.is_anchored else YELLOW + 'building baseline …' + RESET}".ljust(width + 18) + f"{ac}{BOLD}║{RESET}")
    if abs(engine.lowess_slope) > 1000:
        direction = "↗ RISING" if engine.lowess_slope > 0 else "↘ FALLING"; slope_col = RED if engine.lowess_slope > 0 else GREEN
        print(f"{ac}{BOLD}║{RESET} LOWESS slope: {slope_col}{engine.lowess_slope:+,.0f} bytes/obs  {direction}{RESET}".ljust(width + 18) + f"{ac}{BOLD}║{RESET}")
    if engine.is_anchored and engine.gmm_drift > 0.05:
        drift_col = RED if engine.gmm_drift > 0.3 else YELLOW; msg = "⚠ BASELINE COMPROMISED" if engine.gmm_drift > 0.3 else "within tolerance"
        print(f"{ac}{BOLD}║{RESET} GMM drift from anchor: {drift_col}{engine.gmm_drift:.4f}  {msg}{RESET}".ljust(width + 18) + f"{ac}{BOLD}║{RESET}")
    with state_lock:
        hist = list(ip_vol_history[conn.src_ip])
        status = f"uptime {uptime()} | conns {total_connections} | bytes {fmt_bytes(total_bytes)} | IPs {len(ip_byte_totals)} | highest {highest_alert_level()}"
    if len(hist) >= 3:
        print(f"{ac}{BOLD}║{RESET} Volume trend: {CYAN}{sparkline(hist, width=12)}{RESET}  last {len(hist)} connections".ljust(width + 18) + f"{ac}{BOLD}║{RESET}")
    print(f"{ac}{BOLD}╠" + "═" * width + f"╣{RESET}")
    print(f"{ac}{BOLD}║{RESET} STATUS: {alert_colour(highest_alert_level())}{status}{RESET}".ljust(width + 18) + f"{ac}{BOLD}║{RESET}")
    print(f"{ac}{BOLD}╚" + "═" * width + f"╝{RESET}")
    if scores.alert == "HIGH": print(f"{RED}{BOLD}" + "█" * term_width(width) + RESET)


def process_observation(src_ip, src_port, dst_port, payload_bytes):
    global total_connections, total_bytes
    now = time.time(); payload_bytes = payload_bytes or b""
    with state_lock:
        ip_port_hits[src_ip].append((now, dst_port)); ip_recent_ports[src_ip].append((now, dst_port, len(payload_bytes)))
        attack_type = classify_payload(payload_bytes, src_ip=src_ip, dst_port=dst_port, src_port=src_port, now=now)
        conn = ConnectionRecord(src_ip=src_ip, src_port=int(src_port or 0), dst_port=int(dst_port or 0), byte_count=len(payload_bytes), timestamp=now, payload_label=attack_type)
        engine, scores = registry.evaluate(conn)
        total_connections += 1; total_bytes += conn.byte_count; alert_counts[scores.alert] += 1
        ip_byte_totals[src_ip] += conn.byte_count; ip_conn_counts[src_ip] += 1; ip_port_sets[src_ip].add(conn.dst_port)
        ip_vol_history[src_ip].append(conn.byte_count); ip_alert_level[src_ip] = scores.alert; ip_last_seen[src_ip] = now
        ip_attack_types[src_ip].add(attack_type)
        if attack_type in HDT_TYPES: ip_hdt_types[src_ip].add(attack_type)
        elif attack_type in TOOL_TYPES: ip_tool_types[src_ip].add(attack_type)
    
    # 🌟 CORE ACTION: Print to screen AND forward payload to React dashboard
    display_connection(conn, scores, engine, attack_type)
    
    # Fire off webhook to React dev server non-blocking
    threading.Thread(
        target=report_to_web_dashboard, 
        args=(src_ip, src_port, dst_port, len(payload_bytes), attack_type), 
        daemon=True
    ).start()


def summary_row(ip, types_filter):
    types_seen = sorted(t for t in ip_attack_types[ip] if t in types_filter)
    if not types_seen: return None
    ports = ",".join(str(p) for p in sorted(ip_port_sets[ip])) or "-"
    return f"  {ip:<15} ports [{ports:<24}] bytes {fmt_bytes(ip_byte_totals[ip]):>10}  types {', '.join(types_seen):<45} alert {alert_colour(ip_alert_level[ip])}{ip_alert_level[ip]}{RESET}"

def print_summary_section(title, types_filter):
    print(f"\n  {BOLD}{title}{RESET}"); printed = False
    for ip in sorted(ip_byte_totals.keys()):
        row = summary_row(ip, types_filter)
        if row: print(row); printed = True
    if not printed: print(f"  {DIM}(no events yet){RESET}")

def rolling_summary():
    while True:
        time.sleep(30)
        with state_lock:
            if total_connections == 0: continue
            ac = dict(alert_counts)
            print(f"\n{BOLD}{CYAN}╔" + "═" * 92 + f"╗{RESET}")
            print(f"{BOLD}{CYAN}║ ROLLING SUMMARY  uptime {uptime()} | conns {total_connections} | bytes {fmt_bytes(total_bytes)} | IPs {len(ip_byte_totals)}".ljust(110) + f"║{RESET}")
            print(f"{BOLD}{CYAN}╚" + "═" * 92 + f"╝{RESET}")
            print(f"  Alerts: MONITORING={ac['MONITORING']} LOW={ac['LOW']} MEDIUM={ac['MEDIUM']} HIGH={ac['HIGH']}")
            print_summary_section("── HDT ATTACK TRAFFIC ──────────────────────────────", HDT_TYPES)
            print_summary_section("── INDEPENDENT TOOL TRAFFIC ────────────────────────", TOOL_TYPES)
            print("  " + "─" * 92)


def final_report():
    print(f"\n\n {BOLD}{'═' * 76}{RESET}")
    print(f" {BOLD}◈ DRIFT WATCH — SESSION REPORT ◈{RESET}")
    print(f" {'═' * 76}")
    print(f" Session uptime      : {uptime()}")
    print(f" Active mode         : {ACTIVE_MODE}")
    print(f" Total connections   : {total_connections}")
    print(f" Total bytes seen    : {fmt_bytes(total_bytes)}")
    print(f" Unique source IPs   : {len(ip_byte_totals)}")
    print_summary_section("── HDT ATTACK TRAFFIC ──────────────────────────────", HDT_TYPES)
    print_summary_section("── INDEPENDENT TOOL TRAFFIC ────────────────────────", TOOL_TYPES)
    print(f" {'═' * 76}\n")


def handle_connection(conn_sock, addr, dst_port):
    try:
        conn_sock.settimeout(2); chunks = []
        while True:
            try:
                chunk = conn_sock.recv(65536)
                if not chunk: break
                chunks.append(chunk)
            except socket.timeout: break
        process_observation(addr[0], addr[1], dst_port, b"".join(chunks))
        try: conn_sock.sendall(b"HDT monitor received\n")
        except Exception: pass
    except Exception as e:
        print(f"  {RED}✖ connection handler error:{RESET} {e}")
    finally:
        try: conn_sock.close()
        except Exception: pass


def listen_on_port(port, ready_event):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try: srv.bind((HOST, port))
    except OSError as e:
        print(f"  {RED}✖ Could not bind port {port}:{RESET} {e}"); ready_event.set(); return
    srv.listen(20); ready_event.set()
    while True:
        try:
            conn_sock, addr = srv.accept()
            threading.Thread(target=handle_connection, args=(conn_sock, addr, port), daemon=True).start()
        except Exception as e: print(f"  {RED}✖ listener error on port {port}:{RESET} {e}")


def start_socket_mode():
    ready_events = []
    for port in PORTS:
        ev = threading.Event(); ready_events.append(ev)
        threading.Thread(target=listen_on_port, args=(port, ev), daemon=True).start()
    for ev in ready_events: ev.wait(timeout=2)
    print_startup_status()


# TCP stream reassembly buffer for promiscuous mode
# key = (src_ip, sport, dport) → accumulated payload bytes
_stream_buf = {}
_stream_lock = threading.Lock()

def scapy_packet_handler(pkt):
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Raw
        if IP not in pkt or TCP not in pkt: return
        ip = pkt[IP]; tcp = pkt[TCP]
        sport, dport = int(tcp.sport), int(tcp.dport)

        # Only care about packets where the DESTINATION is one of our ports
        if dport not in PORTS: return

        flags = tcp.flags
        payload = bytes(pkt[Raw].load) if Raw in pkt else b""

        # Dedup by (seq, sport, dport, payload_len) — ignore pure ACKs
        sig = (int(tcp.seq), sport, dport, len(payload))
        with _stream_lock:
            if sig in seen_scapy_packets: return
            seen_scapy_packets.add(sig)
            if len(seen_scapy_packets) > 8000: seen_scapy_packets.clear()

        stream_key = (ip.src, sport, dport)

        with _stream_lock:
            if payload:
                _stream_buf[stream_key] = _stream_buf.get(stream_key, b"") + payload

            fin_rst = bool(flags & 0x01) or bool(flags & 0x04)  # FIN=0x01, RST=0x04
            accumulated = _stream_buf.get(stream_key, b"")

            should_score = False
            if fin_rst and accumulated:
                should_score = True
            elif payload and len(accumulated) >= 86:
                should_score = True

            if should_score:
                final_payload = accumulated
                if fin_rst:
                    _stream_buf.pop(stream_key, None)
                process_observation(ip.src, sport, dport, final_payload)

    except Exception as e:
        print(f"  {RED}✖ scapy packet handler error:{RESET} {e}")


def start_promiscuous_mode():
    global ACTIVE_MODE
    try:
        from scapy.all import sniff, conf
    except Exception:
        print(f"\n  {YELLOW}⚠ Scapy is not installed. Falling back to socket listener mode.{RESET}")
        print("  Install with:  pip install scapy")
        ACTIVE_MODE = "SOCKET LISTENERS"; start_socket_mode(); return
    try:
        if os.name == "nt": conf.use_pcap = True
        print_startup_status()
        print(f"  {CYAN}●{RESET}  Scapy interface            {BOLD}{SCAPY_INTERFACE}{RESET}")
        print(f"  {CYAN}●{RESET}  If capture fails on Windows, install/reinstall {BOLD}Npcap with loopback support{RESET}.\n")
        def sniff_worker():
            global ACTIVE_MODE
            try:
                sniff(iface=SCAPY_INTERFACE, filter=CAPTURE_FILTER, prn=scapy_packet_handler, store=False)
            except Exception as e:
                print(f"\n  {YELLOW}⚠ Promiscuous capture stopped/could not start: {e}{RESET}")
                print("  Falls back to socket listener mode.\n")
                ACTIVE_MODE = "SOCKET LISTENERS"; start_socket_mode()
        threading.Thread(target=sniff_worker, daemon=True).start()
    except Exception as e:
        print(f"\n  {YELLOW}⚠ Promiscuous capture could not start: {e}{RESET}")
        print("  Falling back to socket listener mode.\n")
        ACTIVE_MODE = "SOCKET LISTENERS"; start_socket_mode()


def main():
    enable_ansi()
    mode = ask_capture_mode()
    print_banner()
    threading.Thread(target=rolling_summary, daemon=True).start()
    if mode == "promiscuous": start_promiscuous_mode()
    else: start_socket_mode()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        final_report()


if __name__ == "__main__":
    main()
