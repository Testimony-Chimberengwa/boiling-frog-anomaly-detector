#!/usr/bin/env python3
"""
汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇
                     🌀  DRIFT WATCH  —  ATTACK SIMULATOR                      
                          Slow & Low Intensity Attack Testbed                    
                                                                                
                          Testimony Chimberengwa R236592N                             
                          BSc Computer Engineering — Internship Project               
                                                                                
                     Three attack types — each targets a different HDT layer:         
                                                                                
                     [1] SLOW DATA EXFIL      →  triggers L3 LOWESS gradient         
                     [2] BASELINE POISONING   →  triggers ADS anchor divergence      
                     [3] RECON SWEEP          →  triggers L2 KDE density drift       
                                                                                
                     All traffic is real TCP on real ports — Wireshark-verifiable     
  汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇 汇
"""

import socket
import time
import random
import sys
import os
from datetime import datetime

TARGET_HOST = "127.0.0.1"
PORTS       = list(range(5001, 5011))

# ANSI Color escapes
RED     = "\033[31m"
YELLOW  = "\033[33m"
GREEN   = "\033[32m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"


def ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def fmt_bytes(n):
    if n >= 1_048_576:
        return f"{n/1_048_576:.2f} MB"
    if n >= 1024:
        return f"{n/1024:.1f} KB"
    return f"{n} B"

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def divider(char="─", width=74):
    print(f"  {char*width}")

def send(port, payload: bytes, label: str) -> bool:
    """Open a real TCP connection, send payload, close. Returns success."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((TARGET_HOST, port))
        s.sendall(payload)
        try:
            s.recv(256)
        except Exception:
            pass
        s.close()
        print(f"  {GREEN}▶{RESET}  [{ts()}]  port {BOLD}{port}{RESET}  "
              f"│  {CYAN}{fmt_bytes(len(payload))}{RESET}  │  {DIM}{label}{RESET}")
        return True
    except ConnectionRefusedError:
        print(f"  {RED}✖{RESET}  port {port} refused — is the listener running?")
        return False
    except Exception as e:
        print(f"  {RED}✖{RESET}  port {port} error: {e}")
        return False

def countdown(secs, label="Next round in"):
    for i in range(secs, 0, -1):
        print(f"  {DIM}  {label} {i:2d}s …{RESET}", end="\r")
        time.sleep(1)
    print(" " * 40, end="\r")

def wait_for_enter(prompt=""):
    input(f"\n  {YELLOW}{BOLD}▶  {prompt}Press ENTER to begin …{RESET}\n")


def attack_banner(title, target_layer, strategy, colour=RED):
    divider("═")
    print(f"\n  {colour}{BOLD}  ⚑  {title}{RESET}")
    print(f"  {DIM}  Target layer : {target_layer}{RESET}")
    print(f"  {DIM}  Strategy     : {strategy}{RESET}\n")
    divider()


def attack_slow_exfil(rounds=6, start_mb=1, interval_secs=8):
    attack_banner(
        "ATTACK 1 OF 3  —  SLOW DATA EXFILTRATION",
        "L3 LOWESS  (rising upload-byte-ratio gradient)",
        f"Escalating volume: {start_mb} MB → {start_mb+rounds-1} MB  |  "
        f"{interval_secs}s gaps between rounds",
        colour=RED,
    )

    total_sent = 0
    for i in range(rounds):
        mb         = start_mb + i
        chunk_size = mb * 1024 * 1024
        port       = random.choice(PORTS)

        header  = (
            f"EXFIL|ROUND={i+1}|SIZE={mb}MB|TS={ts()}|"
            f"RISING-VOLUME|SESSION=0xBF{i:02X}|"
        ).encode()
        body    = bytes([random.randint(0x20, 0x7E) for _ in range(chunk_size - len(header))])
        payload = header + body

        print(f"\n  {RED}Round {i+1}/{rounds}{RESET}  —  sending {BOLD}{mb} MB{RESET}  on port {port}")
        ok = send(port, payload, f"exfil round {i+1}  ({mb} MB)")

        if ok:
            total_sent += chunk_size
            bar_width   = 20
            filled      = int(((i + 1) / rounds) * bar_width)
            prog_bar    = f"{RED}{'█'*filled}{'░'*(bar_width-filled)}{RESET}"
            print(f"  {'':5}  Progress : {prog_bar}  {i+1}/{rounds} rounds")
            print(f"  {'':5}  Sent so far : {CYAN}{fmt_bytes(total_sent)}{RESET}")

        if i < rounds - 1:
            print(f"  {DIM}  ↺  Waiting {interval_secs}s — staying below threshold …{RESET}")
            countdown(interval_secs)

    divider()
    print(f"\n  {GREEN}✔{RESET}  Exfil complete.  Total sent: {CYAN}{fmt_bytes(total_sent)}{RESET}")
    print(f"  {DIM}  Watch the listener: L3 LOWESS slope should be climbing ↗{RESET}\n")
    divider("═")


def attack_baseline_poison(rounds=12, base_kb=64, interval_secs=5):
    attack_banner(
        "ATTACK 2 OF 3  —  BASELINE POISONING  (GMM Re-baselining)",
        "ADS Sentinel  (μk divergence from anchor)  +  L1 GMM",
        f"{rounds} rounds  |  base {base_kb} KB/packet  |  +5% size per round  |  "
        f"~{interval_secs}s intervals with APT jitter",
        colour=MAGENTA,
    )

    for i in range(rounds):
        port     = PORTS[i % len(PORTS)]
        size     = int(base_kb * 1024 * (1 + i * 0.05))
        drift_pct = i * 5

        header  = (
            f"POISON|ROUND={i+1}|TS={ts()}|"
            f"DRIFT=+{drift_pct}%|SIZE={size//1024}KB|"
        ).encode()
        padding = b"\xAB" * (size - len(header))
        payload = header + padding

        print(f"\n  {MAGENTA}Round {i+1}/{rounds}{RESET}  "
              f"port {port}  │  {fmt_bytes(size)}  │  "
              f"cumulative drift injection {BOLD}+{drift_pct}%{RESET}")
        send(port, payload, f"poison round {i+1}  (drift +{drift_pct}%)")

        if i < rounds - 1:
            jitter     = random.uniform(-1.5, 1.5)
            sleep_time = max(1.0, interval_secs + jitter)
            print(f"  {DIM}  ↺  Sleeping {sleep_time:.1f}s (APT jitter ±1.5s) …{RESET}")
            countdown(int(sleep_time))

    divider()
    print(f"\n  {GREEN}✔{RESET}  Baseline poisoning complete.")
    print(f"  {DIM}  Watch the listener: ADS drift score rising, "
          f"GMM anchor divergence warning{RESET}\n")
    divider("═")


def attack_slow_recon(passes=2, interval_secs=6):
    total_touches = len(PORTS) * passes
    attack_banner(
        "ATTACK 3 OF 3  —  ULTRA-SLOW RECONNAISSANCE SWEEP",
        "L2 KDE  (connection diversity drift into low-density space)",
        f"{passes} passes across all {len(PORTS)} ports  │  "
        f"{interval_secs}s between touches  │  "
        f"~{total_touches * interval_secs}s total",
        colour=YELLOW,
    )

    for p in range(passes):
        print(f"\n  {YELLOW}Pass {p+1}/{passes}{RESET}  —  sweeping ports {PORTS[0]}→{PORTS[-1]}\n")
        for port in PORTS:
            probe   = (
                f"RECON|PASS={p+1}|PORT={port}|TS={ts()}|"
                f"AGENT=APT-SIM|INTENT=PROFILE|SWEEP=HORIZONTAL\r\n"
            ).encode()
            send(port, probe, f"recon pass {p+1}  sweep touch")
            jitter     = random.uniform(-1.0, 1.0)
            sleep_time = max(0.5, interval_secs + jitter)
            countdown(int(sleep_time), label=f"  Next port in")

        if p < passes - 1:
            pause = random.uniform(12, 20)
            print(f"\n  {DIM}  ↺  Pausing {pause:.0f}s between passes "
                  f"(mimics APT patience) …{RESET}")
            countdown(int(pause), label="Next pass in")

    divider()
    print(f"\n  {GREEN}✔{RESET}  Recon sweep complete.")
    print(f"  {DIM}  Watch the listener: L2 KDE density score rising "
          f"as port diversity accumulates{RESET}\n")
    divider("═")


def print_menu():
    clear()
    print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    🌀  DRIFT WATCH  —  ATTACK SIMULATOR                                    ║
║        Slow & Low Intensity Attack Testbed                                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{RESET}

  {BOLD}Select an attack to launch:{RESET}

  {RED}[1]{RESET}  Slow Data Exfiltration     — escalating MB  →  triggers L3 LOWESS
  {MAGENTA}[2]{RESET}  Baseline Poisoning         — GMM re-baselining  →  triggers ADS
  {YELLOW}[3]{RESET}  Ultra-Slow Recon Sweep     — port diversity  →  triggers L2 KDE

  {DIM}[q]{RESET}  Quit

  {DIM}Target: {TARGET_HOST}   Ports: {PORTS[0]}–{PORTS[-1]}{RESET}
""")
    divider()
    return input(f"\n  {BOLD}Select [1 / 2 / 3 / q] :{RESET}  ").strip().lower()


def main():
    try:
        t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.settimeout(2)
        t.connect((TARGET_HOST, 5001))
        t.close()
    except ConnectionRefusedError:
        print(f"\n  {RED}✖  Cannot reach {TARGET_HOST}:5001{RESET}")
        print(f"  Make sure drift_watch_listener.py is running first.\n")
        sys.exit(1)
    except Exception:
        pass

    while True:
        choice = print_menu()

        if choice == "1":
            wait_for_enter("Ready to launch SLOW EXFIL? ")
            attack_slow_exfil()
            input(f"\n  {DIM}Press ENTER to return to menu …{RESET}")

        elif choice == "2":
            wait_for_enter("Ready to launch BASELINE POISONING? ")
            attack_baseline_poison()
            input(f"\n  {DIM}Press ENTER to return to menu …{RESET}")

        elif choice == "3":
            wait_for_enter("Ready to launch RECON SWEEP? ")
            attack_slow_recon()
            input(f"\n  {DIM}Press ENTER to return to menu …{RESET}")

        elif choice == "q":
            print(f"\n  {DIM}Exiting attacker.{RESET}\n")
            sys.exit(0)

        else:
            print(f"  {RED}Invalid choice.{RESET}")
            time.sleep(1)


if __name__ == "__main__":
    main()
