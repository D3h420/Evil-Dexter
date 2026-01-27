#!/usr/bin/env python3
"""
DNS SNIFF - Monitor ruchu DNS w sieci lokalnej
Styl: SwissKnife/Captive Portal
Autor: D3h420
"""

import os
import sys
import time
import socket
import threading
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
import argparse

# Sprawdź zależności
try:
    from scapy.all import *
    from scapy.layers.dns import DNSQR, DNS
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    print("\n[!] Scapy nie jest zainstalowany!")
    print("[+] Instalacja: sudo pip3 install scapy")
    sys.exit(1)

class DNSSniff:
    def __init__(self):
        self.running = False
        self.interface = None
        self.monitor_thread = None
        self.arp_cache = {}
        self.dns_queries = []
        self.device_names = {}
        self.stats = Counter()
        self.filter_domains = ['local', 'lan', 'arpa', 'in-addr.arpa']
    
    def clear_screen(self):
        """Wyczyść ekran"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        """Wyświetl banner"""
        banner = """
        ╔══════════════════════════════════════════════════╗
        ║                 DNS SNIFF v1.0                    ║
        ║            Network DNS Traffic Monitor            ║
        ╚══════════════════════════════════════════════════╝
        """
        print(banner)
    
    def print_menu(self, title, options, current=None):
        """Wyświetl menu w stylu SwissKnife"""
        self.clear_screen()
        self.print_banner()
        
        print(f"\n{'='*55}")
        print(f" {title}")
        print('='*55)
        
        for i, (key, desc) in enumerate(options.items(), 1):
            prefix = ">>" if current == key else "  "
            print(f" {prefix} {i}. {desc}")
        
        print('='*55)
        return input("\n Wybierz opcję: ").strip()
    
    def get_interfaces(self):
        """Pobierz dostępne interfejsy sieciowe"""
        interfaces = []
        try:
            # Użyj iproute2
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if 'mtu' in line and 'state' in line:
                    iface = line.split(':')[1].strip()
                    if iface and not iface.startswith(('lo', 'docker', 'br-', 'veth')):
                        # Pobierz adres IP
                        ip_result = subprocess.run(['ip', '-4', 'addr', 'show', iface],
                                                 capture_output=True, text=True)
                        ip_info = ""
                        for ip_line in ip_result.stdout.split('\n'):
                            if 'inet ' in ip_line:
                                ip = ip_line.split()[1].split('/')[0]
                                ip_info = f" ({ip})"
                                break
                        
                        interfaces.append((iface, iface + ip_info))
            
            # Jeśli iproute2 nie działa, użyj ifconfig
            if not interfaces:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if not line.startswith(' ') and not line.startswith('\t') and ':' in line:
                        iface = line.split(':')[0]
                        if iface and not iface.startswith(('lo', 'docker')):
                            interfaces.append((iface, iface))
        
        except:
            pass
        
        return interfaces
    
    def scan_network(self, interface):
        """Skanuj sieć w poszukiwaniu aktywnych hostów"""
        print(f"\n[+] Skanowanie sieci na {interface}...")
        
        hosts = []
        try:
            # Pobierz adres sieci
            result = subprocess.run(['ip', '-4', 'addr', 'show', interface],
                                  capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    ip_with_mask = line.split()[1]
                    network_ip = ip_with_mask.split('/')[0]
                    prefix = ip_with_mask.split('/')[1]
                    
                    # Proste pingowanie
                    base_ip = '.'.join(network_ip.split('.')[:3])
                    
                    print(f"    Sieć: {base_ip}.0/{prefix}")
                    print("    Skanowanie aktywnych hostów...")
                    
                    # Skanuj pierwszych 20 adresów
                    for i in range(1, 21):
                        ip = f"{base_ip}.{i}"
                        try:
                            # ARP ping
                            packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
                            result = srp(packet, timeout=1, verbose=0, iface=interface)[0]
                            
                            if result:
                                mac = result[0][1].hwsrc
                                
                                # Spróbuj pobrać hostname
                                hostname = self.get_hostname(ip, mac)
                                hosts.append({
                                    'ip': ip,
                                    'mac': mac,
                                    'hostname': hostname
                                })
                                
                                print(f"    [+] {ip:15} - {hostname}")
                            
                        except:
                            continue
            
            print(f"\n[+] Znaleziono {len(hosts)} aktywnych hostów")
            return hosts
            
        except Exception as e:
            print(f"[!] Błąd skanowania: {e}")
            return []
    
    def get_hostname(self, ip, mac):
        """Pobierz hostname dla IP/MAC"""
        # Spróbuj DNS reverse lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname:
                return hostname.split('.')[0]
        except:
            pass
        
        # Spróbuj NetBIOS
        try:
            result = subprocess.run(['nmblookup', '-A', ip],
                                  capture_output=True, text=True, timeout=2)
            for line in result.stdout.split('\n'):
                if '<00>' in line and '<ACTIVE>' in line:
                    name = line.split()[0]
                    if name:
                        return name
        except:
            pass
        
        # Użyj ostatni oktet IP
        return f"Device_{ip.split('.')[-1]}"
    
    def start_dns_monitor(self):
        """Główna funkcja monitorowania DNS"""
        self.clear_screen()
        self.print_banner()
        
        print(f"\n{'='*55}")
        print(f" DNS MONITOR - Interfejs: {self.interface}")
        print('='*55)
        print("\n Nasłuchiwanie zapytań DNS...")
        print(" Naciśnij Enter aby zatrzymać\n")
        print('='*55)
        print("")
        
        # Uruchom wątek monitorujący
        self.running = True
        self.monitor_thread = threading.Thread(target=self._dns_sniffer, daemon=True)
        self.monitor_thread.start()
        
        # Czekaj na Enter
        input()
        self.running = False
        time.sleep(1)
        
        # Pokaż podsumowanie
        self.show_summary()
        
        input("\n Naciśnij Enter aby wrócić do menu...")
    
    def _dns_sniffer(self):
        """Funkcja sniffowania DNS"""
        try:
            # Filtr dla DNS (port 53)
            filter_str = "udp port 53"
            
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=filter_str,
                store=False,
                stop_filter=lambda x: not self.running
            )
            
        except Exception as e:
            print(f"[!] Błąd sniffowania: {e}")
    
    def _process_packet(self, packet):
        """Przetwarzaj przechwycone pakiety"""
        try:
            if packet.haslayer(DNSQR) and packet.haslayer(IP):
                if packet[DNS].qr == 0:  # Tylko zapytania
                    domain = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    src_ip = packet[IP].src
                    
                    # Pomiń niektóre domeny
                    if any(skip in domain.lower() for skip in self.filter_domains):
                        return
                    
                    # Pobierz nazwę urządzenia
                    device_name = self.device_names.get(src_ip)
                    if not device_name:
                        device_name = self.get_hostname(src_ip, "")
                        self.device_names[src_ip] = device_name
                    
                    # Zapisz zapytanie
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    self.dns_queries.append({
                        'time': timestamp,
                        'ip': src_ip,
                        'device': device_name,
                        'domain': domain
                    })
                    
                    # Aktualizuj statystyki
                    self.stats[device_name] += 1
                    
                    # Wyświetl w czasie rzeczywistym
                    print(f" [{timestamp}] {device_name:20} -> {domain}")
                    
        except:
            pass
    
    def show_summary(self):
        """Pokaż podsumowanie po zatrzymaniu"""
        self.clear_screen()
        self.print_banner()
        
        print(f"\n{'='*55}")
        print(f" PODSUMOWANIE")
        print('='*55)
        
        if not self.dns_queries:
            print("\n Brak przechwyconych zapytań DNS")
            return
        
        # Grupuj po urządzeniu
        device_data = defaultdict(list)
        for query in self.dns_queries:
            device_data[query['device']].append(query['domain'])
        
        # Wyświetl statystyki
        print(f"\n Przechwycone zapytania: {len(self.dns_queries)}")
        print(f" Aktywne urządzenia: {len(device_data)}")
        
        print(f"\n{'─'*55}")
        print(" RUCH DNS PODZIELONY NA URZĄDZENIA:")
        print('─'*55)
        
        for device, domains in sorted(device_data.items()):
            domain_counts = Counter(domains)
            top_domains = domain_counts.most_common(10)
            
            print(f"\n {device}:")
            print(f"   Zapytania: {len(domains)}")
            print(f"   Unikalne domeny: {len(set(domains))}")
            
            if top_domains:
                print(f"\n   Najczęstsze domeny:")
                for domain, count in top_domains[:5]:
                    print(f"     - {domain:<30} ({count}x)")
        
        # Zapisz do pliku
        self.save_log()
        
        print(f"\n{'='*55}")
        print(f" Log zapisany do: dns_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    def save_log(self):
        """Zapisz logi do pliku"""
        if not self.dns_queries:
            return
        
        filename = f"dns_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w') as f:
            f.write("DNS Sniff - Log zapytań DNS\n")
            f.write("="*60 + "\n\n")
            f.write(f"Czas rozpoczęcia: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Interfejs: {self.interface}\n")
            f.write(f"Łączna liczba zapytań: {len(self.dns_queries)}\n\n")
            
            # Grupuj chronologicznie
            for query in self.dns_queries:
                f.write(f"[{query['time']}] {query['device']:20} -> {query['domain']}\n")
            
            # Podsumowanie
            f.write("\n" + "="*60 + "\n")
            f.write("PODSUMOWANIE:\n")
            
            device_data = defaultdict(list)
            for query in self.dns_queries:
                device_data[query['device']].append(query['domain'])
            
            for device, domains in sorted(device_data.items()):
                f.write(f"\n{device}:\n")
                f.write(f"  Zapytania: {len(domains)}\n")
                
                unique = set(domains)
                f.write(f"  Unikalne domeny: {len(unique)}\n")
                
                if unique:
                    f.write("  Domeny:\n")
                    for domain in sorted(unique)[:20]:
                        f.write(f"    - {domain}\n")
        
        print(f"[+] Log zapisany do: {filename}")
    
    def run(self):
        """Główna pętla programu"""
        while True:
            # Główne menu
            options = {
                'scan': 'Skanuj sieć i wybierz interfejs',
                'manual': 'Ręczny wybór interfejsu',
                'monitor': 'Start monitoringu DNS',
                'summary': 'Pokaż ostatnie podsumowanie',
                'exit': 'Wyjdź'
            }
            
            choice = self.print_menu("GŁÓWNE MENU", options)
            
            if choice == '1':  # Skanuj sieć
                self.interface_selection_scan()
                
            elif choice == '2':  # Ręczny wybór
                self.interface_selection_manual()
                
            elif choice == '3':  # Start monitoringu
                if not self.interface:
                    print("\n[!] Najpierw wybierz interfejs!")
                    time.sleep(2)
                else:
                    self.start_dns_monitor()
                
            elif choice == '4':  # Podsumowanie
                if self.dns_queries:
                    self.show_summary()
                    input("\n Naciśnij Enter aby kontynuować...")
                else:
                    print("\n[!] Brak danych do wyświetlenia")
                    time.sleep(2)
                
            elif choice == '5':  # Wyjście
                print("\n[+] Do zobaczenia!")
                sys.exit(0)
    
    def interface_selection_scan(self):
        """Automatyczne skanowanie i wybór interfejsu"""
        interfaces = self.get_interfaces()
        
        if not interfaces:
            print("\n[!] Nie znaleziono interfejsów sieciowych")
            time.sleep(2)
            return
        
        self.clear_screen()
        self.print_banner()
        
        print(f"\n{'='*55}")
        print(" WYKRYTE INTERFEJSY SIECIOWE")
        print('='*55)
        
        for i, (iface, desc) in enumerate(interfaces, 1):
            print(f" {i}. {desc}")
        
        print('='*55)
        
        try:
            choice = int(input("\n Wybierz interfejs: ")) - 1
            if 0 <= choice < len(interfaces):
                self.interface = interfaces[choice][0]
                print(f"\n[+] Wybrano interfejs: {self.interface}")
                
                # Skanuj sieć
                hosts = self.scan_network(self.interface)
                if hosts:
                    print("\n[+] Przygotowano monitoring DNS")
                else:
                    print("\n[!] Uwaga: Nie znaleziono aktywnych hostów")
                
                time.sleep(2)
            else:
                print("[!] Nieprawidłowy wybór")
                time.sleep(1)
        except:
            print("[!] Nieprawidłowy wybór")
            time.sleep(1)
    
    def interface_selection_manual(self):
        """Ręczny wybór interfejsu"""
        self.clear_screen()
        self.print_banner()
        
        print(f"\n{'='*55}")
        print(" RĘCZNY WYBÓR INTERFEJSU")
        print('='*55)
        
        # Pokaż dostępne interfejsy
        result = subprocess.run(['ip', 'link', 'show'], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            print(result.stdout)
        else:
            print("[!] Nie można pobrać interfejsów")
        
        print('='*55)
        iface = input("\n Wpisz nazwę interfejsu (np. wlan0, eth0): ").strip()
        
        if iface:
            self.interface = iface
            print(f"\n[+] Ustawiono interfejs: {self.interface}")
            
            # Szybkie sprawdzenie czy interfejs istnieje
            try:
                result = subprocess.run(['ip', 'link', 'show', iface],
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    print("[!] Ostrzeżenie: Interfejs może nie istnieć")
            except:
                pass
            
            time.sleep(2)

def check_dependencies():
    """Sprawdź wymagane zależności"""
    missing = []
    
    # Sprawdź scapy
    try:
        import scapy
    except ImportError:
        missing.append("scapy")
    
    # Sprawdź czy jesteś root
    if os.geteuid() != 0:
        print("\n[!] TEN SKRYPT WYMAGA UPRAWNIEŃ ROOT!")
        print("[+] Uruchom: sudo python3 dns_sniff.py")
        sys.exit(1)
    
    return missing

def main():
    """Funkcja główna"""
    # Sprawdź zależności
    missing = check_dependencies()
    if missing:
        print(f"\n[!] Brakujące zależności: {', '.join(missing)}")
        print("[+] Instalacja: sudo pip3 install scapy")
        sys.exit(1)
    
    # Uruchom program
    app = DNSSniff()
    app.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[+] Zatrzymywanie...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Krytyczny błąd: {e}")
        sys.exit(1)