<img alt="CAA34C68-2185-46F5-BA61-2F88DF8FEC73" src="https://github.com/user-attachments/assets/d56f9519-c044-4daf-a3f7-2de0f2e82a32" />

# SwissKnife 🧰

Wireless "swiss knife" that bundles multiple workflows into one menu-driven tool.
The main entry point is `swiss_knife.py`. Control the chaos with
[Lab5](https://github.com/C5Lab) (responsibly).

## Functions ✨

- Recon - passive discovery of nearby APs/clients
- Deauth - network deauthentication workflow
- Portal - phishing-style portal with logging
- Evil Twin - rogue AP + portal workflow
- ~~Handshaker - PCAP capture~~ (🚧 under construction 🚧)
- ~~DNS Sniff - local DNS traffic monitor~~ (🚧 under construction 🚧)
- ~~Karma - rogue AP auto-responder~~ (🚧 under construction 🚧)

## Quick start ⚡

```bash
git clone https://github.com/D3h420/SwissKnife
cd SwissKnife
sudo chmod +x swiss_knife.py
python3 swiss_knife.py
```

Run as root (required for wireless operations). The menu lets you choose which
attack to run and guides you through the steps.

## Logs and captures 🧾

Captive Portal and Evil Twin store captured submissions in `log/` (created on
first run). Filenames are based on the selected SSID.

## HTML customization 🎨

The portal page is plain HTML and easy to edit in `html/portal.html`. Everything
under `html/` is safe to modify for UI tweaks or branding.

## Requirements 🧩

Core:
- Python 3
- Linux with a wireless adapter that supports monitor mode
- Root privileges

Tools used by the modules:
- `iw`
- `ip` (from `iproute2`)
- `ethtool`
- `iwlist` (from `wireless-tools`)
- `aireplay-ng` (Aircrack-ng suite)
- `hostapd`
- `dnsmasq`
- `iptables`

Optional tools:
- `airodump-ng` (Aircrack-ng suite)
- `mdk4`
- `bully`

Optional for recon:
- `scapy` (required for Handshaker, optional for recon)

## Recon vendor lookup (optional)

If you want vendor names in recon results, add an OUI file at `modules/oui.txt`
or set `SWISSKNIFE_VENDOR_DB` to a custom path.

## Legal note ⚠️

Use only on networks you own or have explicit permission to test.
