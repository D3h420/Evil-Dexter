#!/usr/bin/env python3

"""
Simple launcher that combines the existing attacks into one menu (Airgeddon style).
Each choice runs a separate script and returns to the menu when it exits.
"""

import os
import signal
import subprocess
import sys
from typing import Dict

COLOR_ENABLED = sys.stdout.isatty()
COLOR_RESET = "\033[0m" if COLOR_ENABLED else ""
COLOR_HEADER = "\033[36m" if COLOR_ENABLED else ""
COLOR_HIGHLIGHT = "\033[35m" if COLOR_ENABLED else ""
COLOR_SUCCESS = "\033[32m" if COLOR_ENABLED else ""
STYLE_BOLD = "\033[1m" if COLOR_ENABLED else ""


def color_text(text: str, color: str) -> str:
    return f"{color}{text}{COLOR_RESET}" if color else text


def style(text: str, *styles: str) -> str:
    prefix = "".join(s for s in styles if s)
    return f"{prefix}{text}{COLOR_RESET}" if prefix else text


ASCII_HEADER = r"""
   ___       __         __            __
  / _ )___  / /__ _____/ /_____ _____/ /__
 / _  / _ \/ / _ `/ __/  '_/ -_) __/  '_/
/____/\___/_/\_,_/\__/_/\_\\__/_/ /_/\_\

   WiFi Swiss Knife
"""

SCRIPT_MAP: Dict[str, Dict[str, str]] = {
    "1": {"name": "Deauth", "file": "deauth.py"},
    "2": {"name": "Portal", "file": "portal.py"},
    "3": {"name": "Evil Twin", "file": "twins.py"},
    "4": {"name": "Exit", "file": ""},
}


def base_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def script_path(filename: str) -> str:
    return os.path.join(base_dir(), filename)


def print_header() -> None:
    print(color_text(ASCII_HEADER, COLOR_HEADER))
    print(style("Choose an attack to run:", STYLE_BOLD))
    print()
    for key, meta in SCRIPT_MAP.items():
        label = f"[{key}] {meta['name']}"
        print(f"  {color_text(label, COLOR_HIGHLIGHT)}")
    print()


def run_child(script_file: str) -> None:
    abs_path = script_path(script_file)
    if not os.path.isfile(abs_path):
        print(color_text(f"File not found: {abs_path}", COLOR_HIGHLIGHT))
        return

    cmd = [sys.executable or "python3", abs_path]
    print(style(f"Starting {script_file}...\n", STYLE_BOLD))

    # Let the child handle its own Ctrl+C; the parent just waits.
    previous_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        subprocess.run(cmd)
    finally:
        signal.signal(signal.SIGINT, previous_handler)
    print(style("\nDone. Press Enter to return to the menu.", STYLE_BOLD))
    try:
        input()
    except EOFError:
        pass


def main() -> None:
    if os.geteuid() != 0:
        print(color_text("This launcher must be run as root.", COLOR_HIGHLIGHT))
        sys.exit(1)

    while True:
        print_header()
        choice = input(style("Your choice (1-4): ", STYLE_BOLD)).strip()

        if choice not in SCRIPT_MAP:
            print(color_text("Invalid choice, try again.\n", COLOR_HIGHLIGHT))
            continue

        if choice == "4":
            print(style("Exiting. See you!", COLOR_SUCCESS, STYLE_BOLD))
            break

        run_child(SCRIPT_MAP[choice]["file"])


if __name__ == "__main__":
    main()
