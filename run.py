#!/usr/bin/env python3
"""
Single-command launcher script for the Zero-Knowledge Encrypted File Sharing System.
Installs dependencies, initializes storage, starts the FastAPI server, and opens the UI.
"""

import os
import sys
import subprocess
import webbrowser
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
REQUIREMENTS_FILE = os.path.join(BACKEND_DIR, "requirements.txt")


def print_banner():
    print("=" * 70)
    print("  ZeroVault: Zero-Knowledge Encrypted File Sharing System")
    print("  Native Web Crypto API (AES-256-GCM, RSA-OAEP, PBKDF2)")
    print("=" * 70)


def check_and_install_dependencies():
    print("[1/3] Checking and installing Python dependencies...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS_FILE],
            cwd=BACKEND_DIR
        )
        print("[+] Dependencies verified.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error installing dependencies: {e}")
        sys.exit(1)


def start_server():
    print("[2/3] Starting ZeroVault FastAPI blind backend vault...")
    server_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000", "--reload"],
        cwd=BACKEND_DIR
    )
    
    # Wait for server to bind
    time.sleep(2)
    
    url = "http://127.0.0.1:8000"
    print(f"[3/3] System operational at: {url}")
    print("\n[✓] Opening browser dashboard...")
    try:
        webbrowser.open(url)
    except Exception:
        pass

    print("\nPress Ctrl+C to stop the ZeroVault server.\n")
    try:
        server_process.wait()
    except KeyboardInterrupt:
        print("\n[!] Shutting down ZeroVault...")
        server_process.terminate()
        server_process.wait()
        print("[✓] Server stopped safely.")


if __name__ == "__main__":
    print_banner()
    check_and_install_dependencies()
    start_server()
