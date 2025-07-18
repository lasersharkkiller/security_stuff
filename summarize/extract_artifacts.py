import os
import re
import json
import socket
import base64
import hashlib
import ipaddress
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Dummy:
        def __getattr__(self, attr): return ''
    Fore = Style = Dummy()

# === Setup ===
CURRENT_DIR = Path(".")
DECODED_DIR = CURRENT_DIR / "decoded"
DECODED_DIR.mkdir(exist_ok=True)
OUTPUT_FILE = "decoded_analysis_results.json"

# === Patterns ===
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
HEX_SHELLCODE_REGEX = r'(?:\\x[0-9a-fA-F]{2}){4,}'
RAW_HEX_BLOB_REGEX = r'\b(?:[0-9a-fA-F]{8,})\b'
BASE64_REGEX = r'(?<![\w+/=])(?:[A-Za-z0-9+/]{20,}={0,2})(?![\w+/=])'
ASM_KEYWORDS = ['mov', 'jmp', 'call', 'xor', 'push', 'pop', 'ret', 'int', 'syscall']

HEURISTIC_PATTERNS = {
    "password_grabber": [
        r'(?i)grab(pass(word)?|cred|token)',
        r'(?i)get(stored)?(password|credentials|secrets)',
        r'(?i)chrome.*(password|login)',
        r'(?i)firefox.*(password|login)',
        r'(?i)edge.*(password|login)',
        r'(?i)outlook.*(password|token)',
        r'(?i)browser.*(password|credentials)',
    ],
    "keylogger": [
        r'(?i)keylogger',
        r'(?i)GetAsyncKeyState',
        r'(?i)GetForegroundWindow',
        r'(?i)GetWindowText',
        r'(?i)keyboard hook',
        r'(?i)setwindows(hook)?ex',
        r'(?i)GetKeyState',
        r'(?i)LowLevelKeyboardProc'
    ]
}

MEMORY_HOOK_PATTERNS = [
    r'(?i)SetWindowsHookEx',
    r'(?i)GetAsyncKeyState',
    r'(?i)GetForegroundWindow',
    r'(?i)GetWindowText',
    r'(?i)GetKeyState',
    r'(?i)LowLevelKeyboardProc',
    r'(?i)CreateRemoteThread',
    r'(?i)VirtualAlloc(Ex)?',
    r'(?i)WriteProcessMemory',
    r'(?i)NtQuerySystemInformation',
    r'(?i)EnumWindows',
    r'(?i)ReadProcessMemory'
]

# === Utilities ===
def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False

def extract_intel(text):
    ips = list(set(ip for ip in re.findall(IP_REGEX, text) if is_public_ip(ip)))
    domains = list(set(re.findall(DOMAIN_REGEX, text)))
    return {"ips": ips, "domains": domains}

# === Main analysis ===
def detect_shellcode(text, filename):
    hits = []
    base64_payloads = re.findall(BASE64_REGEX, text)
    heuristic_hits = []
    memory_hooks = []
    decoded_b64 = []

    if re.search(HEX_SHELLCODE_REGEX, text):
        hits.append("hex_shellcode (\\x format)")
    if re.search(RAW_HEX_BLOB_REGEX, text):
        hits.append("raw_hex_blob")
    if any(asm in text.lower() for asm in ASM_KEYWORDS):
        hits.append("assembly keywords")

    # Heuristics
    for tag, patterns in HEURISTIC_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text):
                heuristic_hits.append(tag)
                break

    for pat in MEMORY_HOOK_PATTERNS:
        if re.search(pat, text):
            memory_hooks.append(pat.strip("(?i)"))

    # Base64 decode and analyze
    for b64 in base64_payloads:
        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            if decoded.strip():
                hashval = hashlib.sha256(decoded.encode()).hexdigest()
                outpath = DECODED_DIR / f"{filename}_{hashval[:8]}.txt"
                with open(outpath, "w", encoding="utf-8") as f:
                    f.write(decoded)
                print(f"{Fore.CYAN}[DECODED BASE64] saved to {outpath}{Style.RESET_ALL}")
                decoded_b64.append({
                    "sha256": hashval,
                    "sample": decoded[:100],
                    "file": str(outpath),
                    "intel": extract_intel(decoded)
                })
                for pat in MEMORY_HOOK_PATTERNS:
                    if re.search(pat, decoded):
                        memory_hooks.append(pat.strip("(?i)"))
        except Exception:
            continue

    if hits or decoded_b64 or heuristic_hits or memory_hooks:
        print(f"{Fore.MAGENTA}[SHELLCODE] Detected in {filename}: {', '.join(hits + heuristic_hits)}{Style.RESET_ALL}")
        if memory_hooks:
            print(f"{Fore.LIGHTRED_EX}[MEMORY HOOKS] {filename}: {', '.join(set(memory_hooks))}{Style.RESET_ALL}")
        return {
            "file": filename,
            "shellcode_detected": hits,
            "base64_decoded": decoded_b64,
            "heuristic_flags": heuristic_hits,
            "memory_api_hooks": list(set(memory_hooks))
        }
    return None

# === Run ===
results = []
for file in CURRENT_DIR.glob("*.txt"):
    with open(file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
        entry = detect_shellcode(content, file.name)
        if entry:
            results.append(entry)

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

print(f"\n✅ Analysis complete. Results saved to {OUTPUT_FILE}")
